"""이벤트 처리: 카드 병합, 외부 보강 호출, 매칭, 수정 적용, 재스캔. 담당: D redsun2.

의존 (시그니처만): enrich(B), matcher·priority(C), remediate·sbom(E), store(D).
수집기는 이 모듈을 import하지 않는다 (이벤트만 큐로 보낸다).

흐름: 이벤트 → 카드 병합(별칭) → 보강(OSV·EPSS) → 바뀌었으면 scan → 새 영향 카드마다 act
"""
from __future__ import annotations

import logging
import time
from pathlib import Path

from app import enrich, matcher, priority, remediate, sbom
from app.store import Store
from app.types import Card, Event, Impact, Service

log = logging.getLogger("threat-agent.pipeline")

# 이벤트 fields 중 카드에 그대로 덮어쓰는 단순 필드
_SIMPLE_FIELDS = ("title", "summary", "workaround", "kev", "ransomware", "due_date", "cvss")
OSV_RECHECK_SEC = 3600


def _empty(v) -> bool:
    return v is None or v == "" or v is False or v == []


def _new_card(key: str) -> Card:
    return {
        "key": key, "ids": [], "sources": [], "title": None, "summary": None, "workaround": None,
        "kev": False, "ransomware": False, "due_date": None, "cvss": None, "epss": None,
        "affected": [], "status": "미확정", "version": 0, "osv_checked_at": 0.0, "epss_checked": False,
    }


def _card_key(ids: list[str]) -> str:
    """첫 번째 CVE, 없으면 첫 번째 ID."""
    return next((i for i in ids if i.startswith("CVE-")), ids[0])


def _aff_sig(a: dict) -> tuple:
    return (a.get("ecosystem"), a.get("name"), str(a.get("intervals")))


def merge(card: Card, ev: Event) -> bool:
    """이벤트 내용을 카드에 합친다. 실제로 바뀐 게 있으면 True."""
    changed = False
    for i in ev.get("ids", []):
        if i not in card["ids"]:
            card["ids"].append(i)
            changed = True
    src = ev.get("source")
    if src and src not in card["sources"]:
        card["sources"].append(src)
        changed = True
    fields = ev.get("fields") or {}
    for f in _SIMPLE_FIELDS:
        v = fields.get(f)
        if not _empty(v) and card.get(f) != v:
            card[f] = v
            changed = True
    changed |= _add_affected(card, fields.get("affected") or [])
    return changed


def _add_affected(card: Card, affected: list) -> bool:
    have = {_aff_sig(a) for a in card["affected"]}
    added = False
    for a in affected:
        if _aff_sig(a) not in have:
            card["affected"].append(a)
            have.add(_aff_sig(a))
            added = True
    return added


async def _enrich(card: Card, http) -> bool:
    """범위가 없으면 OSV, EPSS가 없으면 EPSS 조회. 실패해도 예외를 밖으로 내지 않는다."""
    changed = False
    now = time.time()
    if not card["affected"] and now - card["osv_checked_at"] > OSV_RECHECK_SEC:
        card["osv_checked_at"] = now
        # GHSA가 OSV에서 범위 정보가 더 정확하므로 먼저 본다
        for vid in sorted(card["ids"], key=lambda x: not x.startswith("GHSA-")):
            try:
                found = await enrich.osv(http, vid)
            except Exception as e:  # noqa: BLE001
                log.warning("OSV 조회 실패 %s: %r", vid, e)
                continue
            if found and _add_affected(card, found):
                changed = True
                break
    if not card["epss_checked"] and card["key"].startswith("CVE-"):
        card["epss_checked"] = True
        try:
            score = await enrich.epss(http, card["key"])
        except Exception as e:  # noqa: BLE001
            log.warning("EPSS 조회 실패 %s: %r", card["key"], e)
            score = None
        if score is not None and score != card["epss"]:
            card["epss"] = score
            changed = True
    return changed


async def handle_event(
    ev: Event,
    store: Store,
    http,
    services: dict[str, Service],
    workspace: Path,
) -> list[Impact]:
    """이벤트 하나 처리. 새로 생긴 영향 카드(수정 적용 후)를 반환."""
    if ev.get("kind") == "deploy":
        return await on_deploy(ev["service"], store, services, workspace)

    ids = [i.strip().upper() for i in ev.get("ids", []) if i and i.strip()]
    if not ids:
        return []
    ev = {**ev, "ids": ids}

    key = store.find_card(ids) or _card_key(ids)
    card = store.get_card(key) or _new_card(key)
    is_new = card["version"] == 0

    changed = merge(card, ev)
    changed |= await _enrich(card, http)
    card["status"] = "확정" if card["affected"] else "미확정"

    if not changed and not is_new:
        store.put_card(card)  # osv_checked_at 같은 내부 값만 저장, version 유지
        log.info("변경 없음: %s (v%d)", key, card["version"])
        return []

    card["version"] += 1
    card["updated_at"] = time.time()
    store.put_card(card)
    log.info("카드 갱신: %s v%d kev=%s affected=%d", key, card["version"], card["kev"], len(card["affected"]))

    new = scan(card, store, list(services.values()))
    return [act(imp, store, services, workspace) for imp in new]


def _impact_id(card: Card, svc: Service, dep: dict) -> str:
    return f"{card['key']}@{svc['name']}:{dep['ecosystem']}:{dep['name']}"


def scan(card, store: Store, services: list[Service]) -> list[Impact]:
    """새로 생긴 영향 카드만 반환 (같은 id는 재생성하지 않는다).

    이미 있는 영향 카드는 우선순위만 갱신한다. 예: 뉴스로 먼저 잡힌 위협이 KEV에 오르면 등급이 바로 올라간다.
    """
    new: list[Impact] = []
    for svc in services:
        for dep in svc.get("deps", []):
            aff = matcher.match(dep, card)
            if not aff:
                continue
            iid = _impact_id(card, svc, dep)
            prio = priority.score(card, svc)
            old = store.get_impact(iid)
            if old:
                if old["priority"] != prio or old["title"] != card["title"]:
                    old["priority"], old["title"] = prio, card["title"]
                    store.put_impact(old)
                    log.warning("영향 카드 등급 갱신: %s → %s", iid, prio["tier"])
                continue
            imp: Impact = {
                "id": iid,
                "card": card["key"],
                "title": card["title"],
                "service": svc["name"],
                "env": svc["env"],
                "exposed": svc["internet_exposed"],
                "dep": dep["name"],
                "ecosystem": dep["ecosystem"],
                "installed": dep["version"],
                "fixed": matcher.fix_for(dep, aff),
                "priority": prio,
                "status": "미조치",
                "remediation": None,
                "rescan": None,
            }
            store.put_impact(imp)
            log.warning("영향 카드 생성: %s [%s]", iid, prio["tier"])
            new.append(imp)
    return new


def count_hits(card: Card, svc: Service) -> int:
    """서비스에서 이 카드에 여전히 취약한 의존성 수."""
    return sum(1 for dep in svc.get("deps", []) if matcher.match(dep, card))


def act(imp: Impact, store: Store, services: dict[str, Service], workspace: Path) -> Impact:
    """수정 제안을 만들고, 버전 올림이면 워크스페이스 사본으로 재스캔한다."""
    svc = services.get(imp["service"])
    card = store.get_card(imp["card"])
    if not svc or not card:
        return imp
    dep = next(
        (d for d in svc["deps"] if d["name"] == imp["dep"] and d["ecosystem"] == imp["ecosystem"]),
        None,
    )
    if not dep:
        return imp
    try:
        rem = remediate.propose(svc, dep, card, imp["fixed"], workspace)
    except Exception as e:  # noqa: BLE001
        log.warning("수정 제안 실패 %s: %r", imp["id"], e)
        return imp
    imp["remediation"] = rem

    if rem.get("kind") == "bump":
        try:
            fresh = sbom.load_one(svc["name"])  # 워크스페이스 사본 기준으로 다시 읽는다
            services[svc["name"]] = fresh
            imp["rescan"] = count_hits(card, fresh)
        except Exception as e:  # noqa: BLE001
            log.warning("재스캔 실패 %s: %r", imp["id"], e)
            imp["rescan"] = None
        imp["status"] = "수정 완료" if imp["rescan"] == 0 else "수정 후 잔존"
    else:
        imp["status"] = "수정 제안"

    store.put_impact(imp)
    log.warning("수정 처리: %s → %s (rescan=%s)", imp["id"], imp["status"], imp["rescan"])
    return imp


async def on_deploy(name: str, store: Store, services: dict[str, Service], workspace: Path) -> list[Impact]:
    """배포된 서비스 하나만 기존 카드 전체와 다시 매칭한다."""
    svc = sbom.load_one(name)
    services[name] = svc
    out: list[Impact] = []
    for card in store.all_cards():
        for imp in scan(card, store, [svc]):
            out.append(act(imp, store, services, workspace))
    return out
