"""scan/act/handle_event 통합 테스트 (외부 호출 없음). 담당: D redsun2.

다른 역할(B·C·E)의 함수는 monkeypatch로 가짜 구현을 넣어, 그쪽 구현 여부와 관계없이 통과한다.
"""
from __future__ import annotations

import asyncio

import pytest

from app import pipeline

LOG4J = "org.apache.logging.log4j:log4j-core"


def _v(s):
    return tuple(int(x) for x in s.split("."))


def fake_match(dep, card):
    for a in card["affected"]:
        if a["ecosystem"] != dep["ecosystem"] or a["name"] != dep["name"]:
            continue
        for iv in a["intervals"]:
            lo_ok = iv["lo"] is None or _v(dep["version"]) >= _v(iv["lo"])
            hi_ok = iv["hi"] is None or _v(dep["version"]) < _v(iv["hi"])
            if lo_ok and hi_ok:
                return a
    return None


def fake_score(card, svc):
    tier = "긴급" if card["kev"] or card["ransomware"] else "높음" if svc["internet_exposed"] else "보통"
    return {"tier": tier, "rank": [int(card["kev"]), int(card["ransomware"]), int(svc["internet_exposed"]),
                                   card["epss"] or 0, card["cvss"] or 0], "reasons": []}


def make_svc(version="2.14.1"):
    return {"name": "payment-api", "env": "prod", "internet_exposed": True, "manifests": ["pom.xml"],
            "manifest_paths": {}, "deps": [{"ecosystem": "Maven", "name": LOG4J, "version": version,
                                            "source": "pom.xml"}]}


AFFECTED = [{"ecosystem": "Maven", "name": LOG4J,
             "intervals": [{"lo": "2.0.0", "lo_inc": True, "hi": "2.15.0", "hi_inc": False}],
             "fixed_versions": ["2.15.0"], "source": "test"}]


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    async def no_osv(http, vid):
        return []

    async def epss(http, cve):
        return 0.97

    monkeypatch.setattr(pipeline.enrich, "osv", no_osv)
    monkeypatch.setattr(pipeline.enrich, "epss", epss)
    monkeypatch.setattr(pipeline.matcher, "match", fake_match)
    monkeypatch.setattr(pipeline.matcher, "fix_for", lambda dep, aff: aff["fixed_versions"][0])
    monkeypatch.setattr(pipeline.priority, "score", fake_score)
    monkeypatch.setattr(pipeline.remediate, "propose",
                        lambda svc, dep, card, fixed, ws: {"kind": "bump", "text": f"{dep['name']} → {fixed}",
                                                           "diff": "--- a/pom.xml\n+++ b/pom.xml\n"})
    monkeypatch.setattr(pipeline.sbom, "load_one", lambda name: make_svc("2.15.0"))


def run(ev, store, services, tmp_path):
    return asyncio.run(pipeline.handle_event(ev, store, None, services, tmp_path))


def kev_event():
    return {"source": "CISA KEV", "kind": "kev", "ids": ["CVE-2021-44228"],
            "fields": {"title": "Log4Shell", "kev": True, "cvss": 10.0, "affected": AFFECTED}}


def test_kev_event_creates_fixed_impact(store, tmp_path):
    out = run(kev_event(), store, {"payment-api": make_svc()}, tmp_path)
    assert len(out) == 1
    imp = out[0]
    assert imp["id"] == f"CVE-2021-44228@payment-api:Maven:{LOG4J}"
    assert imp["fixed"] == "2.15.0"
    assert imp["priority"]["tier"] == "긴급"
    assert imp["status"] == "수정 완료" and imp["rescan"] == 0
    card = store.get_card("CVE-2021-44228")
    assert card["status"] == "확정" and card["epss"] == 0.97 and card["version"] == 1


def test_same_event_twice_is_idempotent(store, tmp_path):
    services = {"payment-api": make_svc()}
    run(kev_event(), store, services, tmp_path)
    services["payment-api"] = make_svc()  # 같은 상태에서 다시 들어와도
    assert run(kev_event(), store, services, tmp_path) == []
    assert len(store.all_impacts()) == 1
    assert store.get_card("CVE-2021-44228")["version"] == 1


def test_news_then_kev_merges_and_upgrades_tier(store, tmp_path, monkeypatch):
    # 수정 단계를 "제안"으로 바꿔 서비스가 취약한 상태를 유지한다
    monkeypatch.setattr(pipeline.remediate, "propose",
                        lambda *a: {"kind": "workaround", "text": "임시 조치", "diff": None})
    services = {"payment-api": make_svc()}
    news = {"source": "뉴스:The Hacker News", "kind": "news", "ids": ["cve-2021-44228"],
            "fields": {"title": "Log4j 긴급", "affected": AFFECTED}}
    out = run(news, store, services, tmp_path)
    assert out[0]["priority"]["tier"] == "높음" and out[0]["status"] == "수정 제안"

    assert run(kev_event(), store, services, tmp_path) == []  # 새로 만들지 않고
    imp = store.all_impacts()[0]
    assert imp["priority"]["tier"] == "긴급"  # 등급만 올라간다
    card = store.get_card("CVE-2021-44228")
    assert card["version"] == 2 and card["sources"] == ["뉴스:The Hacker News", "CISA KEV"]


def test_empty_values_do_not_overwrite(store, tmp_path):
    run(kev_event(), store, {"payment-api": make_svc()}, tmp_path)
    ev = {"source": "CISA KEV", "kind": "kev", "ids": ["CVE-2021-44228"],
          "fields": {"title": "", "kev": False, "cvss": None, "affected": []}}
    run(ev, store, {"payment-api": make_svc()}, tmp_path)
    card = store.get_card("CVE-2021-44228")
    assert card["title"] == "Log4Shell" and card["kev"] is True and card["cvss"] == 10.0


def test_news_without_range_is_unconfirmed(store, tmp_path):
    ev = {"source": "뉴스", "kind": "news", "ids": ["CVE-2026-0001"], "fields": {"title": "새 취약점"}}
    assert run(ev, store, {"payment-api": make_svc()}, tmp_path) == []
    assert store.get_card("CVE-2026-0001")["status"] == "미확정"


def test_ghsa_alias_joins_existing_card(store, tmp_path):
    run(kev_event(), store, {"payment-api": make_svc()}, tmp_path)
    ev = {"source": "GitHub Advisory", "kind": "advisory", "ids": ["GHSA-jfh8-gbnc-hgf2", "CVE-2021-44228"],
          "fields": {}}
    run(ev, store, {"payment-api": make_svc("2.15.0")}, tmp_path)
    assert len(store.all_cards()) == 1
    assert store.find_card(["GHSA-JFH8-GBNC-HGF2"]) == "CVE-2021-44228"


def test_safe_version_no_impact(store, tmp_path):
    assert run(kev_event(), store, {"payment-api": make_svc("2.17.1")}, tmp_path) == []
    assert store.all_impacts() == []
