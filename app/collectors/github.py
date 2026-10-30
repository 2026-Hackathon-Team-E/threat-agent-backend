"""GitHub Advisory 폴링, security_advisory 웹훅 변환, 서명 검증. 담당: A eddieyee100.

의존: 없음. 범위 문자열 변환(gh_interval)도 이 파일 안에 둔다.
"""
from __future__ import annotations

import calendar
import hashlib
import hmac
import logging
import re
import time

import httpx

from app.types import Affected, Emit, Event, Interval, State

log = logging.getLogger("collectors.github")

GH_ADVISORY_URL = "https://api.github.com/advisories"
SOURCE = "GitHub Advisory"

# GitHub 생태계 이름 → 계약의 생태계 이름 (PyPI | Maven | npm). 그 밖은 지원하지 않는다.
_ECOSYSTEMS = {"pip": "PyPI", "maven": "Maven", "npm": "npm"}
_CLAUSE_RE = re.compile(r"(>=|<=|>|<|=)\s*(\S+)")


def gh_interval(spec: str) -> Interval:
    """GitHub 범위 문자열(">= a, < b") → Interval. 해석할 수 없으면 ValueError."""
    iv: Interval = {"lo": None, "lo_inc": True, "hi": None, "hi_inc": False}
    for clause in spec.split(","):
        clause = clause.strip()
        if not clause:
            continue
        m = _CLAUSE_RE.fullmatch(clause)
        if not m:
            raise ValueError(f"알 수 없는 범위 조건: {clause!r}")
        op, ver = m.groups()
        if op == ">=":
            iv["lo"], iv["lo_inc"] = ver, True
        elif op == ">":
            iv["lo"], iv["lo_inc"] = ver, False
        elif op == "<":
            iv["hi"], iv["hi_inc"] = ver, False
        elif op == "<=":
            iv["hi"], iv["hi_inc"] = ver, True
        else:  # "="
            iv["lo"], iv["lo_inc"] = ver, True
            iv["hi"], iv["hi_inc"] = ver, True
    return iv


def _affected_list(a: dict, source: str) -> list[Affected]:
    out: list[Affected] = []
    for vuln in a.get("vulnerabilities") or []:
        pkg = vuln.get("package") or {}
        ecosystem = _ECOSYSTEMS.get((pkg.get("ecosystem") or "").lower())
        name = pkg.get("name")
        if not ecosystem or not name:
            continue
        intervals: list[Interval] = []
        spec = vuln.get("vulnerable_version_range")
        if spec:
            try:
                intervals.append(gh_interval(spec))
            except ValueError as exc:
                log.warning("범위 해석 실패 %s %s: %s", name, spec, exc)
                continue
        # REST API는 문자열, 일부 웹훅 본문은 {"identifier": ...} 객체로 준다. 둘 다 받는다.
        raw_patched = vuln.get("first_patched_version")
        if isinstance(raw_patched, dict):
            patched = raw_patched.get("identifier")
        else:
            patched = raw_patched or None
        out.append(
            {
                "ecosystem": ecosystem,
                "name": name,
                "intervals": intervals,
                "fixed_versions": [patched] if patched else [],
                "source": source,
            }
        )
    return out


def advisory_event(a: dict, source: str) -> Event:
    """GitHub 어드바이저리(API 또는 웹훅 본문) 하나를 kind=advisory 이벤트로 바꾼다."""
    cve = (a.get("cve_id") or "").strip().upper()
    ghsa = (a.get("ghsa_id") or "").strip().upper()
    cvss = (a.get("cvss") or {}).get("score")
    fields = {
        "title": a.get("summary") or None,
        "summary": a.get("description") or None,
        "cvss": cvss,
        "affected": _affected_list(a, source),
    }
    return {
        "source": source,
        "kind": "advisory",
        "ids": [cve or ghsa] if (cve or ghsa) else [],
        "fields": fields,
    }


def advisory_from_webhook(payload: dict) -> Event:
    """security_advisory 웹훅 본문(payload["security_advisory"])을 이벤트로 바꾼다."""
    return advisory_event(payload.get("security_advisory") or {}, f"{SOURCE} 웹훅")


def verify_signature(body: bytes, header: str | None, secret: str) -> bool:
    """X-Hub-Signature-256 헤더("sha256=<hex>")가 본문과 secret으로 만든 HMAC과 같은지 본다."""
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header[len("sha256="):], expected)


async def poll(http: httpx.AsyncClient, state: State, emit: Emit, lookback_days: int, token: str | None) -> None:
    """GitHub 리뷰 완료 어드바이저리를 가져와 새 항목을 emit 한다.

    첫 실행에는 lookback_days 이내에 발행된 항목만 낸다. 이미 본 GHSA는 mark_seen으로 건너뛴다.
    조회 실패는 로그만 남기고 넘어간다.
    """
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = await http.get(
            GH_ADVISORY_URL,
            params={"type": "reviewed", "per_page": 100, "sort": "published", "direction": "desc"},
            headers=headers,
            timeout=30,
        )
        r.raise_for_status()
        advisories = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("GitHub 어드바이저리 가져오기 실패: %r", exc)
        return
    if not isinstance(advisories, list):
        log.warning("GitHub 어드바이저리 응답 형식이 목록이 아님")
        return

    first = state.get("first_run:github") is None
    for a in advisories:
        ghsa = (a.get("ghsa_id") or "").strip().upper()
        if not ghsa or not state.mark_seen("github", ghsa):
            continue
        if first and not _published_recently(a.get("published_at"), lookback_days):
            continue
        await emit(advisory_event(a, SOURCE))
    state.set("first_run:github", "done")


def _published_recently(published_at: str | None, lookback_days: int) -> bool:
    """published_at(ISO 8601, UTC 'Z')이 lookback_days 이내인지 본다. 파싱 못 하면 최근으로 본다."""
    if not published_at:
        return True
    try:
        ts = calendar.timegm(time.strptime(published_at[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return True
    return ts >= time.time() - lookback_days * 86400
