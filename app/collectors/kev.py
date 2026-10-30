"""CISA KEV 목록 폴링 → kind=kev 이벤트. 담당: A eddieyee100.

의존: 없음 (types.py, 표준 라이브러리, httpx 객체를 인자로 받음).
URL 상수는 이 파일에 둔다. config.py를 import하지 않는다.
"""
from __future__ import annotations

import calendar
import logging
import time

import httpx

from app.types import Emit, Event, State

log = logging.getLogger("collectors.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def kev_event(v: dict) -> Event:
    """KEV 항목 하나를 kind=kev 이벤트로 바꾼다. 빈 값은 fields에 넣지 않는다."""
    cve = (v.get("cveID") or "").strip().upper()
    fields = {
        "title": v.get("vulnerabilityName") or None,
        "summary": v.get("shortDescription") or None,
        "workaround": v.get("requiredAction") or None,
        "kev": True,
        "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
        "due_date": v.get("dueDate") or None,
    }
    return {
        "source": "CISA KEV",
        "kind": "kev",
        "ids": [cve],
        "fields": fields,
    }


def _added_recently(date_added: str | None, lookback_days: int) -> bool:
    """dateAdded(YYYY-MM-DD)가 lookback_days 이내인지 본다. 날짜가 없거나 잘못되면 최근으로 본다."""
    if not date_added:
        return True
    try:
        ts = calendar.timegm(time.strptime(date_added, "%Y-%m-%d"))
    except ValueError:
        return True
    return ts >= time.time() - lookback_days * 86400


async def poll(http: httpx.AsyncClient, state: State, emit: Emit, lookback_days: int) -> None:
    """KEV 목록을 한 번 가져와 새 항목을 emit 한다.

    첫 실행(first_run 메타 없음)에는 lookback_days 이내에 추가된 항목만 낸다.
    이미 본 CVE는 mark_seen으로 걸러서 중복 emit 하지 않는다. 조회 실패는 로그만 남기고 넘어간다.
    """
    try:
        r = await http.get(KEV_URL, timeout=30)
        r.raise_for_status()
        vulnerabilities = r.json().get("vulnerabilities", [])
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("KEV 목록 가져오기 실패: %r", exc)
        return

    first = state.get("first_run:kev") is None
    for v in vulnerabilities:
        cve = (v.get("cveID") or "").strip().upper()
        if not cve or not state.mark_seen("kev", cve):
            continue
        if first and not _added_recently(v.get("dateAdded"), lookback_days):
            continue
        await emit(kev_event(v))
    state.set("first_run:kev", "done")
