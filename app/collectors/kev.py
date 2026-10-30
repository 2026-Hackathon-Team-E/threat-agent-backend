"""CISA KEV 목록 폴링 → kind=kev 이벤트. 담당: A eddieyee100.

의존: 없음 (types.py, 표준 라이브러리, httpx 객체를 인자로 받음).
URL 상수는 이 파일에 둔다. config.py를 import하지 않는다.
상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from app.types import Emit, Event, State

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def kev_event(v: dict) -> Event:
    raise NotImplementedError


async def poll(http, state: State, emit: Emit, lookback_days: int) -> None:
    raise NotImplementedError
