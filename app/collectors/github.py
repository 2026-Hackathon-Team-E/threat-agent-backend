"""GitHub Advisory 폴링, security_advisory 웹훅 변환, 서명 검증. 담당: A eddieyee100.

의존: 없음. 범위 문자열 변환(gh_interval)도 이 파일 안에 둔다.
상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from app.types import Emit, Event, Interval, State

GH_ADVISORY_URL = "https://api.github.com/advisories"


def gh_interval(spec: str) -> Interval:
    """GitHub 범위 문자열(">= a, < b") → Interval."""
    raise NotImplementedError


def advisory_event(a: dict, source: str) -> Event:
    raise NotImplementedError


def advisory_from_webhook(payload: dict) -> Event:
    raise NotImplementedError


def verify_signature(body: bytes, header: str | None, secret: str) -> bool:
    raise NotImplementedError


async def poll(http, state: State, emit: Emit, lookback_days: int, token: str | None) -> None:
    raise NotImplementedError
