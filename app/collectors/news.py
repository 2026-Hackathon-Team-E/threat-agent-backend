"""보안 뉴스 RSS 폴링, CVE 추출, kind=news 이벤트. 담당: B kmssss56.

의존: app.enrich (같은 담당자 영역). 다른 역할 모듈은 import하지 않는다.
상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from app.types import Emit, State

CVE_PATTERN = r"CVE-\d{4}-\d{4,}"


def extract_cves(text: str) -> list[str]:
    """대문자 정규화된 CVE 목록 (중복 제거, 정렬)."""
    raise NotImplementedError


async def poll(
    http,
    state: State,
    emit: Emit,
    lookback_days: int,
    feeds: list[str],
    llm_key: str | None,
    llm_model: str,
) -> None:
    raise NotImplementedError
