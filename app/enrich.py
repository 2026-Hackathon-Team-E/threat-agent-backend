"""외부 보강: OSV 범위 조회, EPSS 점수, LLM 뉴스 추출. 담당: B kmssss56.

의존: 없음. 파이프라인(D)이 호출한다. OSV 응답 → Interval 변환도 이 파일에 둔다.
상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from app.types import Affected, Interval

OSV_URL = "https://api.osv.dev/v1/vulns/{vid}"
EPSS_URL = "https://api.first.org/data/v1/epss"


def osv_intervals(entry: dict) -> list[Interval]:
    """OSV affected 항목의 ranges/versions → Interval 목록."""
    raise NotImplementedError


async def osv(http, vid: str) -> list[Affected]:
    """vid(GHSA/CVE)의 affected 목록. 404나 빈 응답이면 []."""
    raise NotImplementedError


async def epss(http, cve: str) -> float | None:
    raise NotImplementedError


async def llm_extract(http, text: str, api_key: str | None, model: str) -> dict:
    """{"workaround": str, "products": [str]} 형태. 키가 없거나 파싱 실패면 {}."""
    raise NotImplementedError
