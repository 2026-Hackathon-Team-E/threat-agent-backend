"""버전 비교와 취약 구간 판정. 담당: C marineusus. 외부 의존 없음 (타입만 types.py).

계약: docs/CONTRACT.md 2장, 6장. 상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from app.types import Interval


def vkey(v: str) -> tuple[int, ...]:
    raise NotImplementedError


def in_interval(v: str, iv: Interval) -> bool:
    raise NotImplementedError


def best_fix(installed: str, fixed_versions: list[str], intervals: list[Interval]) -> str | None:
    """설치 버전보다 크고 어떤 취약 구간에도 들지 않는 가장 작은 패치 버전. 없으면 None."""
    raise NotImplementedError
