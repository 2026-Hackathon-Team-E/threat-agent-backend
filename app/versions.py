"""버전 비교와 취약 구간 판정. 담당: C marineusus. 외부 의존 없음 (타입만 types.py).

계약: docs/CONTRACT.md 2장, 8장.
PoC에서는 숫자 릴리스 세그먼트만 비교하며 끝의 0은 동일하게 취급한다.
프리릴리스/빌드 접미사는 구분하지 않는다. 생태계별 전체 버전 규칙은 지원하지 않는다.
"""
from __future__ import annotations

import re

from app.types import Interval


def vkey(v: str) -> tuple[int, ...]:
    """숫자 릴리스 접두부를 비교 가능한 키로 만든다 (예: 1.10 > 1.9)."""
    release = re.match(r"[vV]?(\d+(?:\.\d+)*)", v.strip())
    if release is None:
        raise ValueError(f"숫자 릴리스 버전이 필요합니다: {v!r}")
    parts = [int(part) for part in release.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def in_interval(v: str, iv: Interval) -> bool:
    """양 끝의 포함 여부와 무한 경계를 반영해 구간 포함 여부를 반환한다."""
    key = vkey(v)
    if iv["lo"] is not None:
        lower = vkey(iv["lo"])
        if key < lower or (key == lower and not iv["lo_inc"]):
            return False
    if iv["hi"] is not None:
        upper = vkey(iv["hi"])
        if key > upper or (key == upper and not iv["hi_inc"]):
            return False
    return True


def best_fix(installed: str, fixed_versions: list[str], intervals: list[Interval]) -> str | None:
    """설치 버전보다 크고 어떤 취약 구간에도 들지 않는 가장 작은 패치 버전. 없으면 None."""
    installed_key = vkey(installed)
    safe_versions = [
        version
        for version in fixed_versions
        if vkey(version) > installed_key
        and not any(in_interval(version, iv) for iv in intervals)
    ]
    return min(safe_versions, key=vkey, default=None)
