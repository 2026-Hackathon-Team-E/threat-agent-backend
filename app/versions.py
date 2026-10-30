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


def _compare(v: str, bound: str) -> int:
    """v를 bound와 비교해 -1, 0, 1을 돌려준다.

    숫자 릴리스가 같으면 프리릴리스(2.15.0-beta)는 정식(2.15.0)보다 앞선 것으로 본다.
    그래서 2.15.0-beta 는 'fixed 2.15.0' 보다 작고 여전히 취약하다.
    """
    kv, kb = vkey(v), vkey(bound)
    if kv != kb:
        return -1 if kv < kb else 1
    pv, pb = is_pure_release(v), is_pure_release(bound)
    if pv == pb:
        return 0
    return -1 if not pv else 1


def in_interval(v: str, iv: Interval) -> bool:
    """양 끝의 포함 여부와 무한 경계를 반영해 구간 포함 여부를 반환한다."""
    if iv["lo"] is not None:
        c = _compare(v, iv["lo"])
        if c < 0 or (c == 0 and not iv["lo_inc"]):
            return False
    if iv["hi"] is not None:
        c = _compare(v, iv["hi"])
        if c > 0 or (c == 0 and not iv["hi_inc"]):
            return False
    return True


_PURE_RELEASE_RE = re.compile(r"[vV]?\d+(?:\.\d+)*")


def is_pure_release(v: str) -> bool:
    """접미사 없는 순수 숫자 릴리스인지 본다 (예: 2.15.0 은 True, 2.0-rc1 은 False)."""
    return _PURE_RELEASE_RE.fullmatch(v.strip()) is not None


def best_fix(installed: str, fixed_versions: list[str], intervals: list[Interval]) -> str | None:
    """설치 버전보다 크고 어떤 취약 구간에도 들지 않는 가장 작은 패치 버전. 없으면 None.

    프리릴리스(예: 2.0-rc1)는 수정 버전으로 추천하지 않는다.
    설치 버전에 숫자 릴리스가 없으면 비교할 수 없으므로 None을 돌려준다.
    """
    try:
        installed_key = vkey(installed)
    except ValueError:
        return None
    safe_versions = [
        version
        for version in fixed_versions
        if is_pure_release(version)
        and _compare(version, installed) > 0
        and not any(in_interval(version, iv) for iv in intervals)
    ]
    return min(safe_versions, key=vkey, default=None)
