"""패키지 매칭 (생태계 일치, 이름 정규화, 버전 구간 포함). 담당: C marineusus.

상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from app.types import Affected, Card, Dep


def match(dep: Dep, card: Card) -> Affected | None:
    """카드의 affected 중 dep과 맞고 설치 버전이 취약 구간에 드는 항목. 없으면 None."""
    raise NotImplementedError


def fix_for(dep: Dep, affected: Affected) -> str | None:
    raise NotImplementedError
