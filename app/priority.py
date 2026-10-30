"""우선순위 계산 (CONTRACT 6장). 담당: C marineusus. 외부 의존 없음.

상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from app.types import Card, Priority, Service


def score(card: Card, svc: Service) -> Priority:
    raise NotImplementedError
