"""SQLite 저장소. 담당: D redsun2. State 프로토콜을 구현한다 (types.State).

테이블: cards, alias, impacts, seen, meta. 상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from app.types import Card, Impact


class Store:
    def __init__(self, path: str | None = None) -> None:
        raise NotImplementedError

    # State 프로토콜
    def get(self, key: str) -> str | None:
        raise NotImplementedError

    def set(self, key: str, value: str) -> None:
        raise NotImplementedError

    def mark_seen(self, source: str, item_id: str) -> bool:
        raise NotImplementedError

    # 카드
    def get_card(self, key: str) -> Card | None:
        raise NotImplementedError

    def put_card(self, card: Card) -> None:
        raise NotImplementedError

    def all_cards(self) -> list[Card]:
        raise NotImplementedError

    def find_card(self, ids: list[str]) -> str | None:
        """ids 중 alias에 등록된 첫 카드 키."""
        raise NotImplementedError

    def add_alias(self, alias: str, card_key: str) -> None:
        raise NotImplementedError

    # 영향 카드
    def get_impact(self, impact_id: str) -> Impact | None:
        raise NotImplementedError

    def put_impact(self, impact: Impact) -> None:
        raise NotImplementedError

    def all_impacts(self) -> list[Impact]:
        raise NotImplementedError
