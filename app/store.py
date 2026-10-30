"""SQLite 저장소. 담당: D redsun2. State 프로토콜을 구현한다 (types.State).

테이블: cards, alias, impacts, seen, meta.
카드와 영향 카드는 JSON 문자열로 통째로 저장한다 (PoC라 스키마를 단순하게 유지).
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from app.types import Card, Impact

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cards   (key TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alias   (alias TEXT PRIMARY KEY, card_key TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS impacts (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS seen    (source TEXT NOT NULL, item_id TEXT NOT NULL,
                                    PRIMARY KEY (source, item_id));
CREATE TABLE IF NOT EXISTS meta    (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def _norm(s: str) -> str:
    """CVE/GHSA 식별자는 대문자로 비교한다 (CONTRACT.md 머리말)."""
    return s.strip().upper()


class Store:
    def __init__(self, path: str | None = None) -> None:
        """path가 None이면 메모리 DB (테스트용)."""
        if path and path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # FastAPI는 동기 엔드포인트를 스레드풀에서 돌리므로 스레드 공유를 허용하고 락으로 보호한다.
        self._db = sqlite3.connect(path or ":memory:", check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()

    def _exec(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._db.execute(sql, args)
            self._db.commit()
            return cur

    def _rows(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # State 프로토콜
    def get(self, key: str) -> str | None:
        rows = self._rows("SELECT value FROM meta WHERE key = ?", (key,))
        return rows[0][0] if rows else None

    def set(self, key: str, value: str) -> None:
        self._exec(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def mark_seen(self, source: str, item_id: str) -> bool:
        cur = self._exec(
            "INSERT OR IGNORE INTO seen (source, item_id) VALUES (?, ?)", (source, item_id)
        )
        return cur.rowcount == 1

    # 카드
    def get_card(self, key: str) -> Card | None:
        rows = self._rows("SELECT data FROM cards WHERE key = ?", (_norm(key),))
        return json.loads(rows[0][0]) if rows else None

    def put_card(self, card: Card) -> None:
        """카드를 저장하고, 카드의 모든 ids를 별칭으로 등록한다."""
        key = _norm(card["key"])
        self._exec(
            "INSERT INTO cards (key, data) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET data = excluded.data",
            (key, json.dumps(card, ensure_ascii=False)),
        )
        for i in [key, *card.get("ids", [])]:
            self.add_alias(i, key)

    def all_cards(self) -> list[Card]:
        return [json.loads(r[0]) for r in self._rows("SELECT data FROM cards ORDER BY key")]

    def find_card(self, ids: list[str]) -> str | None:
        """ids 중 alias에 등록된 첫 카드 키."""
        for i in ids:
            rows = self._rows("SELECT card_key FROM alias WHERE alias = ?", (_norm(i),))
            if rows:
                return rows[0][0]
        return None

    def add_alias(self, alias: str, card_key: str) -> None:
        # 이미 다른 카드에 묶인 별칭은 바꾸지 않는다 (먼저 만든 카드 우선).
        self._exec(
            "INSERT OR IGNORE INTO alias (alias, card_key) VALUES (?, ?)",
            (_norm(alias), _norm(card_key)),
        )

    # 영향 카드
    def get_impact(self, impact_id: str) -> Impact | None:
        rows = self._rows("SELECT data FROM impacts WHERE id = ?", (impact_id,))
        return json.loads(rows[0][0]) if rows else None

    def put_impact(self, impact: Impact) -> None:
        self._exec(
            "INSERT INTO impacts (id, data) VALUES (?, ?) "
            "ON CONFLICT(id) DO UPDATE SET data = excluded.data",
            (impact["id"], json.dumps(impact, ensure_ascii=False)),
        )

    def all_impacts(self) -> list[Impact]:
        return [json.loads(r[0]) for r in self._rows("SELECT data FROM impacts ORDER BY id")]
