"""오래된 카드 정리와 미확정 카드 갱신 대상 고르기. 순수 함수만 둔다 (저장소·네트워크 접근 없음)."""
from __future__ import annotations

from app.types import Card

DAY = 86400
HOUR = 3600


def _age(card: dict, now: float) -> float:
    # 시각 기록이 없는 예전 카드는 지금 바뀐 것으로 본다 (바로 지우지 않기 위해)
    return now - float(card.get("updated_at") or now)


def expired_keys(cards: list[Card], impact_card_keys: set[str], now: float, news_days: int = 30) -> list[str]:
    """정리 대상: 뉴스만으로 올라온 미확정 카드 중 news_days일 넘게 안 바뀐 것. 영향 카드가 있으면 남긴다."""
    out = []
    for c in cards:
        if not c["key"].startswith("NEWS:"):
            continue
        if c.get("status") != "미확정" or c.get("kev"):
            continue
        if c["key"] in impact_card_keys:
            continue
        if _age(c, now) > news_days * DAY:
            out.append(c["key"])
    return out


def refresh_keys(cards: list[Card], now: float, stale_hours: int = 6, limit: int = 20) -> list[str]:
    """갱신 대상: 미확정 카드 중 stale_hours시간 넘게 안 바뀐 것을 오래된 순으로 최대 limit건."""
    stale = [c for c in cards if c.get("status") == "미확정" and _age(c, now) > stale_hours * HOUR]
    stale.sort(key=lambda c: float(c.get("updated_at") or 0))
    return [c["key"] for c in stale[:limit]]
