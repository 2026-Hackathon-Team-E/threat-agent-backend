"""app/retention.py 테스트. 시간은 인자로 받아 고정한다. 담당: 백엔드 정리·갱신."""
from app.retention import DAY, HOUR, expired_keys, refresh_keys

NOW = 1_800_000_000.0


def card(key, age_days=0, status="미확정", kev=False):
    c = {"key": key, "status": status, "kev": kev}
    if age_days is not None:
        c["updated_at"] = NOW - age_days * DAY
    return c


def test_old_unconfirmed_news_card_is_expired():
    cards = [card("NEWS:AAA", age_days=40)]
    assert expired_keys(cards, set(), NOW, news_days=30) == ["NEWS:AAA"]


def test_recent_news_card_is_kept():
    cards = [card("NEWS:BBB", age_days=5)]
    assert expired_keys(cards, set(), NOW, news_days=30) == []


def test_news_card_with_impact_is_kept():
    cards = [card("NEWS:CCC", age_days=90)]
    assert expired_keys(cards, {"NEWS:CCC"}, NOW, news_days=30) == []


def test_cve_cards_are_never_expired_by_news_rule():
    cards = [card("CVE-2026-1", age_days=400)]
    assert expired_keys(cards, set(), NOW, news_days=30) == []


def test_confirmed_or_kev_news_card_is_kept():
    cards = [card("NEWS:DDD", age_days=90, status="확정"), card("NEWS:EEE", age_days=90, kev=True)]
    assert expired_keys(cards, set(), NOW, news_days=30) == []


def test_card_without_timestamp_is_not_expired_immediately():
    cards = [card("NEWS:FFF", age_days=None)]
    assert expired_keys(cards, set(), NOW, news_days=30) == []


def test_refresh_picks_stale_unconfirmed_oldest_first_with_limit():
    cards = [
        card("CVE-A", age_days=1),  # 미확정 아님 → 제외 (아래에서 status 바꿈)
        {"key": "CVE-B", "status": "미확정", "updated_at": NOW - 10 * HOUR},
        {"key": "CVE-C", "status": "미확정", "updated_at": NOW - 30 * HOUR},
        {"key": "CVE-D", "status": "미확정", "updated_at": NOW - 1 * HOUR},  # 아직 신선
    ]
    cards[0]["status"] = "확정"
    assert refresh_keys(cards, NOW, stale_hours=6, limit=20) == ["CVE-C", "CVE-B"]
    assert refresh_keys(cards, NOW, stale_hours=6, limit=1) == ["CVE-C"]
