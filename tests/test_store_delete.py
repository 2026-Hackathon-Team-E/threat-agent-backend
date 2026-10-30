"""Store.delete_card 테스트: 카드, 별칭, 영향 카드, 번역 캐시가 함께 지워지는지. 담당: 백엔드 저장소."""
from app.store import Store


def test_delete_card_removes_card_alias_impacts_and_cache(tmp_path):
    s = Store(str(tmp_path / "t.db"))
    s.put_card({"key": "NEWS:X1", "ids": ["NEWS:X1"], "status": "미확정", "version": 1, "affected": []})
    s.set("ko_desc:NEWS:X1", "요약")
    s.put_impact({"id": "i1", "card": "NEWS:X1", "service": "payment-api"})
    s.put_impact({"id": "i2", "card": "CVE-KEEP", "service": "payment-api"})

    s.delete_card("NEWS:X1")

    assert s.get_card("NEWS:X1") is None
    assert s.find_card(["NEWS:X1"]) is None
    assert s.get("ko_desc:NEWS:X1") is None
    ids = [i["id"] for i in s.all_impacts()]
    assert ids == ["i2"]
