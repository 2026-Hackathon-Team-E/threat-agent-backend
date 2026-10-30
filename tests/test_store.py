"""Store 단위 테스트. 담당: D redsun2."""
from __future__ import annotations

from app.store import Store


def test_meta_get_set(store):
    assert store.get("kev:last") is None
    store.set("kev:last", "a")
    store.set("kev:last", "b")
    assert store.get("kev:last") == "b"


def test_mark_seen_only_first_time(store):
    assert store.mark_seen("CISA KEV", "CVE-2021-44228") is True
    assert store.mark_seen("CISA KEV", "CVE-2021-44228") is False
    # 소스가 다르면 별개로 본다
    assert store.mark_seen("GitHub Advisory", "CVE-2021-44228") is True


def test_card_roundtrip_and_alias(store, log4shell_card):
    store.put_card(log4shell_card)
    assert store.get_card("CVE-2021-44228") == log4shell_card
    # 다른 별칭, 소문자로도 같은 카드를 찾는다
    assert store.find_card(["GHSA-JFH8-GBNC-HGF2"]) == "CVE-2021-44228"
    assert store.find_card(["cve-2021-44228"]) == "CVE-2021-44228"
    assert store.find_card(["CVE-9999-0001"]) is None


def test_put_card_updates_not_duplicates(store, log4shell_card):
    store.put_card(log4shell_card)
    store.put_card({**log4shell_card, "version": 2, "epss": 0.97})
    cards = store.all_cards()
    assert len(cards) == 1
    assert cards[0]["version"] == 2 and cards[0]["epss"] == 0.97


def test_alias_keeps_first_card(store):
    store.add_alias("GHSA-x", "CVE-1")
    store.add_alias("GHSA-x", "CVE-2")
    assert store.find_card(["GHSA-x"]) == "CVE-1"


def test_impact_roundtrip_and_idempotent(store, sample_impact):
    store.put_impact(sample_impact)
    store.put_impact(sample_impact)
    assert len(store.all_impacts()) == 1
    assert store.get_impact(sample_impact["id"])["installed"] == "2.14.1"
    assert store.get_impact("없는-id") is None


def test_persists_to_file(tmp_path, log4shell_card):
    path = str(tmp_path / "sub" / "db.sqlite")  # 없는 폴더도 만든다
    Store(path).put_card(log4shell_card)
    assert Store(path).get_card("CVE-2021-44228")["kev"] is True


def test_memory_store_default():
    s = Store()
    s.set("k", "v")
    assert s.get("k") == "v"
