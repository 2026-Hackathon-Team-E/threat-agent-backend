"""app/card_view.py 테스트. 외부 호출 없음. 담당: D redsun2 영역."""
from app.card_view import build, products, risk_label, summary_ko

BASE = ("key", "title", "kev", "ransomware", "epss", "status")


def test_kev_is_urgent_and_says_actively_exploited():
    card = {"kev": True, "ransomware": False, "epss": 0.99, "status": "확정"}
    assert risk_label(card) == "긴급"
    assert "악용되고 있는" in summary_ko(card)


def test_ransomware_wording_wins_over_kev():
    card = {"kev": True, "ransomware": True}
    assert "랜섬웨어" in summary_ko(card)


def test_high_epss_without_kev_is_high():
    card = {"kev": False, "epss": 0.6}
    assert risk_label(card) == "높음"


def test_low_signal_news_only_card_is_normal_and_says_unconfirmed():
    card = {"kev": False, "epss": None, "status": "미확정"}
    assert risk_label(card) == "보통"
    assert "아직 확인되지 않은" in summary_ko(card)


def test_confirmed_package_without_kev_mentions_vulnerable_version():
    card = {"kev": False, "epss": 0.01, "status": "확정"}
    assert "취약 버전이 확인됐습니다" in summary_ko(card)


def test_products_use_short_names_and_dedupe():
    card = {"affected": [
        {"name": "org.apache.logging.log4j:log4j-core"},
        {"name": "org.apache.logging.log4j:log4j-core"},
        {"name": "PyYAML"},
    ]}
    assert products(card) == ["log4j-core", "PyYAML"]


def test_build_lists_only_services_with_impacts_for_this_card():
    card = {"key": "CVE-2021-44228", "kev": True, "epss": 0.97, "status": "확정", "title": "x", "affected": []}
    impacts = [
        {"card": "CVE-2021-44228", "service": "payment-api"},
        {"card": "CVE-2021-44228", "service": "payment-api"},
        {"card": "CVE-9999-0001", "service": "internal-report"},
    ]
    out = build(card, impacts, BASE)
    assert out["affected_services"] == ["payment-api"]
    assert out["epss_percent"] == 97.0
    assert out["risk_label"] == "긴급"
    assert out["key"] == "CVE-2021-44228"
