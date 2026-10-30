"""C 담당: 계약 6장의 등급, 내림차순 rank, 설명 근거."""
from copy import deepcopy
from itertools import product

import pytest

from app.priority import score


def _card(**overrides):
    card = {
        "key": "CVE-2021-44228", "ids": ["CVE-2021-44228"],
        "sources": ["CISA KEV"], "title": "Test advisory",
        "summary": None, "workaround": None, "kev": False, "ransomware": False,
        "due_date": None, "cvss": None, "epss": None, "affected": [],
        "status": "미확정", "version": 1, "osv_checked_at": 0.0, "epss_checked": False,
    }
    return card | overrides


def _service(exposed=False):
    return {
        "name": "payment-api", "env": "prod", "internet_exposed": exposed,
        "manifests": [], "manifest_paths": {}, "deps": [],
    }


@pytest.mark.parametrize(("kev", "ransomware", "exposed"), list(product([False, True], repeat=3)))
def test_tiers_and_flag_rank(kev, ransomware, exposed):
    result = score(_card(kev=kev, ransomware=ransomware), _service(exposed))
    if kev or ransomware:
        assert result["tier"] == "긴급"
    elif exposed:
        assert result["tier"] == "높음"
    else:
        assert result["tier"] == "보통"
    assert result["rank"] == [int(kev), int(ransomware), int(exposed), 0.0, 0.0]


def test_internal_kev_outranks_exposed_high_epss_and_cvss():
    kev = score(_card(kev=True, epss=0.01, cvss=2.0), _service())
    exposed = score(_card(epss=0.99, cvss=10.0), _service(True))
    assert kev["tier"] == "긴급"
    assert exposed["tier"] == "높음"
    assert kev["rank"] > exposed["rank"]


def test_descending_order_respects_all_five_rank_positions():
    priorities = [
        score(_card(kev=True), _service()),
        score(_card(ransomware=True, epss=1.0, cvss=10.0), _service(True)),
        score(_card(epss=0.1, cvss=1.0), _service(True)),
        score(_card(epss=0.9, cvss=1.0), _service()),
        score(_card(epss=0.1, cvss=9.0), _service()),
        score(_card(epss=0.1, cvss=1.0), _service()),
    ]
    assert sorted(reversed(priorities), key=lambda p: p["rank"], reverse=True) == priorities


def test_reasons_explain_real_flags_and_known_metrics():
    result = score(_card(kev=True, ransomware=True, epss=0.97, cvss=10.0), _service(True))
    assert result == {
        "tier": "긴급", "rank": [1, 1, 1, 0.97, 10.0],
        "reasons": ["KEV 등록(실제 악용)", "랜섬웨어 악용", "인터넷 노출", "EPSS 0.97", "CVSS 10.0"],
    }


def test_unknown_metrics_have_zero_sort_values_but_no_invented_reasons():
    assert score(_card(), _service()) == {"tier": "보통", "rank": [0, 0, 0, 0.0, 0.0], "reasons": []}


def test_known_zero_metrics_are_not_treated_as_unknown():
    result = score(_card(epss=0.0, cvss=0.0), _service())
    assert result["rank"] == [0, 0, 0, 0.0, 0.0]
    assert result["reasons"] == ["EPSS 0.0", "CVSS 0.0"]


def test_score_is_repeatable_and_does_not_mutate_inputs():
    card = _card(kev=True, epss=0.5, cvss=7.0)
    service = _service(True)
    before = deepcopy((card, service))
    assert score(card, service) == score(card, service)
    assert (card, service) == before
