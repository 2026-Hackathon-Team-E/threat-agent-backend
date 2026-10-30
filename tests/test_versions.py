"""C 담당: 숫자 버전 비교, 열린/닫힌 경계, 안전한 패치 선택."""
from copy import deepcopy

import pytest

from app.versions import best_fix, in_interval, vkey


@pytest.mark.parametrize(
    ("lower", "higher"),
    [("1.9", "1.10"), ("2.9.9", "2.10"), ("1.0", "1.0.1"), ("0.9", "1")],
)
def test_numeric_release_order(lower, higher):
    assert vkey(lower) < vkey(higher)


@pytest.mark.parametrize("version", ["1", "1.0", "1.0.0", "01.00"])
def test_equivalent_release_spellings(version):
    assert vkey(version) == vkey("1")


def test_prerelease_and_build_ordering_is_outside_poc():
    assert vkey("1.2.3-rc.1") == vkey("1.2.3+build.9") == vkey("1.2.3")


@pytest.mark.parametrize("version", ["", "unknown"])
def test_version_without_numeric_release_is_rejected(version):
    with pytest.raises(ValueError):
        vkey(version)


@pytest.mark.parametrize(
    ("version", "expected"),
    [("1.9.9", False), ("2.0", True), ("2.14.1", True), ("2.15.0", False), ("2.16", False)],
)
def test_contract_half_open_interval(version, expected):
    interval = {"lo": "2.0.0", "lo_inc": True, "hi": "2.15.0", "hi_inc": False}
    assert in_interval(version, interval) is expected


@pytest.mark.parametrize(
    ("lo_inc", "hi_inc", "at_lower", "at_upper"),
    [(True, True, True, True), (True, False, True, False),
     (False, True, False, True), (False, False, False, False)],
)
def test_all_boundary_inclusion_combinations(lo_inc, hi_inc, at_lower, at_upper):
    interval = {"lo": "1", "lo_inc": lo_inc, "hi": "2", "hi_inc": hi_inc}
    assert in_interval("1.0", interval) is at_lower
    assert in_interval("1.5", interval)
    assert in_interval("2.0.0", interval) is at_upper


@pytest.mark.parametrize("version", ["0", "0.0.1", "1.9"])
def test_unbounded_lower_end_includes_all_lower_versions(version):
    interval = {"lo": None, "lo_inc": False, "hi": "2", "hi_inc": False}
    assert in_interval(version, interval)


def test_unbounded_upper_end():
    interval = {"lo": "2", "lo_inc": True, "hi": None, "hi_inc": False}
    assert in_interval("999.1", interval)
    assert not in_interval("1.9", interval)


def test_both_unbounded():
    assert in_interval("0", {"lo": None, "lo_inc": False, "hi": None, "hi_inc": False})


@pytest.mark.parametrize("included", [True, False])
def test_single_version_interval(included):
    interval = {"lo": "1.2", "lo_inc": included, "hi": "1.2", "hi_inc": True}
    assert in_interval("1.2.0", interval) is included
    assert not in_interval("1.2.1", interval)


def test_inverted_interval_matches_nothing():
    assert not in_interval("2", {"lo": "3", "lo_inc": True, "hi": "1", "hi_inc": True})


def test_best_fix_uses_smallest_safe_upgrade_and_preserves_inputs():
    versions = ["2.17.1", "2.15.0", "2.14.1", "2.16.0", "2.17.1"]
    intervals = [
        {"lo": "2", "lo_inc": True, "hi": "2.15", "hi_inc": False},
        {"lo": "2.15", "lo_inc": True, "hi": "2.17.1", "hi_inc": False},
    ]
    before = deepcopy((versions, intervals))
    assert best_fix("2.14.1", versions, intervals) == "2.17.1"
    assert (versions, intervals) == before


def test_best_fix_compares_numerically_and_accepts_excluded_upper_boundary():
    intervals = [{"lo": None, "lo_inc": True, "hi": "1.9", "hi_inc": False}]
    assert best_fix("1.8", ["1.10", "1.9"], intervals) == "1.9"


@pytest.mark.parametrize(
    ("versions", "intervals"),
    [([], []), (["1", "2.0.0"], []),
     (["3", "4"], [{"lo": None, "lo_inc": True, "hi": None, "hi_inc": False}])],
)
def test_best_fix_returns_none_when_no_safe_upgrade_exists(versions, intervals):
    assert best_fix("2", versions, intervals) is None


def test_empty_intervals_do_not_disqualify_patch_candidates():
    assert best_fix("1", ["3", "2"], []) == "2"
