"""C 담당: 생태계·이름·취약 구간 매칭과 수정 버전 제안."""
from copy import deepcopy

import pytest

from app.matcher import fix_for, match


def _affected(ecosystem="PyPI", name="my-package"):
    return {
        "ecosystem": ecosystem, "name": name,
        "intervals": [{"lo": "1", "lo_inc": True, "hi": "2", "hi_inc": False}],
        "fixed_versions": ["3", "2"], "source": "GitHub Advisory",
    }


def _dep(ecosystem="PyPI", name="my-package", version="1.5"):
    return {"ecosystem": ecosystem, "name": name, "version": version, "source": "requirements.txt"}


def _card(affected):
    return {
        "key": "CVE-2021-44228", "ids": ["CVE-2021-44228"],
        "sources": ["GitHub Advisory"], "title": "Test advisory",
        "summary": None, "workaround": None, "kev": False, "ransomware": False,
        "due_date": None, "cvss": None, "epss": None, "affected": affected,
        "status": "확정" if affected else "미확정", "version": 1,
        "osv_checked_at": 0.0, "epss_checked": False,
    }


@pytest.mark.parametrize("name", ["my-package", "MY-PACKAGE", "My_Package"])
def test_pypi_case_and_underscore_normalization(name):
    affected = _affected(name=name)
    assert match(_dep(name="MY_package"), _card([affected])) == affected


@pytest.mark.parametrize(
    ("ecosystem", "name"),
    [("Maven", "my-package"), ("npm", "my-package"), ("PyPI", "unrelated")],
)
def test_different_ecosystem_or_package_does_not_match(ecosystem, name):
    assert match(_dep(), _card([_affected(ecosystem, name)])) is None


@pytest.mark.parametrize("ecosystem", ["Maven", "npm"])
@pytest.mark.parametrize("name", ["MY-PACKAGE", "my_package"])
def test_pypi_normalization_does_not_leak_to_other_ecosystems(ecosystem, name):
    assert match(_dep(ecosystem), _card([_affected(ecosystem, name)])) is None


def test_maven_contract_example_and_fix():
    name = "org.apache.logging.log4j:log4j-core"
    dep = _dep("Maven", name, "2.14.1")
    affected = _affected("Maven", name)
    affected["intervals"] = [{"lo": "2", "lo_inc": True, "hi": "2.15.0", "hi_inc": False}]
    affected["fixed_versions"] = ["2.17.1", "2.15.0"]
    assert match(dep, _card([affected])) == affected
    assert fix_for(dep, affected) == "2.15.0"
    dep["version"] = "2.15.0"
    assert match(dep, _card([affected])) is None


@pytest.mark.parametrize("version", ["0.9", "2", "2.0.0", "3"])
def test_non_vulnerable_version_does_not_match(version):
    assert match(_dep(version=version), _card([_affected()])) is None


def test_empty_affected_or_unknown_intervals_do_not_match():
    assert match(_dep(), _card([])) is None
    affected = _affected()
    affected["intervals"] = []
    assert match(_dep(), _card([affected])) is None


def test_intervals_are_or_and_search_continues_past_unrelated_entries():
    affected = _affected()
    affected["intervals"] = [
        {"lo": "0", "lo_inc": True, "hi": "1", "hi_inc": False},
        {"lo": "1.4", "lo_inc": True, "hi": "1.6", "hi_inc": True},
    ]
    assert match(_dep(), _card([_affected(name="other"), affected])) == affected


def test_search_continues_past_same_package_with_nonmatching_range():
    first = _affected()
    first["intervals"] = [{"lo": "3", "lo_inc": True, "hi": None, "hi_inc": False}]
    second = _affected()
    assert match(_dep(), _card([first, second])) == second


def test_fix_for_excludes_candidates_that_are_still_vulnerable():
    affected = _affected()
    affected["intervals"].append({"lo": "2", "lo_inc": True, "hi": "3", "hi_inc": False})
    assert fix_for(_dep(), affected) == "3"


def test_fix_for_without_safe_candidate():
    affected = _affected()
    affected["fixed_versions"] = []
    assert fix_for(_dep(), affected) is None


def test_match_and_fix_for_leave_nested_inputs_unchanged():
    dep = _dep(name="MY_package")
    card = _card([_affected()])
    before = deepcopy((dep, card))
    first = match(dep, card)
    assert first is not None
    assert fix_for(dep, first) == "2"
    assert match(dep, card) == first
    assert (dep, card) == before


@pytest.mark.parametrize("version", ["", "unknown"])
def test_unparseable_installed_version_is_skipped_not_crashing(version):
    assert match(_dep(version=version), _card([_affected()])) is None
