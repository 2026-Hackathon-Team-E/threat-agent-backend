"""패키지 매칭 (생태계 일치, 이름 정규화, 버전 구간 포함). 담당: C marineusus.

계약: docs/CONTRACT.md 2장, 8장. 외부 I/O 없이 입력만 사용한다.
"""
from __future__ import annotations

from app.types import Affected, Card, Dep
from app.versions import best_fix, in_interval


def _normalize_name(name: str, ecosystem: str) -> str:
    """계약에서 정한 PyPI 정규화만 적용한다. 다른 생태계 이름은 보존한다."""
    return name.lower().replace("_", "-") if ecosystem == "PyPI" else name


def match(dep: Dep, card: Card) -> Affected | None:
    """카드의 affected 중 dep과 맞고 설치 버전이 취약 구간에 드는 항목. 없으면 None."""
    ecosystem = dep["ecosystem"]
    name = _normalize_name(dep["name"], ecosystem)
    for affected in card["affected"]:
        if affected["ecosystem"] != ecosystem:
            continue
        if _normalize_name(affected["name"], ecosystem) != name:
            continue
        if any(in_interval(dep["version"], iv) for iv in affected["intervals"]):
            return affected
    return None


def fix_for(dep: Dep, affected: Affected) -> str | None:
    """일치한 affected의 후보 중 설치 버전보다 높은 최소 안전 버전을 고른다."""
    return best_fix(dep["version"], affected["fixed_versions"], affected["intervals"])
