"""패키지 매칭 (생태계 일치, 이름 정규화, 버전 구간 포함). 담당: C marineusus.

계약: docs/CONTRACT.md 2장, 8장. 외부 I/O 없이 입력만 사용한다.
"""
from __future__ import annotations

import logging

from app.types import Affected, Card, Dep
from app.versions import best_fix, in_interval

log = logging.getLogger("matcher")


def _normalize_name(name: str, ecosystem: str) -> str:
    """계약에서 정한 PyPI 정규화만 적용한다. 다른 생태계 이름은 보존한다."""
    return name.lower().replace("_", "-") if ecosystem == "PyPI" else name


# [계획, 미구현] 제품 연결 단계: LLM이 기사 속 제품명(예: "Apache Log4j")을
# SBOM의 패키지(예: log4j-core)에 대응하는 후보로 제안하고, 여기서 SBOM 존재 여부와
# 버전 범위를 코드로 다시 확인한다. 모델은 판단하지 않고 후보만 낸다. 현재는 미구현.
def match(dep: Dep, card: Card) -> Affected | None:
    """카드의 affected 중 dep과 맞고 설치 버전이 취약 구간에 드는 항목. 없으면 None.

    설치 버전이 숫자 릴리스가 아니면(예: 빈 문자열, 버전 미상) 판정할 수 없으므로 건너뛰고 경고만 남긴다.
    """
    ecosystem = dep["ecosystem"]
    name = _normalize_name(dep["name"], ecosystem)
    for affected in card["affected"]:
        if affected["ecosystem"] != ecosystem:
            continue
        if _normalize_name(affected["name"], ecosystem) != name:
            continue
        try:
            if any(in_interval(dep["version"], iv) for iv in affected["intervals"]):
                return affected
        except ValueError:
            log.warning("버전을 판정할 수 없어 건너뜀: %s %s@%r", ecosystem, dep["name"], dep["version"])
            return None
    return None


def fix_for(dep: Dep, affected: Affected) -> str | None:
    """일치한 affected의 후보 중 설치 버전보다 높은 최소 안전 버전을 고른다."""
    return best_fix(dep["version"], affected["fixed_versions"], affected["intervals"])
