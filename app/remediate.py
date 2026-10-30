"""수정 제안: 버전 올림 사본(workspace), unified diff, workaround. 담당: E soobin7131.

의존: 없음 (sbom.active_path는 같은 담당자 영역이며 타입만 공유).
원본 sbom/은 쓰지 않는다. 결과는 workspace 아래에만 쓴다.
상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from pathlib import Path

from app.types import Card, Dep, Remediation, Service


def bump_manifest(fname: str, text: str, name: str, fixed: str) -> str:
    """해당 패키지 줄의 버전만 교체한 전체 텍스트. 주석과 다른 줄은 그대로."""
    raise NotImplementedError


def propose(
    svc: Service,
    dep: Dep,
    card: Card,
    fixed: str | None,
    workspace: Path,
) -> Remediation:
    """fixed가 있고 source가 있으면 bump(사본 + diff), fixed가 없으면 workaround,
    source가 없으면 manual."""
    raise NotImplementedError
