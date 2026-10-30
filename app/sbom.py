"""SBOM 로드와 매니페스트 파싱 (requirements.txt, pom.xml). 담당: E soobin7131.

의존: 없음 (파일 시스템만 사용). 원본 sbom/은 읽기만 한다.
상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from pathlib import Path

from app.types import Dep, Service

SBOM_DIR = Path(__file__).resolve().parent.parent / "sbom"
WORKSPACE_DIR = Path(__file__).resolve().parent.parent / "workspace"


def parse_manifest(fname: str, text: str) -> list[Dep]:
    """requirements.txt(name==version), pom.xml(dependency 블록). source는 채우지 않는다."""
    raise NotImplementedError


def active_path(name: str, fname: str) -> Path:
    """워크스페이스 사본이 있으면 사본, 없으면 sbom/ 원본."""
    raise NotImplementedError


def load_all(services_dir: Path | None = None) -> dict[str, Service]:
    raise NotImplementedError


def load_one(name: str) -> Service:
    """없는 서비스면 KeyError."""
    raise NotImplementedError
