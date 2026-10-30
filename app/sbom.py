from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# app/types.py에 정의된 타입을 가져오되, 아직 없을 경우를 대비해 fallback 처리
try:
    from app.types import Dep, Service
except ImportError:
    Dep = dict[str, Any]
    Service = dict[str, Any]

BASE_DIR = Path(__file__).resolve().parent.parent
SBOM_DIR = BASE_DIR / "sbom"
WORKSPACE_DIR = BASE_DIR / "workspace"

# requirements.txt: name==version 형태만 매칭 (주석 및 >=, ~= 등은 무시)
REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)==([^\s#]+)")

# pom.xml: <dependency>...</dependency> 블록 내부만 추출하여 프로젝트 자체 <version> 제외
DEP_BLOCK_RE = re.compile(r"<dependency>(.*?)</dependency>", re.DOTALL)
GROUP_RE = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>")
ARTIFACT_RE = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>")
VERSION_RE = re.compile(r"<version>\s*([^<\s]+)\s*</version>")


def parse_manifest(fname: str, text: str) -> list[Dep]:
    """매니페스트 파일명과 텍스트를 파싱해 Dep 리스트를 반환합니다."""
    deps: list[Dep] = []
    base_fname = Path(fname).name

    if base_fname == "requirements.txt":
        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = REQ_LINE_RE.match(raw_line)
            if m:
                deps.append({
                    "ecosystem": "PyPI",
                    "name": m.group(1),
                    "version": m.group(2),
                    "source": base_fname,
                })

    elif base_fname == "pom.xml":
        for block in DEP_BLOCK_RE.findall(text):
            g = GROUP_RE.search(block)
            a = ARTIFACT_RE.search(block)
            v = VERSION_RE.search(block)
            if g and a and v:
                deps.append({
                    "ecosystem": "Maven",
                    "name": f"{g.group(1)}:{a.group(1)}",
                    "version": v.group(1),
                    "source": base_fname,
                })

    return deps


def active_path(
    name: str,
    fname: str,
    services_dir: Path | str | None = None,
    workspace: Path | str | None = None,
) -> Path:
    """워크스페이스 사본이 있으면 사본 경로를, 없으면 원본 sbom 경로를 반환합니다."""
    ws_root = Path(workspace) if workspace is not None else WORKSPACE_DIR
    sbom_root = Path(services_dir) if services_dir is not None else SBOM_DIR

    ws_file = ws_root / name / fname
    if ws_file.exists():
        return ws_file
    return sbom_root / name / fname


def _read_services_meta(services_dir: Path) -> list[dict[str, Any]]:
    meta_file = services_dir / "services.json"
    raw = json.loads(meta_file.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        if "services" in raw and isinstance(raw["services"], list):
            return raw["services"]
        return [{"name": k, **v} for k, v in raw.items()]
    return []


def load_one(
    name: str,
    services_dir: Path | str | None = None,
    workspace: Path | str | None = None,
) -> Service:
    """단일 서비스의 SBOM을 CONTRACT.md 4장 Service 규격으로 로드합니다."""
    sbom_root = Path(services_dir) if services_dir is not None else SBOM_DIR
    services_meta = _read_services_meta(sbom_root)

    svc_meta = next((s for s in services_meta if s["name"] == name), None)
    if svc_meta is None:
        raise KeyError(f"Service '{name}' not found in {sbom_root / 'services.json'}")

    manifests: list[str] = list(svc_meta.get("manifests", []))
    manifest_paths: dict[str, str] = {}
    deps: list[Dep] = []

    for fname in manifests:
        path = active_path(name, fname, services_dir=sbom_root, workspace=workspace)
        manifest_paths[fname] = str(path.resolve())
        if path.exists():
            text = path.read_text(encoding="utf-8")
            deps.extend(parse_manifest(fname, text))

    # services.json에 직접 정의된 source: null 의존성(예: npm lodash) 추가
    for static_dep in svc_meta.get("deps", []):
        if static_dep.get("source") is None:
            deps.append({
                "ecosystem": static_dep["ecosystem"],
                "name": static_dep["name"],
                "version": static_dep["version"],
                "source": None,
            })

    return {
        "name": svc_meta["name"],
        "env": svc_meta["env"],
        "internet_exposed": bool(svc_meta["internet_exposed"]),
        "manifests": manifests,
        "manifest_paths": manifest_paths,
        "deps": deps,
    }


def load_all(
    services_dir: Path | str | None = None,
    workspace: Path | str | None = None,
) -> dict[str, Service]:
    """모든 서비스를 로드하여 {service_name: Service} 딕셔너리로 반환합니다."""
    sbom_root = Path(services_dir) if services_dir is not None else SBOM_DIR
    services_meta = _read_services_meta(sbom_root)
    return {
        s["name"]: load_one(s["name"], services_dir=sbom_root, workspace=workspace)
        for s in services_meta
    }
