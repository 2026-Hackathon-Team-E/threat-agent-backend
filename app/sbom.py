"""SBOM 로드와 매니페스트 파싱 (requirements.txt, pom.xml). 담당: E soobin7131.

의존: 없음 (파일 시스템만 사용). 원본 sbom/은 읽기만 한다.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from app.types import Dep, Service

SBOM_DIR = Path(__file__).resolve().parent.parent / "sbom"
WORKSPACE_DIR = Path(__file__).resolve().parent.parent / "workspace"

# requirements.txt: name==version 줄만 매칭 (주석 및 >=, ~= 등 제외)
REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)==([^\s#]+)")

# pom.xml: <dependency>...</dependency> 블록만 추출 (프로젝트 자체 <version> 제외)
DEP_BLOCK_RE = re.compile(r"<dependency>(.*?)</dependency>", re.DOTALL)
GROUP_RE = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>")
ARTIFACT_RE = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>")
VERSION_RE = re.compile(r"<version>\s*([^<\s]+)\s*</version>")


def parse_manifest(fname: str, text: str) -> list[Dep]:
    """requirements.txt(name==version), pom.xml(dependency 블록). source는 채우지 않는다."""
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
                })

    return deps


def active_path(name: str, fname: str) -> Path:
    """워크스페이스 사본이 있으면 사본, 없으면 sbom/ 원본."""
    ws_file = WORKSPACE_DIR / name / fname
    if ws_file.exists():
        return ws_file
    return SBOM_DIR / name / fname


def _read_services_meta(services_dir: Path | None = None) -> tuple[Path, list[dict]]:
    sbom_root = Path(services_dir) if services_dir is not None else SBOM_DIR
    meta_file = sbom_root / "services.json"
    if not meta_file.exists():
        return sbom_root, []
    raw = json.loads(meta_file.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return sbom_root, raw
    if isinstance(raw, dict):
        if "services" in raw and isinstance(raw["services"], list):
            return sbom_root, raw["services"]
        return sbom_root, [{"name": k, **v} for k, v in raw.items()]
    return sbom_root, []


def _build_service(svc_meta: dict, sbom_root: Path) -> Service:
    name = svc_meta["name"]
    manifests: list[str] = list(svc_meta.get("manifests", []))
    manifest_paths: dict[str, str] = {}
    deps: list[Dep] = []

    for fname in manifests:
        # 기본 SBOM_DIR를 사용할 때는 active_path() 호출, 커스텀 services_dir일 때는 워크스페이스 우선 확인 후 해당 경로 사용
        if sbom_root == SBOM_DIR:
            path = active_path(name, fname)
        else:
            ws_file = WORKSPACE_DIR / name / fname
            path = ws_file if ws_file.exists() else (sbom_root / name / fname)

        manifest_paths[fname] = str(path)
        if path.exists():
            text = path.read_text(encoding="utf-8")
            for d in parse_manifest(fname, text):
                deps.append({
                    "ecosystem": d["ecosystem"],
                    "name": d["name"],
                    "version": d["version"],
                    "source": fname,
                })

    # services.json에 정의된 매니페스트 없는 의존성(source: null, 예: npm lodash) 병합
    for static_dep in svc_meta.get("deps", []):
        if static_dep.get("source") is None:
            deps.append({
                "ecosystem": static_dep["ecosystem"],
                "name": static_dep["name"],
                "version": static_dep["version"],
                "source": None,
            })

    return {
        "name": name,
        "env": svc_meta["env"],
        "internet_exposed": bool(svc_meta["internet_exposed"]),
        "manifests": manifests,
        "manifest_paths": manifest_paths,
        "deps": deps,
    }


def load_all(services_dir: Path | None = None) -> dict[str, Service]:
    sbom_root, services_meta = _read_services_meta(services_dir)
    return {
        s["name"]: _build_service(s, sbom_root) for s in services_meta
    }


def load_one(name: str) -> Service:
    """없는 서비스면 KeyError."""
    sbom_root, services_meta = _read_services_meta(SBOM_DIR)
    svc_meta = next((s for s in services_meta if s["name"] == name), None)
    if svc_meta is None:
        raise KeyError(f"Service '{name}' not found.")
    return _build_service(svc_meta, sbom_root)
