"""SBOM 로드와 매니페스트 파싱 (requirements.txt, pom.xml). 담당: E soobin7131.

의존: 없음 (파일 시스템만 사용). 원본 sbom/은 읽기만 한다.
버전을 알 수 없는 Maven 의존성은 version을 ""로 두고 경고를 남긴다.
"""
from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.types import Dep, Service

log = logging.getLogger("sbom")

BASE_DIR = Path(__file__).resolve().parent.parent
SBOM_DIR = BASE_DIR / "sbom"
WORKSPACE_DIR = BASE_DIR / "workspace"

# requirements.txt: name==version 만 매칭. extras(name[x]==1)는 허용, >=, ~= 등은 무시.
# 뒤따르는 환경 마커(; python_version ...)와 주석(#)은 버전에서 떼어낸다.
REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?==([^\s#;]+)")
PROP_RE = re.compile(r"\$\{([^}]+)\}")
# remediate.py가 pom.xml의 <dependency> 블록을 바꿀 때 쓴다. 이름을 바꾸지 말 것.
DEP_BLOCK_RE = re.compile(r"<dependency>(.*?)</dependency>", re.DOTALL)


def _local(tag: str) -> str:
    """'{namespace}name' 형태의 태그에서 네임스페이스를 떼고 이름만 돌려준다."""
    return tag.rsplit("}", 1)[-1]


def _child_text(elem: ET.Element, name: str) -> str | None:
    for child in elem:
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return None


def _pom_properties(root: ET.Element) -> dict[str, str]:
    props: dict[str, str] = {}
    for child in root:
        if _local(child.tag) == "properties":
            for prop in child:
                props[_local(prop.tag)] = (prop.text or "").strip()
    # ${project.version} 같은 참조를 위해 프로젝트 자신의 좌표도 넣는다
    for key in ("groupId", "artifactId", "version"):
        value = _child_text(root, key)
        if value:
            props.setdefault(f"project.{key}", value)
    return props


def _resolve(value: str, props: dict[str, str]) -> str:
    """${key} 참조를 properties 값으로 치환한다. 한 번만 치환하며 모르는 키는 그대로 둔다."""
    return PROP_RE.sub(lambda m: props.get(m.group(1), m.group(0)), value)


def _parse_requirements(base_fname: str, text: str) -> list[Dep]:
    deps: list[Dep] = []
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
    return deps


def _parse_pom(base_fname: str, text: str) -> list[Dep]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        log.warning("pom.xml 파싱 실패 (%s): %s", base_fname, exc)
        return []

    props = _pom_properties(root)
    deps: list[Dep] = []
    # 직접 의존성만 본다. dependencyManagement 안의 항목은 "선언"이지 실제 의존성이 아니다.
    for dependencies in root:
        if _local(dependencies.tag) != "dependencies":
            continue
        for dep in dependencies:
            if _local(dep.tag) != "dependency":
                continue
            group = _child_text(dep, "groupId")
            artifact = _child_text(dep, "artifactId")
            if not group or not artifact:
                log.warning("pom.xml 의존성에 groupId/artifactId가 없음 (%s)", base_fname)
                continue
            raw_version = _child_text(dep, "version")
            version = _resolve(raw_version, props) if raw_version else ""
            if not version or "${" in version:
                # 부모 BOM이 버전을 관리하는 경우 등. 조용히 빼지 않고 표시만 남긴다.
                log.warning("버전을 알 수 없는 의존성 %s:%s (%s)", group, artifact, base_fname)
                version = ""
            deps.append({
                "ecosystem": "Maven",
                "name": f"{group}:{artifact}",
                "version": version,
                "source": base_fname,
            })
    return deps


def parse_manifest(fname: str, text: str) -> list[Dep]:
    """매니페스트 파일명과 텍스트를 파싱해 Dep 리스트를 반환합니다.

    지원하지 않는 파일명이면 빈 리스트를 돌려준다. source는 파일명으로 채운다.
    """
    base_fname = Path(fname).name
    if base_fname == "requirements.txt":
        return _parse_requirements(base_fname, text)
    if base_fname == "pom.xml":
        return _parse_pom(base_fname, text)
    return []


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
    """단일 서비스의 SBOM을 CONTRACT.md 4장 Service 규격으로 로드합니다. 없으면 KeyError."""
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
        else:
            log.warning("매니페스트 없음: %s", path)

    # manifest가 있는 의존성은 위에서 읽었으므로, 여기서는 source가 null인 정적 의존성만 추가한다.
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
