from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any

try:
    from app.types import Dep, Remediation, Service, ThreatCard
except ImportError:
    Dep = dict[str, Any]
    Remediation = dict[str, Any]
    Service = dict[str, Any]
    ThreatCard = dict[str, Any]

from app.sbom import DEP_BLOCK_RE, SBOM_DIR, WORKSPACE_DIR, active_path


def bump_manifest(fname: str, text: str, name: str, fixed: str) -> str:
    """
    지정된 의존성 버전만 fixed로 교체하고, 나머지 줄·주석·들여쓰기·줄바꿈은 원본 그대로 유지합니다.
    """
    base_fname = Path(fname).name

    if base_fname == "requirements.txt":
        pattern = re.compile(
            rf"^(\s*{re.escape(name)}==)([^\s#]+)(.*)$",
            re.MULTILINE,
        )
        return pattern.sub(rf"\g<1>{fixed}\g<3>", text)

    elif base_fname == "pom.xml" and ":" in name:
        group_id, artifact_id = name.split(":", 1)

        def _replace_dep(match: re.Match) -> str:
            block = match.group(0)
            has_g = re.search(rf"<groupId>\s*{re.escape(group_id)}\s*</groupId>", block)
            has_a = re.search(rf"<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>", block)
            if has_g and has_a:
                return re.sub(
                    r"(<version>\s*)[^<\s]+(\s*</version>)",
                    rf"\g<1>{fixed}\g<2>",
                    block,
                    count=1,
                )
            return block

        return DEP_BLOCK_RE.sub(_replace_dep, text)

    return text


def propose(
    svc: Service,
    dep: Dep,
    card: ThreatCard,
    fixed: str | None,
    workspace: Path | str | None = None,
) -> Remediation:
    """
    CONTRACT.md 5장 및 8.2절 규격에 따른 Remediation 생성:
    - source가 없으면(null): kind = "manual"
    - fixed가 있으면: workspace/<svc_name>/<source>에 사본 작성 후 kind = "bump" 및 unified diff 반환
    - fixed가 없으면: kind = "workaround" 및 권고 문구 반환
    """
    svc_name = svc["name"]
    dep_name = dep["name"]
    installed = dep.get("version", "")
    source = dep.get("source")
    workaround_msg = (card or {}).get("workaround") or ""

    # 1. 매니페스트 source가 없는 의존성 (예: source: null 인 npm lodash)
    if not source:
        text = workaround_msg or f"{dep_name} ({installed}): 매니페스트 파일이 없어 수동 조치가 필요합니다."
        return {
            "kind": "manual",
            "text": text,
            "diff": None,
        }

    # 2. 패치 버전이 없는 경우 -> workaround 제안
    if not fixed:
        text = workaround_msg or f"{dep_name} ({installed}): 패치 버전이 없으므로 임시 완화 조치를 적용하세요."
        return {
            "kind": "workaround",
            "text": text,
            "diff": None,
        }

    # 3. 패치 버전(fixed)이 있는 경우 -> workspace 사본 저장 및 unified diff 생성
    ws_root = Path(workspace) if workspace is not None else WORKSPACE_DIR

    # 현재 매니페스트 경로 확인 (manifest_paths 우선, 없으면 active_path)
    manifest_paths = svc.get("manifest_paths") or {}
    if source in manifest_paths and Path(manifest_paths[source]).exists():
        src_path = Path(manifest_paths[source])
    else:
        src_path = active_path(svc_name, source, workspace=ws_root)

    old_text = src_path.read_text(encoding="utf-8")
    new_text = bump_manifest(source, old_text, dep_name, fixed)

    # workspace/<서비스>/<매니페스트>에 사본 기록 (원본 sbom/은 절대 건드리지 않음)
    target_dir = ws_root / svc_name
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / source
    target_file.write_text(new_text, encoding="utf-8")

    # 서비스 객체의 manifest_paths가 최신 워크스페이스 사본을 가리키도록 갱신
    if "manifest_paths" in svc and isinstance(svc["manifest_paths"], dict):
        svc["manifest_paths"][source] = str(target_file.resolve())

    diff_text = "".join(
        difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=f"a/{source}",
            tofile=f"b/{source}",
        )
    )

    return {
        "kind": "bump",
        "text": f"{dep_name} {installed} → {fixed}",
        "diff": diff_text,
    }
