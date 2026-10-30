"""매니페스트 버전 수정 및 완화 조치 제안. 담당: E soobin7131.

의존: app.sbom (같은 담당). 원본 sbom/은 읽기만 하고 수정본은 workspace/에 기록한다.
"""
from __future__ import annotations

import difflib
import re
from pathlib import Path

from app.sbom import DEP_BLOCK_RE, WORKSPACE_DIR, active_path
from app.types import Dep, Remediation, Service, ThreatCard


def bump_manifest(fname: str, text: str, name: str, fixed: str) -> str:
    """대상 의존성의 버전이 적힌 줄만 수정하고 나머지 줄은 원본 그대로 유지한다."""
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
    workspace: Path | None = None,
) -> Remediation:
    """패치가 있으면 workspace/<서비스>/에 사본을 쓰고 unified diff를 반환한다.
    패치가 없으면 workaround, source가 없으면 manual을 반환한다.
    """
    svc_name = svc["name"]
    dep_name = dep["name"]
    installed = dep.get("version", "")
    source = dep.get("source")
    workaround_msg = (card or {}).get("workaround") or ""

    # 1. source가 없으면 manual
    if not source:
        return {
            "kind": "manual",
            "text": workaround_msg or f"{dep_name} ({installed}): 매니페스트(source)가 없어 수동 조치가 필요합니다.",
            "diff": None,
        }

    # 2. 패치 버전(fixed)이 없으면 workaround
    if not fixed:
        return {
            "kind": "workaround",
            "text": workaround_msg or f"{dep_name} ({installed}): 패치 버전이 없으므로 임시 완화 조치를 적용하세요.",
            "diff": None,
        }

    # 3. 패치 버전이 있으면 workspace/<서비스>/에 사본 저장 및 unified diff 생성
    ws_root = Path(workspace) if workspace is not None else WORKSPACE_DIR

    manifest_paths = svc.get("manifest_paths") or {}
    ws_candidate = ws_root / svc_name / source
    if ws_candidate.exists():
        src_path = ws_candidate
    elif source in manifest_paths and Path(manifest_paths[source]).exists():
        src_path = Path(manifest_paths[source])
    else:
        src_path = active_path(svc_name, source)

    old_text = src_path.read_text(encoding="utf-8")
    new_text = bump_manifest(source, old_text, dep_name, fixed)

    out_dir = ws_root / svc_name
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / source
    out_file.write_text(new_text, encoding="utf-8")

    if "manifest_paths" in svc and isinstance(svc["manifest_paths"], dict):
        svc["manifest_paths"][source] = str(out_file)

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
