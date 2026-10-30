import hashlib
from pathlib import Path
from app import sbom
from app.sbom import SBOM_DIR, load_one
from app.remediate import bump_manifest, propose
from app.types import Card


def _snapshot_hashes(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def _dummy_card(workaround: str | None = None) -> Card:
    return {
        "key": "CVE-2021-44228",
        "ids": ["CVE-2021-44228"],
        "sources": ["CISA KEV"],
        "title": "Log4j RCE",
        "summary": "...",
        "workaround": workaround,
        "kev": True,
        "ransomware": False,
        "due_date": None,
        "cvss": 10.0,
        "epss": 0.97,
        "affected": [],
        "status": "확정",
        "version": 1,
        "osv_checked_at": 0.0,
        "epss_checked": True,
    }


def test_bump_manifest_only_changes_same_line_pom():
    orig = (SBOM_DIR / "payment-api" / "pom.xml").read_text(encoding="utf-8")
    bumped = bump_manifest("pom.xml", orig, "org.apache.logging.log4j:log4j-core", "2.15.0")

    orig_lines = orig.splitlines()
    bumped_lines = bumped.splitlines()
    assert len(orig_lines) == len(bumped_lines)

    diff_indices = [i for i, (a, b) in enumerate(zip(orig_lines, bumped_lines)) if a != b]
    assert len(diff_indices) == 1
    assert "2.15.0" in bumped_lines[diff_indices[0]]


def test_bump_manifest_only_changes_same_line_requirements():
    orig = "# header\n\nPyYAML==5.3 # keep comment\nrequests>=2.25.0\n"
    bumped = bump_manifest("requirements.txt", orig, "PyYAML", "6.0.1")

    orig_lines = orig.splitlines()
    bumped_lines = bumped.splitlines()
    assert len(orig_lines) == len(bumped_lines)

    diff_indices = [i for i, (a, b) in enumerate(zip(orig_lines, bumped_lines)) if a != b]
    assert diff_indices == [2]
    assert bumped_lines[2] == "PyYAML==6.0.1 # keep comment"


def test_propose_preserves_original_sbom_hashes(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(sbom, "WORKSPACE_DIR", tmp_path)
    before_hashes = _snapshot_hashes(SBOM_DIR)

    svc = load_one("payment-api")
    dep = next(d for d in svc["deps"] if d["name"] == "org.apache.logging.log4j:log4j-core")
    card = _dummy_card(workaround="Set formatMsgNoLookups=true")

    rem = propose(svc, dep, card, fixed="2.15.0", workspace=tmp_path)

    assert rem["kind"] == "bump"
    assert rem["text"] == "org.apache.logging.log4j:log4j-core 2.14.1 → 2.15.0"
    assert "--- a/pom.xml" in rem["diff"]
    assert "+++ b/pom.xml" in rem["diff"]
    assert (tmp_path / "payment-api" / "pom.xml").exists()

    after_hashes = _snapshot_hashes(SBOM_DIR)
    assert before_hashes == after_hashes


def test_propose_workaround_and_manual(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(sbom, "WORKSPACE_DIR", tmp_path)
    svc = load_one("payment-api")
    card = _dummy_card(workaround="JNDI lookup 비활성화")

    maven_dep = next(d for d in svc["deps"] if d["source"] == "pom.xml")
    rem_wa = propose(svc, maven_dep, card, fixed=None, workspace=tmp_path)
    assert rem_wa["kind"] == "workaround"
    assert rem_wa["text"] == "JNDI lookup 비활성화"
    assert rem_wa["diff"] is None

    # services.json에는 source가 null인 의존성이 없으므로 테스트 안에서 직접 만든다 (sbom/ 원본은 수정하지 않음)
    npm_dep = {"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "source": None}
    rem_manual = propose(svc, npm_dep, card, fixed="4.17.21", workspace=tmp_path)
    assert rem_manual["kind"] == "manual"
    assert rem_manual["diff"] is None
