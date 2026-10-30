"""SBOM 파싱 테스트.

담당: E soobin7131
상태: 구현 완료. 계약은 docs/CONTRACT.md 4장 참고. 실제 sbom/은 건드리지 않고 tmp_path에 픽스처를 만든다.
"""
import json

import pytest

from app import sbom


POM_HEADER = '<project xmlns="http://maven.apache.org/POM/4.0.0">'


def _pom(deps: str, props: str = "") -> str:
    return (
        f"{POM_HEADER}"
        f"<modelVersion>4.0.0</modelVersion>"
        f"<groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version>"
        f"{props}"
        f"<dependencies>{deps}</dependencies>"
        f"</project>"
    )


def _dep(group: str, artifact: str, version: str | None) -> str:
    ver = f"<version>{version}</version>" if version is not None else ""
    return f"<dependency><groupId>{group}</groupId><artifactId>{artifact}</artifactId>{ver}</dependency>"


# parse_manifest: requirements.txt

def test_parse_requirements_pins_only():
    text = "# comment\nrequests==2.31.0\nPyYAML==5.3\nflask>=2.0\n\n"
    deps = sbom.parse_manifest("requirements.txt", text)
    assert deps == [
        {"ecosystem": "PyPI", "name": "requests", "version": "2.31.0", "source": "requirements.txt"},
        {"ecosystem": "PyPI", "name": "PyYAML", "version": "5.3", "source": "requirements.txt"},
    ]


def test_parse_requirements_handles_extras_and_markers():
    text = "uvicorn[standard]==0.30.1\nnumpy==1.26.4 ; python_version >= '3.12'\n"
    deps = sbom.parse_manifest("requirements.txt", text)
    assert [(d["name"], d["version"]) for d in deps] == [("uvicorn", "0.30.1"), ("numpy", "1.26.4")]


# parse_manifest: pom.xml

def test_parse_pom_reads_direct_dependencies():
    pom = _pom(_dep("org.apache.logging.log4j", "log4j-core", "2.14.1"))
    deps = sbom.parse_manifest("pom.xml", pom)
    assert deps == [
        {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "source": "pom.xml"}
    ]


def test_parse_pom_ignores_dependency_management():
    pom = (
        f"{POM_HEADER}<groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version>"
        "<dependencyManagement><dependencies>"
        + _dep("org.managed", "only-declared", "9.9.9")
        + "</dependencies></dependencyManagement>"
        "<dependencies>" + _dep("org.real", "used", "1.2.3") + "</dependencies>"
        "</project>"
    )
    names = [d["name"] for d in sbom.parse_manifest("pom.xml", pom)]
    assert names == ["org.real:used"]


def test_parse_pom_resolves_properties():
    props = "<properties><log4j.version>2.14.1</log4j.version></properties>"
    pom = _pom(_dep("org.apache.logging.log4j", "log4j-core", "${log4j.version}"), props)
    deps = sbom.parse_manifest("pom.xml", pom)
    assert deps[0]["version"] == "2.14.1"


def test_parse_pom_missing_version_is_empty_string():
    pom = _pom(_dep("org.parent", "managed-by-bom", None))
    deps = sbom.parse_manifest("pom.xml", pom)
    assert deps[0]["name"] == "org.parent:managed-by-bom"
    assert deps[0]["version"] == ""


def test_parse_pom_invalid_xml_returns_empty():
    assert sbom.parse_manifest("pom.xml", "<project><unclosed>") == []


def test_parse_manifest_unknown_filename_returns_empty():
    assert sbom.parse_manifest("package.json", '{"dependencies": {}}') == []


# active_path

def test_active_path_prefers_workspace_copy(tmp_path):
    sbom_root = tmp_path / "sbom"
    ws_root = tmp_path / "workspace"
    (sbom_root / "svc").mkdir(parents=True)
    (ws_root / "svc").mkdir(parents=True)
    (sbom_root / "svc" / "requirements.txt").write_text("a==1\n")
    (ws_root / "svc" / "requirements.txt").write_text("a==2\n")

    assert sbom.active_path("svc", "requirements.txt", sbom_root, ws_root) == ws_root / "svc" / "requirements.txt"


def test_active_path_falls_back_to_original(tmp_path):
    sbom_root = tmp_path / "sbom"
    expected = sbom_root / "svc" / "requirements.txt"
    assert sbom.active_path("svc", "requirements.txt", sbom_root, tmp_path / "workspace") == expected


# load_one / load_all

def _write_sbom(root, services):
    root.mkdir(parents=True, exist_ok=True)
    (root / "services.json").write_text(json.dumps(services), encoding="utf-8")


def test_load_one_builds_service_from_manifests(tmp_path):
    sbom_root = tmp_path / "sbom"
    _write_sbom(sbom_root, {
        "payment-api": {"env": "prod", "internet_exposed": True, "manifests": ["requirements.txt"]},
    })
    (sbom_root / "payment-api").mkdir()
    (sbom_root / "payment-api" / "requirements.txt").write_text("PyYAML==5.3\n")

    svc = sbom.load_one("payment-api", services_dir=sbom_root, workspace=tmp_path / "ws")

    assert svc["name"] == "payment-api"
    assert svc["env"] == "prod"
    assert svc["internet_exposed"] is True
    assert svc["manifests"] == ["requirements.txt"]
    assert svc["manifest_paths"]["requirements.txt"].endswith("payment-api/requirements.txt")
    assert svc["deps"] == [{"ecosystem": "PyPI", "name": "PyYAML", "version": "5.3", "source": "requirements.txt"}]


def test_load_one_adds_static_deps_with_null_source(tmp_path):
    sbom_root = tmp_path / "sbom"
    _write_sbom(sbom_root, {
        "web": {
            "env": "dev",
            "internet_exposed": False,
            "manifests": [],
            "deps": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "source": None}],
        },
    })
    svc = sbom.load_one("web", services_dir=sbom_root, workspace=tmp_path / "ws")
    assert svc["deps"] == [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "source": None}]


def test_load_one_missing_manifest_gives_no_deps(tmp_path):
    sbom_root = tmp_path / "sbom"
    _write_sbom(sbom_root, {"ghost": {"env": "dev", "internet_exposed": False, "manifests": ["pom.xml"]}})
    svc = sbom.load_one("ghost", services_dir=sbom_root, workspace=tmp_path / "ws")
    assert svc["deps"] == []
    assert svc["manifest_paths"]["pom.xml"].endswith("ghost/pom.xml")


def test_load_one_unknown_service_raises_keyerror(tmp_path):
    sbom_root = tmp_path / "sbom"
    _write_sbom(sbom_root, {})
    with pytest.raises(KeyError):
        sbom.load_one("nope", services_dir=sbom_root, workspace=tmp_path / "ws")


def test_load_all_returns_every_service(tmp_path):
    sbom_root = tmp_path / "sbom"
    _write_sbom(sbom_root, {
        "a": {"env": "prod", "internet_exposed": True, "manifests": []},
        "b": {"env": "dev", "internet_exposed": False, "manifests": []},
    })
    result = sbom.load_all(services_dir=sbom_root, workspace=tmp_path / "ws")
    assert set(result) == {"a", "b"}
    assert result["b"]["env"] == "dev"


def test_load_all_accepts_list_form(tmp_path):
    sbom_root = tmp_path / "sbom"
    _write_sbom(sbom_root, [{"name": "only", "env": "prod", "internet_exposed": False, "manifests": []}])
    assert list(sbom.load_all(services_dir=sbom_root, workspace=tmp_path / "ws")) == ["only"]
