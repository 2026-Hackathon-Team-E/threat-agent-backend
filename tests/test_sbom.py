from pathlib import Path
import pytest
from app import sbom
from app.sbom import SBOM_DIR, active_path, load_all, load_one, parse_manifest


def test_parse_requirements_ignores_comments_and_other_lines():
    text = "# comment\n\nPyYAML==5.3\nrequests>=2.28.0\n  flask==2.0.1 # inline\n"
    deps = parse_manifest("requirements.txt", text)
    assert deps == [
        {"ecosystem": "PyPI", "name": "PyYAML", "version": "5.3", "source": None},
        {"ecosystem": "PyPI", "name": "flask", "version": "2.0.1", "source": None},
    ]


def test_parse_pom_ignores_project_version():
    text = """<project>
      <groupId>com.example</groupId>
      <artifactId>payment-api</artifactId>
      <version>1.0.0-SNAPSHOT</version>
      <dependencies>
        <dependency>
          <groupId>org.apache.logging.log4j</groupId>
          <artifactId>log4j-core</artifactId>
          <version>2.14.1</version>
        </dependency>
      </dependencies>
    </project>"""
    deps = parse_manifest("pom.xml", text)
    assert deps == [
        {
            "ecosystem": "Maven",
            "name": "org.apache.logging.log4j:log4j-core",
            "version": "2.14.1",
            "source": None,
        }
    ]


def test_load_one_matches_contract_section_4(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(sbom, "WORKSPACE_DIR", tmp_path)
    svc = load_one("payment-api")
    assert svc["name"] == "payment-api"
    assert svc["env"] in ("prod", "dev")
    assert svc["internet_exposed"] is True
    assert svc["manifests"] == ["requirements.txt", "pom.xml"]
    assert Path(svc["manifest_paths"]["requirements.txt"]).name == "requirements.txt"
    assert svc["deps"] == [
        {"ecosystem": "PyPI", "name": "PyYAML", "version": "5.3", "source": "requirements.txt"},
        {
            "ecosystem": "Maven",
            "name": "org.apache.logging.log4j:log4j-core",
            "version": "2.14.1",
            "source": "pom.xml",
        },
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "source": None},
    ]


def test_active_path_prefers_workspace(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(sbom, "WORKSPACE_DIR", tmp_path)
    orig = active_path("payment-api", "requirements.txt")
    assert orig == SBOM_DIR / "payment-api" / "requirements.txt"

    ws_copy = tmp_path / "payment-api" / "requirements.txt"
    ws_copy.parent.mkdir(parents=True, exist_ok=True)
    ws_copy.write_text("PyYAML==6.0.1\n", encoding="utf-8")

    assert active_path("payment-api", "requirements.txt") == ws_copy


def test_load_one_missing_raises_key_error():
    with pytest.raises(KeyError):
        load_one("non-existent-service")


def test_load_all_returns_service_dict(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(sbom, "WORKSPACE_DIR", tmp_path)
    services = load_all(SBOM_DIR)
    assert "payment-api" in services
    assert "internal-report" in services
