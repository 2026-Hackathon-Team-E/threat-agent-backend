"""스캐폴드·API 스모크 테스트. 담당: D redsun2."""
import os

os.environ.setdefault("POLLERS", "off")  # 테스트에서 외부 호출 금지


def test_package_imports():
    import app  # noqa: F401


def test_api_endpoints(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app import main
    from app.store import Store

    monkeypatch.setattr(main.S, "store", Store(str(tmp_path / "api.db")))
    with TestClient(main.app) as c:
        assert c.get("/health").json()["status"] == "ok"
        assert c.post("/ingest", json={"ids": []}).status_code == 400
        assert c.post("/ingest", json={"ids": ["CVE-2021-44228"]}).status_code == 202
        assert c.post("/replay/cve-2021-44228").json() == {"queued": "CVE-2021-44228"}
        assert c.post("/webhooks/deploy", json={"service": "없는서비스"}).status_code == 404
        assert c.get("/cards").status_code == 200
        assert c.get("/cards/CVE-0000-0000").status_code == 404
        assert c.get("/impacts").status_code == 200
        svcs = c.get("/services").json()
        assert {s["name"] for s in svcs} == {"payment-api", "internal-report"}
        assert all("manifest_paths" not in s for s in svcs)
