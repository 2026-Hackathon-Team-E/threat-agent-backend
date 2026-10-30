"""app/linker.py 테스트. 외부 호출 없이 가짜 HTTP로 검증. 담당: kmssss56."""
import asyncio

import httpx

from app import linker

CANDIDATES = ["log4j-core", "PyYAML", "requests"]


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeHttp:
    def __init__(self, routes):
        self.routes = routes  # 키: URL 일부 문자열, 값: FakeResponse 또는 Exception

    async def post(self, url, **kwargs):
        for key, val in self.routes.items():
            if key in url:
                if isinstance(val, Exception):
                    raise val
                return val
        return FakeResponse(404, {})


def run(coro):
    return asyncio.run(coro)


def test_pick_keeps_only_candidates():
    http = FakeHttp({"/api/generate": FakeResponse(200, {"response": '["log4j-core", "unknown-lib"]'})})
    out = run(linker.pick_packages(http, "log4j 기사", CANDIDATES, "http://x", "m"))
    assert out == ["log4j-core"]


def test_pick_bad_output_returns_empty():
    http = FakeHttp({"/api/generate": FakeResponse(200, {"response": "모르겠습니다"})})
    assert run(linker.pick_packages(http, "t", CANDIDATES, "http://x", "m")) == []


def test_pick_server_down_returns_empty():
    http = FakeHttp({"/api/generate": httpx.ConnectError("down")})
    assert run(linker.pick_packages(http, "t", CANDIDATES, "http://x", "m")) == []


def test_affected_from_vuln_only_matching_package():
    vuln = {
        "id": "GHSA-x",
        "aliases": ["CVE-2021-44228"],
        "affected": [
            {"package": {"ecosystem": "Maven", "name": "other:lib"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]},
            {"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}]},
        ],
    }
    aff = linker.affected_from_vuln(vuln, "Maven", "org.apache.logging.log4j:log4j-core")
    assert aff["fixed_versions"] == ["2.15.0"]
    assert aff["source"] == "OSV:GHSA-x"


def test_link_news_card_attaches_only_cve_matching_vulns():
    card = {"ids": ["NEWS:X", "CVE-2021-44228"], "title": "Log4j 취약점", "summary": ""}
    deps = [{"ecosystem": "PyPI", "name": "PyYAML"}, {"ecosystem": "Maven", "name": "log4j-core"}]
    vulns = {"vulns": [
        {"id": "GHSA-1", "aliases": ["CVE-2021-44228"], "affected": [
            {"package": {"ecosystem": "Maven", "name": "log4j-core"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}]}]},
        {"id": "GHSA-2", "aliases": ["CVE-2099-0001"], "affected": []},
    ]}
    http = FakeHttp({
        "/api/generate": FakeResponse(200, {"response": '["log4j-core"]'}),
        "/v1/query": FakeResponse(200, vulns),
    })
    out = run(linker.link_news_card(http, card, deps, "http://x", "m"))
    assert [a["name"] for a in out] == ["log4j-core"]
    assert out[0]["source"] == "OSV:GHSA-1"


def test_link_news_card_without_cve_does_nothing():
    http = FakeHttp({})
    card = {"ids": ["NEWS:Y"], "title": "t", "summary": ""}
    assert run(linker.link_news_card(http, card, [{"ecosystem": "PyPI", "name": "PyYAML"}], "http://x", "m")) == []
