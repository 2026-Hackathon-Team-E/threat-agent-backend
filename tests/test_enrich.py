"""app/enrich.py 테스트. 외부 호출 없이 가짜 HTTP 객체로 검증한다. 담당: B kmssss56."""
import json
from pathlib import Path

import httpx
import pytest

from app import enrich

import asyncio
import functools


def arun(fn):
    """async 테스트를 동기 테스트로 감싼다 (pytest-asyncio 없이 실행)."""

    @functools.wraps(fn)
    def wrapper():
        asyncio.run(fn())

    return wrapper

FIXTURES = Path(__file__).parent / "fixtures"


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeHttp:
    """get/post 호출을 기록하고 미리 정한 응답을 돌려준다. 예외를 던질 수도 있다."""

    def __init__(self, response=None, exc=None):
        self.response = response
        self.exc = exc
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if self.exc:
            raise self.exc
        return self.response

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if self.exc:
            raise self.exc
        return self.response


def _fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# osv_intervals

def test_osv_intro_zero_fixed_gives_open_lower_bound():
    ivs = enrich.osv_intervals({"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]})
    assert ivs == [{"lo": None, "lo_inc": True, "hi": "5.4", "hi_inc": False}]


def test_osv_last_affected_is_inclusive():
    ivs = enrich.osv_intervals(
        {"ranges": [{"type": "SEMVER", "events": [{"introduced": "2.16.0"}, {"last_affected": "2.16.0"}]}]}
    )
    assert ivs == [{"lo": "2.16.0", "lo_inc": True, "hi": "2.16.0", "hi_inc": True}]


def test_osv_multiple_ranges_and_explicit_versions():
    entry = {
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}, {"introduced": "2.16.0"}, {"fixed": "2.16.1"}]}],
        "versions": ["1.0.0"],
    }
    ivs = enrich.osv_intervals(entry)
    assert len(ivs) == 3
    assert ivs[0]["hi"] == "2.15.0" and ivs[0]["hi_inc"] is False
    assert ivs[1]["lo"] == "2.16.0" and ivs[1]["hi"] == "2.16.1"
    assert ivs[2] == {"lo": "1.0.0", "lo_inc": True, "hi": "1.0.0", "hi_inc": True}


def test_osv_skips_unknown_range_types():
    assert enrich.osv_intervals({"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}) == []


# osv

@arun
async def test_osv_returns_affected_from_fixture():
    http = FakeHttp(FakeResponse(200, _fixture("osv_sample.json")))
    out = await enrich.osv(http, "GHSA-8q59-vrmh-qqgf")
    names = {(a["ecosystem"], a["name"]) for a in out}
    assert names == {("PyPI", "PyYAML"), ("Maven", "org.apache.logging.log4j:log4j-core")}
    pyyaml = next(a for a in out if a["name"] == "PyYAML")
    assert pyyaml["fixed_versions"] == ["5.4"]
    assert pyyaml["source"] == "OSV:GHSA-8q59-vrmh-qqgf"
    assert http.calls[0][1].endswith("/v1/vulns/GHSA-8q59-vrmh-qqgf")


@arun
async def test_osv_404_returns_empty():
    assert await enrich.osv(FakeHttp(FakeResponse(404, {})), "CVE-0000-0000") == []


@arun
async def test_osv_network_error_returns_empty():
    assert await enrich.osv(FakeHttp(exc=httpx.ConnectError("down")), "CVE-2020-14343") == []


@arun
async def test_osv_skips_package_without_ranges():
    payload = {"affected": [{"package": {"ecosystem": "npm", "name": "x"}}]}
    assert await enrich.osv(FakeHttp(FakeResponse(200, payload)), "GHSA-x") == []


# epss

@arun
async def test_epss_returns_score_from_fixture():
    http = FakeHttp(FakeResponse(200, _fixture("epss_sample.json")))
    assert await enrich.epss(http, "CVE-2024-3094") == pytest.approx(0.91234)
    assert http.calls[0][2]["params"] == {"cve": "CVE-2024-3094"}


@arun
async def test_epss_empty_data_is_none():
    assert await enrich.epss(FakeHttp(FakeResponse(200, {"data": []})), "CVE-1") is None


@arun
async def test_epss_error_is_none():
    assert await enrich.epss(FakeHttp(exc=httpx.ReadTimeout("slow")), "CVE-1") is None


# llm_extract

@arun
async def test_llm_without_key_does_not_call_api():
    http = FakeHttp(FakeResponse(200, {}))
    assert await enrich.llm_extract(http, "text", None, "claude-haiku-5-5") == {}
    assert http.calls == []


@arun
async def test_llm_parses_json_from_text_block():
    reply = {"content": [{"type": "text", "text": 'Result: {"workaround": "pin 5.4.6", "products": ["xz"]}'}]}
    out = await enrich.llm_extract(FakeHttp(FakeResponse(200, reply)), "t", "key", "claude-haiku-5-5")
    assert out == {"workaround": "pin 5.4.6", "products": ["xz"]}


@arun
async def test_llm_sends_expected_headers_and_model():
    http = FakeHttp(FakeResponse(200, {"content": [{"type": "text", "text": "{}"}]}))
    await enrich.llm_extract(http, "t", "secret-key", "claude-haiku-5-5")
    _, url, kwargs = http.calls[0]
    assert url == enrich.ANTHROPIC_URL
    assert kwargs["headers"]["x-api-key"] == "secret-key"
    assert kwargs["json"]["model"] == "claude-haiku-5-5"


@arun
async def test_llm_bad_json_returns_empty():
    reply = {"content": [{"type": "text", "text": "no braces here"}]}
    assert await enrich.llm_extract(FakeHttp(FakeResponse(200, reply)), "t", "k", "m") == {}


@arun
async def test_llm_http_error_returns_empty():
    assert await enrich.llm_extract(FakeHttp(exc=httpx.ConnectError("x")), "t", "k", "m") == {}


@arun
async def test_llm_non_list_products_becomes_empty_list():
    reply = {"content": [{"type": "text", "text": '{"workaround": "", "products": "xz"}'}]}
    out = await enrich.llm_extract(FakeHttp(FakeResponse(200, reply)), "t", "k", "m")
    assert out == {"workaround": "", "products": []}
