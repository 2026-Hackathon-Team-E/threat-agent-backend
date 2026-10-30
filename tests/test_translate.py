"""app/translate.py 테스트. 외부 호출 없이 가짜 HTTP 객체로 검증. 담당: kmssss56."""
import asyncio

import httpx

from app.translate import translate_ko


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeHttp:
    def __init__(self, response=None, exc=None):
        self.response = response
        self.exc = exc
        self.calls = []

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.exc:
            raise self.exc
        return self.response


def run(coro):
    return asyncio.run(coro)


def test_returns_model_response_and_calls_generate_endpoint():
    http = FakeHttp(FakeResponse(200, {"response": "요약입니다."}))
    out = run(translate_ko(http, "Some description", "http://localhost:11434", "qwen2.5:7b"))
    assert out == "요약입니다."
    url, kwargs = http.calls[0]
    assert url == "http://localhost:11434/api/generate"
    assert kwargs["json"]["model"] == "qwen2.5:7b"
    assert kwargs["json"]["stream"] is False


def test_empty_text_skips_call():
    http = FakeHttp(FakeResponse(200, {"response": "x"}))
    assert run(translate_ko(http, "   ", "http://localhost:11434", "m")) is None
    assert http.calls == []


def test_server_down_returns_none():
    http = FakeHttp(exc=httpx.ConnectError("refused"))
    assert run(translate_ko(http, "text", "http://localhost:11434", "m")) is None


def test_bad_status_returns_none():
    http = FakeHttp(FakeResponse(500, {}))
    assert run(translate_ko(http, "text", "http://localhost:11434", "m")) is None


def test_long_input_is_truncated():
    http = FakeHttp(FakeResponse(200, {"response": "ok"}))
    run(translate_ko(http, "a" * 5000, "http://localhost:11434", "m", max_chars=100))
    prompt = http.calls[0][1]["json"]["prompt"]
    assert prompt.endswith("a" * 100)


from app import translate as _tr


def test_clean_rejects_chinese_or_japanese_mixed_output():
    assert _tr._clean("Vapor Panda利用ARTEX攻击200多家") is None
    assert _tr._clean("Syrian黑客致1360亿美元股市暴跌") is None


def test_clean_rejects_latin_dominant_output():
    assert _tr._clean("GitLab critical flaw exploited in the wild") is None


def test_clean_keeps_korean_sentence():
    assert _tr._clean('"GitLab 치명적 취약점, 실제 공격에 악용 확인"') == "GitLab 치명적 취약점, 실제 공격에 악용 확인"


def test_headline_too_long_returns_none():
    http = FakeHttp(FakeResponse(200, {"response": "가" * 50}))
    assert run(_tr.headline_ko(http, "t", "s", "http://localhost:11434", "m")) is None


def test_headline_chinese_returns_none():
    http = FakeHttp(FakeResponse(200, {"response": "Binance 安全事件"}))
    assert run(_tr.headline_ko(http, "t", "s", "http://localhost:11434", "m")) is None
