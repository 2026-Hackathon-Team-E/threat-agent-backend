"""app/collectors/news.py 테스트. 외부 호출 없이 fixture RSS와 가짜 객체로 검증한다. 담당: B kmssss56."""
from pathlib import Path

import httpx
import pytest

from app.collectors import news

import asyncio
import functools


def arun(fn):
    """async 테스트를 동기 테스트로 감싼다 (pytest-asyncio 없이 실행)."""

    @functools.wraps(fn)
    def wrapper():
        asyncio.run(fn())

    return wrapper

FIXTURES = Path(__file__).parent / "fixtures"
FEEDS = ["https://example.com/feed.xml"]


class FakeResponse:
    def __init__(self, content=b"", status_code=200):
        self.content = content
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("bad", request=None, response=None)


class FakeHttp:
    def __init__(self, responses):
        self.responses = responses  # url -> FakeResponse 또는 Exception
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append(url)
        item = self.responses[url]
        if isinstance(item, Exception):
            raise item
        return item

    async def post(self, url, **kwargs):
        raise AssertionError("LLM 호출이 없어야 함 (키 없음)")


class FakeState:
    def __init__(self):
        self.kv = {}
        self.seen = set()

    def get(self, key):
        return self.kv.get(key)

    def set(self, key, value):
        self.kv[key] = value

    def mark_seen(self, source, item_id):
        key = (source, item_id)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


def _sample():
    return (FIXTURES / "news_feed_sample.xml").read_bytes()


async def _run(http, state, lookback_days=7, feeds=FEEDS):
    out = []

    async def emit(ev):
        out.append(ev)

    await news.poll(http, state, emit, lookback_days, feeds, None, "claude-haiku-5-5")
    return out


def test_extract_cves_uppercases_dedupes_and_sorts():
    text = "cve-2024-3094 and CVE-2021-44228, again CVE-2024-3094"
    assert news.extract_cves(text) == ["CVE-2021-44228", "CVE-2024-3094"]


def test_extract_cves_empty_text():
    assert news.extract_cves("") == []
    assert news.extract_cves(None) == []


def test_is_security_news_keywords_english_and_korean():
    assert news.is_security_news("Ransomware gang hits hospital")
    assert news.is_security_news("새로운 보안 취약점 발견")
    assert not news.is_security_news("Company announces quarterly earnings and new office")


def test_news_id_is_stable_per_link_and_prefixed():
    a = news.news_id("https://example.com/news/x")
    assert a == news.news_id("https://example.com/news/x")
    assert a != news.news_id("https://example.com/news/y")
    assert a.startswith("NEWS:") and len(a) == len("NEWS:") + 12


@arun
async def test_poll_emits_cve_articles_and_security_news_without_cve():
    http = FakeHttp({FEEDS[0]: FakeResponse(_sample())})
    state = FakeState()
    events = await _run(http, state, lookback_days=365 * 30)  # 샘플의 2001년 기사까지 포함
    ids = [e["ids"] for e in events]
    assert ["CVE-2024-3094"] in ids
    assert ["CVE-2019-0001"] in ids
    assert all(e["kind"] == "news" for e in events)
    assert all(e["source"].startswith("뉴스:") for e in events)
    # 'Quarterly threat report'는 CVE는 없지만 보안 키워드('vulnerability')가 있어서 NEWS: id로 수집된다
    no_cve = [e for e in events if e["ids"][0].startswith("NEWS:")]
    assert len(no_cve) == 1
    assert no_cve[0]["fields"]["title"] == "Quarterly threat report"
    assert len(events) == 3


@arun
async def test_first_run_skips_old_entries():
    http = FakeHttp({FEEDS[0]: FakeResponse(_sample())})
    state = FakeState()
    events = await _run(http, state, lookback_days=7)
    ids = [e["ids"] for e in events]
    assert ids == []  # 샘플 CVE 기사는 모두 lookback 밖 날짜이므로 첫 실행에서 제외
    assert state.get("first_run:news") == "done"


@arun
async def test_second_poll_does_not_emit_duplicates():
    http = FakeHttp({FEEDS[0]: FakeResponse(_sample())})
    state = FakeState()
    first = await _run(http, state, lookback_days=365 * 30)
    second = await _run(http, state, lookback_days=365 * 30)
    assert len(first) == 3  # CVE 기사 2건 + CVE 없는 보안 기사 1건
    assert second == []


@arun
async def test_failed_feed_does_not_stop_other_feeds():
    bad, good = "https://bad.example/feed", "https://good.example/feed"
    http = FakeHttp({bad: httpx.ConnectError("down"), good: FakeResponse(_sample())})
    state = FakeState()
    events = await _run(http, state, lookback_days=365 * 30, feeds=[bad, good])
    assert len(events) == 3
    assert http.calls == [bad, good]


@arun
async def test_http_status_error_is_skipped():
    http = FakeHttp({FEEDS[0]: FakeResponse(b"", status_code=503)})
    assert await _run(http, FakeState(), lookback_days=365 * 30) == []


@arun
async def test_event_fields_match_contract():
    http = FakeHttp({FEEDS[0]: FakeResponse(_sample())})
    events = await _run(http, FakeState(), lookback_days=365 * 30)
    ev = next(e for e in events if e["ids"] == ["CVE-2024-3094"])
    assert set(ev) == {"source", "kind", "ids", "fields"}
    assert ev["fields"]["title"].startswith("Backdoor")
    assert "summary" in ev["fields"]
    assert ev["fields"]["workaround"] is None  # 키 없으면 임시 조치는 비어 있음


@arun
async def test_emit_failure_for_one_entry_does_not_stop_others():
    http = FakeHttp({FEEDS[0]: FakeResponse(_sample())})
    calls = []

    async def flaky_emit(ev):
        calls.append(ev["ids"])
        if len(calls) == 1:
            raise RuntimeError("queue full")

    await news.poll(http, FakeState(), flaky_emit, 365 * 30, FEEDS, None, "claude-haiku-5-5")
    # 보안 기사 3건(CVE 2건 + CVE 없는 1건)을 모두 시도해야 한다 (첫 건 실패가 나머지를 막지 않음)
    assert len(calls) == 3
