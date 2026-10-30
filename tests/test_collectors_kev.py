"""KEV 수집 테스트. 외부 호출 없이 가짜 HTTP와 가짜 상태로 검증한다. 담당: A eddieyee100."""
import asyncio
import functools
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.collectors import kev


def arun(fn):
    """async 테스트를 동기 테스트로 감싼다 (pytest-asyncio 없이 실행)."""

    @functools.wraps(fn)
    def wrapper():
        asyncio.run(fn())

    return wrapper


SAMPLE = {
    "cveID": "CVE-2021-44228",
    "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
    "shortDescription": "Log4j2 JNDI RCE",
    "requiredAction": "Apply updates per vendor instructions.",
    "dueDate": "2021-12-24",
    "dateAdded": "2021-12-10",
    "knownRansomwareCampaignUse": "Known",
}


class FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("bad", request=None, response=None)

    def json(self):
        return self._payload


class FakeHttp:
    def __init__(self, response=None, exc=None):
        self.response = response
        self.exc = exc

    async def get(self, url, **kwargs):
        if self.exc:
            raise self.exc
        return self.response


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


def _recent(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d")


def test_kev_event_maps_contract_fields():
    ev = kev.kev_event(SAMPLE)
    assert ev["source"] == "CISA KEV"
    assert ev["kind"] == "kev"
    assert ev["ids"] == ["CVE-2021-44228"]
    f = ev["fields"]
    assert f["title"] == "Apache Log4j2 Remote Code Execution"
    assert f["kev"] is True
    assert f["ransomware"] is True
    assert f["due_date"] == "2021-12-24"
    assert f["workaround"] == "Apply updates per vendor instructions."


def test_kev_event_not_ransomware_when_unknown_and_normalizes_id():
    ev = kev.kev_event({"cveID": " cve-2024-0001 ", "knownRansomwareCampaignUse": "Unknown"})
    assert ev["ids"] == ["CVE-2024-0001"]
    assert ev["fields"]["ransomware"] is False
    assert ev["fields"]["due_date"] is None


@arun
async def test_poll_emits_recent_entries_once():
    payload = {"vulnerabilities": [dict(SAMPLE, dateAdded=_recent(1))]}
    emitted = []

    async def emit(ev):
        emitted.append(ev)

    state = FakeState()
    await kev.poll(FakeHttp(FakeResponse(payload)), state, emit, lookback_days=7)
    await kev.poll(FakeHttp(FakeResponse(payload)), state, emit, lookback_days=7)
    assert [e["ids"] for e in emitted] == [["CVE-2021-44228"]]


@arun
async def test_first_run_skips_entries_older_than_lookback():
    payload = {"vulnerabilities": [dict(SAMPLE, dateAdded="2021-12-10")]}
    emitted = []

    async def emit(ev):
        emitted.append(ev)

    await kev.poll(FakeHttp(FakeResponse(payload)), FakeState(), emit, lookback_days=7)
    assert emitted == []


@arun
async def test_network_error_is_logged_and_skipped():
    emitted = []

    async def emit(ev):
        emitted.append(ev)

    await kev.poll(FakeHttp(exc=httpx.ConnectError("down")), FakeState(), emit, lookback_days=7)
    assert emitted == []
