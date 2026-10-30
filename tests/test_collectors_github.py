"""GitHub 수집·서명 검증 테스트. 외부 호출 없이 가짜 HTTP와 가짜 상태로 검증한다. 담당: A eddieyee100."""
import asyncio
import functools
import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.collectors import github


def arun(fn):
    """async 테스트를 동기 테스트로 감싼다 (pytest-asyncio 없이 실행)."""

    @functools.wraps(fn)
    def wrapper():
        asyncio.run(fn())

    return wrapper


ADVISORY = {
    "ghsa_id": "GHSA-JFH8-GBNC-HGF2",
    "cve_id": "CVE-2021-44228",
    "summary": "Log4j RCE",
    "description": "JNDI lookup allows RCE",
    "cvss": {"score": 10.0},
    "published_at": "2021-12-10T12:00:00Z",
    "vulnerabilities": [
        {
            "package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"},
            "vulnerable_version_range": ">= 2.0.0, < 2.15.0",
            "first_patched_version": {"identifier": "2.15.0"},
        },
        {
            "package": {"ecosystem": "go", "name": "unsupported/module"},
            "vulnerable_version_range": "< 1.0",
            "first_patched_version": None,
        },
    ],
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
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
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


# gh_interval

def test_gh_interval_range_with_both_bounds():
    iv = github.gh_interval(">= 2.0.0, < 2.15.0")
    assert iv == {"lo": "2.0.0", "lo_inc": True, "hi": "2.15.0", "hi_inc": False}


def test_gh_interval_upper_only_and_exact():
    assert github.gh_interval("< 1.0") == {"lo": None, "lo_inc": True, "hi": "1.0", "hi_inc": False}
    assert github.gh_interval("= 3.1") == {"lo": "3.1", "lo_inc": True, "hi": "3.1", "hi_inc": True}


def test_gh_interval_rejects_unknown_clause():
    with pytest.raises(ValueError):
        github.gh_interval("~> 2.0")


# advisory_event / advisory_from_webhook

def test_advisory_event_maps_affected_and_ids():
    ev = github.advisory_event(ADVISORY, "GitHub Advisory")
    assert ev["kind"] == "advisory"
    assert ev["source"] == "GitHub Advisory"
    assert ev["ids"] == ["CVE-2021-44228"]
    affected = ev["fields"]["affected"]
    # go 생태계는 계약 밖이라 제외된다
    assert [(a["ecosystem"], a["name"]) for a in affected] == [("Maven", "org.apache.logging.log4j:log4j-core")]
    assert affected[0]["fixed_versions"] == ["2.15.0"]
    assert affected[0]["source"] == "GitHub Advisory"
    assert affected[0]["intervals"][0]["hi"] == "2.15.0"
    assert ev["fields"]["cvss"] == 10.0


def test_advisory_event_accepts_string_first_patched_version_as_real_api_returns():
    # 실제 REST API 응답: first_patched_version 이 문자열이다 (라이브 실행에서 발견한 버그)
    a = {
        "ghsa_id": "GHSA-XXXX-YYYY-ZZZZ",
        "cve_id": "CVE-2024-0002",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "requests"},
                "vulnerable_version_range": "< 2.32.0",
                "first_patched_version": "2.32.0",
            },
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "vulnerable_version_range": "< 4.17.21",
                "first_patched_version": None,
            },
        ],
    }
    affected = github.advisory_event(a, "GitHub Advisory")["fields"]["affected"]
    assert affected[0]["fixed_versions"] == ["2.32.0"]
    assert affected[1]["fixed_versions"] == []


def test_advisory_event_falls_back_to_ghsa_when_no_cve():
    ev = github.advisory_event({"ghsa_id": "ghsa-aaaa-bbbb-cccc"}, "GitHub Advisory")
    assert ev["ids"] == ["GHSA-AAAA-BBBB-CCCC"]


def test_advisory_from_webhook_reads_security_advisory_body():
    ev = github.advisory_from_webhook({"action": "published", "security_advisory": ADVISORY})
    assert ev["ids"] == ["CVE-2021-44228"]
    assert ev["source"].startswith("GitHub Advisory")


# verify_signature

def test_verify_signature_accepts_matching_hmac():
    body = b'{"action":"published"}'
    secret = "s3cret"
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert github.verify_signature(body, sig, secret) is True


def test_verify_signature_rejects_wrong_secret_missing_or_malformed_header():
    body = b"{}"
    good = "sha256=" + hmac.new(b"right", body, hashlib.sha256).hexdigest()
    assert github.verify_signature(body, good, "wrong") is False
    assert github.verify_signature(body, None, "right") is False
    assert github.verify_signature(body, good.replace("sha256=", "sha1="), "right") is False


# poll

@arun
async def test_poll_sends_token_and_emits_once():
    http = FakeHttp(FakeResponse([ADVISORY]))
    emitted = []

    async def emit(ev):
        emitted.append(ev)

    state = FakeState()
    recent = dict(ADVISORY, published_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    http.response = FakeResponse([recent])
    await github.poll(http, state, emit, 7, token="tkn")
    await github.poll(http, state, emit, 7, token="tkn")
    assert len(emitted) == 1
    assert http.calls[0][1]["headers"]["Authorization"] == "Bearer tkn"


@arun
async def test_poll_first_run_skips_old_advisories():
    emitted = []

    async def emit(ev):
        emitted.append(ev)

    await github.poll(FakeHttp(FakeResponse([ADVISORY])), FakeState(), emit, 7, token=None)
    assert emitted == []


@arun
async def test_poll_network_error_is_logged_and_skipped():
    emitted = []

    async def emit(ev):
        emitted.append(ev)

    await github.poll(FakeHttp(exc=httpx.ConnectError("down")), FakeState(), emit, 7, token=None)
    assert emitted == []
