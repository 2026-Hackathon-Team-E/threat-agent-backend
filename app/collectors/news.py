"""보안 뉴스 RSS 폴링, CVE 추출, kind=news 이벤트. 담당: B kmssss56.

의존: app.enrich(같은 담당), app.types. 설정 상수는 이 파일이나 인자로만 받는다.
CVE가 있는 기사는 CVE를 id로, CVE가 없어도 보안 키워드가 있으면 링크 해시를 id로 낸다.
임시 조치는 LLM으로 뽑는다(키가 없으면 빈 값).
"""
from __future__ import annotations

import calendar
import hashlib
import logging
import re
import time

import feedparser
import httpx

from app.enrich import llm_extract
from app.types import Emit, State

log = logging.getLogger("collectors.news")

CVE_PATTERN = r"CVE-\d{4}-\d{4,}"
_CVE_RE = re.compile(CVE_PATTERN, re.IGNORECASE)
MAX_ENTRIES_PER_FEED = 30


def extract_cves(text: str) -> list[str]:
    """대문자로 정규화한 CVE 목록 (중복 제거, 정렬)."""
    return sorted({m.upper() for m in _CVE_RE.findall(text or "")})


# CVE가 없어도 보안 기사로 볼 키워드 (영문은 대소문자 무시, 한국어는 부분 일치)
SECURITY_KEYWORDS = (
    "security", "vulnerab", "exploit", "malware", "ransomware", "breach", "hack",
    "phishing", "zero-day", "zero day", "data leak", "attack", "botnet", "backdoor",
    "patch", "supply chain", "spyware", "ddos", "credential",
    "보안", "취약점", "해킹", "랜섬웨어", "악성코드", "침해", "피싱", "공격", "유출", "패치",
)


def is_security_news(text: str) -> bool:
    """CVE가 없어도 보안 관련 기사인지 키워드로 본다."""
    low = (text or "").lower()
    return any(k in low for k in SECURITY_KEYWORDS)


def news_id(link: str) -> str:
    """CVE가 없는 기사의 식별자. 링크의 해시라서 같은 기사는 항상 같은 id가 된다."""
    return "NEWS:" + hashlib.sha1(link.encode("utf-8")).hexdigest()[:12].upper()


def _is_recent(published_parsed, lookback_days: int) -> bool:
    """날짜가 없으면 최근으로 본다. feedparser의 published_parsed는 UTC 기준."""
    if not published_parsed:
        return True
    return calendar.timegm(published_parsed) >= time.time() - lookback_days * 86400


async def poll(
    http: httpx.AsyncClient,
    state: State,
    emit: Emit,
    lookback_days: int,
    feeds: list[str],
    llm_key: str | None,
    llm_model: str,
) -> None:
    """RSS 피드들을 한 번 훑어 새 기사 중 보안 기사(CVE 있음 또는 보안 키워드)를 emit 한다.

    첫 실행(first_run 메타 없음)에는 lookback_days 이내 기사만 낸다.
    한 피드가 실패해도 나머지 피드는 계속 처리한다.
    """
    first = state.get("first_run:news") is None
    for url in feeds:
        try:
            r = await http.get(url, timeout=20)
            r.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("뉴스 피드 가져오기 실패 %s: %s", url, exc)
            continue

        feed = feedparser.parse(r.content)
        src = feed.feed.get("title", url)
        for entry in feed.entries[:MAX_ENTRIES_PER_FEED]:
            link = entry.get("link") or entry.get("id")
            if not link or not state.mark_seen("news", link):
                continue
            if first and not _is_recent(entry.get("published_parsed"), lookback_days):
                continue

            title = entry.get("title", "")
            summary = entry.get("summary", "")
            text = f"{title}\n{summary}"
            cves = extract_cves(text)
            if cves:
                ids = cves
            elif is_security_news(text):
                # CVE가 없는 보안 기사: 링크 해시를 식별자로 쓴다 (카드는 '미확정'으로 남는다)
                ids = [news_id(link)]
            else:
                continue

            info = await llm_extract(http, text, llm_key, llm_model)
            event = {
                "source": f"뉴스:{src}",
                "kind": "news",
                "ids": ids,
                "fields": {
                    "title": title,
                    "summary": summary,
                    "workaround": info.get("workaround") or None,
                },
            }
            try:
                await emit(event)
            except Exception as exc:  # noqa: BLE001
                # 한 기사의 emit 실패가 나머지 기사 처리를 막지 않도록 한다
                log.warning("뉴스 이벤트 전달 실패 %s: %r", link, exc)
    state.set("first_run:news", "done")
