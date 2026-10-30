"""외부 보강: OSV 범위 조회, EPSS 점수, LLM 뉴스 추출. 담당: B kmssss56.

의존: 없음 (types.py와 httpx 객체만 사용). 파이프라인(D)이 호출한다.
OSV 응답 → Interval 변환도 이 파일에 둔다. 네트워크 실패는 예외 대신 빈 결과로 돌려준다.
"""
from __future__ import annotations

import json
import re

import httpx

from app.types import Affected, Interval

OSV_URL = "https://api.osv.dev/v1/vulns/{vid}"
EPSS_URL = "https://api.first.org/data/v1/epss"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

LLM_SYSTEM = (
    "너는 보안 뉴스 요약 도우미다. 사용자가 준 기사에서 임시 조치(workaround)와 "
    "영향받는 제품명(products)을 찾아 JSON 객체 하나만 출력한다. "
    '형식: {"workaround": "...", "products": ["..."]}. '
    "모르면 빈 문자열이나 빈 배열을 쓴다. JSON 밖의 설명은 쓰지 않는다."
)


def osv_intervals(entry: dict) -> list[Interval]:
    """OSV affected 항목의 ranges와 versions를 Interval 목록으로 바꾼다.

    introduced → fixed 는 hi 미포함(hi_inc=False), last_affected 는 hi 포함.
    introduced 가 "0" 이면 하한 없음(lo=None).
    """
    out: list[Interval] = []
    for rng in entry.get("ranges", []):
        if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        cur: Interval | None = None
        for ev in rng.get("events", []):
            if "introduced" in ev:
                cur = {
                    "lo": None if ev["introduced"] == "0" else ev["introduced"],
                    "lo_inc": True,
                    "hi": None,
                    "hi_inc": False,
                }
                out.append(cur)
            elif "fixed" in ev and cur is not None:
                cur["hi"], cur["hi_inc"] = ev["fixed"], False
                cur = None
            elif "last_affected" in ev and cur is not None:
                cur["hi"], cur["hi_inc"] = ev["last_affected"], True
                cur = None
    for v in entry.get("versions", []):
        out.append({"lo": v, "lo_inc": True, "hi": v, "hi_inc": True})
    return out


async def osv(http: httpx.AsyncClient, vid: str) -> list[Affected]:
    """vid(GHSA 또는 CVE)의 affected 목록. 404, 네트워크 오류, 빈 응답이면 []."""
    try:
        r = await http.get(OSV_URL.format(vid=vid), timeout=20)
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    try:
        data = r.json()
    except ValueError:
        return []

    out: list[Affected] = []
    for a in data.get("affected", []):
        pkg = a.get("package") or {}
        if not pkg.get("name") or not pkg.get("ecosystem"):
            continue
        intervals = osv_intervals(a)
        if not intervals:
            continue
        fixed = [ev["fixed"] for rng in a.get("ranges", []) for ev in rng.get("events", []) if "fixed" in ev]
        out.append(
            {
                "ecosystem": pkg["ecosystem"],
                "name": pkg["name"],
                "intervals": intervals,
                "fixed_versions": fixed,
                "source": f"OSV:{vid}",
            }
        )
    return out


async def epss(http: httpx.AsyncClient, cve: str) -> float | None:
    """EPSS 악용 확률 (0~1). 데이터가 없거나 오류면 None."""
    try:
        r = await http.get(EPSS_URL, params={"cve": cve}, timeout=20)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    try:
        rows = r.json().get("data") or []
        return float(rows[0]["epss"]) if rows else None
    except (ValueError, KeyError, TypeError, IndexError):
        return None


async def llm_extract(http: httpx.AsyncClient, text: str, api_key: str | None, model: str) -> dict:
    """뉴스 본문에서 {"workaround": str, "products": [str]} 를 뽑는다.

    api_key가 없으면 호출하지 않고 {}. 응답 파싱이 실패해도 {}.
    """
    if not api_key:
        return {}
    body = {
        "model": model,
        "max_tokens": 400,
        "system": LLM_SYSTEM,
        "messages": [{"role": "user", "content": text[:4000]}],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    try:
        r = await http.post(ANTHROPIC_URL, headers=headers, json=body, timeout=60)
    except httpx.HTTPError:
        return {}
    if r.status_code != 200:
        return {}
    try:
        blocks = r.json().get("content", [])
    except ValueError:
        return {}
    txt = "".join(b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")
    m = re.search(r"\{.*\}", txt, re.S)
    if not m:
        return {}
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    products = data.get("products")
    return {
        "workaround": str(data.get("workaround") or "")[:500],
        "products": [str(p) for p in products] if isinstance(products, list) else [],
    }
