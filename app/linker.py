"""뉴스 카드와 우리 SBOM 패키지를 잇는다. 담당: 백엔드 (kmssss56).

역할 분담:
- 모델(Ollama): 기사 속 제품 이름이 SBOM 후보 중 어떤 패키지인지 고른다 (후보 목록 안에서만).
- 코드: 고른 패키지를 OSV에서 조회하고, 카드의 CVE와 맞는 취약 범위만 가져온다.
  영향 여부와 우선순위는 코드가 판단한다 (모델은 판단하지 않는다).
"""
from __future__ import annotations

import json
import re

import httpx

from app import translate
from app.enrich import osv_intervals
from app.types import Affected

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

PICK_PROMPT = (
    "다음은 보안 기사다. 아래 후보 패키지 목록 중에서 기사가 말하는 제품과 같은 것만 골라라. "
    "목록에 없는 이름은 쓰지 않는다. 해당하는 것이 없으면 빈 배열 []을 출력한다. "
    'JSON 배열만 출력한다. 예: ["log4j-core"]\n\n'
)


def _parse_list(text: str) -> list[str]:
    m = re.search(r"\[.*?\]", text or "", re.S)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return []
    return [str(x) for x in data] if isinstance(data, list) else []


async def pick_packages(
    http: httpx.AsyncClient, text: str, candidates: list[str], base_url: str, model: str
) -> list[str]:
    """모델이 고른 패키지 이름 중 후보 목록에 실제로 있는 것만 돌려준다 (없는 이름은 버린다)."""
    if not candidates or not text.strip():
        return []
    payload = {
        "model": model,
        "prompt": PICK_PROMPT + "후보: " + ", ".join(candidates) + "\n\n기사:\n" + text[:1200],
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 80},
    }
    try:
        r = await http.post(f"{base_url.rstrip('/')}/api/generate", json=payload, timeout=120)
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    try:
        picked = _parse_list(str(r.json().get("response", "")))
    except ValueError:
        return []
    allowed = set(candidates)
    return [p for p in picked if p in allowed]


def affected_from_vuln(vuln: dict, ecosystem: str, name: str) -> Affected | None:
    """OSV 취약점 한 건에서, 해당 패키지의 취약 범위만 꺼낸다."""
    for a in vuln.get("affected", []) or []:
        pkg = a.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or pkg.get("name") != name:
            continue
        intervals = osv_intervals(a)
        if not intervals:
            continue
        fixed = [ev["fixed"] for rng in a.get("ranges", []) for ev in rng.get("events", []) if "fixed" in ev]
        return {
            "ecosystem": ecosystem,
            "name": name,
            "intervals": intervals,
            "fixed_versions": fixed,
            "source": f"OSV:{vuln.get('id', '')}",
        }
    return None


async def osv_package_vulns(http: httpx.AsyncClient, ecosystem: str, name: str) -> list[dict]:
    """패키지 기준 OSV 조회. 실패하면 빈 목록."""
    try:
        r = await http.post(
            OSV_QUERY_URL, json={"package": {"ecosystem": ecosystem, "name": name}}, timeout=20
        )
    except httpx.HTTPError:
        return []
    if r.status_code != 200:
        return []
    try:
        return list(r.json().get("vulns", []) or [])
    except ValueError:
        return []


async def link_news_card(
    http: httpx.AsyncClient,
    card: dict,
    sbom_deps: list[dict],
    base_url: str,
    model: str,
) -> list[Affected]:
    """뉴스 카드 하나에 대해: 모델이 고른 SBOM 패키지 → OSV → 카드 CVE와 맞는 취약 범위만 반환."""
    cves = {i for i in card.get("ids", []) if str(i).startswith("CVE-")}
    if not cves:
        return []
    text = f"{card.get('title') or ''}\n{card.get('summary') or ''}"
    pairs = sorted({(d["ecosystem"], d["name"]) for d in sbom_deps})
    names = [n for _, n in pairs]
    picked = set(await pick_packages(http, text, names, base_url, model))
    out: list[Affected] = []
    for eco, name in pairs:
        if name not in picked:
            continue
        for vuln in await osv_package_vulns(http, eco, name):
            ids = {vuln.get("id", ""), *(vuln.get("aliases") or [])}
            if not (ids & cves):
                continue
            aff = affected_from_vuln(vuln, eco, name)
            if aff:
                out.append(aff)
    return out
