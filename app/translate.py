"""로컬 Ollama로 취약점 설명을 한국어 요약으로 바꾼다. 담당: 백엔드 표시 보조 (kmssss56).

외부 API 키가 필요 없다. Ollama 서버가 없거나 응답이 없으면 None을 돌려주고, 호출한 쪽은 원문을 그대로 쓴다.
"""
from __future__ import annotations

import httpx

PROMPT = (
    "다음은 보안 취약점 설명이다. 한국어로 2~3문장으로 쉽게 요약하라. "
    "CVE 번호, 패키지 이름, 제품 이름, 버전은 원문 그대로 쓴다. 요약문만 출력하고 다른 말은 쓰지 않는다.\n\n"
)


async def translate_ko(
    http: httpx.AsyncClient, text: str, base_url: str, model: str, max_chars: int = 1500
) -> str | None:
    """설명 원문을 한국어 요약으로 만든다. 실패하면 None."""
    body_text = (text or "").strip()
    if not body_text:
        return None
    payload = {
        "model": model,
        "prompt": PROMPT + body_text[:max_chars],
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 220},
    }
    try:
        r = await http.post(f"{base_url.rstrip('/')}/api/generate", json=payload, timeout=120)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    try:
        out = str(r.json().get("response", "")).strip()
    except ValueError:
        return None
    return out or None


HEADLINE_PROMPT = (
    "다음은 보안 뉴스 기사 제목과 요약이다. 기사의 핵심을 한국어 제목 한 줄(25자 이내)로 쓴다. "
    "회사명, 제품명, CVE 번호는 원문 그대로 쓴다. 예: '신한은행 고객정보 해킹 발생', '빗썸 거래소 취약점 발견'. "
    "제목 한 줄만 출력한다.\n\n"
)


async def headline_ko(http: httpx.AsyncClient, title: str, summary: str, base_url: str, model: str) -> str | None:
    """뉴스 기사 한 줄 한국어 제목. 실패하면 None."""
    body_text = f"{title}\n{summary}".strip()
    if not body_text:
        return None
    payload = {
        "model": model,
        "prompt": HEADLINE_PROMPT + body_text[:1000],
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 60},
    }
    try:
        r = await http.post(f"{base_url.rstrip('/')}/api/generate", json=payload, timeout=120)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    try:
        out = str(r.json().get("response", "")).strip().splitlines()[0].strip().strip('"\'')
    except (ValueError, IndexError):
        return None
    return out[:60] or None

