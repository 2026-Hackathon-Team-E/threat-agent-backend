"""로컬 Ollama로 취약점 설명을 한국어 요약으로 바꾼다. 담당: 백엔드 표시 보조 (kmssss56).

외부 API 키가 필요 없다. Ollama 서버가 없거나 응답이 없으면 None을 돌려주고, 호출한 쪽은 원문을 그대로 쓴다.
"""
from __future__ import annotations

import re

import httpx
_CJK = re.compile(r"[\u3400-\u9fff\uf900-\ufaff\u3040-\u30ff]")
_HANGUL = re.compile(r"[\uac00-\ud7a3]")


def _clean(text: str) -> str | None:
    """모델 출력이 한국어 문장인지 검사한다. 중국어·일본어 글자가 섞였거나 한글이 거의 없으면 None."""
    out = (text or "").strip().strip('"\'').strip()
    if not out or _CJK.search(out):
        return None
    hangul = len(_HANGUL.findall(out))
    if hangul < max(4, len(out) // 4):
        return None
    return out



PROMPT = (
    "다음은 보안 취약점 또는 보안 뉴스 원문이다. 한국어로 3~4문장을 쓴다. "
    "1) 어떤 제품·기능에 무슨 취약점이 있는지, 2) 어떤 공격인지(누가·어떻게 악용하는지, 실제 공격이 확인됐는지), "
    "3) 어떤 대상이 위험한지, 4) 조치 방법이 원문에 있으면 짧게 덧붙인다. "
    "CVE 번호, 제품 이름, 패키지 이름, 버전, 회사 이름은 원문 그대로 쓴다. 원문에 없는 내용은 쓰지 않는다. "
    "중국어나 일본어를 쓰지 않는다. 요약문만 출력한다.\n\n"
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
        "options": {"temperature": 0.2, "num_predict": 320},
    }
    try:
        r = await http.post(f"{base_url.rstrip('/')}/api/generate", json=payload, timeout=120)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    try:
        out = _clean(str(r.json().get("response", "")))
    except ValueError:
        return None
    return out


HEADLINE_PROMPT = (
    "다음 보안 기사의 원문 제목을 한국어 한 줄 제목(30자 이내)으로 옮긴다. "
    "원문 제목이 영어면 자연스러운 한국어로 번역하고, 핵심 사건(누가·무엇이·어떻게)만 남긴다. "
    "회사명, 제품명, CVE 번호는 원문 그대로 쓴다. 원문에 없는 사실은 절대 추가하지 않는다. "
    "중국어나 일본어를 쓰지 않는다. 제목 한 줄만 출력한다.\n\n"
)


async def headline_ko(http: httpx.AsyncClient, title: str, summary: str, base_url: str, model: str) -> str | None:
    """뉴스 기사 한 줄 한국어 제목. 실패하면 None."""
    title = (title or "").strip()
    if not title and not summary:
        return None
    body_text = f"원문 제목: {title}\n원문 요약: {(summary or '')[:400]}"
    payload = {
        "model": model,
        "prompt": HEADLINE_PROMPT + body_text,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 60},
    }
    try:
        r = await http.post(f"{base_url.rstrip('/')}/api/generate", json=payload, timeout=120)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    try:
        first = str(r.json().get("response", "")).strip().splitlines()[0]
    except (ValueError, IndexError):
        return None
    out = _clean(first)
    if not out or len(out) > 40:
        return None
    return out

