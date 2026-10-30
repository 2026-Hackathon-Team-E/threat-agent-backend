"""위협 카드 목록용 표시 필드. 한국어 요약, 위험 등급, 영향 서비스, 대상 제품을 만든다.

순수 함수만 둔다 (외부 호출·저장소 접근 없음). 담당: D redsun2 영역의 표시 보조 모듈.
"""
from __future__ import annotations


def risk_label(card: dict) -> str:
    """긴급: KEV 등록 또는 랜섬웨어 악용. 높음: EPSS 50% 이상. 그 외 보통."""
    if card.get("kev") or card.get("ransomware"):
        return "긴급"
    if (card.get("epss") or 0) >= 0.5:
        return "높음"
    return "보통"


def summary_ko(card: dict) -> str:
    """영문 제목 대신 읽을 수 있는 한 줄 설명."""
    if card.get("ransomware"):
        return "랜섬웨어 공격에 실제로 쓰인 취약점입니다."
    if card.get("kev"):
        return "이미 실제 공격에 악용되고 있는 취약점입니다."
    if (card.get("epss") or 0) >= 0.5:
        return "곧 공격에 쓰일 가능성이 높은 취약점입니다."
    if card.get("status") == "확정":
        return "취약한 패키지 버전이 확인된 취약점입니다."
    return "뉴스로 보고됐고, 영향 범위는 아직 확인되지 않았습니다."


def products(card: dict, limit: int = 3) -> list[str]:
    """대상 패키지 짧은 이름 목록 (Maven은 artifactId만)."""
    names: list[str] = []
    for a in card.get("affected", []) or []:
        short = str(a.get("name", "")).split(":")[-1]
        if short and short not in names:
            names.append(short)
    return names[:limit]


def build(card: dict, impacts: list[dict], base_fields: tuple[str, ...]) -> dict:
    """목록 응답 한 건. base_fields는 기존 응답 필드, 나머지는 표시용 필드."""
    out = {k: card.get(k) for k in base_fields}
    out["risk_label"] = risk_label(card)
    out["summary_ko"] = summary_ko(card)
    out["products"] = products(card)
    out["affected_services"] = sorted({i["service"] for i in impacts if i.get("card") == card["key"]})
    epss = card.get("epss")
    out["epss_percent"] = round(epss * 100, 1) if epss is not None else None
    return out
