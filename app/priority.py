"""우선순위 계산 (CONTRACT 6장). 담당: C marineusus. 외부 의존 없음.

rank는 [kev, ransomware, exposed, epss, cvss] 순이며 내림차순 정렬용이다.
"""
from __future__ import annotations

from app.types import Card, Priority, Service


def score(card: Card, svc: Service) -> Priority:
    """악용 여부, 노출 여부, 알려진 점수로 등급·정렬 키·표시 근거를 만든다."""
    kev = card.get("kev", False)
    ransomware = card.get("ransomware", False)
    exposed = svc["internet_exposed"]
    epss = card.get("epss")
    cvss = card.get("cvss")

    tier = "긴급" if kev or ransomware else "높음" if exposed else "보통"
    reasons = []
    if kev:
        reasons.append("KEV 등록(실제 악용)")
    if ransomware:
        reasons.append("랜섬웨어 악용")
    if exposed:
        reasons.append("인터넷 노출")
    if epss is not None:
        reasons.append(f"EPSS {epss}")
    if cvss is not None:
        reasons.append(f"CVSS {cvss}")

    return {
        "tier": tier,
        "rank": [
            int(kev), int(ransomware), int(exposed),
            epss if epss is not None else 0.0,
            cvss if cvss is not None else 0.0,
        ],
        "reasons": reasons,
    }
