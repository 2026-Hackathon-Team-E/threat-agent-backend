"""공용 fixture: 임시 Store, 샘플 카드·영향 카드.

담당: D redsun2. 계약은 docs/CONTRACT.md 참고.
"""
from __future__ import annotations

import pytest

from app.store import Store


@pytest.fixture
def store(tmp_path) -> Store:
    """테스트마다 새 SQLite 파일을 쓰는 Store."""
    return Store(str(tmp_path / "test.db"))


@pytest.fixture
def log4shell_card() -> dict:
    return {
        "key": "CVE-2021-44228",
        "ids": ["CVE-2021-44228", "GHSA-jfh8-gbnc-hgf2"],
        "sources": ["CISA KEV"],
        "title": "Apache Log4j2 Remote Code Execution",
        "summary": None,
        "workaround": None,
        "kev": True,
        "ransomware": False,
        "due_date": "2021-12-24",
        "cvss": 10.0,
        "epss": None,
        "affected": [
            {
                "ecosystem": "Maven",
                "name": "org.apache.logging.log4j:log4j-core",
                "intervals": [{"lo": "2.0.0", "lo_inc": True, "hi": "2.15.0", "hi_inc": False}],
                "fixed_versions": ["2.15.0"],
                "source": "GitHub Advisory",
            }
        ],
        "status": "확정",
        "version": 1,
        "osv_checked_at": 0.0,
        "epss_checked": False,
    }


@pytest.fixture
def sample_impact() -> dict:
    return {
        "id": "CVE-2021-44228@payment-api:Maven:org.apache.logging.log4j:log4j-core",
        "card": "CVE-2021-44228",
        "title": "Apache Log4j2 Remote Code Execution",
        "service": "payment-api",
        "env": "prod",
        "exposed": True,
        "dep": "org.apache.logging.log4j:log4j-core",
        "ecosystem": "Maven",
        "installed": "2.14.1",
        "fixed": "2.15.0",
        "priority": {"tier": "긴급", "rank": [1, 0, 1, 0.97, 10.0], "reasons": ["KEV 등록(실제 악용)"]},
        "status": "미조치",
        "remediation": None,
        "rescan": None,
    }
