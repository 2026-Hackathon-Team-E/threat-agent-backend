"""앱 설정 (환경변수). 담당: D redsun2. 수집기 모듈은 여기를 import하지 않는다."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "7"))
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") or None
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET") or None
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY") or None
LLM_MODEL = os.getenv("LLM_MODEL", "claude-haiku-5-5")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:8080").split(",") if o.strip()]

# 폴링 주기 (초)
NEWS_INTERVAL = int(os.getenv("NEWS_INTERVAL", "300"))
KEV_INTERVAL = int(os.getenv("KEV_INTERVAL", "600"))
GH_INTERVAL = int(os.getenv("GH_INTERVAL", "900"))

# 폴러를 끄고 싶을 때 (오프라인 데모, 테스트) POLLERS=off
POLLERS_ENABLED = os.getenv("POLLERS", "on").lower() != "off"

# 경로
DB_PATH = os.getenv("DB_PATH", str(ROOT / "data" / "app.db"))
SBOM_DIR = ROOT / "sbom"
WORKSPACE_DIR = ROOT / "workspace"

# 보안 뉴스 RSS (B 담당 news.poll에 인자로 넘긴다)
NEWS_FEEDS = [
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://github.blog/category/security/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.securityweek.com/feed/",
    "https://www.theregister.com/security/headlines.atom",
    "https://krebsonsecurity.com/feed/",
    "https://www.php.net/feed.atom",  # PHP 공식 뉴스 (CVE 포함 기사만 수집됨)
]

# 로컬 Ollama (한국어 설명 요약). 서버가 없으면 빈 값으로 두면 번역을 건너뛴다.
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")

# 정리·갱신 (retention 루프)
RETENTION_INTERVAL = int(os.getenv("RETENTION_INTERVAL", "3600"))
NEWS_RETENTION_DAYS = int(os.getenv("NEWS_RETENTION_DAYS", "30"))
REFRESH_STALE_HOURS = int(os.getenv("REFRESH_STALE_HOURS", "6"))
REFRESH_BATCH = int(os.getenv("REFRESH_BATCH", "20"))

