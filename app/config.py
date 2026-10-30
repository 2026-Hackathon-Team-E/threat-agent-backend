"""앱 설정 (환경변수). 담당: D redsun2. 수집기 모듈은 여기를 import하지 않는다.

상태: 구현 전.
"""
from __future__ import annotations

import os

LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "7"))
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
LLM_MODEL = os.getenv("LLM_MODEL", "claude-haiku-5-5")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:8080").split(",")
