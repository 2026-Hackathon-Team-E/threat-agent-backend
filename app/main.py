"""FastAPI 앱: lifespan(워커·폴러 시작), 엔드포인트, CORS. 담당: D redsun2.

docs/API.md 참고. 설정값은 이 파일 또는 config.py에서 읽어 각 수집기에 인자로 넘긴다.
상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="threat-agent-backend")
