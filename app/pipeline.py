"""이벤트 처리: 카드 병합, 외부 보강 호출, 매칭, 수정 적용, 재스캔. 담당: D redsun2.

의존 (시그니처만): enrich(B), matcher·priority(C), remediate·sbom(E), store(D).
수집기는 이 모듈을 import하지 않는다 (이벤트만 큐로 보낸다).
상태: 시그니처만 확정, 구현 전.
"""
from __future__ import annotations

from pathlib import Path

from app.store import Store
from app.types import Event, Impact, Service


async def handle_event(
    ev: Event,
    store: Store,
    http,
    services: dict[str, Service],
    workspace: Path,
) -> list[Impact]:
    raise NotImplementedError


def scan(card, store: Store, services: list[Service]) -> list[Impact]:
    """새로 생긴 영향 카드만 반환 (같은 id는 재생성하지 않는다)."""
    raise NotImplementedError


def act(imp: Impact, store: Store, services: dict[str, Service], workspace: Path) -> Impact:
    raise NotImplementedError


async def on_deploy(name: str, store: Store, services: dict[str, Service], workspace: Path) -> list[Impact]:
    raise NotImplementedError
