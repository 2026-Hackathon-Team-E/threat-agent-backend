"""공유 데이터 타입. 계약 문서 docs/CONTRACT.md 1~5장과 1:1로 대응한다.

담당: 공유 (리드 redsun2). 이 파일은 타입 선언만 두며 로직을 넣지 않는다.
모든 모듈은 이 파일만 import할 수 있다 (다른 역할 모듈 import 금지).
"""
from __future__ import annotations

from typing import Awaitable, Callable, Protocol, TypedDict


class Interval(TypedDict):
    lo: str | None
    lo_inc: bool
    hi: str | None
    hi_inc: bool


class Affected(TypedDict):
    ecosystem: str
    name: str
    intervals: list[Interval]
    fixed_versions: list[str]
    source: str


class Dep(TypedDict):
    ecosystem: str
    name: str
    version: str
    source: str | None


class Service(TypedDict):
    name: str
    env: str
    internet_exposed: bool
    manifests: list[str]
    manifest_paths: dict[str, str]
    deps: list[Dep]


class Event(TypedDict, total=False):
    source: str
    kind: str
    ids: list[str]
    fields: dict
    observed_at: float
    service: str


class Card(TypedDict):
    key: str
    ids: list[str]
    sources: list[str]
    title: str | None
    summary: str | None
    workaround: str | None
    kev: bool
    ransomware: bool
    due_date: str | None
    cvss: float | None
    epss: float | None
    affected: list[Affected]
    status: str
    version: int
    osv_checked_at: float
    epss_checked: bool


class Priority(TypedDict):
    tier: str
    rank: list[int | float]
    reasons: list[str]


class Remediation(TypedDict):
    kind: str
    text: str
    diff: str | None


class Impact(TypedDict):
    id: str
    card: str
    title: str | None
    service: str
    env: str
    exposed: bool
    dep: str
    ecosystem: str
    installed: str
    fixed: str | None
    priority: Priority
    status: str
    remediation: Remediation | None
    rescan: int | None


class State(Protocol):
    """수집기가 주입받는 상태 저장소 인터페이스. Store(D)가 구현한다."""

    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str) -> None: ...

    def mark_seen(self, source: str, item_id: str) -> bool:
        """처음 보면 True, 이미 봤으면 False."""
        ...


Emit = Callable[[Event], Awaitable[None]]
