"""FastAPI 앱: lifespan(워커·폴러 시작), 엔드포인트, CORS. 담당: D redsun2.

docs/API.md 참고. 설정값은 config.py에서 읽어 각 수집기에 인자로 넘긴다.
다른 역할 함수가 아직 구현 전(NotImplementedError)이어도 서버는 죽지 않는다.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from app import card_view, config, pipeline, sbom
from app.collectors import github, kev, news
from app.store import Store
from app.types import Event, Service

log = logging.getLogger("threat-agent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# 데모용 오프라인 이벤트. KEV 목록에는 패키지 버전 범위가 없어서,
# 네트워크(OSV)가 안 되는 발표장에서도 영향 카드가 나오도록 affected를 미리 넣어 둔다.
DEMO_EVENTS: dict[str, Event] = {
    "CVE-2021-44228": {
        "source": "CISA KEV",
        "kind": "kev",
        "ids": ["CVE-2021-44228", "GHSA-jfh8-gbnc-hgf2"],
        "fields": {
            "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
            "summary": "JNDI lookup을 통한 원격 코드 실행",
            "workaround": "log4j2.formatMsgNoLookups=true 설정 또는 JndiLookup 클래스 제거",
            "kev": True,
            "ransomware": True,
            "due_date": "2021-12-24",
            "cvss": 10.0,
            "affected": [
                {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                    "intervals": [{"lo": "2.0.0", "lo_inc": True, "hi": "2.15.0", "hi_inc": False}],
                    "fixed_versions": ["2.15.0", "2.16.0", "2.17.1"],
                    "source": "GitHub Advisory",
                }
            ],
        },
    },
}


class AppState:
    def __init__(self) -> None:
        self.store = Store(config.DB_PATH)
        self.queue: asyncio.Queue[Event] = asyncio.Queue()
        self.services: dict[str, Service] = load_services()
        self.http: httpx.AsyncClient | None = None
        self.tasks: list[asyncio.Task] = []


def load_services() -> dict[str, Service]:
    """E의 sbom.load_all. 구현 전이면 services.json만 읽어 deps 없이 채운다."""
    try:
        return sbom.load_all()
    except Exception as e:  # noqa: BLE001 - 구현 전 스텁 포함
        log.warning("sbom.load_all 실패, services.json만 사용: %r", e)
        raw = json.loads((config.SBOM_DIR / "services.json").read_text(encoding="utf-8"))
        return {
            name: {
                "name": name,
                "env": v.get("env", "dev"),
                "internet_exposed": bool(v.get("internet_exposed")),
                "manifests": v.get("manifests", []),
                "manifest_paths": {},
                "deps": [],
            }
            for name, v in raw.items()
        }


async def emit(ev: Event) -> None:
    """수집기·웹훅이 이벤트를 큐에 넣는 단일 입구."""
    ev.setdefault("observed_at", time.time())
    await S.queue.put(ev)


async def worker() -> None:
    while True:
        ev = await S.queue.get()
        try:
            log.info("이벤트 처리: %s %s %s", ev.get("kind"), ev.get("source"), ev.get("ids") or ev.get("service"))
            if ev.get("kind") == "deploy":
                S.services = load_services()
                await pipeline.on_deploy(ev["service"], S.store, S.services, config.WORKSPACE_DIR)
            else:
                await pipeline.handle_event(ev, S.store, S.http, S.services, config.WORKSPACE_DIR)
        except Exception:  # noqa: BLE001 - 한 이벤트 실패가 워커를 죽이지 않게
            log.exception("이벤트 처리 실패: %s", ev.get("ids") or ev.get("service"))
        finally:
            S.queue.task_done()


async def run_poller(name: str, interval: int, fn) -> None:
    """fn()을 주기적으로 실행. 실패해도 다음 주기에 다시 시도한다."""
    while True:
        try:
            await fn()
            log.info("폴링 완료: %s", name)
        except NotImplementedError:
            log.warning("폴러 %s: 아직 구현 전", name)
        except Exception as e:  # noqa: BLE001
            log.warning("폴러 %s 실패: %r", name, e)
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    S.http = httpx.AsyncClient(timeout=20, follow_redirects=True)
    S.tasks.append(asyncio.create_task(worker()))
    if config.POLLERS_ENABLED:
        lb = config.LOOKBACK_DAYS
        S.tasks += [
            asyncio.create_task(run_poller("kev", config.KEV_INTERVAL,
                                           lambda: kev.poll(S.http, S.store, emit, lb))),
            asyncio.create_task(run_poller("github", config.GH_INTERVAL,
                                           lambda: github.poll(S.http, S.store, emit, lb, config.GITHUB_TOKEN))),
            asyncio.create_task(run_poller("news", config.NEWS_INTERVAL,
                                           lambda: news.poll(S.http, S.store, emit, lb, config.NEWS_FEEDS,
                                                             config.ANTHROPIC_API_KEY, config.LLM_MODEL))),
        ]
    yield
    for t in S.tasks:
        t.cancel()
    await S.http.aclose()


S = AppState()
app = FastAPI(title="threat-agent-backend", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- 엔드포인트 (docs/API.md) ----------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "queue": S.queue.qsize(),
        "cards": len(S.store.all_cards()),
        "impacts": len(S.store.all_impacts()),
    }


@app.post("/ingest", status_code=202)
async def ingest(ev: dict):
    if not ev.get("ids"):
        raise HTTPException(400, "ids가 최소 한 개 필요합니다")
    ev.setdefault("source", "수동 입력")
    ev.setdefault("kind", "advisory")
    ev.setdefault("fields", {})
    await emit(ev)
    return {"queued": True}


@app.post("/webhooks/github-advisory", status_code=202)
async def github_webhook(request: Request):
    body = await request.body()
    if config.GITHUB_WEBHOOK_SECRET:
        sig = request.headers.get("X-Hub-Signature-256")
        if not github.verify_signature(body, sig, config.GITHUB_WEBHOOK_SECRET):
            raise HTTPException(401, "서명 불일치")
    payload = json.loads(body or b"{}")
    if request.headers.get("X-GitHub-Event") != "security_advisory" or payload.get("action") != "published":
        return {"ignored": payload.get("action") or request.headers.get("X-GitHub-Event")}
    await emit(github.advisory_from_webhook(payload))
    return {"queued": True}


@app.post("/webhooks/deploy", status_code=202)
async def deploy_webhook(body: dict):
    name = body.get("service")
    if name not in S.services:
        raise HTTPException(404, f"모르는 서비스: {name}")
    await emit({"source": "배포", "kind": "deploy", "service": name})
    return {"queued": name}


@app.post("/replay/{cve}", status_code=202)
async def replay(cve: str):
    cve = cve.upper()
    if cve in DEMO_EVENTS:  # 오프라인 데모 우선
        await emit(json.loads(json.dumps(DEMO_EVENTS[cve])))  # 깊은 복사
        return {"queued": cve}
    # 업스트림(KEV) 조회 실패는 404가 아니라 503으로 알린다. 화면에서 "KEV에 없는 CVE"로 오인하지 않도록.
    try:
        r = await S.http.get(kev.KEV_URL)
        r.raise_for_status()
        vulnerabilities = r.json().get("vulnerabilities", [])
    except Exception as e:  # noqa: BLE001
        log.warning("KEV 조회 실패: %r", e)
        raise HTTPException(503, "KEV 조회에 실패했습니다. 잠시 후 다시 시도하세요.")
    for v in vulnerabilities:
        if v.get("cveID", "").upper() == cve:
            await emit(kev.kev_event(v))
            return {"queued": cve}
    raise HTTPException(404, f"KEV에서 찾을 수 없음: {cve}")


_CARD_LIST_FIELDS = ("key", "ids", "sources", "title", "kev", "ransomware", "epss", "cvss", "status", "version")


@app.get("/cards")
def list_cards():
    impacts = S.store.all_impacts()
    return [card_view.build(c, impacts, _CARD_LIST_FIELDS) for c in S.store.all_cards()]


@app.get("/cards/{key}")
def get_card(key: str):
    c = S.store.get_card(key)
    if not c:
        raise HTTPException(404, f"카드 없음: {key}")
    return c


@app.get("/impacts")
def list_impacts():
    imps = S.store.all_impacts()
    return sorted(imps, key=lambda i: i.get("priority", {}).get("rank", []), reverse=True)


@app.get("/services")
def list_services():
    return [{k: v for k, v in s.items() if k != "manifest_paths"} for s in S.services.values()]
