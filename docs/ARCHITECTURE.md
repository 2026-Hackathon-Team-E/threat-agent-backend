# 실시간 보안 위협 대응 에이전트 — 아키텍처 (PoC)

## 1. 목표와 범위

- 새 취약점 정보가 올라오면 수 분 안에 감지하고, 우리 서비스의 SBOM과 매칭해 영향 카드를 만든 뒤, 수정안(diff)과 재스캔 결과까지 보여준다.
- PoC 범위: 실제 소스(KEV, GitHub Advisory, 보안 뉴스 RSS, EPSS, OSV)를 붙이고, 우리 쪽 SBOM과 배포는 샘플로 둔다.
- PoC에서 하지 않는 것: 실제 PR 생성, 자동 머지, 영구 DB, 다중 테넌트, 인증된 대시보드.

## 2. 확정한 결정

| 항목 | 결정 | 이유 |
|---|---|---|
| 언어/프레임워크 | Python 3.12+, FastAPI, httpx, feedparser, packaging | 보안 쪽 생태계와 버전 비교 라이브러리가 잘 갖춰짐 |
| 실행 구조 | 단일 프로세스, asyncio 큐로 단계 연결 | PoC에서 Kafka/Redis 없이 이벤트 기반 흐름을 보여줄 수 있음 |
| 저장소 | SQLite 단일 파일 (`Store` 클래스 뒤에 숨김) | 재시작 후에도 카드·수정 상태가 남음. 설치 없이 표준 라이브러리로 동작 |
| 버전 비교 | 코드로만 처리. LLM 사용 금지 | 정확성과 재현성 |
| LLM 사용 범위 | 뉴스 본문에서 임시 조치·영향 제품 추출, 요약 | 구조화되지 않은 텍스트만 맡김. CVE 번호는 정규식으로 먼저 추출 |
| 우선순위 | 긴급(KEV 또는 랜섬웨어) > 높음(인터넷 노출) > 보통. 같은 등급 안에서 EPSS, CVSS 순으로 정렬 | 사전식 정렬은 상위 항목 하나가 나머지를 덮어 운영에 불편. 등급을 나누면 설명도 쉬움 |
| 수정 범위 | 워크스페이스 사본에만 적용, 원본 SBOM과 실제 저장소는 건드리지 않음 | 안전. "수정 완료"와 "재스캔 0건"은 사본 기준으로 실제 계산 |
| 지원 매니페스트 | `requirements.txt`(PyPI), `pom.xml`(Maven) | 자동 수정까지 시연 가능한 최소 조합. npm은 제안만 |

## 3. 시스템 구성

```
 [외부 소스]                       [수집 계층]                   [코어 파이프라인]               [출력]
 GitHub 보안 권고 웹훅 ──┐
 (security_advisory)     │
                         ├──▶ POST /ingest ──▶ asyncio 큐 ──▶ 1. 카드 병합 (CVE/GHSA 별칭)
 GitHub Advisory API ────┤    (정규화된 이벤트)                 2. 외부 보강 (OSV, EPSS)
   (폴링, 10~15분)        │                                      3. 매칭 (SBOM × 카드)
 CISA KEV JSON ──────────┤                                      4. 우선순위 계산
   (목록 diff, 10분)      │                                      5. 수정 제안 + 워크스페이스 적용
 보안 뉴스 RSS ──────────┤                                      6. 재스캔
   (5분)                 │                                           │
 NVD/EPSS ───────────────┘ (EPSS는 보강 단계에서 조회)                ▼
                                                              Store (SQLite)
 배포 웹훅 POST /webhooks/deploy ──▶ 큐 (kind=deploy) ──▶ 해당 서비스만 재매칭    │
                                                                   ▼
                                                     GET /cards, /impacts, /services
                                                     POST /replay/{cve}  (데모용)
```

- 웹훅이 있는 소스는 웹훅으로 받고, 없는 소스는 폴링으로 받는다. 둘 다 `/ingest`와 같은 큐로 들어간다.
- GitHub의 `security_advisory` 웹훅은 해당 저장소나 조직이 권고를 게시할 때만 온다. 전체 GitHub Advisory DB를 실시간으로 주는 웹훅은 없으므로 전체 감지는 폴링으로 한다. 이 점은 발표에서 정확히 말해야 한다.
- 이벤트는 큐에서 한 개씩 순서대로 처리한다. 같은 카드를 동시에 두 번 고치는 경쟁을 피하기 위해서다.

## 4. 데이터 계약 (역할 간 인터페이스)

이 계약이 역할 간 유일한 약속이다. 계약이 바뀌면 전원이 같이 본다.

### 4.1 NormalizedEvent (수집 → 코어)

```json
{
  "source": "CISA KEV",
  "kind": "kev | advisory | news | deploy",
  "ids": ["CVE-2021-44228", "GHSA-jfh8-gbnc-hgf2"],
  "fields": {
    "title": "...",
    "summary": "...",
    "workaround": "...",
    "kev": true,
    "ransomware": false,
    "due_date": "2021-12-24",
    "cvss": 10.0,
    "affected": [ <Affected> ]
  }
}
```

- `kind=deploy`는 `ids` 대신 `"service": "payment-api"`를 가진다.
- `fields`에 있는 키만 병합한다. 빈 값은 기존 값을 덮지 않는다.

### 4.2 Affected (취약 범위, 생태계 공통 형식)

```json
{
  "ecosystem": "PyPI | Maven | npm",
  "name": "org.apache.logging.log4j:log4j-core",
  "intervals": [{"lo": "2.0.0", "lo_inc": true, "hi": "2.15.0", "hi_inc": false}],
  "fixed_versions": ["2.15.0", "2.17.1"],
  "source": "GitHub Advisory | OSV:GHSA-..."
}
```

- GitHub의 `>= a, < b` 문자열과 OSV의 `introduced/fixed/last_affected` 이벤트는 모두 이 형식으로 바꾼다. 변환은 수집 쪽 책임이고, 매칭은 이 형식만 본다.

### 4.3 ThreatCard (코어 내부 상태)

```
key, ids[], sources[], title, summary, workaround,
kev, ransomware, due_date, cvss, epss,
affected[], status(확정|미확정), version(int)
```
- `key`: 첫 번째 CVE. CVE가 없으면 첫 번째 ID.
- `status`: `affected`가 하나라도 있으면 "확정", 없으면 "미확정"(뉴스만 있는 상태).

### 4.4 Service (SBOM)

```
name, env(prod|dev), internet_exposed(bool),
manifests[] (파일명),
deps[]: {ecosystem, name, version, source(파일명|null)}
```
- `source`가 있으면 해당 매니페스트를 수정할 수 있다. `null`이면 수동 수정 제안만 한다.

### 4.5 Impact (영향 카드, 코어 → 출력)

```
id, card, service, env, exposed, dep, ecosystem, installed, fixed,
priority: {tier: 긴급|높음|보통, rank: [kev, ransomware, exposed, epss, cvss], reasons[]},
status: 미조치 | 수정 제안 | 수정 완료 | 수정 후 잔존,
remediation: {kind: bump|workaround|manual, text, diff},
rescan: int | null
```

## 5. 역할 분담

네 개 역할로 나눴다. 한 사람이 여러 역할을 맡아도 된다. 역할마다 **담당 파일**과 **완료 기준**을 정했다.

### 역할 A. 수집 (Ingest)

- 담당 파일: `app/sources.py`, `app/enrich.py`, `app/versions.py`(gh/osv 변환 함수만)
- 하는 일
  - KEV 목록 diff 폴링 (10분)
  - GitHub Advisory API 폴링 (15분), 토큰이 있으면 사용
  - 보안 뉴스 RSS 폴링 (5분): CISA 권고, The Hacker News, GitHub 보안 블로그
  - 뉴스 본문에서 CVE는 정규식으로 추출, 임시 조치와 제품명은 LLM으로 추출 (키가 없으면 빈 값)
  - EPSS 조회, OSV 조회(카드에 affected가 없을 때만, 15분 간격 재시도)
  - GitHub `security_advisory` 웹훅 수신 (서명 검증 포함)
- 완료 기준
  - 각 소스에서 `NormalizedEvent`가 계약대로 큐에 들어간다.
  - 같은 항목을 두 번 emit하지 않는다. (`store.seen` 사용)
  - 첫 실행 때 오래된 항목은 `LOOKBACK_DAYS`로 걸러낸다.
  - 외부 호출 실패가 전체 루프를 죽이지 않는다.

### 역할 B. 코어 판단 (Correlate & Match)

- 담당 파일: `app/pipeline.py`, `app/store.py`, `app/matcher.py`, `app/priority.py`, `app/versions.py`(비교 함수)
- 하는 일
  - 이벤트를 카드에 병합하고 별칭(`alias`)을 등록
  - 카드가 바뀌면 전체 서비스와 매칭, 서비스가 배포되면 그 서비스만 기존 카드 전체와 매칭
  - 이미 알린 영향 카드는 다시 만들지 않음 (멱등성)
  - 우선순위 계산
- 완료 기준
  - `versions.py`, `matcher.py`, `priority.py`는 순수 함수로 작성하고 단위 테스트가 있다.
  - 같은 이벤트를 두 번 넣어도 영향 카드가 늘지 않는다.
  - 우선순위 순서 테스트: KEV 카드(내부망)가 노출된 높은 EPSS 카드보다 위에 온다.

### 역할 C. 수정 (Remediation)

- 담당 파일: `app/remediate.py`, `app/sbom.py`
- 하는 일
  - `requirements.txt`와 `pom.xml`에서 의존성 목록 파싱
  - 패치 버전이 있으면 해당 줄의 버전을 올린 사본을 `workspace/<서비스>/`에 저장하고 unified diff 생성
  - 패치 버전이 없으면 KEV의 `requiredAction`이나 뉴스의 임시 조치를 제안 텍스트로 제공
  - `npm`이나 매니페스트가 없는 경우는 수동 수정 제안
  - 적용 후 서비스 의존성을 워크스페이스 기준으로 다시 읽음
- 완료 기준
  - 원본 `sbom/`은 절대 수정하지 않는다.
  - 버전 올림 후 재스캔에서 같은 영향 카드가 사라진다.
  - 주석 줄(`# PyYAML==1`)과 다른 패키지 줄은 바뀌지 않는다.

### 역할 D. 인터페이스·데모·운영 (Interface & Demo)

- 담당 파일: `app/main.py`, `app/config.py`, `app/__init__.py`, `sbom/`(샘플 데이터), `tests/`(통합 테스트), `README.md`, `scripts/`
- 하는 일
  - FastAPI 앱 조립: lifespan에서 워커와 폴러 시작, 엔드포인트 연결
  - 엔드포인트: `POST /ingest`, `POST /webhooks/github-advisory`, `POST /webhooks/deploy`, `POST /replay/{cve}`, `GET /cards`, `GET /impacts`, `GET /services`
  - 샘플 SBOM 작성: `payment-api`(인터넷 노출, requests, PyYAML 5.3, log4j-core 2.14.1), `internal-report`(내부망, log4j-core 2.17.1)
  - 시연 스크립트: 실제 Log4Shell(KEV 등록)을 `/replay`로 넣고, 영향 카드와 수정 diff, 재스캔 0건을 순서대로 보여줌
  - 시간 측정: 각 이벤트에 `observed_at`(수집 시각)을 찍고, 카드 생성·영향 판정·수정 완료 시각을 로그에 남김. 발표용 "감지까지 걸린 시간"을 실제 측정값으로 쓰기 위해서다.
- 완료 기준
  - `uvicorn app.main:app`만으로 실행된다.
  - 데모 스크립트를 한 번에 돌리면 감지 → 영향 → 수정 → 재스캔 로그가 시간과 함께 출력된다.

## 6. 작업 순서

1. **계약 확정 (전원)**: 이 문서의 4장을 기준으로 합의. 합의 후 변경은 문서에 먼저 반영.
2. **병렬 작업**
   - B: `versions.py`, `matcher.py`, `priority.py`와 단위 테스트 (외부 호출 없음)
   - C: `sbom.py` 파싱과 `remediate.py` 버전 올림, 단위 테스트 (샘플 파일로)
   - A: 각 소스 폴러를 실제 엔드포인트로 호출해 계약 형태의 이벤트가 나오는지 확인 (코어 없이 출력만 확인)
   - D: `main.py` 골격과 샘플 SBOM 작성
3. **통합**: `pipeline.py`로 A의 이벤트를 B와 C에 연결. 이 단계는 한 사람이 맡는 것이 안전.
4. **데모 검증**: `/replay/CVE-2021-44228` 한 번으로 전체 흐름이 도는지 확인, 로그 시간 기록.

## 7. 위험과 열린 질문

- **OSV 데이터 지연**: KEV가 먼저 올라오고 OSV에 범위 정보가 나중에 들어올 수 있다. 그래서 affected가 없는 카드는 15분마다 재조회한다. 데모 전에 실제 CVE로 확인해야 한다.
- **버전 비교 한계**: 숫자 세그먼트 기준이라 `2.15.0-rc1`처럼 프리릴리스 구분이 없다. PoC에서는 제한 사항으로 두고 문서에 명시한다.
- **LLM 키**: `ANTHROPIC_API_KEY`가 없으면 뉴스 임시 조치는 빈 값이 된다. 데모는 KEV의 `requiredAction`으로 대체 가능.
- **NVD**: PoC에서는 제외. CVSS는 GitHub Advisory 값을 사용한다.
- **열린 질문 1**: 역할을 몇 명이 나눠 맡는가? 한 명이면 A → B → C → D 순서로 진행한다.
- **열린 질문 2**: 발표 데모에서 뉴스 감지를 실제 라이브 피드로 보일지, 녹화된 뉴스 재생으로 보일지. 라이브는 시간이 예측되지 않는다.
- **결정 완료 (구 열린 질문 3)**: 카드·영향 카드·수정 상태는 SQLite에 저장해 재시작 후에도 유지한다. 워크스페이스 사본 디렉터리는 실행할 때마다 비운다. 상태(DB)와 사본(워크스페이스)을 분리해 둔 것이다.

## 8. 최소 스택 (구현 기준, 확정)

PoC 구현에 필요한 것만 적었다. 배포, 컨테이너, 외부 인프라는 고려하지 않는다.

| 층 | 기술 | 용도 |
|---|---|---|
| 언어 | Python 3.12+ | 백엔드 전체 |
| 웹 프레임워크 | FastAPI + Uvicorn | 엔드포인트, 웹훅 수신, 정적 프론트 서빙 |
| 데이터 검증 | Pydantic v2 | 이벤트·카드·영향 카드 계약을 코드로 검사. LLM 출력 검증에도 사용 |
| HTTP 클라이언트 | httpx | KEV, GitHub, OSV, EPSS, LLM API 호출 |
| 뉴스 파싱 | feedparser | RSS/Atom 파싱 |
| 버전 비교 | packaging (PyPI), 자체 숫자 비교 (Maven, npm) | 생태계별 버전 비교 |
| DB | SQLite (표준 라이브러리 `sqlite3`) | 카드, 영향 카드, 수집 이력(`seen`), 별칭(`alias`), 서비스 |
| 큐 | `asyncio.Queue` | 수집 → 코어 이벤트 전달 (프로세스 내부) |
| 프론트 | HTML 1장 + 바닐라 JS, `fetch`로 3초마다 갱신 | 카드·영향 카드 목록, 수정 diff 보기, 재스캔 결과 표시. 빌드 도구 없음 |
| LLM | Anthropic Messages API (`claude-haiku-5-5`), httpx로 직접 호출 | 뉴스에서 임시 조치·제품명 추출. 키가 없으면 비활성 |
| 테스트 | pytest | 순수 함수 단위 테스트, 파이프라인 통합 테스트 |
| 환경 관리 | uv | 가상환경과 패키지 설치. 이 기기의 시스템 `ensurepip` 실패를 피하기 위함 |
| 설정 | 환경변수 (`app/config.py`) | 폴링 주기, API 키, 룩백 일수 |
| 로그 | 표준 `logging` | 이벤트별 `observed_at`과 단계 전환 시각을 한 줄씩 기록 |

### 8.1 DB 테이블 (SQLite)

```
cards     (key TEXT PRIMARY KEY, body TEXT)          -- ThreatCard JSON
alias     (id TEXT PRIMARY KEY, card_key TEXT)       -- CVE/GHSA → 카드 키
services  (name TEXT PRIMARY KEY, body TEXT)         -- Service JSON (원본 기준)
impacts   (id TEXT PRIMARY KEY, body TEXT)           -- Impact JSON
seen      (source TEXT, item_id TEXT, PRIMARY KEY (source, item_id))
```

- 본문은 JSON 문자열로 저장한다. 조회 조건은 `key`, `id`, `source`만 쓰므로 정규화된 컬럼은 필요 없다.
- `Store` 클래스가 이 테이블만 다루고, 파이프라인은 `Store` 메서드만 호출한다.

### 8.2 프론트 화면 (최소)

- 위쪽: 긴급 / 높음 / 보통 카운트
- 가운데: 영향 카드 목록 (우선순위 순, 상태 배지, 근거 `reasons`)
- 선택 시: 수정 diff와 재스캔 결과, 원본 출처 링크
- 아래: 카드 목록(확정/미확정, KEV 여부, EPSS)
- 데모용 버튼: "CVE 재생" (`POST /replay/{cve}` 호출)

### 8.3 구현 시 디렉터리 (확정)

```
threat-agent-poc/
  app/        main.py, config.py, store.py, pipeline.py, sources.py, enrich.py,
              versions.py, matcher.py, priority.py, sbom.py, remediate.py
  static/     index.html (프론트 한 장)
  sbom/       services.json, payment-api/, internal-report/   (샘플, 읽기 전용)
  workspace/  실행할 때마다 비움 (수정 사본)
  tests/      test_versions.py, test_matcher.py, test_priority.py, test_remediate.py, test_pipeline.py
  docs/       ARCHITECTURE.md
  data/       app.db (SQLite 파일, 실행 시 생성)
```

### 8.4 PoC에서 쓰지 않는 것

Docker, 배포 설정, 인증·권한, 다중 인스턴스, 외부 메시지 브로커, 외부 DB 서버, 프론트 빌드 도구(React 등). 필요해지면 그때 추가한다.

## 9. 보류 기술 (나중에 검토)

PoC 이후 실제 도입 단계에서 검토한다. 지금은 구현하지 않는다.

- 이벤트 백본: Apache Kafka 또는 Redpanda (토픽 분리, 재처리)
- 상태 집계: Kafka Streams (KTable), Flink (시간 창 상관분석)
- 토픽 보관: Kafka 로그 컴팩션 (카드 최신 상태)
- 운영 DB: PostgreSQL (JSONB)
- 중복 제거 공유: Redis (TTL)
- 승인 대기 흐름: Temporal (내구 실행)
- 정책 분리: OPA (Rego) 또는 Cedar
- SBOM 표준: CycloneDX, Syft/cdxgen
- 관계 분석: Neo4j
- 이벤트 스키마 관리: Avro/Protobuf + Schema Registry
- 관측성: OpenTelemetry 추적, Prometheus/Grafana
- 기존 도구 비교: OWASP Dependency-Track (SBOM 기반 취약점 관리 플랫폼과 기능이 겹침)
