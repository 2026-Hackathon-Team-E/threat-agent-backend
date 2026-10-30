# 역할 분담 (백엔드 6인 체계 중 백엔드 5역할 + 프론트 1역할)

팀원 6명이 **파일 단위로 겹치지 않게** 나눈다. 역할의 상세 규칙은 `CLAUDE.md`를 따른다.

## 한눈에 보기

| 역할 | 담당자 | 레포 | 핵심 산출물 |
|---|---|---|---|
| A. KEV·GitHub 수집 | eddieyee100 | backend | `collectors/kev.py`, `collectors/github.py` |
| B. 뉴스·외부 보강 | kmssss56 | backend | `collectors/news.py`, `enrich.py` |
| C. 판단 로직 | marineusus | backend | `versions.py`, `matcher.py`, `priority.py` |
| D. 파이프라인·저장·API | redsun2 | backend | `main.py`, `pipeline.py`, `store.py`, `config.py`, `types.py`, `docs/API.md` |
| E. SBOM·수정 | soobin7131 | backend | `sbom.py`, `remediate.py`, `sbom/` |
| F. 프론트엔드 | tmdtndks | frontend | `index.html`, `src/` |

## 의존 관계 (v0.2: 역할 간 import 없음)

- 역할 간에는 **import 의존이 없다.** 공유하는 것은 `app/types.py`(타입)와 `docs/CONTRACT.md` 8장(함수 시그니처)뿐이다.
- A(KEV·GitHub), B(뉴스·보강), C(판단), E(SBOM·수정)는 **지금 바로 동시에 시작한다.** 각자 시그니처대로 스텁을 구현하고 샘플 fixture로 테스트한다.
- D(파이프라인·API)만 C·E·B의 함수를 호출한다. D는 시그니처 기준으로 호출 코드를 먼저 짜고, 상대 구현이 올라오면 연결만 확인하면 된다.
- F(프론트)는 `tests/fixtures/`와 `docs/API.md`만 보고 시작한다. 백엔드 구현을 기다리지 않는다.

```
A ──┐
B ──┤
C ──┼──(시그니처만)──▶ D (통합)
E ──┘
F  (API 명세와 fixture만 사용, 독립)
```

## 역할별 상세

### A. KEV·GitHub 수집 (eddieyee100)

- 담당 파일
  - `app/collectors/kev.py`: `kev_event(v)`, `poll(http, state, emit, lookback_days)`
  - `app/collectors/github.py`: `gh_interval`, `advisory_event(a, source)`, `advisory_from_webhook(payload)`, `verify_signature(body, header, secret)`, `poll(http, state, emit, lookback_days, token)`
  - `tests/test_collectors_kev.py`, `tests/test_collectors_github.py`
  - `tests/fixtures/kev_sample.json`, `tests/fixtures/github_advisories_sample.json`
- 해야 할 일
  - KEV 목록을 받아 새 CVE만 이벤트로 만든다. 첫 실행은 `LOOKBACK_DAYS` 이내만 낸다.
  - GitHub Advisory API를 폴링한다. 토큰이 있으면 헤더에 넣는다.
  - GitHub `security_advisory` 웹훅 페이로드를 같은 이벤트 형태로 바꾼다.
  - 서명 검증 함수는 시크릿이 없으면 항상 통과가 아니라 "검증 생략"을 명시적 값으로 반환한다.
  - GitHub 범위 문자열 `">= a, < b"` → Interval 변환은 이 파일 안의 `gh_interval`로 한다(외부 의존 없음).
- 완료 기준
  - 샘플 응답으로 이벤트가 계약(`CONTRACT.md` 1·2장)과 일치한다.
- 같은 항목을 두 번 폴링해도 이벤트가 한 번만 나온다(`state.mark_seen` 사용 확인, `state`는 테스트에서 가짜 객체로 주입).
  - 서명 검증 실패 케이스 테스트가 있다.

### B. 뉴스·외부 보강 (kmssss56)

- 담당 파일
  - `app/collectors/news.py`: `extract_cves(text)`, `poll(http, state, emit, lookback_days, feeds, llm_key, llm_model)`
  - `app/enrich.py`: `osv_intervals(entry)`, `osv(http, vid)`, `epss(http, cve)`, `llm_extract(http, text, api_key, model)`
  - `tests/test_news.py`, `tests/test_enrich.py`
  - `tests/fixtures/news_feed_sample.xml`, `tests/fixtures/osv_sample.json`, `tests/fixtures/epss_sample.json`
- 해야 할 일
  - RSS 3개(CISA 권고, The Hacker News, GitHub 보안 블로그)를 폴링한다. 제목과 요약에서 CVE만 정규식으로 뽑는다.
  - CVE가 있는 기사만 이벤트로 낸다. 임시 조치와 제품명은 LLM으로 추출한다.
  - LLM 출력은 JSON만 허용하고, 파싱 실패하면 빈 dict를 돌려준다. 키가 없으면 LLM을 호출하지 않는다.
- OSV 응답 → Interval 변환은 `app/enrich.py`의 `osv_intervals`로 한다(외부 의존 없음).
  - EPSS 응답에서 점수만 꺼낸다.
- 완료 기준
  - 키 없이도 전체 테스트가 통과한다(LLM 테스트는 모킹).
  - 깨진 RSS, 빈 응답, 404 OSV에서 예외 없이 빈 결과를 낸다.

### C. 판단 로직 (marineusus)

- 담당 파일
  - `app/versions.py`: `vkey`, `in_interval`, `best_fix` (범위 변환 함수는 A·B 파일에 있음)
  - `app/matcher.py`: `match(dep, card)`, `fix_for(dep, affected)`, 이름 정규화
  - `app/priority.py`: `score(card, svc)`
  - `tests/test_versions.py`, `tests/test_matcher.py`, `tests/test_priority.py`
- 해야 할 일
  - 버전 비교: 숫자 세그먼트 기준. 프리릴리스 구분은 PoC 제외(문서에 명시).
  - 범위 판정: GitHub 문자열과 OSV 이벤트를 같은 `intervals` 형식으로 바꾼다.
  - `best_fix`: 설치 버전보다 크고 어떤 취약 구간에도 들지 않는 가장 작은 패치 버전을 고른다.
  - PyPI 이름 정규화: 소문자, `_`를 `-`로.
  - 우선순위 `rank`와 `tier` 계산(`CONTRACT.md` 6장).
- 완료 기준
  - 모든 함수가 순수 함수다(외부 I/O 없음).
  - 경계값 테스트: `hi_inc=false`에서 `hi` 버전은 취약하지 않다, `lo=null`은 모든 낮은 버전을 포함한다.
  - KEV 카드(내부망)가 노출된 고 EPSS 카드보다 위에 온다.

### D. 파이프라인·저장·API (redsun2)

- 담당 파일
  - `app/config.py`: 환경변수, URL, 폴링 주기, 경로
  - `app/store.py`: SQLite `Store` 클래스 (`cards`, `alias`, `impacts`, `seen`, `meta` 테이블)
  - `app/pipeline.py`: `handle_event`, `scan`, `act`, `count_hits`, `on_deploy`
  - `app/main.py`: FastAPI 앱, lifespan(워커·폴러 시작), 엔드포인트, CORS
  - `tests/conftest.py`(공용 fixture), `tests/test_store.py`, `tests/test_pipeline.py`
  - `docs/API.md`
- 해야 할 일
  - 큐 워커: `asyncio.Queue`에서 이벤트를 한 개씩 처리한다.
  - 카드 병합: CVE/GHSA 별칭으로 기존 카드를 찾고, 없으면 만든다. 변경이 있을 때만 `version`을 올린다.
  - 재매칭 범위: 카드가 바뀌면 전체 서비스, 배포 이벤트면 해당 서비스만 기존 카드 전체와 매칭한다.
  - 멱등성: 같은 영향 카드 ID는 다시 만들지 않는다.
  - 엔드포인트: `POST /ingest`, `POST /webhooks/github-advisory`, `POST /webhooks/deploy`, `POST /replay/{cve}`, `GET /cards`, `GET /cards/{key}`, `GET /impacts`, `GET /services`, `GET /health`
  - 웹훅 시크릿이 설정되면 서명 검증을 강제한다(검증 함수는 A의 `github.verify_signature`).
- 완료 기준
  - `uv run uvicorn app.main:app`으로 실행되고 `/health`가 200을 준다.
  - 같은 이벤트를 두 번 넣어도 `impacts` 개수가 변하지 않는다.
  - `docs/API.md`의 모든 엔드포인트에 요청·응답 예시가 있다.

### E. SBOM·수정 (soobin7131)

- 담당 파일
  - `app/sbom.py`: `parse_manifest(fname, text)`, `active_path(name, fname)`, `load_all()`, `load_one(name)`
  - `app/remediate.py`: `bump_manifest(fname, text, name, fixed)`, `propose(svc, dep, card, fixed)`
  - `sbom/services.json`, `sbom/payment-api/requirements.txt`, `sbom/payment-api/pom.xml`, `sbom/internal-report/pom.xml`
  - `tests/test_sbom.py`, `tests/test_remediate.py`
- 해야 할 일
  - `requirements.txt`: `name==version` 줄만 읽는다. 주석과 다른 패키지 줄은 건드리지 않는다.
  - `pom.xml`: `<dependency>` 블록의 `groupId:artifactId`와 `version`을 읽는다. 프로젝트 자신의 `<version>`은 제외한다.
  - `propose`: 패치 버전이 있으면 `workspace/<서비스>/`에 사본을 쓰고 unified diff를 만든다. 원본 `sbom/`은 읽기만 한다.
  - 패치가 없으면 `workaround` 제안 텍스트를 돌려준다. `source`가 없으면 `manual`.
- 완료 기준
  - 샘플 SBOM 로드 결과가 `CONTRACT.md` 4장과 일치한다.
  - 버전 올린 뒤 같은 줄 외에는 파일이 그대로다(diff 테스트).
  - 원본 `sbom/` 파일의 해시가 테스트 전후로 같다.

### F. 프론트엔드 (tmdtndks, 별도 레포 `threat-agent-frontend`)

- 담당 파일: 레포 전체 (`index.html`, `src/`, `docs/SCREENS.md`)
- 해야 할 일
  - 상단: 긴급/높음/보통 카운트
  - 영향 카드 목록: 우선순위 순, 상태 배지, 근거(`reasons`)
  - 선택하면 수정 diff와 재스캔 결과 표시
  - 카드 목록: 확정/미확정, KEV 여부, EPSS
  - 데모 버튼: "CVE 재생" → `POST /replay/{cve}`
  - 3초마다 `GET /impacts`, `GET /cards` 갱신
- 완료 기준
  - 백엔드 없이 `tests/fixtures/`의 샘플 JSON으로 화면이 그려진다.
  - 백엔드 실행 후 데모 버튼으로 영향 카드가 나타난다.
  - CORS 오류 없이 호출된다(백엔드 `CORS_ORIGINS` 설정 확인).

## 전원 공통

- `CLAUDE.md` 규칙 준수, `uv run pytest` 통과 후 PR
- PR은 owner 한 명의 경로만 변경
- 계약 변경이 필요하면 `docs/CONTRACT.md` 수정 PR을 먼저 올리고 전원 리뷰
- 막히면 owner에게 이슈로 질문, 임의로 다른 파일을 고치지 않는다

## 진행 순서 (권장)

1. Day 1: 계약 리뷰 (`CONTRACT.md`, `API.md`) → 전원 승인
2. Day 1~2: A, B, C, E 병렬 구현 (각자 샘플 fixture 기반)
3. Day 2: D가 `pipeline.py`로 통합, 실패하는 테스트부터 맞춘다
4. Day 2~3: F가 실제 API로 화면 연결, 데모 시나리오(Log4Shell 재생) 점검
5. Day 3: 리드 리뷰, 데모 리허설
