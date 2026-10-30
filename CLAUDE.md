# CLAUDE.md — 백엔드 하네스 (에이전트·팀원 공통 규칙)

이 파일은 Claude Code를 포함한 모든 작업자가 가장 먼저 읽는다. 작업 전에 아래 규칙을 확인한다.

## 1. 프로젝트 한 줄 요약

실시간 보안 위협 대응 에이전트 백엔드. KEV·GitHub Advisory·보안 뉴스를 수집해 위협 카드를 만들고, 우리 SBOM과 매칭해 영향 카드와 수정 diff를 만든다.

- 설계 전체: `docs/ARCHITECTURE.md`
- 역할 간 데이터 계약: `docs/CONTRACT.md` (이벤트, 카드, 취약 범위, 영향 카드 스키마)
- HTTP 엔드포인트: `docs/API.md`
- 역할 분담과 완료 기준: `docs/ROLES.md`

## 2. 실행과 검증

```bash
uv sync                 # 의존성 설치 (dev 그룹 포함)
uv run pytest           # 전체 테스트 — PR 올리기 전 반드시 통과
uv run uvicorn app.main:app --reload --port 8000
```

- 테스트는 외부 네트워크를 호출하지 않는다. 외부 응답은 `tests/fixtures/`에 저장한 샘플을 쓴다.
- Python 3.12 이상. 시스템 pip 대신 `uv`를 쓴다.

## 3. 파일 소유권 (가장 중요)

한 파일은 한 사람만 수정한다. 다른 사람의 파일이 필요하면 직접 고치지 말고 해당 owner에게 이슈로 요청하거나, 인터페이스 변경을 `docs/CONTRACT.md` PR로 먼저 올린다.

| 역할 | owner | 담당 경로 |
|---|---|---|
| A. KEV·GitHub 수집 | eddieyee100 | `app/collectors/kev.py`, `app/collectors/github.py`, `tests/test_collectors_kev.py`, `tests/test_collectors_github.py` |
| B. 뉴스·외부 보강 | kmssss56 | `app/collectors/news.py`, `app/enrich.py`, `tests/test_news.py`, `tests/test_enrich.py` |
| C. 판단 로직 (순수 함수) | marineusus | `app/versions.py`, `app/matcher.py`, `app/priority.py`, `tests/test_versions.py`, `tests/test_matcher.py`, `tests/test_priority.py` |
| D. 파이프라인·저장·API | redsun2 | `app/main.py`, `app/config.py`, `app/store.py`, `app/pipeline.py`, `tests/conftest.py`, `tests/test_store.py`, `tests/test_pipeline.py`, `docs/API.md` |
| E. SBOM·수정 | soobin7131 | `app/sbom.py`, `app/remediate.py`, `sbom/**`, `tests/test_sbom.py`, `tests/test_remediate.py` |
| 공유·리드 | redsun2 (리뷰 총괄) | `CLAUDE.md`, `docs/CONTRACT.md`, `docs/ROLES.md`, `docs/ARCHITECTURE.md`, `pyproject.toml`, `.github/**` |

- `app/collectors/__init__.py`는 비워 둔다. 공용 헬퍼가 필요하면 D에게 요청한다.
- 프론트엔드 레포(`threat-agent-frontend`)는 tmdtndks 담당이며 이 레포에서 건드리지 않는다.

## 4. 계약 우선 원칙

- 역할 간 데이터 형태는 `docs/CONTRACT.md`가 유일한 기준이다. 코드와 문서가 다르면 문서를 먼저 고치고 PR을 따로 올린다.
- 계약 변경 PR은 모든 owner의 리뷰를 받아야 머지한다.
- 필드 추가는 호환된다(기존 소비자가 무시). 필드 이름 변경과 삭제는 계약 버전을 올린다.

## 5. 코딩 규칙

- 함수는 외부 상태에 의존하지 않게 쓴다. 판단 로직(A 제외)은 입력 dict를 받아 dict를 돌려주는 순수 함수로 만든다.
- 외부 HTTP 호출은 `collectors/`와 `enrich.py`에만 둔다.
- 시간은 `time.time()`(초 단위 float)으로 기록하고 이벤트에 `observed_at`을 붙인다.
- 로그는 표준 `logging`. 이벤트 단계마다 INFO, 영향 카드 생성은 WARNING.
- 한국어 주석과 문서는 허용. 식별자는 영어.
- 비밀값(API 키, 웹훅 시크릿)은 코드와 커밋에 넣지 않는다. `.env`로 관리하고 `.env.example`만 커밋한다.
- `sbom/` 원본은 수정하지 않는다. 수정 결과는 `workspace/`에만 쓴다.

## 6. Git과 PR 규칙

- 기본 브랜치 `main`에 직접 커밋하지 않는다.
- 브랜치 이름: `feat/<owner>-<주제>` (예: `feat/marineusus-matcher-range`). 수정은 `fix/`, 문서는 `docs/`.
- 커밋 메시지는 한 줄 요약 + 필요하면 본문. 예: `feat(matcher): 생태계별 이름 정규화 추가`.
- PR 본문은 `.github/pull_request_template.md`를 채운다. 테스트 결과를 포함한다.
- PR 하나는 owner 한 명의 경로만 바꾼다. 여러 역할을 건드려야 하면 PR을 나눈다.
- 리뷰어는 CODEOWNERS가 자동 지정한다. 리드(redsun2)가 최종 확인한다.

## 7. 완료 기준 (공통)

- `uv run pytest` 통과
- 담당 파일의 함수마다 최소 1개 테스트
- 계약에 맞는 입력·출력 예시가 테스트에 있음
- `docs/ROLES.md`의 해당 역할 완료 기준 충족

## 8. 하지 말 것

- 다른 owner의 파일 직접 수정
- 테스트에서 실제 외부 API 호출
- `main` 브랜치 force push
- 실제 PR 자동 생성·자동 머지 기능 추가 (PoC 범위 밖)
- 이 문서에 없는 기술 스택 추가 (고급 기술은 `docs/ARCHITECTURE.md` 9장에 보류 기록만)
