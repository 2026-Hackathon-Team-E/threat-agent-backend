# threat-agent-backend

실시간 보안 위협 대응 에이전트의 백엔드(PoC). 취약점 소스를 수집해 위협 카드를 만들고, 우리 SBOM과 매칭해 영향 카드와 수정 diff를 만든다.

## 빠른 시작

```bash
cp .env.example .env         # 필요한 값만 채운다 (대부분 비워도 실행됨)
uv sync                      # 의존성 설치
uv run pytest                # 테스트
uv run uvicorn app.main:app --reload --port 8000
```

- 기본 실행은 외부 소스(KEV, GitHub Advisory, RSS, OSV, EPSS)를 실제로 호출한다. 네트워크가 없으면 수집 로그에 경고만 남고 서버는 계속 뜬다.
- API 문서: `docs/API.md`. 데이터 형태: `docs/CONTRACT.md`.

## 문서 지도

| 문서 | 내용 |
|---|---|
| `CLAUDE.md` | 작업 규칙, 파일 소유권, PR 규칙 (먼저 읽기) |
| `docs/ARCHITECTURE.md` | 설계 배경, 흐름, 기술 선택 이유 |
| `docs/CONTRACT.md` | 이벤트·카드·취약 범위·영향 카드 스키마 |
| `docs/API.md` | HTTP 엔드포인트 |
| `docs/ROLES.md` | 역할 6명 분담과 완료 기준 |

## 디렉터리

```
app/
  main.py              FastAPI 앱, 엔드포인트, 워커·폴러 시작     (D)
  config.py            환경변수와 URL                              (D)
  store.py             SQLite 저장소                               (D)
  pipeline.py          카드 병합, 매칭, 수정 적용                  (D)
  enrich.py            OSV, EPSS, LLM 추출                         (B)
  versions.py          버전 비교, 범위 판정                        (C)
  matcher.py           패키지 매칭                                 (C)
  priority.py          우선순위 계산                               (C)
  sbom.py              SBOM 로드, 매니페스트 파싱                  (E)
  remediate.py         버전 올림 사본, diff                        (E)
  collectors/
    kev.py             CISA KEV                                    (A)
    github.py          GitHub Advisory 폴링·웹훅                   (A)
    news.py            보안 뉴스 RSS                               (B)
sbom/                  샘플 서비스 SBOM (읽기 전용, E 담당)
tests/                 단위·통합 테스트 (외부 네트워크 호출 금지)
docs/                  설계·계약·API·역할 문서
workspace/             수정 사본 (실행 시 생성, 커밋 금지)
data/                  SQLite 파일 (실행 시 생성, 커밋 금지)
```

## 데모 흐름

1. 서버 실행 후 `POST /replay/CVE-2021-44228` (Log4Shell, KEV 등록)
2. `GET /impacts`에서 `payment-api` 영향 카드 확인 (긴급, 인터넷 노출)
3. 카드의 `remediation.diff`와 `rescan: 0` 확인

## 프론트엔드

별도 레포 `threat-agent-frontend`. 기본 주소 `http://localhost:8080`에서 띄우고 `CORS_ORIGINS`에 포함시킨다.
