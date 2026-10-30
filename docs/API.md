# HTTP API

기본 주소: `http://localhost:8000`. 응답은 모두 JSON. 오류는 FastAPI 기본 형식 `{"detail": "..."}`.
프론트엔드(`http://localhost:8080`)의 CORS는 `CORS_ORIGINS` 환경변수로 허용한다.

## 엔드포인트 요약

| 메서드 | 경로 | 용도 | 응답 |
|---|---|---|---|
| GET | `/health` | 상태 확인 | 200 |
| POST | `/ingest` | 정규화된 이벤트 직접 주입 (테스트·수동) | 202 |
| POST | `/webhooks/github-advisory` | GitHub `security_advisory` 웹훅 수신 | 202 / 401 |
| POST | `/webhooks/deploy` | 서비스 배포 알림 → 해당 서비스 재매칭 | 202 / 404 |
| POST | `/replay/{cve}` | KEV에 있는 CVE를 즉시 재생 (데모용) | 202 / 404 |
| GET | `/cards` | 위협 카드 목록 | 200 |
| GET | `/cards/{key}` | 위협 카드 한 개 | 200 / 404 |
| GET | `/impacts` | 영향 카드 목록 (우선순위 내림차순) | 200 |
| GET | `/services` | 서비스 목록 (SBOM 기준) | 200 |

## GET /health

```json
{ "status": "ok", "queue": 0, "cards": 3, "impacts": 1 }
```

## POST /ingest

요청: `CONTRACT.md` 1장의 NormalizedEvent. `ids`는 최소 한 개 필요하다.

```json
{
  "source": "수동 입력",
  "kind": "kev",
  "ids": ["CVE-2021-44228"],
  "fields": { "kev": true, "title": "Log4Shell" }
}
```

응답 202

```json
{ "queued": true }
```

- 큐에 넣기만 하고 즉시 반환한다. 처리 결과는 `/impacts`에서 확인한다.
- `ids`가 없거나 비어 있으면 400.

## POST /webhooks/github-advisory

- 헤더 `X-GitHub-Event: security_advisory`, `X-Hub-Signature-256`이 필요하다.
- `GITHUB_WEBHOOK_SECRET`이 설정되어 있으면 서명이 맞아야 한다. 아니면 401.
- `action`이 `published`가 아니면 무시하고 `{"ignored": "..."}`를 200으로 준다.

## POST /webhooks/deploy

요청

```json
{ "service": "payment-api" }
```

- `sbom/services.json`에 없는 서비스면 404.
- 응답 202. 큐에서 해당 서비스의 SBOM을 다시 읽고 기존 카드 전체와 매칭한다.

## POST /replay/{cve}

- 경로의 CVE를 KEV 목록에서 찾아 이벤트로 넣는다. 대소문자는 무시한다.
- KEV에 없으면 404.

```json
{ "queued": "CVE-2021-44228" }
```

## GET /cards

```json
[
  {
    "key": "CVE-2021-44228",
    "ids": ["CVE-2021-44228"],
    "sources": ["CISA KEV"],
    "title": "Apache Log4j2 Remote Code Execution",
    "kev": true,
    "ransomware": false,
    "epss": 0.97,
    "cvss": 10.0,
    "status": "확정",
    "version": 2
  }
]
```

- `affected` 같은 긴 필드는 목록에 포함하지 않는다. 상세가 필요하면 `/cards/{key}`를 쓴다.

## GET /cards/{key}

- `CONTRACT.md` 3장 ThreatCard 전체를 돌려준다.

## GET /impacts

우선순위 내림차순(`priority.rank` 기준).

```json
[
  {
    "id": "CVE-2021-44228@payment-api:Maven:org.apache.logging.log4j:log4j-core",
    "card": "CVE-2021-44228",
    "title": "Apache Log4j2 Remote Code Execution",
    "service": "payment-api",
    "env": "prod",
    "exposed": true,
    "dep": "org.apache.logging.log4j:log4j-core",
    "ecosystem": "Maven",
    "installed": "2.14.1",
    "fixed": "2.15.0",
    "priority": {
      "tier": "긴급",
      "rank": [1, 1, 1, 0.97, 10.0],
      "reasons": ["KEV 등록(실제 악용)", "인터넷 노출", "EPSS 0.97", "CVSS 10.0"]
    },
    "status": "수정 완료",
    "remediation": {
      "kind": "bump",
      "text": "org.apache.logging.log4j:log4j-core 2.14.1 → 2.15.0",
      "diff": "--- a/pom.xml\n+++ b/pom.xml\n@@ -8 +8 @@\n-      <version>2.14.1</version>\n+      <version>2.15.0</version>\n"
    },
    "rescan": 0
  }
]
```

- `status` 값: `미조치`, `수정 제안`, `수정 완료`, `수정 후 잔존`
- `remediation.kind`: `bump`, `workaround`, `manual`
- `rescan`: 수정 적용 후 남은 건수. 적용 전이면 `null`

## GET /services

```json
[
  {
    "name": "payment-api",
    "env": "prod",
    "internet_exposed": true,
    "manifests": ["requirements.txt", "pom.xml"],
    "deps": [
      { "ecosystem": "PyPI", "name": "PyYAML", "version": "5.3", "source": "requirements.txt" }
    ]
  }
]
```

- `manifest_paths`(서버 경로)는 응답에서 뺀다. 보안상 노출하지 않는다.

## 변경 규칙

- 응답 필드를 추가하는 것은 하위 호환이다. 이름 변경과 삭제는 `CONTRACT.md` 버전을 올린다.
- 이 문서를 바꾸면 D(redsun2) 리뷰와 F(tmdtndks) 확인이 필요하다.
