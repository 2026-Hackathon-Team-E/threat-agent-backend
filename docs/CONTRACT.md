# 데이터 계약 (역할 간 인터페이스)

이 문서가 역할 간 데이터 형태의 유일한 기준이다. 변경은 리드와 모든 owner 리뷰를 거친다.
모든 시각은 Unix 시간(초, float). 모든 식별자 문자열은 대문자 정규화 후 비교한다(CVE, GHSA).

## 1. NormalizedEvent — 수집 → 파이프라인

수집기(A, B)와 웹훅이 큐에 넣는 단위다.

```json
{
  "source": "CISA KEV",
  "kind": "kev | advisory | news | deploy",
  "ids": ["CVE-2021-44228"],
  "fields": {
    "title": "Apache Log4j2 Remote Code Execution",
    "summary": "…",
    "workaround": "임시 조치 또는 권고 문구",
    "kev": true,
    "ransomware": false,
    "due_date": "2021-12-24",
    "cvss": 10.0,
    "affected": [ { "...Affected 참고": "" } ]
  },
  "observed_at": 1762000000.0
}
```

- `kind = "deploy"`이면 `ids` 대신 `"service": "payment-api"`를 가진다.
- `fields`에 없는 키는 무시한다. 값이 비어 있으면(`null`, `""`, `false`, `[]`) 기존 값을 덮지 않는다.
- `observed_at`은 수집기가 아니라 `POST /ingest` 진입 시점에 `setdefault`로 찍는다.

## 2. Affected — 취약 범위 (생태계 공통)

```json
{
  "ecosystem": "PyPI | Maven | npm",
  "name": "org.apache.logging.log4j:log4j-core",
  "intervals": [
    { "lo": "2.0.0", "lo_inc": true, "hi": "2.15.0", "hi_inc": false }
  ],
  "fixed_versions": ["2.15.0", "2.17.1"],
  "source": "GitHub Advisory | OSV:GHSA-jfh8-gbnc-hgf2"
}
```

- `lo`/`hi`가 `null`이면 그쪽은 무한대다.
- `intervals`는 OR 관계다. 하나라도 포함하면 취약하다.
- `fixed_versions`는 패치 버전 후보 목록이다. 수정 시 `versions.best_fix`가 골라 쓴다.
- `intervals`가 비어 있으면 매칭되지 않는다. 범위를 모르는 항목을 전부 취약으로 보지 않기 위해서다.
- 변환 규칙
  - GitHub `">= 2.0.0, < 2.15.0"` → `lo=2.0.0 lo_inc=true hi=2.15.0 hi_inc=false`
  - OSV `introduced`/`fixed`/`last_affected` 이벤트 → 구간 목록 (담당 A의 `versions.osv_intervals`가 변환)
  - OSV `versions` 목록 → 구간 `[v, v]`

## 3. ThreatCard — 파이프라인 내부 상태 (DB 저장)

```json
{
  "key": "CVE-2021-44228",
  "ids": ["CVE-2021-44228", "GHSA-jfh8-gbnc-hgf2"],
  "sources": ["CISA KEV", "뉴스:The Hacker News"],
  "title": "...", "summary": "...", "workaround": "...",
  "kev": true, "ransomware": false, "due_date": "2021-12-24",
  "cvss": 10.0, "epss": 0.97,
  "affected": [ "...Affected 배열..." ],
  "status": "확정 | 미확정",
  "version": 3,
  "osv_checked_at": 1762000000.0,
  "epss_checked": true
}
```

- `key`: 첫 번째 CVE. CVE가 없으면 첫 번째 ID.
- `status`: `affected`가 있으면 `확정`, 없으면 `미확정`(뉴스만 있는 상태).
- `version`: 내용이 바뀔 때마다 1씩 증가. 같은 이벤트 재수신은 증가시키지 않는다.

## 4. Service — SBOM (파일에서 로드)

`sbom/services.json`의 항목과 실행 시 매니페스트를 읽어 만든 결과.

```json
{
  "name": "payment-api",
  "env": "prod | dev",
  "internet_exposed": true,
  "manifests": ["requirements.txt", "pom.xml"],
  "manifest_paths": { "requirements.txt": "/…/sbom/payment-api/requirements.txt" },
  "deps": [
    { "ecosystem": "PyPI", "name": "PyYAML", "version": "5.3", "source": "requirements.txt" },
    { "ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "source": "pom.xml" },
    { "ecosystem": "npm", "name": "lodash", "version": "4.17.20", "source": null }
  ]
}
```

- `source`가 `null`이면 매니페스트가 없는 의존성이다. 자동 수정하지 않고 수동 제안만 한다.
- `manifest_paths`는 워크스페이스 사본이 있으면 사본 경로, 없으면 원본 경로다.

## 5. Impact — 영향 카드 (파이프라인 → API)

```json
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
    "tier": "긴급 | 높음 | 보통",
    "rank": [1, 1, 1, 0.97, 10.0],
    "reasons": ["KEV 등록(실제 악용)", "인터넷 노출", "EPSS 0.97", "CVSS 10.0"]
  },
  "status": "미조치 | 수정 제안 | 수정 완료 | 수정 후 잔존",
  "remediation": {
    "kind": "bump | workaround | manual",
    "text": "org.apache.logging.log4j:log4j-core 2.14.1 → 2.15.0",
    "diff": "--- a/pom.xml\n+++ b/pom.xml\n@@ ..."
  },
  "rescan": 0
}
```

- `priority.rank` 순서: `[kev, ransomware, exposed, epss, cvss]`. 정렬은 내림차순.
- `tier`: KEV 또는 랜섬웨어면 `긴급`, 노출이면 `높음`, 그 외 `보통`.
- `rescan`: 수정 적용 후 해당 서비스에서 남은 영향 건수. 적용 전에는 `null`.
- `diff`: 수정이 있을 때만 값이 있다. unified diff 형식.

## 6. 우선순위 규칙 (확정)

1. KEV 등록 또는 랜섬웨어 악용 → `긴급`
2. 인터넷 노출 → `높음`
3. 그 외 → `보통`
4. 같은 등급 안에서 `rank` 내림차순(EPSS, CVSS)으로 정렬

## 7. 변경 이력

- v0.1: 최초 작성 (프로토타입 기준)
