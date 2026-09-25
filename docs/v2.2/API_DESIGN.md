# CPSM API 및 동작순서 상세설계서

- 문서 버전: 2.1
- 상태: 현재 구현·운영 검증과 QR 단일 확인 알림 설계를 분리해 기록
- 기준일: 2026-09-25
- 상위 설계서: [`DESIGN.md`](./DESIGN.md)
- 서버 코드: `/home/ubuntu/web-service/cpsm-server`
- Android/Windows 코드: `/home/ubuntu/web-service-archive/childrens_pc_security_monitoring/`
- 운영 API base URL: `https://pm-oci.duckdns.org/cpsm-api`

> 이 문서는 API 계약과 호출 순서를 기록한다. 실제 구현 완료 여부는 각 항목의 `상태`를 따른다. `구현`과 `설계/구현 예정`을 섞어서 완료로 해석하지 않는다.

## 1. 시스템 경계와 역할

```text
cpsm-p  ──부모 session/API──┐
                            │
                            ▼
                       cpsm-server
                            ▲
                            │
 cpsm-m ──자녀 Android──────┤
 cpsm-c ──자녀 Windows──────┘
```

제품별 책임은 다음과 같다.

- `cpsm-m`: Android 자녀 기기의 등록, OS/API metadata 전송, 관계 동의, 정책 sync/검증/로컬 저장, Android 상태·이벤트 보고, 서버 명령 실행.
- `cpsm-c`: Windows 자녀 PC의 heartbeat, 이벤트 queue 업로드, 정책 sync, 승인 명령 실행, Windows 로컬 관리 API와 OTA 처리.
- `cpsm-p`: 부모 기기 enrollment, Family/자녀 조회, 매핑·부모 동의, 정책 규칙 작성, 자녀 이벤트·승인 요청 조회, allow/terminate 결정.
- `cpsm-server`: 인증·인가, Device/Parent/Family 관계, 동의 상태, 정책 버전·서명, command queue, event/approval 기록, OTA artifact metadata, FCM wake-up 중계.

`cpsm-server`는 자녀 앱을 직접 제어하지 않는다. 부모의 의도를 인증된 `commands`로 저장하고, 자녀가 `/sync` 또는 `/commands/poll`로 가져가 실행한 뒤 result를 반환하는 중계·권위 서버다.

## 2. 공통 규약

### 2.1 URL 규칙

- 외부 base: `https://pm-oci.duckdns.org/cpsm-api`
- 서버 route의 `/api/...` 앞에 reverse proxy prefix `/cpsm-api`가 붙는다.
- 문서의 route는 `/api/...`부터 표기한다.
- 부모 Android client의 기본 prefix는 `/v1/parent`이며, 서버가 `/v1/parent/...`를 `/api/parent/...`로 normalize한다.
- 부모 client 설정을 `/api/parent`로 직접 지정하는 것도 가능하지만 운영 기본값은 `/v1/parent`다.

### 2.2 JSON·시간·ID

- 모든 state-changing 요청은 `Content-Type: application/json`을 사용한다.
- 시간은 ISO-8601 UTC 문자열 또는 API가 명시한 epoch milliseconds를 사용한다.
- `deviceId`: `[A-Za-z0-9._:-]{1,128}`.
- `requestId`, `mappingId`, `commandId`, `eventId`, `errorId`: UUID 또는 서버가 발급한 opaque identifier.
- 알 수 없는 필드는 서버에서 보존하지 않는 것을 기본값으로 한다.
- 오류·stack trace·context에는 token, password, private key, bootstrap code, signing key, FCM credential를 넣지 않는다.

### 2.3 Device 인증

등록 직후를 제외한 자녀 Device API는 다음 둘 중 하나를 사용한다.

#### A. Android Keystore public-key proof

```text
X-CPSM-Device-Id: {deviceId}
X-CPSM-Device-Public-Key: {base64 DER SPKI public key}
X-CPSM-Device-Timestamp: {epoch milliseconds}
X-CPSM-Device-Nonce: {8..128 chars}
X-CPSM-Device-Signature: {base64 signature}
```

서명 원문:

```text
METHOD\nrequestPathWithQuery\ntimestamp\nnonce\nbase64(rawBody)
```

서버는 등록된 public key, timestamp window, nonce replay, body/path binding을 확인한다.

#### B. Windows/dev HMAC compatibility

```text
X-CPSM-Device-Id: {deviceId}
X-CPSM-Timestamp: {epoch milliseconds}
X-CPSM-Nonce: {8..128 chars}
X-CPSM-Signature: {hex/base64 HMAC-SHA256}
```

서명 원문:

```text
METHOD\nrequestPathWithQuery\ntimestamp\nnonce\nsha256(rawBody)
```

실패 시 대표 응답:

```json
{"ok":false,"error":"invalid_device_signature"}
```

가능한 인증 오류: `device_id_mismatch`, `invalid_device_auth`, `stale_device_request`, `replayed_device_request`, `device_key_not_enrolled`, `device_auth_not_configured`.

### 2.4 Parent 인증

Enrollment 성공 후 `cpsm-p`는 session token을 Android Keystore AES key로 암호화하여 저장한다.

```http
Authorization: Bearer {redacted-parent-session-token}
```

서버는 먼저 short-lived parent session을 확인하고, 호환 경로에서는 configured parent/admin bearer token도 확인한다. Parent API는 session의 `family_id`, `parent_id` 범위를 벗어난 데이터에 접근할 수 없다.

### 2.5 공개·초기 접근 API

다음은 최초 설치·업데이트 전에도 접근할 수 있는 경로다. `cpsm-p`는 Android Keystore 공개키를 사용해 자동 enrollment하고, QR pairing preview와 스캔 기기의 단일 확인 전에는 자녀 데이터·정책에 접근할 수 없다.

- `GET /api/status`
- `GET /api/updates/manifest?platform=...&product=...`
- `GET /api/updates/download?platform=...&product=...`
- `GET /api/updates/android/{product}/manifest.json`
- `GET /api/updates/android/{product}/latest.apk`
- `POST /api/parent/auth/auto-enroll`: 공개키 fingerprint 일치 검증 후 Parent profile/session 생성
- `POST /api/parent/auth/enroll`: 통제된 레거시/관리자 복구용 bootstrap route; 일반 사용자 UI에는 노출하지 않음

## 3. API catalog — `cpsm-m` Android 자녀 앱

### M-01. 자녀 자동 등록

```http
POST /api/devices/register
```

- 호출 주체: `cpsm-m` 최초 실행·재실행
- 인증: 최초 bootstrap route. 요청에 Keystore public key를 포함한다.
- 상태: 구현

요청:

```json
{
  "device_id": "5cef1474-ca5c-437b-b3a9-bbc289b54674",
  "public_key": "base64-der-spki",
  "auth_mode": "android_keystore_ec_signature",
  "device_name": "samsung SM-N950N",
  "child_name": "자녀",
  "metadata": {
    "wifi_ip": "192.0.2.10",
    "model": "SM-N950N",
    "manufacturer": "samsung",
    "device": "greatlteks",
    "product": "greatlteks",
    "android_api_level": 28,
    "os_release": "9",
    "security_patch": "2021-10-01",
    "app_version_code": 8,
    "app_version_name": "0.1.7-stale-policy-fix"
  }
}
```

파라미터 규칙:

- `device_id`: 앱이 생성하고 Keystore identity와 함께 유지하는 device ID.
- `public_key`: private key가 아니라 public key만 전송.
- `metadata.android_api_level`: `Build.VERSION.SDK_INT`.
- `metadata.os_release`: `Build.VERSION.RELEASE`.
- `metadata.security_patch`: `Build.VERSION.SECURITY_PATCH`.
- `wifi_ip`, `phone_number`는 identity가 아니며 선택적 진단 metadata다.

응답 `201`:

```json
{
  "ok": true,
  "device_id": "...",
  "registration_status": "registered_unpaired",
  "relationship_status": "unpaired",
  "policy_ready": false
}
```

서버 동작:

1. device ID와 public key 형식·유효성을 검사한다.
2. 같은 device ID와 같은 public key의 재등록이면 `registered_paired`를 보존한다.
3. Device/Profile을 upsert한다.
4. `child_device_registered` audit event를 기록한다.
5. 부모 관계나 정책을 자동 확정하지 않는다.

### M-02. 등록·관계·정책 상태 조회

```http
GET /api/devices/{deviceId}/registration-status
```

- 호출 주체: `cpsm-m` resume, foreground service, 화면 새로고침
- 인증: Device public-key proof 또는 HMAC
- 상태: 구현

Path parameter:

- `deviceId`: URL encoded device ID.

응답 주요 필드:

```json
{
  "ok": true,
  "device_id": "...",
  "registration_status": "registered_unpaired|registered_paired",
  "relationship_status": "unpaired|pending_consent|confirmed",
  "policy_ready": false,
  "policy_assignment": {
    "assignment_id": "...",
    "version": 1,
    "status": "pending|applied|rejected",
    "rejection_reason": ""
  },
  "policy_receipt": {
    "version": 0,
    "status": "pending_or_rejected|applied",
    "local_state": "missing|fresh|expired_or_invalid",
    "signature_status": "unknown|verified|unsigned_dev_mode",
  },
  "device_compatibility": {
    "status": "supported|unsupported|review_required|unknown",
    "apiLevel": 28,
    "minSupportedApi": 26,
    "testedThroughApi": 36,
    "updateVerifier": "legacy_signatures|signing_info"
  },
  "consent_requests": [],
  "mappings": []
}
```

호환성 판정:

- API `< 26`: `unsupported`.
- API `26..36`: `supported`.
- API `> 36`: `review_required`.
- API `< 28` update signer verifier: `legacy_signatures`.
- API `>= 28` update signer verifier: `signing_info`.

### M-03. 자녀 관계 동의

```http
POST /api/devices/{deviceId}/consent-requests/{requestId}/decision
```

- 호출 주체: `cpsm-m`에 pending child consent가 표시될 때
- 인증: Device proof
- 상태: 구현

요청:

```json
{
  "decision": "approve"
}
```

허용 값:

- `decision=approve` 또는 `consent=true` 또는 `decision=accept`.
- 거절은 `consent=false` 또는 승인 외 decision으로 처리되는 client/server 정책을 별도로 고정해야 한다. 현재 UI의 정상 흐름은 approve다.

서버 동작:

1. request가 해당 device의 child recipient인지 확인한다.
2. mapping의 `child_consent=true`를 저장한다.
3. `parent_consent=true`이고 `child_consent=true`일 때만 mapping을 `confirmed`로 전환한다.
4. confirmed 순간 device를 `registered_paired`로 전환하고 policy assignment를 만든다.
5. FCM이 꺼져 있어도 consent state를 저장한다.

응답:

```json
{
  "ok": true,
  "mapping_id": "...",
  "status": "pending_consent|confirmed",
  "parent_consent": true,
  "child_consent": true,
  "policy_ready": true
}
```

### M-04. 자녀 heartbeat

```http
POST /api/devices/{deviceId}/heartbeat
```

- 상태: 구현
- 호출 주기: foreground service/agent가 결정하며 실제 간격을 health에 기록

요청:

```json
{
  "hostname": "samsung SM-N950N",
  "deviceName": "...",
  "childName": "자녀",
  "platform": "android",
  "status": "running|degraded|stale|offline",
  "currentApp": "com.example.app",
  "health": {
    "state": "running",
    "last_local_check_at": "2026-09-24T12:00:00Z",
    "check_age_ms": 68452,
    "network": true,
    "battery_optimization_exempt": false,
    "device_owner": false,
    "device_admin": false,
    "usage_access": false,
    "policy": {}
  }
}
```

서버는 device status, current app, health를 update하고 `{ "ok": true }`를 반환한다.

### M-05. 자녀 정책·명령 sync

```http
POST /api/devices/{deviceId}/sync
```

- 상태: 구현
- 목적: health upload + policy receipt upload + queued command pull + policy availability 확인

요청:

```json
{
  "device_id": "...",
  "platform": "android",
  "local_policy_version": 0,
  "last_event_seq": 0,
  "events": [],
  "status": {
    "health": {
      "state": "missing|fresh|expired_or_invalid",
      "version": 0,
      "canonical_hash": "",
      "signature_status": "unknown|verified|unsigned_dev_mode",
      "last_rejection": "",
      "last_check_age_ms": 239
    },
    "policy": {},
    "auth_mode": "android_keystore_ec_signature"
  }
}
```

서버 응답:

```json
{
  "ok": true,
  "server_time": "2026-09-24T12:00:00.000Z",
  "registration": {
    "status": "registered_unpaired|registered_paired",
    "relationship_status": "unpaired|pending_consent|confirmed",
    "policy_ready": false
  },
  "policy_receipt": {
    "status": "pending_or_rejected|applied",
    "version": 0,
    "local_state": "missing|fresh|expired_or_invalid",
    "signature_status": "unknown|verified|unsigned_dev_mode"
  },
  "policy": {
    "available": false,
    "changed": false,
    "version": 0,
    "hash": "",
    "canonical_hash": "",
    "reason": "parent_mapping_required|mutual_consent_required"
  },
  "commands": [],
  "next_sync_after_ms": 38124
}
```

정책 분기:

- Android가 unpaired 또는 mutual consent pending이면 `available=false`, policy body를 내려주지 않는다.
- confirmed이고 `local_policy_version < server version`이면 `available=true`, `changed=true`, `download_url`을 반환한다.
- `next_sync_after_ms`는 jitter를 포함한다.
- 명령은 FCM 도착 여부와 무관하게 응답에 포함될 수 있다.

### M-06. 정책 다운로드

```http
GET /api/devices/{deviceId}/policy?version={version}
```

- 상태: 구현
- 인증: Device proof
- Android 관계 미확정 시 `409 policy_not_ready`.

응답 정책 payload:

```json
{
  "policyId": "family-policy-...",
  "version": 1,
  "timezone": "Asia/Seoul",
  "enforcementMode": "enforce",
  "appRules": [
    {
      "id": "rule-1",
      "platform": "android",
      "name": "Example",
      "match": {"type": "package", "packageName": "com.example.app"},
      "action": "block",
      "reason": "parent_policy"
    }
  ],
  "expiresAt": "2026-09-25T05:49:11.626Z",
  "canonicalHash": "sha256...",
  "canonical_hash": "sha256...",
  "signatureAlgorithm": "Ed25519",
  "signature_algorithm": "Ed25519",
  "signatureMetadata": {"algorithm": "Ed25519", "keyId": "..."},
  "signature_metadata": {"algorithm": "Ed25519", "keyId": "..."},
  "signature": "base64 signature",
  "keyId": "...",
  "key_id": "..."
}
```

Child 검증 순서:

1. HTTPS response와 JSON 형식을 확인한다.
2. version이 0보다 크고 local version보다 낮지 않은지 확인한다.
3. signature/hash metadata를 canonical field에서 제외한 canonical JSON을 만든다.
4. `canonical_hash`와 계산 hash를 비교한다.
5. policy signing public key로 signature를 검증한다.
6. expiry를 확인한다.
7. 같은 version의 다른 hash, downgrade, invalid signature는 거부한다.
8. pending copy를 저장한 뒤 검증 성공 시 last-known-good를 atomic commit한다.
9. 실패하면 last-known-good를 유지하고 rejection reason만 기록한다.

### M-07. 자녀 이벤트 업로드

현재 Android `PolicySyncClient`는 sync body에 events를 포함할 수 있고, 별도 event client 확장은 같은 서버 API를 사용할 수 있다.

```http
POST /api/devices/{deviceId}/events
```

- 상태: 서버 구현, Android event producer 범위는 부분 구현
- 인증: Device proof

요청:

```json
{
  "device_id": "...",
  "events": [
    {
      "eventId": "uuid",
      "sequence": 1042,
      "type": "boot|health_check|app_foreground|app_background|app_blocked|policy_applied|permission_lost|command_result|error",
      "eventTime": "2026-09-24T12:00:00Z",
      "payload": {
        "appName": "com.example.app",
        "action": "block",
        "matchedRuleId": "rule-1"
      },
      "schema_version": 1
    }
  ]
}
```

응답:

```json
{
  "ok": true,
  "received": 1,
  "acknowledgedEventIds": ["uuid"],
  "acknowledgedSequences": [1042]
}
```

`device_id + event_id` 및 sequence를 기준으로 중복을 제거한다. `require_approval` event는 server가 approval request를 만들고 parent notification/wake-up을 시도한다.

### M-08. 자녀 명령 결과

```http
POST /api/devices/{deviceId}/commands/{commandId}/result
```

- 상태: 서버 구현, Android command executor는 구현 범위에 따라 확장
- 인증: Device proof

요청 예시:

```json
{
  "status": "completed|failed|expired",
  "result": {
    "action": "app.terminate|app.allow.temporary|policy.refresh",
    "package_name": "com.example.app",
    "message": ""
  },
  "completed_at": "2026-09-24T12:00:00Z",
  "error_code": ""
}
```

서버는 command가 해당 device의 command인지 확인하고 상태·result를 기록한다. 없는 command는 `404 command_not_found`다.

### M-09. Child OTA

현재 Child는 public query API를 사용한다.

```http
GET /api/updates/manifest?platform=android&product=cpsm-m
GET /api/updates/download?platform=android&product=cpsm-m
```

stable alias:

```http
GET /api/updates/android/cpsm-m/manifest.json
GET /api/updates/android/cpsm-m/latest.apk
```

manifest 필드:

- `platform`, `product`
- `versionCode`, `versionName`
- `packageName`
- `artifact`, `size`, `sha256`
- `signingCertificateSha256`가 있으면 진단 metadata로 사용
- `minVersionCode`, `channel`, `releaseNotes`, `publishedAt`

Android validator:

1. HTTPS와 product/platform 확인.
2. package name 확인.
3. versionCode downgrade/equal 여부 확인.
4. size와 SHA-256 확인.
5. 설치된 package의 현재 signer와 archive signer 비교.
6. 통과 후 Android Package Installer를 호출한다.
7. 사용자의 Package Installer 승인이 필요하며 일반 앱의 silent install은 보장하지 않는다.

## 4. API catalog — `cpsm-c` Windows 자녀 agent

### C-01. Windows heartbeat

```http
POST /api/devices/{deviceId}/heartbeat
```

요청은 M-04와 같은 구조를 사용하되 `platform: "windows"`로 보낸다.

```json
{
  "hostname": "child-pc",
  "childName": "자녀",
  "platform": "windows",
  "status": "running",
  "currentApp": "chrome.exe",
  "health": {
    "service_alive": true,
    "queue_depth": 0,
    "last_local_check_at": "2026-09-24T12:00:00Z"
  }
}
```

### C-02. Windows 이벤트 업로드

```http
POST /api/devices/{deviceId}/events
```

요청 형식은 M-07과 같으며 `payload`는 Windows process name, executable path, PID, creation time, action, matched rule ID를 포함할 수 있다.

Windows agent는 `event_id`와 sequence가 서버 ACK를 받을 때까지 local queue에서 삭제하지 않는다.

### C-03. Windows 정책 sync

```http
POST /api/devices/{deviceId}/sync
```

요청:

```json
{
  "device_id": "local-device",
  "platform": "windows",
  "local_policy_version": 1,
  "status": {
    "status": "running",
    "current_app": "chrome.exe",
    "health": {}
  }
}
```

응답의 `policy.changed`, `policy.version`, `policy.download_url`, `commands`, `next_sync_after_ms`를 처리한다.

### C-04. Windows 정책 다운로드

```http
GET /api/devices/{deviceId}/policy
```

Windows는 server 정책을 받아 local policy file에 저장하고, polling 없이도 local last-known-good 정책으로 process inspection을 수행한다.

### C-05. Windows 명령 polling/result

```http
GET  /api/devices/{deviceId}/commands/poll
POST /api/devices/{deviceId}/commands/{commandId}/result
```

대표 command type:

- `policy.refresh`
- `app.terminate`
- `app.allow.temporary`

`app.terminate`는 process name만 믿지 않고 policy match, executable path, PID creation time을 검증하는 방향으로 유지한다.

### C-06. Windows OTA

```http
GET /api/updates/manifest?platform=windows&product=cpsm-c
GET /api/updates/download?platform=windows&product=cpsm-c
```

Windows local API가 update flow를 제어한다.

```http
GET  http://127.0.0.1:{localPort}/api/update
POST http://127.0.0.1:{localPort}/api/update/check
POST http://127.0.0.1:{localPort}/api/update/download
POST http://127.0.0.1:{localPort}/api/update/apply
```

`POST /api/update/apply` 요청:

```json
{"confirm": true}
```

local mutation auth:

```http
Authorization: Bearer {local_control_token}
```

또는 `X-CPSM-Local-Token`. 개발 예외를 제외하고 token 없는 mutation은 `401 local_control_auth_required`다.

### C-07. Windows local API

읽기 API:

```http
GET /api/status
GET /api/update
GET /api/events?limit=50
GET /api/policy
```

쓰기 API:

```http
POST /api/policy/reload
POST /api/policy
POST /api/allow-temporary
```

`POST /api/policy` body는 policy patch, `POST /api/allow-temporary` body는 다음과 같다.

```json
{
  "processName": "notepad.exe",
  "minutes": 15
}
```

`minutes`는 1분 이상 7일 이하로 제한한다. 이 local API는 부모 제어 API가 아니라 설치된 agent의 운영·진단 경계다.

## 5. API catalog — `cpsm-p` Android 부모 앱

### P-01. Parent 자동 enrollment

```http
POST /v1/parent/auth/auto-enroll
```

서버 canonical route:

```http
POST /api/parent/auth/auto-enroll
```

- 인증: bearer 없음; Android Keystore public key와 fingerprint 일치 검증
- 상태: 구현
- 목적: 일반 사용자에게 bootstrap code·Parent session·Device-ID 입력을 요구하지 않고 첫 실행 세션을 생성

요청:

```json
{
  "device_pubkey": "base64 DER SPKI",
  "device_fingerprint": "sha256(raw DER public key)",
  "platform": "android",
  "display_name": "부모",
  "metadata": {
    "android_api_level": 35,
    "os_release": "15",
    "security_patch": "2026-...",
    "manufacturer": "samsung",
    "model": "SM-G991N",
    "device": "o1s",
    "product": "..."
  }
}
```

응답:

```json
{
  "ok": true,
  "enrollment": "automatic",
  "parent": {"parent_id": "parent-...", "family_id": "family-..."},
  "session": {
    "session_token": "{not logged}",
    "family_id": "family-...",
    "parent_id": "parent-...",
    "expires_at": "2026-09-24T13:00:00Z",
    "device_compatibility": {}
  }
}
```

서버는 token 원문을 DB에 저장하지 않고 session hash를 저장한다. Parent client는 response를 local encrypted storage에 저장한다. 자동 enrollment 자체는 빈 Parent family/profile을 만들 뿐이며, 자녀 정보 접근은 QR one-time claim, 이름 preview, 스캔 기기의 단일 confirm 이후에만 가능하다.

### P-01-L. Legacy/admin bootstrap enrollment

`POST /v1/parent/auth/enroll` (`/api/parent/auth/enroll`)는 통제된 복구·관리자 도구 호환용으로 유지한다. 일반 Parent 앱 UI와 제품 onboarding에서는 호출하지 않는다. bootstrap code는 APK·QR·로그·GitHub에 포함하지 않는다.

### P-02. Parent dashboard

```http
GET /v1/parent/dashboard
```

- canonical route: `/api/parent/dashboard`
- 인증: Parent session
- 상태: 구현

응답 표시 대상:

- policy version
- blocked/rule count
- device online/total
- pending approval count
- recent events

### P-03. Family와 child discovery

```http
GET /v1/parent/families
GET /v1/parent/children/available
```

`children/available` 응답 child item:

```json
{
  "child_id": "child-...",
  "device_id": "...",
  "display_name": "자녀",
  "device_name": "SM-N950N",
  "registration_status": "registered_unpaired",
  "relationship_status": "unpaired",
  "compatibility": {
    "status": "supported",
    "apiLevel": 28,
    "minSupportedApi": 26,
    "testedThroughApi": 36,
    "updateVerifier": "signing_info"
  },
  "metadata": {}
}
```

### P-04. Parent-child mapping

```http
POST /v1/parent/mappings
GET  /v1/parent/mappings
```

POST body:

```json
{"child_device_id":"5cef1474-ca5c-437b-b3a9-bbc289b54674"}
```

서버 동작:

1. parent session의 family/parent profile을 확인한다.
2. child device를 family에 연결할 pending mapping을 생성한다.
3. parent recipient와 child recipient 각각에 consent request를 만든다.
4. FCM enabled이면 알림을 시도하고, disabled이면 pending notification/log fallback만 남긴다.
5. mapping은 아직 `pending_consent`다.

### P-04-Q. 양방향 QR 기반 자녀 식별 UI

QR은 별도 인증서·비밀번호·장기 token을 담지 않는 단기 pairing session 보조 수단이다. 양쪽 앱이 같은 payload 형식을 사용한다.

```text
cpsm://pair?version=3&role=parent|child&session_id={session-id}&pairing_code={short-lived-code}
```

Parent와 Child 어느 쪽이든 서버에서 2분 TTL·1회 사용 session을 발급하고, 자신이 발급한 role과 session ID·code로 QR Bitmap을 로컬 생성한다. 서버에는 code 원문이 아닌 hash만 저장한다.

실제 동작 순서:

1. Child가 `자녀 매핑 QR 표시`를 누르면 인증된 `POST /api/devices/{deviceId}/pairing-sessions`로 `role=child` session을 발급받는다.
2. Parent가 `QR로 자녀 추가`를 누르고 Child QR을 촬영한다. Parent 앱은 `role=child`를 검증한 뒤 `/api/parent/pairing-sessions/{sessionId}/claim`을 호출한다.
3. Parent가 `부모 매핑 QR 표시`를 누르면 인증된 `POST /api/parent/pairing-sessions`로 `role=parent` session을 발급받는다.
4. Child가 `부모 매핑 QR 스캔`을 누르고 Parent QR을 촬영한다. Child 앱은 `role=parent`를 검증한 뒤 `/api/devices/{deviceId}/pairing-sessions/{sessionId}/claim`을 호출한다.
5. 서버는 TTL·code hash·issuer role·claimant 인증을 검증하고 이름 preview와 `pending_consent` mapping을 반환한다. session은 `claimed`로 전환되어 재사용할 수 없다.
6. 스캔한 앱이 `부모: XXX / 자녀: ZZZ / 페어링하시겠습니까?` 확인창을 표시한다.
7. 확인 시 `/confirm`을 호출하고 서버가 부모·자녀 consent를 원자적으로 승인하여 mapping을 `confirmed`로 전환한다. 취소하면 mapping은 `declined`로 전환된다.

QR을 읽는 것만으로 서버 관계를 즉시 확정하지는 않는다. QR 표시 행위는 issuer의 pairing 의사로 취급하고, 스캔한 기기의 이름 확인창이 최종 명시적 동의다. QR 사진 유출·재촬영에 대비한 장기 credential은 QR에 넣지 않으며, server authentication, issuer/claimant role 검증, one-time code, 이름 확인, 단일 confirm이 보안 경계다. Bluetooth는 현재 관계 확정 경로로 사용하지 않으며, 향후 추가하더라도 proximity discovery 보조 수단으로만 취급한다.

### P-04-Q API contract

Child-issued session:

```http
POST /api/devices/{deviceId}/pairing-sessions
Authorization: device signature headers
Body: {}
```

Parent-issued session:

```http
POST /api/parent/pairing-sessions
Authorization: parent session bearer
Body: {}
```

Session response `201`:

```json
{
  "pairing_session_id": "opaque-session-id",
  "pairing_code": "short-lived-code",
  "expires_at": "ISO-8601",
  "role": "parent|child"
}
```

Parent claims Child QR:

```http
POST /api/parent/pairing-sessions/{sessionId}/claim
Authorization: parent session bearer
Body: {"pairing_code":"short-lived-code"}
```

Child claims Parent QR:

```http
POST /api/devices/{deviceId}/pairing-sessions/{sessionId}/claim
Authorization: device signature headers
Body: {"pairing_code":"short-lived-code"}
```

Both claim responses contain:

```json
{
  "mapping": {"status": "pending_consent"},
  "preview": {
    "parent": {"display_name": "부모 이름"},
    "child": {"display_name": "자녀 이름"}
  }
}
```

The scanning app must display the preview before confirmation. The QR flow then uses one of these authenticated endpoints:

```http
POST /api/parent/pairing-sessions/{sessionId}/confirm
Authorization: parent *** bearer
Body: {"consent": true}
```

```http
POST /api/devices/{deviceId}/pairing-sessions/{sessionId}/confirm
Authorization: device *** headers
Body: {"consent": true}
```

`consent=true` atomically sets both relationship consent flags, marks the mapping and pairing session `confirmed`, activates the child family member, and makes the policy eligible. `consent=false` marks the mapping/session `declined`. A pairing session cannot be confirmed by an actor different from the claimant that performed the claim. The server never returns a long-term credential in the QR payload.

### P-04-Q-N. QR 상태 통지와 Parent QR 종료

현재 구현된 authoritative 상태 조회는 다음 endpoint다.

```http
GET /api/parent/pairing-sessions/{sessionId}
Authorization: parent *** bearer
```

응답의 `status`는 `pending`, `claimed`, `confirmed`, `declined`, `expired` 중 하나이며, `mapping`은 서버에 저장된 관계 상태를 나타낸다. Parent QR은 `confirmed` 응답을 받은 뒤에만 관계 확정으로 처리한다. FCM 전달 자체는 상태의 증거가 아니다.

권장 최종 동작:

```text
server confirm
→ FCM {type, pairing_session_id, status} wake-up 시도
→ Parent 수신
→ 위 status GET 1회
→ confirmed이면 QR 종료
```

운영 FCM이 비활성화되거나 메시지가 유실될 때는 5분 단일 연결 대신 30~45초 Long Polling을 사용하고, timeout 후 제한된 횟수만 재연결한다. 이 Long Polling endpoint와 FCM pairing-session handler는 현재 미구현이다.

현재 공개 Parent version 19는 위 최종 구조가 아닌 1.5초 status polling으로 자동 종료한다. 이는 임시 호환 구현이며, 서버 부하를 줄이기 위한 FCM wake-up + Long Polling fallback 구현 후 제거 대상이다.

### P-05. Parent consent

```http
POST /v1/parent/mappings/{mappingId}/consent
```

요청:

```json
{"consent": true}
```

또는:

```json
{"decision": "approve"}
```

이 endpoint는 기존 수동 mapping/관리자 호환 경로다. QR 사용자 흐름은 위 P-04-Q의 `/pairing-sessions/{sessionId}/confirm`을 사용하며, 스캔한 기기의 단일 확인창에서 부모·자녀 consent를 원자적으로 처리한다.

### P-06. Consent request 조회

```http
GET /v1/parent/consent-requests
```

응답은 해당 parent recipient의 pending request만 반환한다.

### P-07. Child health/timeline

```http
GET /v1/parent/devices/{deviceId}/health
GET /v1/parent/devices/{deviceId}/timeline
```

- health: 현재 device state, OS/API metadata, local health, registration state.
- timeline: 최근 event 최대 200건을 reverse chronological로 반환.
- authorization: parent session family scope.

### P-08. Approval request 읽기·결정

```http
GET  /v1/parent/approval-requests/{requestId}
GET  /v1/parent/approval-requests
POST /v1/parent/approval-requests/{requestId}/decision
```

결정 요청 body:

```json
{
  "request_id": "request-...",
  "decision": "allow|terminate",
  "idempotency_key": "uuid"
}
```

Parent client 동작:

1. 요청을 다시 GET한다.
2. `status`가 pending인지 확인한다.
3. `expires_at`이 지났는지 확인한다.
4. 기기 인증 step-up을 수행한다.
5. decision API를 호출한다.

서버 동작:

- `allow`: `app.allow.temporary`, payload `{processName, minutes:120, requestId}`를 queue한다.
- `terminate`: `app.terminate`, payload `{pid, processName, requestId}`를 queue한다.
- idempotency key로 중복 효과를 방지한다.

호환 route:

```http
POST /api/parent/approval-requests/{requestId}/allow
POST /api/parent/approval-requests/{requestId}/terminate
```

### P-09. 정책 조회·저장

```http
GET /v1/parent/policies/current
PUT /v1/parent/policies/current
```

PUT body:

```json
{
  "rules": [
    {
      "id": "rule-1",
      "name": "Game",
      "platform": "android|windows",
      "match": {"type":"package|processName", "packageName":"com.example.game"},
      "action": "monitor|block|require_approval|allow",
      "excludedUntil": "",
      "reason": "parent_policy"
    }
  ]
}
```

제약:

- 최대 500 rules.
- 잘못된 rule은 `invalid_rules`, `invalid_rule`, `rule_name_required`.
- server가 version을 증가시키고 expiresAt을 갱신한다.
- family session이면 `family_policies`에 저장하고 confirmed child assignment를 pending으로 만든다.
- 모든 device에 `policy.refresh` command를 queue한다.

호환 route:

```http
GET  /api/parent/blocked-apps
POST /api/parent/blocked-apps
```

POST blocked-app body는 단일 rule이며 `deviceId`가 있으면 특정 device, 없으면 전체 device에 policy refresh를 queue한다.

### P-10. Parent FCM token

```http
POST /v1/parent/devices/fcm-token
```

요청:

```json
{"fcm_token":"{token}"}
```

- 상태: API 구현, production FCM disabled.
- FCM disabled이면 Parent client가 token 조회·등록을 호출하지 않는다.
- FCM delivery는 관계 확정·명령 완료의 증거가 아니다.

### P-11. Parent OTA

Parent APK도 Child와 동일하게 public update route를 사용한다.

```http
GET /api/updates/manifest?platform=android&product=cpsm-p
GET /api/updates/download?platform=android&product=cpsm-p
GET /api/updates/android/cpsm-p/manifest.json
GET /api/updates/android/cpsm-p/latest.apk
```

Parent validator도 package/version/size/SHA-256/current signer/Package Installer approval을 확인한다.

## 6. API catalog — `cpsm-server` 공개·관리·중계 API

### S-01. Health/status

```http
GET /api/status
```

응답:

```json
{
  "ok": true,
  "service": "cpsm-server",
  "storage": "sqlite",
  "devices": 1,
  "pendingCommands": 0,
  "policyVersion": 1,
  "fcmEnabled": false,
  "authMode": "strict"
}
```

secret, device key, DB path, bootstrap code, FCM credential는 포함하지 않는다.

### S-02. Public artifact API

```http
GET /api/updates/manifest?platform=android|windows&product=cpsm-m|cpsm-p|cpsm-c
GET /api/updates/download?platform=android|windows&product=...
```

selector 조합:

- `android + cpsm-m`
- `android + cpsm-p`
- `windows + cpsm-c`

그 외 조합은 `400 invalid_update_selector`.

### S-03. Admin device credential API

```http
POST /api/admin/devices/{deviceId}/secret
```

- auth: admin bearer
- body: `{ "secret": "..." }` 또는 `{ "publicKey": "...", "platform":"android|windows", "deviceName":"...", "childName":"..." }`
- secret/public key 원문은 문서·로그에 기록하지 않는다.
- 운영에서는 Android 자동 등록의 public key를 우선한다.

### S-04. Parent enrollment

상세는 P-01 참조. 서버 책임은 다음과 같다.

- bootstrap code timing-safe compare
- parent profile/family ensure
- metadata normalization
- session hash 저장
- session token을 response 한 번에 반환
- audit event 기록

### S-05. Relationship/policy middle layer

서버는 다음 순서를 강제한다.

```text
Device register
 → Parent profile/session
 → Child discovery
 → Mapping request
 → Parent consent
 → Child consent
 → confirmed
 → Family policy assignment pending
 → Child policy download/verify/commit
 → authenticated receipt
 → assignment applied
```

어느 단계에서도 FCM send 성공만으로 다음 단계로 이동하지 않는다.

### S-06. Event-to-approval middle layer

```text
child POST /events
 → event dedup
 → action= require_approval?
 → approval_requests insert
 → parent notification attempt/fallback log
 → parent GET approval request
 → parent POST decision
 → commands insert
 → child sync/poll
 → child result
 → command status update
```

### S-07. Error telemetry API — 구현 완료

오류는 화면에만 표시하지 않고, device가 authenticated HTTPS로 서버에 업로드한다.

```http
POST /api/devices/{deviceId}/errors
```

인증: Device public-key proof/HMAC.

요청:

```json
{
  "client_request_id": "uuid",
  "platform": "android|windows",
  "product": "cpsm-m|cpsm-c",
  "app_version": {
    "version_code": 8,
    "version_name": "0.1.7-stale-policy-fix"
  },
  "runtime": {
    "android_api_level": 28,
    "os_release": "9",
    "security_patch": "2021-10-01",
    "manufacturer": "samsung",
    "model": "SM-N950N",
    "device": "greatlteks"
  },
  "errors": [
    {
      "error_id": "uuid",
      "occurred_at": "2026-09-24T12:00:00Z",
      "error_code": "canonical_hash_invalid",
      "category": "policy|network|auth|permission|ota|command|runtime|storage",
      "severity": "info|warning|error|critical",
      "operation": "policy_sync",
      "component": "LocalPolicyStore",
      "message": "redacted short message",
      "stack_trace": "redacted bounded stack",
      "request_id": "uuid",
      "correlation_id": "uuid",
      "context": {
        "policy_version": 1,
        "local_policy_version": 0,
        "http_status": 200,
        "retry_count": 2
      }
    }
  ]
}
```

업로드 규칙:

- 한 요청 최대 50건.
- `message`, `stack_trace` 길이 제한.
- 서버에서 secret/token/password/private-key/credential 필드 redaction.
- 동일 `fingerprint`는 issue aggregate에 묶고 occurrence count를 증가.
- 서버는 raw error를 무기한 보존하지 않고 retention policy를 적용.
- device가 offline이면 `cpsm-m`은 `SharedPreferences` durable outbox, `cpsm-c`는 `queue/errors.ndjson`에 저장한다.
- upload 실패 시 두 client 모두 exponential backoff를 적용하고, 성공 response의 `acknowledged_error_ids`만 제거한다. 반복 실패는 dead-letter 상태로 보존한다.
- client queue의 error ID는 재전송 중에도 유지되어 server occurrence 중복을 방지한다.

응답:

```json
{
  "ok": true,
  "accepted": 1,
  "deduplicated": 0,
  "acknowledged_error_ids": ["uuid"],
  "next_retry_after_ms": 30000
}
```

### S-08. Error review API — 구현 완료

관리자/운영 scope 전용:

```http
GET   /api/admin/errors?status=new&product=cpsm-m&limit=100&cursor=...
GET   /api/admin/errors/{errorId}
PATCH /api/admin/errors/{errorId}
GET   /api/admin/app-versions?platform=android&product=cpsm-m
POST  /api/admin/app-versions
GET   /api/admin/app-versions/{platform}/{product}/{versionCode}/changes
POST  /api/admin/app-versions/{platform}/{product}/{versionCode}/changes
PATCH /api/admin/app-versions/{platform}/{product}/{versionCode}/changes/{changeId}
```

PATCH body:

```json
{
  "status": "triaged|in_progress|resolved|wont_fix",
  "is_fixed": true,
  "fixed_in_version_code": 8,
  "resolution_note": "canonical candidate cleanup added"
}
```

`is_fixed=true` 또는 `status=resolved`는 다음을 모두 만족해야 한다.

1. 같은 `platform/product/version_code`의 `app_versions` row가 존재한다.
2. 해당 issue를 `issue_id`로 가리키는 `change_type=fixed` 변경 row가 존재한다.
3. `PATCH .../changes/{changeId}`로 그 변경 row가 `is_verified=true`가 되었고 `verification_note`가 있다.
4. 위 변경과 연결된 `error_app_version_links(relation=fixed, verified=1)`가 존재한다.

변경 workflow는 `POST /api/admin/app-versions` → `POST .../changes` → `PATCH .../changes/{changeId}`(verification) → `PATCH /api/admin/errors/{errorId}`(resolved) 순서다. 새 occurrence가 들어오면 aggregate는 `regressed`/`is_fixed=false`로 되돌아간다.

운영 API 응답에는 private key, device public key 원문, bootstrap code, raw bearer token을 포함하지 않는다.

### 6.1 API coverage addendum — 현재 구현된 보조 경로

#### M-10. Device notification key 등록

```http
POST /api/devices/{deviceId}/notification-key
```

- 호출 주체: `cpsm-m`/`cpsm-c`의 optional notification integration
- 인증: Device proof/HMAC
- 상태: server 구현; production FCM disabled
- path: `deviceId`
- body:

```json
{
  "provider": "fcm",
  "token": "provider token; never log"
}
```

`token` 대신 `fcm_token`도 호환 입력으로 허용된다. 응답은 `{ "ok": true, ... }`이며 token 원문을 포함하지 않아야 한다. 등록 성공은 동의·관계 확정·command 완료의 증거가 아니다.

#### M-11. Device-authenticated OTA

```http
GET /api/devices/{deviceId}/updates/manifest?product=cpsm-m
GET /api/devices/{deviceId}/updates/download?product=cpsm-m
```

- 인증: Device proof/HMAC
- query: `product` 필수; Android device는 `cpsm-m`, Windows device는 `cpsm-c`만 허용
- 오류: `400/403 artifact_product_not_for_device`, signature/auth 오류
- public bootstrap route와 달리 등록된 device에 대한 authenticated artifact 경로다.

#### P-12. Parent authenticated OTA compatibility route

```http
GET /v1/parent/updates/manifest?product=cpsm-p
GET /v1/parent/updates/download?product=cpsm-p
```

canonical route는 각각 `/api/parent/updates/manifest`, `/api/parent/updates/download`다.

- 인증: Parent bearer session
- query: `product`는 `cpsm-p`만 허용; 생략 시 server default도 `cpsm-p`
- 오류: `403 artifact_product_not_for_parent`
- 현재 Parent updater의 기본 경로는 public query/stable alias지만, 이 route는 authenticated compatibility 경계로 유지한다.

#### S-03.1. Admin portal token compatibility route

```http
POST /api/admin/portal-device/token
```

- 인증: admin bearer
- body: `{ "fcm_token": "..." }` 또는 `{ "token": "..." }`
- 상태: server 구현, production FCM disabled
- side effect: legacy parent token compatibility storage
- 응답: `{ "ok": true, "registered": true }`

운영 로그와 오류 payload에는 token 원문을 기록하지 않는다.

## 7. 데이터 모델 — 오류와 App Version 변경 이력

### 7.1 기존 App Version

현재 구현 table:

```text
app_versions(
  platform,
  product,
  version_code,
  version_name,
  artifact,
  sha256,
  size,
  package_name,
  signing_certificate_sha256,
  channel,
  release_notes,
  published_at,
  PRIMARY KEY(platform, product, version_code)
)
```

이 table은 artifact release 자체의 immutable metadata다. 기존 version row를 덮어쓰지 않고 새 version을 추가한다.

### 7.2 app_version_changes — 구현 완료

```sql
CREATE TABLE app_version_changes (
  change_id TEXT PRIMARY KEY,
  platform TEXT NOT NULL,
  product TEXT NOT NULL,
  version_code INTEGER NOT NULL,
  previous_version_code INTEGER,
  change_type TEXT NOT NULL,
  component TEXT NOT NULL,
  change_key TEXT NOT NULL,
  change_summary TEXT NOT NULL,
  issue_id TEXT,
  source_ref TEXT,
  is_verified INTEGER NOT NULL DEFAULT 0,
  verification_note TEXT NOT NULL DEFAULT '',
  verified_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(platform, product, version_code)
    REFERENCES app_versions(platform, product, version_code)
);
```

`change_type`:

- `added`: 새 API/클래스/DB field/기능 추가
- `modified`: 기존 동작·parameter·검증 변경
- `fixed`: 오류 수정
- `removed`: 제거
- `security`: 보안 관련 변경
- `compatibility`: Android API/OS/device 호환성 변경

`change_key` 예시:

```text
cpsm-m.PolicySyncClient.clearPendingCandidate
cpsm-server.POST:/api/devices/{deviceId}/errors
cpsm-p.CpsmParentEnrollmentActivity.bootstrap-session
```

### 7.3 device_errors — 구현 완료

```sql
CREATE TABLE device_errors (
  error_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  device_id TEXT,
  platform TEXT NOT NULL,
  product TEXT NOT NULL,
  version_code INTEGER NOT NULL,
  version_name TEXT NOT NULL,
  error_code TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  component TEXT NOT NULL,
  operation TEXT NOT NULL,
  message_redacted TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'new',
  is_fixed INTEGER NOT NULL DEFAULT 0,
  fixed_in_version_code INTEGER,
  fixed_at TEXT,
  resolution_note TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

필수 상태:

- `new`: 최초 수신
- `triaged`: 원인 분류 완료
- `in_progress`: 수정 작업 중
- `resolved`: 수정 version에서 확인 완료
- `wont_fix`: 수정하지 않기로 결정

`is_fixed`는 운영자가 검증한 수정 여부이며, 단순히 새 APK를 publish했다고 자동으로 true가 되지 않는다.

### 7.4 device_error_occurrences — 구현 완료

```sql
CREATE TABLE device_error_occurrences (
  occurrence_id TEXT PRIMARY KEY,
  error_id TEXT NOT NULL,
  client_error_id TEXT NOT NULL,
  device_id TEXT,
  request_id TEXT,
  correlation_id TEXT,
  occurred_at TEXT NOT NULL,
  runtime_json TEXT NOT NULL,
  context_json TEXT NOT NULL,
  stack_trace_redacted TEXT,
  upload_status TEXT NOT NULL DEFAULT 'accepted',
  created_at TEXT NOT NULL,
  FOREIGN KEY(error_id) REFERENCES device_errors(error_id)
);
```

`device_errors`는 deduplicated issue, `device_error_occurrences`는 실제 기기에서 반복 발생한 개별 occurrence다. 둘을 분리해야 한 오류의 발생 횟수·기기 분포·version별 재현을 알 수 있다.

### 7.5 error_app_version_links — 구현 완료

```sql
CREATE TABLE error_app_version_links (
  error_id TEXT NOT NULL,
  platform TEXT NOT NULL,
  product TEXT NOT NULL,
  version_code INTEGER NOT NULL,
  relation TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  PRIMARY KEY(error_id, platform, product, version_code, relation),
  FOREIGN KEY(error_id) REFERENCES device_errors(error_id),
  FOREIGN KEY(platform, product, version_code)
    REFERENCES app_versions(platform, product, version_code)
);
```

`relation`:

- `introduced`: 이 version에서 처음 발생
- `observed`: 이 version에서 관찰
- `fixed`: 이 version에서 수정 확인
- `regressed`: 수정 후 다시 발생
- `not_reproduced`: 해당 version에서 재현되지 않음

### 7.6 DB 상태 전이

```text
error upload
  → fingerprint lookup
  → new issue 또는 occurrence append
  → triaged
  → in_progress
  → new app_versions row published
  → app_version_changes 기록
  → error_app_version_links(relation=fixed)
  → physical/automated verification
  → device_errors.is_fixed=1, status=resolved
```

오류가 다시 발생하면:

```text
resolved + new occurrence
  → is_fixed=0 또는 status=regressed
  → error_app_version_links(relation=regressed)
```

## 8. API 동작 순서

### 8.1 Child 최초 실행 → 서버 등록

| 순서 | 소속 | API/동작 | parameter 핵심 | 결과 |
|---:|---|---|---|---|
| 1 | cpsm-m | Keystore key 생성 | 내부 device ID, public key | private key는 기기 밖으로 나가지 않음 |
| 2 | cpsm-m → server | `POST /api/devices/register` | `device_id`, `public_key`, `auth_mode`, `device_name`, `child_name`, `metadata.android_api_level`, `os_release`, `security_patch`, model/device/product/app version | device/profile upsert |
| 3 | server → cpsm-m | register response | `registration_status`, `relationship_status`, `policy_ready` | 보통 `registered_unpaired`, `unpaired`, `false` |
| 4 | cpsm-m → server | `GET /api/devices/{deviceId}/registration-status` | device proof headers | 관계·consent·compatibility 표시 |
| 5 | cpsm-m | `ProtectionForegroundService` 시작 | local health | 정책 없이는 보호 설정 controls를 활성화하지 않음 |

### 8.2 Parent 최초 실행 → 자동 session 발급

| 순서 | 소속 | API/동작 | parameter 핵심 | 결과 |
|---:|---|---|---|---|
| 1 | cpsm-p | `hasSession()` | encrypted local session | 없으면 자동 enrollment 화면 |
| 2 | cpsm-p | Android Keystore key 생성/reuse | public key, raw DER fingerprint | private key는 기기 밖으로 나가지 않음 |
| 3 | cpsm-p → server | `POST /v1/parent/auth/auto-enroll` | `device_pubkey`, `device_fingerprint`, `platform`, runtime `metadata` | parent/family profile 생성 또는 reuse |
| 4 | server → cpsm-p | enrollment response | `session_token`, `family_id`, `parent_id`, `expires_at`, compatibility | session token을 local encrypted storage에 저장 |
| 5 | cpsm-p | QR onboarding 화면 | QR 생성 또는 카메라 호출 | 자녀 QR/부모 QR 양방향 pairing 가능 |
| 6 | cpsm-p → server | `GET /v1/parent/dashboard` | Authorization bearer | dashboard 표시 |

`POST /v1/parent/auth/enroll`은 통제된 레거시/관리자 복구용으로만 유지한다. 일반 사용자는 bootstrap code를 보거나 입력하지 않는다.

### 8.3 Parent mapping + 양쪽 consent

| 순서 | 소속 | API/동작 | parameter 세팅값 | 서버 상태 |
|---:|---|---|---|---|
| 1 | cpsm-p → server | `POST /v1/parent/mappings` | `{child_device_id: childDeviceId}` | mapping=`pending_consent`; parent/child request 2개 생성 |
| 2 | server | FCM/fallback notify | `type=cpsm_relationship_consent`, `mapping_id`, status | FCM은 hint일 뿐 |
| 3 | cpsm-p → server | `POST /v1/parent/mappings/{mappingId}/consent` | `{consent:true}` | `parent_consent=true`, 아직 policy 차단 |
| 4 | cpsm-m → server | `GET /api/devices/{deviceId}/registration-status` | device proof | pending child request 표시 |
| 5 | cpsm-m → server | `POST /api/devices/{deviceId}/consent-requests/{requestId}/decision` | `{decision:"approve"}` | child consent 저장 |
| 6 | server | state transition | 양쪽 consent 모두 true인지 확인 | `confirmed`, `registered_paired`, policy assignment pending |
| 7 | cpsm-m → server | registration-status 재조회 | 없음 | `policy_ready=true` |

한쪽 consent만 true인 상태에서 policy endpoint를 호출하면 Android는 `409 policy_not_ready`다.

### 8.4 Parent 정책 작성 → Child 정책 적용

| 순서 | 소속 | API/동작 | parameter 세팅값 | 결과 |
|---:|---|---|---|---|
| 1 | cpsm-p → server | `PUT /v1/parent/policies/current` | `{rules:[{id,name,platform,match,action,excludedUntil,reason}]}` | family/global policy version 증가 |
| 2 | server | internal | confirmed child에 assignment 생성/갱신 | assignment=`pending` |
| 3 | server | internal | child별 `policy.refresh` command queue | 다음 sync에서 수신 가능 |
| 4 | cpsm-m/c | `POST /api/devices/{deviceId}/sync` | local version, last event seq, health/policy receipt | `policy.changed=true`와 download URL |
| 5 | cpsm-m/c → server | `GET /api/devices/{deviceId}/policy?version=N` | device proof | signed policy payload |
| 6 | cpsm-m | local validation | canonical hash, signature, expiry, downgrade | 성공 시 last-known-good commit |
| 7 | cpsm-m/c → server | 다음 sync | `status.policy.state=fresh`, `version=N`, signature status | receipt accepted |
| 8 | server | internal | receipt accepted + fresh + version >= assignment | assignment=`applied` |

### 8.5 자녀 앱 이벤트 → 부모 승인 → 명령 실행

| 순서 | 소속 | API/동작 | parameter 세팅값 | 결과 |
|---:|---|---|---|---|
| 1 | cpsm-c/m | local policy evaluation | app/process/package + matched rule | monitor/block/require_approval 결정 |
| 2 | cpsm-c/m → server | `POST /api/devices/{deviceId}/events` | `eventId`, sequence, type, payload.action, app/process, pid | event dedup/store |
| 3 | server | internal | action=`require_approval`이면 approval request 생성 | pending request |
| 4 | server → cpsm-p | FCM 또는 fallback | `request_id`, `event_id`, `device_id`, app name 최소값 | 알림은 optional |
| 5 | cpsm-p → server | `GET /v1/parent/approval-requests/{requestId}` | bearer | status/expiry 재확인 |
| 6 | cpsm-p | device step-up | local Keystore/auth | decision 권한 확인 |
| 7 | cpsm-p → server | `POST /v1/parent/approval-requests/{requestId}/decision` | `decision=allow|terminate`, idempotency key | command queue insert |
| 8 | cpsm-c/m → server | `/sync` 또는 `/commands/poll` | device proof | command delivery |
| 9 | cpsm-c/m | local execution | process/package + policy validation | allow temporary 또는 terminate |
| 10 | cpsm-c/m → server | command result | `status`, result, error_code | command completed/failed |
| 11 | cpsm-p → server | dashboard/timeline 재조회 | bearer | 최종 결과 표시 |

### 8.6 OTA update

| 순서 | 소속 | API/동작 | parameter 세팅값 | 결과 |
|---:|---|---|---|---|
| 1 | cpsm-m/p/c | update check | 제품별 public query manifest | latest metadata |
| 2 | cpsm-m/p/c | manifest validation | product, platform, package, version, size, hash | invalid이면 중단 |
| 3 | cpsm-m/p/c | download | public download route | APK/ZIP bytes |
| 4 | cpsm-m/p/c | integrity validation | SHA-256, size, signer/package | 실패 시 installer 실행 금지 |
| 5 | Android | Package Installer | user approval | silent install 주장 금지 |
| 6 | Windows | staged updater | confirm=true, backup, restart | rollback/verification |
| 7 | server/admin | app version record | platform/product/versionCode/artifact metadata | immutable release record |
| 8 | server/admin | version changes | change_type/component/change_summary | release diff trace |

### 8.7 오류 업로드 → 수정 version 추적

| 순서 | 소속 | API/동작 | parameter 세팅값 | 결과 |
|---:|---|---|---|---|
| 1 | cpsm-m/c | local catch | error_code/category/severity/operation/component | redacted error object |
| 2 | cpsm-m/c | local queue | `error_id`, `occurred_at`, app version, runtime | offline 보관 |
| 3 | cpsm-m/c → server | `POST /api/devices/{deviceId}/errors` | `platform`, `product`, `app_version`, `runtime`, `errors[]` | issue/occurrence 저장 |
| 4 | server | fingerprint dedup | normalized code/component/message | `device_errors` aggregate 갱신 |
| 5 | maintainer | error review | status, is_fixed, resolution note | triage/in-progress |
| 6 | maintainer | publish new app | new versionCode | `app_versions` insert |
| 7 | maintainer | record changes | component, change_key, change_type, issue_id | `app_version_changes` insert |
| 8 | maintainer | link fix | error_id + versionCode + relation=fixed | fix candidate 연결 |
| 9 | QA/device | verify | same scenario/API/device matrix | verified true |
| 10 | server | close issue | `is_fixed=1`, `status=resolved`, `fixed_in_version_code=N` | 수정 여부 확정 |

### 8.5 오류 upload → triage → verified fix

| 순서 | 소속 | API/동작 | parameter 핵심 | 결과 |
|---:|---|---|---|---|
| 1 | cpsm-m/c | local error capture | `error_code`, category/severity, operation/component, redacted message/stack, runtime/version | durable outbox append; same `error_id` 유지 |
| 2 | cpsm-m/c → server | `POST /api/devices/{deviceId}/errors` | `platform`, `product`, `app_version`, `runtime`, `errors[<=50]` | fingerprint aggregate + occurrence 저장 |
| 3 | server → cpsm-m/c | upload ACK | `accepted`, `deduplicated`, `acknowledged_error_ids` | ACK ID만 local queue에서 삭제; 실패는 exponential retry |
| 4 | admin → server | `GET /api/admin/errors` / `GET /api/admin/errors/{errorId}` | status/product/limit/cursor 또는 issue ID | issue·occurrence·version link 검토 |
| 5 | admin → server | `PATCH /api/admin/errors/{errorId}` | `status=triaged|in_progress`, resolution note | triage 상태 기록 |
| 6 | admin → server | `POST /api/admin/app-versions` | platform/product/version/artifact/sha256/signing metadata | immutable release row 등록 |
| 7 | admin → server | `POST .../{versionCode}/changes` | `change_type=fixed`, component/key/summary, `issue_id` | fixed link 생성, 아직 unverified |
| 8 | admin → server | `PATCH .../changes/{changeId}` | `is_verified=true`, `verification_note` | fixed link `verified=1` |
| 9 | admin → server | `PATCH /api/admin/errors/{errorId}` | `status=resolved`, `is_fixed=true`, fixed version | 조건 검증 후 resolved 저장 |
| 10 | cpsm-m/c → server | 새 occurrence upload | 동일 fingerprint + newer version | aggregate를 `regressed`, `is_fixed=false`로 되돌림 |

## 9. 상태 전이와 불변 조건

### 9.1 Family lifecycle

```text
UNREGISTERED
  → CHILD_REGISTERED_UNPAIRED
  → PARENT_MAPPED_PENDING_CONSENT
  → PARENT_CHILD_CONFIRMED
  → POLICY_SYNCED
  → PROTECTED_RUNNING
```

실제 server fields:

- `registration_status`: `unregistered`, `registered_unpaired`, `registered_paired`.
- `relationship_status`: `unpaired`, `pending_consent`, `confirmed`.
- `policy_assignment.status`: `pending`, `applied`, `rejected`.
- local policy: `missing`, `fresh`, `expired_or_invalid`.

### 9.2 불변 조건

1. 같은 device/public key 재등록은 confirmed 관계를 unpaired로 되돌리지 않는다.
2. parent consent 하나만으로 confirmed가 되지 않는다.
3. FCM send 성공은 consent/relationship/command completion의 근거가 아니다.
4. Android 정책은 confirmed 관계와 local signature/hash/expiry 검증을 모두 통과해야 저장한다.
5. 정책 receipt가 fresh·accepted가 되기 전에는 assignment를 applied로 표시하지 않는다.
6. update equal/downgrade, package mismatch, SHA mismatch, signer mismatch는 installer로 넘기지 않는다.
7. error `is_fixed=1`은 새 version publish만으로 자동 설정하지 않고 검증 후 설정한다.
8. public artifact routes에는 secret, DB, signing private key, device private key가 포함되지 않는다.

## 10. 미구현·검증 대기 경계

현재 구현됨:

- SQLite canonical storage와 Family lifecycle tables.
- Child automatic registration/status/consent.
- Parent bootstrap enrollment/session/family mapping/consent.
- Parent dashboard/approval/policy API.
- Child/Windows sync, policy, events, commands server routes.
- Android OS/API metadata collection·compatibility classification.
- Android public OTA manifest/download aliases와 signer continuity validation.
- FCM disabled-safe polling/fallback.
- 양쪽 앱의 QR session 발급·role 검증·카메라 스캔과 반대 역할 claim API.

현재 부분 구현 또는 검증 대기:

- 실제 Note8/S21 physical install/update/Package Installer approval.
- API 26 LG Q9, API 31 LG V50, API 35 S21, API 36 device behavior.
- Device Owner provisioning·reboot·package suspension.
- Android UsageStats event producer와 complete command executor.
- Windows production service wrapper/strong local IPC.
- One-time short-TTL bootstrap code issuance UI/service.
- Error telemetry API와 SQLite error tables (`device_errors`, `device_error_occurrences`, `app_version_changes`, `error_app_version_links`) 구현 및 server smoke 검증.
- `cpsm-m` `LocalErrorStore`(SharedPreferences)와 `cpsm-c` `ErrorStore`(NDJSON) local queue/retry/dead-letter 구현.
- Admin error review 및 App Version change verification workflow 구현.

## 11. 검토 체크리스트

- [ ] API path가 실제 client 호출 path와 일치하는가?
- [ ] `/v1/parent`와 `/api/parent` normalize 규칙이 문서화되었는가?
- [ ] device/parent/public/admin auth 경계가 분리되었는가?
- [ ] 모든 API의 path/query/body parameter와 allowed value가 있는가?
- [ ] server가 중계하는 것과 client가 직접 실행하는 것이 분리되었는가?
- [ ] consent 두 단계와 policy_ready gate가 순서에 포함되었는가?
- [ ] FCM disabled에서도 polling/manual refresh가 가능한가?
- [ ] OTA의 artifact/hash/signer/Package Installer 경계가 포함되었는가?
- [ ] 오류의 aggregate, occurrence, fix version, changed files/fields가 연결되는가?
- [ ] 오류 payload에서 credential·token·private key가 제외되는가?
- [ ] 구현 완료와 physical-device 미검증을 구분했는가?

---

## 12. v2.2 addendum — 사용시간 관리 · 부모 명령 (2026-09-25)

이 장은 v2.1 catalog 이후 실제 구현·검증된 추가/변경분만 정리한다. 상세 배경은 `CHANGES_v2.2.md`.

### 12.1 정책 v2 (`screenTime`)

`family_policies.policy`에 아래 절이 추가된다. 서버가 검증·서명하고, 기기 sync 시 플랫폼별 view로 재구성해 Ed25519 서명한다(`schemaVersion: 2`). canonical hash·서명이 `screenTime`을 포함함을 `scripts/policy-v2-test.js`가 검증한다.

```
screenTime {
  dailyLimitMinutes: int 0..1440
  downtime: [ { days:[1..7], start:"HH:MM", end:"HH:MM" } ]   # end<start ⇒ 익일까지, 요일=시작일 기준
  alwaysAllowed: { android:[pkg...], windows:[proc...] }       # 기본값에 전화/긴급전화 포함
  bootGuard: bool                                              # Usage Access 없을 때 fail-closed
  message: string(≤120)
}
appRules[].dailyLimitMinutes: int 0..1440                      # 앱별 하루 한도
```

`rules`만 갱신하는 클라이언트 호출은 `screenTime`을 보존한다(`replaceFamilyPolicyRules(familyId, rules, screenTime=undefined)`).

### 12.2 P-신규 — 부모 기기·명령 API

- `P-D1 GET /api/parent/devices` → 가족 confirmed 기기 요약(presence·protection·screen_time).
- `P-D2 POST /api/parent/devices/{deviceId}/commands` → `device.lock|device.unlock|screen_time.bonus|sync_now`, `idempotency_key`, lock 24h·기타 1h 만료.
- `P-D3 GET /api/parent/devices/{deviceId}/commands` → 명령 상태 목록.

권한: parent session은 자기 family의 confirmed 기기만(그 외 404 `device_not_found`). 정적 operator token(세션 없음)은 legacy 전역 뷰.

### 12.3 M/C-변경 — 이벤트 수신과 시간 요청

- device `sync`의 `events[{seq,type,timestamp_ms,...}]`를 저장하고 `accepted_event_seq` 반환. `foreground_app`→`app.foreground`, `health_check` 제외.
- `time_request` 이벤트 → 부모 approval request(`kind:"screen_time"`, `requestedMinutes`). allow 시 `screen_time.bonus` 명령.

### 12.4 상태 전이·불변식 보강

- confirmed 자녀는 다른 family로 재페어링 불가(claim 409 `child_already_paired`); 같은 family 두 번째 부모는 허용.
- 무인증 `register`는 기존 공개키를 변경 불가(409 `device_key_conflict`).
- parent session ≠ admin scope.
- Windows(키 기반) 자녀도 confirmed 전 정책 미전달.

### 12.5 검증 경계

`npm run test:v2`(strict 인증)로 12.1~12.4를 서버 레벨 검증. 물리 Android/Windows 기기의 접근성/워크스테이션 잠금 실제 동작은 미검증(§4 사용자 구현 대상).
