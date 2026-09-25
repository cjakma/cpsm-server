# cpsm-server API 명세

> 기준: `src/index.js`, `src/auth.js`, `src/store.js` (git 저장소 아님 · package `cpsm-server`) · 갱신 2026-09-25
> 저장 스키마: [../SCHEMA.md](../SCHEMA.md) · 배포: [../DEPLOYMENT.md](../DEPLOYMENT.md)

CPSM(자녀 PC·모바일 보호) 중앙 서버. 자녀 기기(`cpsm-c` Windows, `cpsm-m` Android)는 정책을 동기화하고
이벤트를 올리며, 부모앱(`cpsm-p`)은 최초 실행 시 Android Keystore 기기로 자동 등록되고, QR 양방향 pairing·이름 preview·스캔 기기의 단일 확인 이후 규칙 작성·허락/종료 결정을 한다.

## 1. 공통

| 항목 | 값 |
|---|---|
| 리스너 | `172.18.0.1:18732` (`PORT`, `CPSM_SERVER_HOST`; 코드 기본 `127.0.0.1`) |
| 공개 URL | `https://pm-oci.duckdns.org/cpsm-api` (blacklist-guard → `172.18.0.1:18732`) |
| 인증 모드 | `CPSM_AUTH_MODE` — 운영 `strict`, `disabled` 는 로컬 개발 전용 |
| 응답 | JSON, 오류 `{"ok":false,"error":"<code>"}` |

### 인증 3종

| 대상 | 방식 |
|---|---|
| 🛡 관리자 | `Authorization: Bearer $CPSM_ADMIN_TOKEN` |
| 👪 부모 | `Authorization: Bearer <부모 세션 토큰>` (`/api/parent/auth/enroll` 로 발급) 또는 `CPSM_PARENT_TOKEN`/관리자 토큰. `/api/parent/*` 전체에 적용 |
| 📱 자녀 기기 | 경로의 `{deviceId}` 와 `X-CPSM-Device-Id` 일치 + 아래 서명 중 하나 |

#### 기기 서명 A — HMAC (공유 비밀)
```
X-CPSM-Device-Id: win-home-01
X-CPSM-Timestamp: 1790260000000            (ms, 허용 오차 CPSM_DEVICE_AUTH_MAX_AGE_MS)
X-CPSM-Nonce:     n-2f9c1a7e              ([A-Za-z0-9._:-]{8,128}, 재사용 시 409)
X-CPSM-Signature: hex(HMAC-SHA256(secret, METHOD \n path \n timestamp \n nonce \n sha256hex(body)))
```
#### 기기 서명 B — 공개키
```
X-CPSM-Device-Public-Key: <등록된 공개키 PEM/base64>
X-CPSM-Device-Signature:  base64(sign_sha256(privateKey, METHOD \n path \n timestamp \n nonce \n base64(body)))
(+ X-CPSM-Timestamp, X-CPSM-Nonce)
```
인증 오류 코드: `device_id_mismatch` · `invalid_device_auth` · `stale_device_request` · `invalid_device_signature` ·
`device_key_not_enrolled`(403) · `device_public_key_mismatch` · `replayed_device_request`(409) · `invalid_bearer_token`(401) · `auth_not_configured`(503)

### 정책 action
| 값 | 동작 |
|---|---|
| `monitor` | 실행 허용 + 이벤트 업로드 + 부모 알림 |
| `block` | 즉시 차단 + 이벤트 + 알림 (규칙 기본값) |
| `require_approval` | 부모 허락/종료 결정 요청 |
| `allow` | 명시 허용 |

## 2. 엔드포인트 요약

| Method | Path | 권한 | 설명 |
|---|---|---|---|
| GET | `/api/status` | - | 상태 |
| GET | `/api/updates/manifest`, `/api/updates/download` | - | 앱 업데이트 |
| GET | `/api/updates/android/{cpsm-m\|cpsm-p}/{manifest.json\|latest.apk}` | - | 안정판 Android 배포 |
| POST | `/api/devices/register` | - | 자녀 기기 등록 요청 |
| GET | `/api/devices/{id}/registration-status` | 📱 | 등록/동의 상태 |
| POST | `/api/devices/{id}/heartbeat` | 📱 | 생존 신호 |
| POST | `/api/devices/{id}/sync` | 📱 | 정책·명령 동기화 |
| GET | `/api/devices/{id}/policy` | 📱 | 정책 본문 |
| POST | `/api/devices/{id}/events` | 📱 | 이벤트 업로드 |
| POST | `/api/devices/{id}/errors` | 📱 | 클라이언트 오류 보고 (202) |
| POST | `/api/devices/{id}/notification-key` | 📱 | FCM 토큰 등록 |
| POST | `/api/devices/{id}/consent-requests/{rid}/decision` | 📱 | 자녀 측 동의 |
| GET | `/api/devices/{id}/commands/poll` | 📱 | 명령 큐 |
| POST | `/api/devices/{id}/commands/{cid}/result` | 📱 | 명령 결과 |
| GET | `/api/devices/{id}/updates/manifest\|download?product=` | 📱 | 기기별 업데이트 |
| POST | `/api/parent/auth/auto-enroll` | - | Android Keystore 기반 자동 부모 기기 등록 → 세션 |
| POST | `/api/parent/auth/enroll` | 레거시/관리자 | 통제된 복구용 bootstrap enrollment → 세션 |
| POST | `/api/parent/devices/fcm-token` | 👪 | 부모 FCM 토큰 |
| GET | `/api/parent/families`, `/api/parent/children/available` | 👪 | 가족·연결 가능 자녀 |
| POST | `/api/parent/pairing-sessions` | 👪 | 부모 QR 발급 |
| GET | `/api/parent/pairing-sessions/{id}` | 👪 | 부모 QR 세션 상태 조회 |
| POST | `/api/parent/pairing-sessions/{id}/claim` | 👪 | 자녀 QR claim + 이름 preview |
| POST | `/api/parent/pairing-sessions/{id}/confirm` | 👪 | 확인창 동의/취소 및 관계 확정 |
| POST | `/api/devices/{id}/pairing-sessions` | 📱 | 자녀 QR 발급 |
| POST | `/api/devices/{id}/pairing-sessions/{sessionId}/claim` | 📱 | 부모 QR claim + 이름 preview |
| POST | `/api/devices/{id}/pairing-sessions/{sessionId}/confirm` | 📱 | 확인창 동의/취소 및 관계 확정 |
| GET/POST | `/api/parent/mappings` | 👪 | 부모-자녀 연결 |
| POST | `/api/parent/mappings/{id}/consent` | 👪 | 연결 동의 |
| GET | `/api/parent/consent-requests` | 👪 | 동의 요청 목록 |
| GET | `/api/parent/devices/{id}/health\|timeline` | 👪 | 기기 상태·타임라인 |
| GET | `/api/parent/dashboard` | 👪 | 대시보드 |
| GET | `/api/parent/approval-requests[/{id}]` | 👪 | 허락 요청 |
| POST | `/api/parent/approval-requests/{id}/decision` | 👪 | 허락/종료 결정 |
| POST | `/api/parent/approval-requests/{id}/allow\|terminate` | 👪 | 위의 단축형 |
| GET | `/api/parent/policies/current` | 👪 | 현재 정책 |
| POST / PUT | `/api/parent/policies` / `/api/parent/policies/current` | 👪 | 정책 저장 (버전 증가) |
| GET/POST | `/api/parent/blocked-apps` | 👪 | 규칙 목록 / 규칙 추가 (이름은 호환용, 내용은 전체 규칙) |
| GET | `/api/parent/updates/manifest\|download?product=cpsm-p` | 👪 | 부모앱 업데이트 |
| POST | `/api/admin/portal-device/token` | 🛡 | 관리자 FCM 토큰 |
| POST | `/api/admin/devices/{id}/secret` | 🛡 | 기기 비밀/공개키 발급 |
| GET/POST | `/api/admin/app-versions` | 🛡 | 앱 버전 목록 / 등록 |
| GET/POST | `/api/admin/app-versions/{product}/{platform}/{versionCode}/changes` | 🛡 | 변경 사항 |
| PATCH | `/api/admin/app-versions/{product}/{platform}/{versionCode}/changes/{changeId}` | 🛡 | 변경 검증 표시 |
| GET | `/api/admin/errors?product=&status=&limit=&cursor=` | 🛡 | 클라이언트 오류 목록 |
| GET/PATCH | `/api/admin/errors/{id}` | 🛡 | 오류 상세/상태 변경 |

### QR pairing 상태 통지 경계

QR 관계 확정의 authoritative 순서는 다음과 같다.

```text
claim
→ preview 반환
→ 스캔한 기기의 단일 confirm
→ server mapping/session = confirmed
→ 선택적 FCM wake-up
→ Parent가 인증된 GET /api/parent/pairing-sessions/{id}
→ confirmed일 때 QR 종료
```

FCM은 관계 확정의 증거가 아니다. 활성화할 경우 payload에는 `type`, `pairing_session_id`, `status` 정도만 포함하고, Parent는 메시지를 받은 뒤 상태 API를 재조회한다. 운영 FCM은 현재 disabled다.

현재 Parent version 19는 위 상태 API를 1.5초 polling한다. 이는 임시 compatibility path이며, 장시간 QR 표시 때 request가 누적될 수 있다. 최종 설계는 FCM wake-up + 인증 GET 1회이며, FCM이 비활성화·유실된 경우 30~45초 Long Polling을 제한적으로 재연결한다. Long Polling endpoint와 pairing-specific FCM handler는 현재 미구현이다.

## 3. 상태

```bash
curl -s https://pm-oci.duckdns.org/cpsm-api/api/status
```
```json
{"ok":true,"service":"cpsm-server","storage":"sqlite","devices":3,"pendingCommands":0,"policyVersion":1,"fcmEnabled":false,"authMode":"strict"}
```

## 4. 자녀 기기

### 등록
```bash
curl -s -X POST https://pm-oci.duckdns.org/cpsm-api/api/devices/register -H 'Content-Type: application/json' -d '{
  "device_id":"win-home-01","device_name":"거실 PC","child_name":"민준","platform":"windows",
  "auth_mode":"public_key","public_key":"MCowBQYDK2VwAyEA…","metadata":{"os":"Windows 11 23H2","agent":"cpsm-c 0.4.2"}}'
# 201 → 부모 동의 후 활성
```

### 동기화 (주기 호출)
```bash
BODY='{"platform":"windows","local_policy_version":1,"last_event_seq":2081,"status":{"status":"running","current_app":"chrome.exe"}}'
TS=$(date +%s%3N); NONCE=n-$(openssl rand -hex 6)
SIG=$(printf 'POST\n/api/devices/win-home-01/sync\n%s\n%s\n%s' "$TS" "$NONCE" "$(printf %s "$BODY" | sha256sum | cut -d' ' -f1)" \
      | openssl dgst -sha256 -hmac "$CPSM_DEVICE_SECRET" -hex | awk '{print $2}')
curl -s -X POST https://pm-oci.duckdns.org/cpsm-api/api/devices/win-home-01/sync \
  -H 'Content-Type: application/json' -H 'X-CPSM-Device-Id: win-home-01' \
  -H "X-CPSM-Timestamp: $TS" -H "X-CPSM-Nonce: $NONCE" -H "X-CPSM-Signature: $SIG" -d "$BODY"
```
```json
{ "ok": true,
  "policy": { "changed": true, "version": 2, "hash": "sha256…", "download_url": "/api/devices/win-home-01/policy?version=2" },
  "commands": [], "next_sync_after_ms": 38124 }
```
`next_sync_after_ms` 에는 jitter 가 들어간다.

### 이벤트 업로드
```json
{ "events": [ { "event_id": "evt-000123", "sequence": 2082, "occurred_at": "2026-09-24T14:05:11Z",
                "payload": { "action": "require_approval", "app": "steam.exe", "pid": 4412, "rule_id": "r-steam" } } ] }
```
→ `{"ok":true,"received":1,"acknowledgedEventIds":["evt-000123"],"acknowledgedSequences":[2082]}`
`require_approval` 이벤트는 부모 허락 요청을 만들고 부모에게 FCM 을 보낸다(같은 pid 대기 요청이 있으면 생략).

### 그 외 기기 호출
```bash
# heartbeat: platform, hostname, deviceName, childName, status, current_app, health
# notification-key: {"provider":"fcm","fcm_token":"…"}
# errors: {"client_request_id":"…", …오류 정보…}  → 202
# commands/poll → {"commands":[ … 대기 중 명령 … ]}
# commands/{cid}/result: 실행 결과 본문
```

## 5. 부모앱

### 등록 (세션 발급)
```bash
curl -s -X POST https://pm-oci.duckdns.org/cpsm-api/api/parent/auth/enroll -H 'Content-Type: application/json' -d '{
  "bootstrap_code":"<CPSM_BOOTSTRAP_CODE>","family_id":"fam-home","parent_name":"엄마","platform":"android",
  "device_fingerprint":"a1b2c3…","device_pubkey":"MFkwEwYH…","metadata":{"app":"cpsm-p 0.3.0"}}'
```
```json
{"ok":true,"session":{"session_token":"ps_…","family_id":"fam-home","expires_at":"2026-10-24T14:00:00Z"}}
```
부트스트랩 코드 미설정 `503 bootstrap_not_configured`, 불일치 `401 invalid_bootstrap_code`.

### 정책
```bash
curl -s https://pm-oci.duckdns.org/cpsm-api/api/parent/policies/current -H "Authorization: Bearer $PARENT"
curl -s -X PUT https://pm-oci.duckdns.org/cpsm-api/api/parent/policies/current -H "Authorization: Bearer $PARENT" \
  -H 'Content-Type: application/json' -d '{"rules":[
    {"id":"r-steam","name":"Steam","platform":"windows","match":{"process":"steam.exe"},"action":"require_approval","reason":"평일 게임 제한"},
    {"id":"r-kakao","name":"KakaoTalk","platform":"android","match":{"package":"com.kakao.talk"},"action":"monitor"}]}'
```
규칙 필드: `id`, `name`, `platform`, `match`, `action`(기본 `block`), `reason`, `excludedUntil`.

### 허락 요청 처리
```bash
curl -s https://pm-oci.duckdns.org/cpsm-api/api/parent/approval-requests -H "Authorization: Bearer $PARENT"
curl -s -X POST https://pm-oci.duckdns.org/cpsm-api/api/parent/approval-requests/apr-001/decision -H "Authorization: Bearer $PARENT" \
  -H 'Content-Type: application/json' -d '{"decision":"allow","idempotency_key":"k-20260924-1405"}'
# decision: allow | terminate (그 외 400 invalid_decision) → 자녀 기기 명령 큐로 변환
```

### 연결 · 대시보드
```bash
curl -s -X POST https://pm-oci.duckdns.org/cpsm-api/api/parent/mappings -H "Authorization: Bearer $PARENT" \
  -H 'Content-Type: application/json' -d '{"child_device_id":"win-home-01"}'            # 201
curl -s -X POST https://pm-oci.duckdns.org/cpsm-api/api/parent/mappings/map-001/consent -H "Authorization: Bearer $PARENT" \
  -H 'Content-Type: application/json' -d '{"consent":true}'      # 또는 {"decision":"accept"}
# → {"ok":true,"mapping":{…},"policy_ready":true}   (양측 동의 시 status "confirmed")
curl -s https://pm-oci.duckdns.org/cpsm-api/api/parent/dashboard -H "Authorization: Bearer $PARENT"
curl -s https://pm-oci.duckdns.org/cpsm-api/api/parent/devices/win-home-01/timeline -H "Authorization: Bearer $PARENT"
```
부모 세션에 프로필이 없으면 `403 parent_session_profile_required`.

## 6. 관리자

```bash
curl -s -X POST https://pm-oci.duckdns.org/cpsm-api/api/admin/devices/win-home-01/secret -H "Authorization: Bearer $CPSM_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"platform":"windows","deviceName":"거실 PC","childName":"민준","publicKey":"MCowBQYDK2VwAyEA…"}'
curl -s 'https://pm-oci.duckdns.org/cpsm-api/api/admin/app-versions?product=cpsm-m&platform=android&limit=20' -H "Authorization: Bearer $CPSM_ADMIN_TOKEN"
curl -s 'https://pm-oci.duckdns.org/cpsm-api/api/admin/errors?product=cpsm-c&status=open&limit=50' -H "Authorization: Bearer $CPSM_ADMIN_TOKEN"
curl -s -X PATCH https://pm-oci.duckdns.org/cpsm-api/api/admin/app-versions/cpsm-m/android/42/changes/chg-7 -H "Authorization: Bearer $CPSM_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"verified":true,"verification_note":"기기 2대에서 확인"}'
```

## 7. 환경변수

`CPSM_AUTH_MODE`, `CPSM_ADMIN_TOKEN`, `CPSM_PARENT_TOKEN`, `CPSM_BOOTSTRAP_CODE`, `CPSM_DEVICE_SECRET`, `CPSM_DEVICE_SECRETS`(JSON),
`CPSM_DEVICE_PUBLIC_KEYS`(JSON), `CPSM_DEVICE_AUTH_MAX_AGE_MS`, `CPSM_DEVICE_NONCE_TTL_MS`, `CPSM_PARENT_SESSION_TTL_MS`,
`CPSM_MAX_BODY_BYTES`, `CPSM_SERVER_DATA_DIR`, `CPSM_ARTIFACTS_DIR`, `CPSM_SERVER_HOST`, `PORT`, `CPSM_LOCAL_DEV`

---

## v2.2 추가 엔드포인트

### 부모 — 자녀 기기 상태·명령 (parent session 필요)

| Method · Path | 설명 |
|---|---|
| `GET /api/parent/devices` | 가족의 confirmed 기기 목록. 각 항목: `device_id`, `platform`, `presence`(online≤3분 / stale≤30분 / offline), `last_seen_age_ms`, `protection`{level, reasons[], accessibility, device_owner, usage_access, boot_guard_gap_ms}, `screen_time`{used_today_minutes, daily_limit_minutes, bonus_minutes, state, remaining_minutes, top_apps[]}, `compatibility` |
| `POST /api/parent/devices/{deviceId}/commands` | body `{type, minutes?, idempotency_key?}`. type: `device.lock`(minutes 0=부모 해제 전까지, 1~1440), `device.unlock`(minutes>0=다운타임·한도 무시 자유 사용), `screen_time.bonus`(1~240분), `sync_now`. 201 `{command}` |
| `GET /api/parent/devices/{deviceId}/commands` | 최근 명령 20건과 상태(queued→delivered→succeeded/failed) |

다른 가족 기기 접근·존재하지 않는 기기는 404 `device_not_found`. 알 수 없는 명령 타입은 400.

### 정책 — screenTime (parent session 필요)

`PUT /v1/parent/policies/current` (= `POST /api/parent/policies`) body에 `screenTime` 추가:

```json
{
  "rules": [ { "id":"yt","name":"YouTube","platform":"android","action":"monitor","dailyLimitMinutes":45,
               "match":{"type":"package","packageName":"com.google.android.youtube"} } ],
  "screenTime": {
    "dailyLimitMinutes": 120,
    "downtime": [{ "days":[1,2,3,4,5], "start":"22:00", "end":"07:00" }],
    "alwaysAllowed": { "android":["com.android.dialer"], "windows":["cpsm-c.exe"] },
    "bootGuard": true,
    "message": "학습 시간입니다"
  }
}
```

- `rules`만 보내면 기존 `screenTime`은 유지된다.
- 검증 실패 코드: `invalid_downtime_time`, `invalid_downtime_days`, `invalid_daily_limit`, `invalid_always_allowed_android|windows`, `invalid_rule_daily_limit`.

### 기기 sync 정책 응답 (device signature 필요)

`POST /api/devices/{deviceId}/sync`의 서명 정책(`/policy` 다운로드)에 v2 필드가 포함된다.

```json
{
  "schemaVersion": 2,
  "appRules": [ { "id":"yt", "action":"monitor", "dailyLimitMinutes":45, "match":{...} } ],
  "screenTime": { "dailyLimitMinutes":120, "downtime":[...], "alwaysAllowed":["com.android.dialer"], "bootGuard":true },
  "canonicalHash": "...", "signature": "...", "signatureAlgorithm": "Ed25519", "keyId": "dccb0a194e4fcd9a"
}
```

`alwaysAllowed`는 해당 기기 플랫폼 목록만 포함한다. sync 요청의 `events`(로컬 큐, `seq` 포함)는 서버가 저장하고 응답 `accepted_event_seq`로 ack한다. `time_request` 이벤트는 부모 승인 요청(`kind: "screen_time"`)이 된다.

### 승인 요청 종류

`GET /api/parent/approval-requests` 항목에 `kind`(`app_launch`|`screen_time`)와 `requestedMinutes`가 추가된다. `kind=screen_time`을 allow하면 `screen_time.bonus` 명령이 생성된다.
