# cpsm-server API 명세

> 기준: `src/index.js`, `src/auth.js`, `src/store.js` (git 저장소 아님 · package `cpsm-server`) · 갱신 2026-10-14
> 현재 API 연동 규격: [API_SPEC_CURRENT.md](API_SPEC_CURRENT.md) · 현재 ERD: [ERD_CURRENT.md](ERD_CURRENT.md) · 저장 스키마: [../SCHEMA.md](../SCHEMA.md) · 배포: [../DEPLOYMENT.md](../DEPLOYMENT.md)

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
| POST/GET | `/api/devices/{id}/app-install-requests` | 📱 | Android 앱 설치 요청 생성/조회 |
| POST | `/api/devices/{id}/app-install-requests/{requestId}/cancel` | 📱 | 대기 중인 본인 요청 취소 |
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
| GET | `/api/devices/{id}/pairing-sessions/{sessionId}/wait?since=` | 📱 | 자녀 QR 상태 롱폴링(≤25초, claim/confirm 즉시 응답) — 2026-11-04 |
| POST | `/api/devices/{id}/pairing-sessions/{sessionId}/claim` | 📱 | 부모 QR claim + 이름 preview |
| POST | `/api/devices/{id}/pairing-sessions/{sessionId}/confirm` | 📱 | 확인창 동의/취소 및 관계 확정 |
| POST | `/api/parent/family-invites` | 👪 | 공동 보호자 초대 발급(1회용·10분) — 2026-11-03 |
| POST | `/api/parent/family-invites/{id}/accept` | 👪 | 초대 수락 → 그 가족에 `guardian` 으로 참가 |
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
| GET/POST | `/api/parent/blocked-apps` | 👪 | 규칙 목록 / 규칙 추가 (이름은 호환용, 내용은 전체 규칙). 규칙 저장(이것과 PUT policies/current) 시 같은 가족의 다른 부모에게 FCM `cpsm_policy_changed`, 응답 `parents_notified` |
| GET | `/api/parent/updates/manifest\|download?product=cpsm-p` | 👪 | 부모앱 업데이트 |
| POST | `/api/admin/portal-device/token` | 🛡 | 관리자 FCM 토큰 |
| POST | `/api/admin/devices/{id}/secret` | 🛡 | 기기 비밀/공개키 발급 |
| GET/POST | `/api/admin/app-versions` | 🛡 | 앱 버전 목록 / 등록 |
| GET/POST | `/api/admin/app-versions/{product}/{platform}/{versionCode}/changes` | 🛡 | 변경 사항 |
| PATCH | `/api/admin/app-versions/{product}/{platform}/{versionCode}/changes/{changeId}` | 🛡 | 변경 검증 표시 |
| GET | `/api/admin/errors?product=&status=&limit=&cursor=` | 🛡 | 클라이언트 오류 목록 |
| GET/PATCH | `/api/admin/errors/{id}` | 🛡 | 오류 상세/상태 변경 |
| GET | `/api/parent/app-install-requests?status=` | 👪 | 가족 자녀 요청 목록 (`pending` 또는 `all`) |
| POST | `/api/parent/app-install-requests/{requestId}/decision` | 👪 | 요청 승인/거절 기록 |
| POST/GET | `/api/parent/missions` | 👪 | 확인된 Android 자녀 대상 텍스트 미션 생성/가족 목록 |
| POST | `/api/parent/missions/{missionId}/cancel` | 👪 | 활성 미션 취소 |
| POST | `/api/parent/missions/{missionId}/review` | 👪 | 대기 중인 제출 승인/거절 및 보상 기록 |
| GET | `/api/devices/{deviceId}/missions?status=all|active` | 📱 | 현재 가족의 자녀 미션 목록 |
| POST | `/api/devices/{deviceId}/missions/{missionId}/submissions` | 📱 | 텍스트 제출 |

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

FCM은 관계 확정의 증거가 아니다. payload 에는 `type`·`mapping_id`·`relationship_status` 정도만 있고, 받은 쪽은 상태 API 를 다시 읽는다. **운영 FCM 은 2026-11-04 부터 켜져 있다**(`CPSM_FCM_ENABLED=1`).

- **자녀가 띄운 QR (2026-11-04 구현)**: 자녀 앱은 QR 이 떠 있는 동안 `GET /api/devices/{id}/pairing-sessions/{sid}/wait?since=<마지막 상태>` 롱폴링을 하나 유지한다(요청당 ≤25초 — guard 프록시 30초 아래, 2분 QR 당 많아야 ~5회, 실패 시 3초·6초…≤30초). FCM `cpsm_relationship_consent` 를 받으면 즉시 한 번 더 묻는다. `confirmed` 면 창을 닫고 등록 상태를 다시 받는다. 창에는 `expires_at` 기준 남은 시간을 보이고, 만료·거절되면 [새 QR 받기].
- **부모가 띄운 QR**: 부모 앱은 아직 `GET /api/parent/pairing-sessions/{id}` 를 짧은 주기로 조회한다(롱폴링 미적용 — 같은 방식으로 바꿀 대상).

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

### 가족 범위 텍스트 미션

미션은 텍스트 전용이며 이미지/사진/오디오/비디오/파일/첨부 업로드 필드를 받지 않습니다. 부모는 현재 가족의 활성 멤버여야 하고, 대상은 현재 확인된 가족 관계에 속한 Android 자녀여야 합니다. `request_id`는 필수 UUID이며, `(family_id,parent_id,request_id)`와 정규화 payload fingerprint로 생성 요청을 멱등 처리합니다. 같은 키/같은 payload 재시도는 기존 미션을 반환하고, 같은 키/다른 payload는 `409 mission_request_id_conflict`입니다. `title`은 1–80자, `instructions`는 1–1000자, `bonus_minutes`는 반드시 명시하는 정수 0–240입니다. 0은 칭찬 전용이며 기본 보너스는 없습니다.

```http
POST /api/parent/missions
{"request_id":"550e8400-e29b-41d4-a716-446655440000","device_id":"android-child-1","title":"책상 정리","instructions":"책상을 정리하고 완료 메시지를 보내 주세요.","bonus_minutes":15}
GET /api/parent/missions?status=all
POST /api/parent/missions/{missionId}/cancel
GET /api/devices/{deviceId}/missions?status=active
POST /api/devices/{deviceId}/missions/{missionId}/submissions
{"message":"책상을 정리했어요."}
POST /api/parent/missions/{missionId}/review
{"submission_id":"...","decision":"approve","note":"수고했어요"}
```

제출 메시지는 1–2000자, 검토 메모는 0–500자입니다. 부모가 `approve` 또는 `reject`를 명시해야 합니다. 거절은 미션을 다시 `active`로 만들고 제출/검토 이력을 보존합니다. 승인만 보상을 부여하며, 보상 원장과 명령은 별도 `mission_rewards` / `commands` 레코드입니다. 양수 보너스는 idempotency key `mission-reward:<submission_id>`인 기존 `screen_time.bonus` 명령 하나로 전달되고, 0분은 원장만 만들며 명령을 생성하지 않습니다. 만료된 미전달 queued 미션 보상은 다음 기기 poll에서 같은 명령 ID/key로 TTL을 갱신하며, 그 밖의 명령 만료 규칙은 변하지 않습니다. 동일 제출/결정의 승인 재시도는 동일한 결과를 돌려줍니다. 생성/취소/텍스트 제출/승인/거절 audit에는 식별자와 결정 메타데이터만 기록하며, 미션 안내·제출 본문·검토 메모는 넣지 않습니다.

상태: 미션 `active | pending_review | completed | cancelled`, 제출 `pending_review | approved | rejected`. 부모 목록은 `all | active | pending_review | completed | cancelled`, 자녀 목록은 `all | active`를 지원합니다. 관계가 해제되거나 현재 가족이 바뀌면 예전 미션 내역은 노출되지 않습니다.

### Android 앱 설치 요청

자녀 기기는 확인된 가족 연결 이후 `POST /api/devices/{deviceId}/app-install-requests`로 package name, 앱 이름, 요청 이유를 제출하고, 같은 경로의 `GET`으로 본인 요청 상태를 확인합니다. 보호자는 가족 범위의 `GET /api/parent/app-install-requests`로 조회한 뒤 `POST /api/parent/app-install-requests/{requestId}/decision`에서 `approve` 또는 `deny`를 기록합니다. 보호자 승인은 설치 명령이 아니며, 자녀가 Play Store와 Android 설치 확인을 직접 완료해야 합니다. 상세 계약은 [`docs/v2.2/APP_INSTALL_REQUESTS.md`](v2.2/APP_INSTALL_REQUESTS.md)를 참고하세요.

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
