# cpsm-server

`cpsm-server`는 CPSM의 중앙 서버입니다. 현재는 단일 Node.js 프로세스와 SQLite canonical store로 인증, 관계·동의, 정책, 명령, 이벤트, 위치 이력을 처리합니다. 향후 PostgreSQL, Redis, queue, WebSocket gateway로 분리할 수 있도록 클라이언트 프로토콜을 유지합니다.

## 역할

- `cpsm-c` Windows 자녀 PC 에이전트 이벤트 수신
- `cpsm-m` Android 자녀 앱 이벤트와 상태 수신
- 부모앱 `cpsm-p`에서 작성한 정책 규칙 저장 및 버전 관리
- 자녀 기기의 `/sync` 요청에 정책 변경 여부와 명령 큐 반환
- `monitor`, `block`, `require_approval` 이벤트 처리
- 가족별 안심구역, 위치 양측 동의, 1회 위치 요청/표본/타임라인과 보수적인 geofence 전이
- 완료된 위치 표본·전이·요청·명령 및 관련 audit의 기본 30일 보관 정리
- 부모 기기로 FCM data message 발송 시도
- 부모의 허락/종료 결정을 자녀 기기 명령으로 변환

## 현재 설계

정책 원본은 서버에 있습니다. 부모앱이 규칙을 작성하면 서버는 정책 버전을 증가시키고, 자녀 기기(`cpsm-c`, `cpsm-m`)는 인증된 `/sync`를 호출해 새 버전이 있는지 확인합니다. 서버는 SQLite canonical store에 lifecycle, pairing, policy, command, event, error telemetry를 저장합니다.

현재는 HTTP polling을 사용합니다. 동접 5만 명으로 커질 때도 이 프로토콜은 유지할 수 있고, 내부 구현만 다음처럼 분리하면 됩니다. FCM은 명령·관계 확정의 authoritative transport가 아니라 wake-up/notification hint입니다.

```text
현재 MVP:
cpsm-c/cpsm-m -> cpsm-server(Node) -> SQLite + optional FCM wake-up

확장 목표:
cpsm-c/cpsm-m -> API Gateway -> App Server
                           -> PostgreSQL(policy/event)
                           -> Redis(device presence, command queue)
                           -> Queue(event fanout)
                           -> FCM worker
```

## 정책 action

```text
monitor           실행 허용 + 이벤트 업로드 + 부모 알림
block             즉시 차단 + 이벤트 업로드 + 부모 알림
require_approval  부모 허락/종료 결정 요청
allow             명시 허용
```

Steam은 예시일 뿐입니다. Epic Games, KakaoTalk, Android package name 등 모든 앱은 동일한 정책 규칙 모델로 처리합니다.

## 주요 API

> 전체 엔드포인트(관리자·기기 등록·동의·업데이트 포함 약 45개), 기기 서명 규칙, 파라미터 샘플은 [docs/API.md](docs/API.md) 참고. GitHub 저장소는 `https://github.com/cjakma/cpsm-server`입니다.

```http
GET  /api/status
POST /api/admin/portal-device/token
POST /api/devices/{deviceId}/heartbeat
POST /api/devices/{deviceId}/sync
POST /api/devices/{deviceId}/events
GET  /api/devices/{deviceId}/policy
GET  /api/devices/{deviceId}/commands/poll
POST /api/devices/{deviceId}/commands/{commandId}/result

GET  /api/parent/dashboard
GET  /api/parent/approval-requests
POST /api/parent/approval-requests/{requestId}/allow
POST /api/parent/approval-requests/{requestId}/terminate
GET  /api/parent/policies/current
POST /api/parent/policies
GET  /api/parent/blocked-apps
POST /api/parent/blocked-apps
POST /api/parent/pairing-sessions
GET  /api/parent/pairing-sessions/{id}
POST /api/parent/pairing-sessions/{id}/claim
POST /api/parent/pairing-sessions/{id}/confirm
GET  /api/parent/geofences
POST /api/parent/geofences
GET  /api/parent/devices/{deviceId}/location-consent
POST /api/parent/devices/{deviceId}/location-consent
POST /api/parent/devices/{deviceId}/location-requests
GET  /api/parent/devices/{deviceId}/location-timeline
```

`/api/parent/blocked-apps`는 기존 부모앱 UI 호환을 위해 이름을 유지합니다. 현재 응답 내용은 차단 목록만이 아니라 `monitor`, `block`, `require_approval` 전체 정책 규칙입니다. QR pairing의 관계 확정은 claim preview와 스캔한 기기의 단일 confirm 뒤에만 허용됩니다.

## QR pairing 상태 통지

```text
claim → 부모·자녀 이름 preview → 스캔한 기기 단일 confirm
→ mapping/session=confirmed → 선택적 FCM wake-up
→ Parent가 인증된 pairing-session status 재조회
```

FCM payload는 `type`, `pairing_session_id`, `status` 정도의 최소 정보만 사용하며, FCM 수신 자체로 QR을 닫거나 관계를 확정하지 않습니다. 현재 운영 FCM은 disabled이고 Parent version 19는 임시 1.5초 status polling을 사용합니다. 최종 설계는 FCM wake-up 후 인증 GET 1회와 30~45초 Long Polling fallback이며, 해당 endpoint와 pairing-specific handler는 아직 구현되지 않았습니다.

## Device Sync

자녀 기기는 주기적으로 아래 API를 호출합니다.

```http
POST /api/devices/{deviceId}/sync
```

요청 예시:

```json
{
  "platform": "windows",
  "local_policy_version": 1,
  "last_event_seq": 2081,
  "status": {
    "status": "running",
    "current_app": "chrome.exe"
  }
}
```

응답 예시:

```json
{
  "ok": true,
  "policy": {
    "changed": true,
    "version": 2,
    "hash": "sha256...",
    "download_url": "/api/devices/local-device/policy?version=2"
  },
  "commands": [],
  "next_sync_after_ms": 38124
}
```

`next_sync_after_ms`에는 jitter가 들어갑니다. 많은 기기가 동시에 서버로 몰리는 상황을 줄이기 위한 기본 장치입니다.

## 실행

```powershell
cd C:\env\workspace\childrens_pc_security_monitoring\cpsm-server
npm run dev
```

기본 주소:

```text
http://127.0.0.1:18732
```

## FCM 설정 및 경계

Firebase Admin SDK service account 파일은 아래 경로를 기본으로 사용합니다.

```text
cpsm-server\secrets\firebase-adminsdk.json
```

운영 credential는 저장소에 포함하지 않습니다. 문서와 GitHub에는 다음과 같은 비밀값 placeholder만 기록합니다.

```text
project_id: [REDACTED]
client_email: [REDACTED]
```

다른 경로를 쓰려면 환경 변수를 설정합니다.

```powershell
$env:GOOGLE_APPLICATION_CREDENTIALS='C:\path\firebase-service-account.json'
$env:FIREBASE_PROJECT_ID='your-firebase-project-id'
```

Android 앱의 `google-services.json`은 Firebase **클라이언트 설정**이며 server sender credential가 아닙니다. 실제 server 발송에는 Admin SDK service-account JSON과 `CPSM_FCM_ENABLED=1`이 필요합니다.

현재 운영 `/api/status`는 `fcmEnabled: false`를 반환합니다. 이번 Android OTA APK는 FCM token 등록/wake-up 코드를 포함하지만 server sender는 활성화하지 않았으므로 실제 push는 아직 전송되지 않습니다. 자녀의 주기적 서명 HTTPS sync가 명령 수신 fallback입니다. 위치 FCM payload에는 wake-up type만 싣고 위치 좌표·request ID는 넣지 않습니다.

서비스 계정 파일은 `cpsm-server/secrets/firebase-adminsdk.json` 또는 `GOOGLE_APPLICATION_CREDENTIALS`로 지정한 secret-store 경로에서 읽습니다. 서비스 계정 JSON과 private key는 저장소에 넣거나 README·채팅·APK에 기록하지 않습니다.

## 현재 공개된 Android OTA artifacts

아래 값은 공개 HTTPS manifest와 다운로드 alias를 읽어 확인했습니다. 두 클라이언트는 OTA check를 켜고 빌드했으며 package/version/size/SHA-256/signer를 APK 자체와 대조했습니다.

- CPSM-m: `com.cpsm.child`, `0.2.3-fcm-wakeup` (versionCode `21`), 4,662,950 bytes, SHA-256 `71edc6d5224a8d066320c6de2836790ca6ba22f814b12fe000ee415d8e5dc268`
  - Manifest: `https://pm-oci.duckdns.org/cpsm-api/api/updates/android/cpsm-m/manifest.json`
  - Download: `https://pm-oci.duckdns.org/cpsm-api/api/updates/android/cpsm-m/latest.apk`
- CPSM-p: `com.cpsm.parents`, `0.2.5-fcm-wakeup` (versionCode `25`), 8,510,183 bytes, SHA-256 `508049a1ea0bbf09eb94b0ae51ddd8b394586da83e6335457ebe99a2507867e1`
  - Manifest: `https://pm-oci.duckdns.org/cpsm-api/api/updates/android/cpsm-p/manifest.json`
  - Download: `https://pm-oci.duckdns.org/cpsm-api/api/updates/android/cpsm-p/latest.apk`
- Both APKs use signing certificate SHA-256 `6c28052e2c1eb827cdddaa8931e1d2b30c260cadcd0f237113d30b6d04905d3c`.
- Both were built as Gradle `debug` variants (`debuggable=true`) to match the existing OTA signing continuity. They are internal OTA artifacts, not hardened Play Store release builds; physical installer acceptance remains unverified.

The FCM data-only wake-up remains best-effort; authenticated sync is authoritative. OTA APKs are live, but the running server still lacks the newly added location routes; location consent/request/history therefore remains unavailable until a separate backend rollout. This README release entry documents client delivery, not end-to-end feature availability.

## 이벤트 흐름

1. 부모가 `cpsm-p`에서 앱 규칙을 작성합니다.
2. 서버가 정책 버전을 증가시킵니다.
3. `cpsm-c` 또는 `cpsm-m`이 `/sync`에서 새 정책 버전을 확인합니다.
4. 자녀 기기가 `/policy`를 다운로드해 로컬에 저장합니다.
5. 자녀 기기에서 정책 대상 앱이 실행되면 action에 따라 이벤트를 서버로 보냅니다.
6. FCM sender가 설정된 경우에만 server가 부모에게 최소 FCM data message를 보냅니다. 현재 운영에서는 disabled이며 authenticated API polling/sync가 fallback입니다.
7. `require_approval`이면 부모가 허락 또는 종료를 선택합니다.
8. 서버는 `app.allow.temporary` 또는 `app.terminate` 명령을 자녀 기기 큐에 넣습니다.
9. 자녀 기기가 다음 `/sync` 또는 command poll에서 명령을 받아 실행합니다.

## 검증

```powershell
npm run check
npm run smoke
```

서버/API smoke는 SQLite lifecycle, 양방향 QR claim, preview, 단일 confirm, role 검증, policy gate, error telemetry, OTA metadata를 확인합니다. 운영 status와 public artifact readback은 별도의 배포 검증입니다.

---

## v2.2 추가 (2026-09-25) — 사용시간 관리 · 부모 명령

전체 변경과 사용자 작업은 [CHANGES_v2.2.md](CHANGES_v2.2.md) 참조.

### 사용시간 정책 v2

부모앱 정책(`family_policies.policy`)에 `screenTime` 절이 추가되었습니다. 규칙만 저장하는 옛 클라이언트가 호출해도 사용시간 설정은 유지됩니다.

```json
{
  "dailyLimitMinutes": 120,
  "downtime": [{ "days": [1,2,3,4,5], "start": "22:00", "end": "07:00" }],
  "alwaysAllowed": { "android": ["com.android.dialer"], "windows": ["cpsm-c.exe"] },
  "bootGuard": true
}
```

기기 sync 응답 정책은 플랫폼별 allowlist만 담아 서명하며 `schemaVersion: 2`, 앱 규칙에는 `dailyLimitMinutes`(앱별 한도)가 포함될 수 있습니다.

### 부모 API 추가

```http
GET  /api/parent/devices
POST /api/parent/devices/{deviceId}/commands   # device.lock | device.unlock | screen_time.bonus | sync_now
GET  /api/parent/devices/{deviceId}/commands
```

`GET /api/parent/devices`는 가족의 confirmed 기기별 presence(online/stale/offline)·보호 수준·오늘 사용시간을 반환합니다. 명령은 `idempotency_key`로 중복을 막고 자녀 sync로 전달되어 ack까지 추적됩니다.

### 보안 경계 (수정됨)

- 부모 세션은 admin 스코프를 통과하지 못합니다.
- 부모 세션은 자기 가족의 confirmed 기기에만 접근합니다(dashboard·approval·health·timeline·command 모두 가족 범위).
- 무인증 `register` 재호출로 기존 기기 공개키를 바꿀 수 없습니다(409 `device_key_conflict`).
- confirmed된 자녀를 다른 가족으로 재페어링할 수 없습니다(409 `child_already_paired`).

### 검증

```bash
npm run smoke      # 기존 흐름
npm run test:v2    # strict 인증: 스코프/가족 격리, 탈취·재페어링 거부, 정책 v2 서명, 이벤트 ack, 시간요청 승인, 잠금 전달·ack
```
