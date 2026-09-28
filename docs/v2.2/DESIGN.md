# CPSM 통합 재설계서

- 문서 버전: 2.1
- 기준일: 2026-09-25
- 작성 상태: 현재 구현·운영 검증과 QR 단일 확인 알림 설계를 분리해 기록
- 대상 저장소:
  - `cpsm-c`: Windows 자녀 PC agent
  - `cpsm-m`: Android 자녀 device agent
  - `cpsm-p`: Android 부모 app
  - `cpsm-server`: 중앙 API·정책·명령·알림 서버
- 기준 경로: `/home/ubuntu/web-service-archive/childrens_pc_security_monitoring`
- 운영 서버 경로: `/home/ubuntu/web-service/cpsm-server`
- 현재 구현과 미구현/검증 대기를 문서에서 구분한다.
- 상세 API 계약과 호출 순서: [`API_DESIGN.md`](./API_DESIGN.md)
- DB 현재 schema: `/home/ubuntu/web-service/cpsm-server/SCHEMA.md`

## 1. 목표

현재 CPSM MVP를 다음 목표를 만족하는 보호 시스템으로 재구성한다.

1. 자녀 Android 기기가 재부팅된 뒤 보호 앱이 늦게 시작되거나 동작하지 않는 구간을 최소화한다.
2. 기기 내부에서 보호 상태를 주기적으로 점검하고 부모에게 stale/offline 상태를 알린다.
3. Family Link가 부모 화면에서 제공하는 핵심 범주를 공개 Android API와 자체 이벤트로 최대한 재현한다.
4. 부모 명령과 정책이 인증·서명·재전송·중복 방지되는 구조를 만든다.
5. Windows PC와 Android 기기를 동일한 정책·이벤트·명령 모델로 관리한다.
6. 로컬 우회, 서버 무인증, 고정 device ID, FCM 의존 명령 유실, 재부팅 후 미동작 문제를 제거한다.
7. 개인정보를 과도하게 수집하지 않고, 위치 등 민감한 데이터는 별도 opt-in으로 운영한다.

## 2. Family Link 기준선과 범위

### 2.1 공식 문서에서 확인된 부모 기능

Google Family Link 공식 도움말 기준으로 부모가 확인·관리하는 범주는 다음과 같다.

- 전체 화면 시간과 기기별 화면 시간
- 앱별 사용 시간
- 일일 사용 한도
- Downtime/School time과 주간 일정
- 앱별 차단, 허용, 앱 사용 시간 제한, Unlimited time 설정
- Google Play 앱 설치·구매 승인과 앱 권한 관리
- 자녀 Android 기기 위치 및 위치 정확도 설정
- 가족 장소 도착/이탈 알림
- 자녀 기기 잠금·해제 및 보너스 시간
- 자녀 계정의 일부 Google Activity/콘텐츠/Chrome/Play 설정
- 새 앱, 웹사이트 요청, Activity settings 변경, 위치 설정 변경 등의 알림

공식 문서:

- [Get started with Family Link](https://support.google.com/families/answer/7101025?hl=en)
- [Manage your child's screen time](https://support.google.com/families/answer/7103340?hl=en)
- [Manage your child's Google Play apps](https://support.google.com/families/answer/7103028?hl=en)
- [Find & manage your child's location](https://support.google.com/families/answer/7103413?hl=en)
- [Turn Family Link notifications on or off](https://support.google.com/families/answer/7184159?hl=en)
- [Unlock your child's device](https://support.google.com/families/answer/7307262?hl=en)

### 2.2 CPSM에서 재현할 데이터

| 범주 | 수집 데이터 | 수집 방법 | 정확도/제한 |
|---|---|---|---|
| 기기 상태 | `device_id`, 모델, Android/Windows 버전, 시간대, 네트워크 상태 | 공개 OS API | Family Link 내부 값과 동일하다고 주장하지 않음 |
| 부팅 | `boot_id`, 부팅 시각, uptime, 마지막 agent 시작 시각 | `SystemClock`, OS 상태, agent 기록 | 재부팅 감지와 offline 원인 분류에 사용 |
| 보호 상태 | Device Owner, Device Admin, Usage Access, 정책 서명, 정책 버전, 서비스 실행 여부 | `DevicePolicyManager`, `AppOpsManager`, local state | 권한이 없으면 `unknown/disabled`로 표시 |
| 앱 목록 | package/process name, version, 설치·삭제 시각, allow/block 상태 | `PackageManager`, Windows inventory | 시스템 앱은 차단 대상에서 제외하거나 별도 분류 |
| 앱 사용 | foreground app/package, 시작·종료, 사용 시간, 현재 앱 | Android `UsageStatsManager`, Windows process events | Google과 동일한 계산 결과를 보장하지 않음; background 실행은 별도 표시 |
| 정책 | daily limit, per-app limit, downtime, school time, allowed apps, blocked apps, bonus time | CPSM 정책 | 서버 서명 및 로컬 last-known-good 저장 |
| 이벤트 | 앱 실행, 종료, 차단, 승인 요청, 정책 변경, 부팅, 권한 상실, clock anomaly | 각 agent | event ID와 sequence로 중복 제거 |
| 명령 | lock, unlock, block, allow temporary, terminate, policy refresh, request sync | 서버 command queue | FCM은 wake-up 용도, 실제 명령은 HTTPS pull/ack |
| 연결 | last heartbeat, last sync, last event upload, retry count, server time offset | agent heartbeat | 연결 불량과 agent 중지를 구분 |
| 배터리 | battery percent, charging state, battery saver | Android 공개 API/Windows best effort | 위치·배터리 값은 권한/OS에 따라 unavailable 가능 |
| 위치 | timestamp, lat/lng, accuracy, provider, permission state | Android location API | 부모 opt-in, 보존기간 제한, 정확한 Family Link 내부 데이터가 아님 |
| 알림 | 이벤트 유형, request ID, parent decision 상태 | FCM + 서버 DB | notification payload에는 최소 정보만 포함 |

### 2.3 수집하지 않는 데이터

다음은 Google 내부 구현 또는 계정 보안 데이터이므로 수집·복제·스크래핑 대상에서 제외한다.

- Family Link 앱 내부 DB, private API, hidden RPC, 내부 인증 토큰
- Google 계정 비밀번호, Parent Access Code, OAuth refresh token
- Google이 서버 내부에서 산출하는 원본 screen-time ledger
- Google Maps/Family Link 내부 location history 원본
- 다른 앱의 콘텐츠, 메시지 본문, 키 입력, 화면 캡처
- AccessibilityService를 이용한 광범위한 화면 감시
- 사용자가 동의하지 않은 위치 추적

CPSM은 Family Link의 내부 저장값을 읽거나 우회하지 않는다. 동일한 목적의 데이터가 필요하면 공개 Android API와 명시적 권한으로 자체 측정한다.

## 3. 핵심 설계 결정

### 3.1 보호 권한 모델

Android 자녀 기기는 강제 차단 기능을 사용하려면 Device Owner로 프로비저닝한다.

- 초기 설정: QR provisioning 또는 Android Enterprise provisioning
- 일반 앱 설치만으로는 강제 보호를 보장하지 않는다.
- Device Admin은 상태 표시·보조 기능으로만 사용한다.
- `DevicePolicyManager.setPackagesSuspended()`는 Device Owner/Profile Owner 범위에서 사용한다.
- 보호 대상 패키지를 suspend하고, 허용 목록·전화·메시지 등 필수 앱은 명시적으로 allowlist한다.
- Device Owner가 아니거나 정책 서명이 실패하면 상태를 `degraded`로 올리고 부모에게 알린다.
- Device Owner 프로비저닝은 기기 초기화/QR provisioning 등 사용자가 명시적으로 승인하는 절차가 필요할 수 있다. 기존 개인용 기기를 백그라운드에서 몰래 Device Owner로 승격한다고 가정하지 않는다.
- Device Owner가 된 뒤에는 agent 자체 uninstall 차단, 필요 시 `DISALLOW_SAFE_BOOT`, `DISALLOW_ADD_USER`, unknown-source 설치 제한 등 우회 경로를 기기/Android 버전별로 검증해 적용한다.
- 공장 초기화나 OEM 복구 등 Device Owner 바깥의 물리적 탈출 경로는 완전 차단을 보장하지 않으며, 새 enrollment 또는 unknown device를 부모에게 알리는 방식으로 처리한다.
- 사용자에게 보이지 않는 감시 방식은 사용하지 않는다. foreground service를 사용하면 시스템 알림을 표시한다.

Android 공개 문서상 `setPackagesSuspended()`는 Device Owner/Profile Owner 기반 DPC가 앱 접근을 일시 중지하는 방식이다.

### 3.2 5분 점검의 현실적인 구현

Android `WorkManager`의 periodic work 최소 주기는 15분이고 Doze 등에 의해 지연될 수 있으므로 5분 강제 점검 수단으로 사용하지 않는다.

설계:

1. Device Owner 자녀앱이 `ProtectionForegroundService`를 실행한다.
2. 서비스는 명시적인 보호 상태 notification을 표시한다.
3. 서비스 내부 watchdog가 목표 주기 5분으로 다음을 검사한다.
   - Device Owner 상태
   - Device Admin 상태
   - Usage Access 상태
   - 현재 정책의 서명·버전·만료
   - 마지막 서버 sync 시간
   - 현재 boot ID와 uptime
   - agent process/service 상태
   - 대상 앱 suspend 상태
   - 앱 배터리 최적화/백그라운드 제한 상태
4. 매 검사 결과를 local health record에 원자적으로 저장한다.
5. 실제 검사 간격이 5분을 초과하면 `health.stale` 이벤트를 만든다.
6. server heartbeat에는 `last_local_check_at`, `check_age_ms`, `protection_state`를 포함한다.
7. FGS를 시작할 수 없는 OS 상태에서는 즉시 `degraded`로 표시하고, 가능한 범위에서 boot receiver/OS callback/최소 주기 재시작 경로를 사용한다.

중요한 한계:

- 일반 Android API만으로 정확히 매 5분 실행을 절대 보장할 수 없다.
- Android 12+ background FGS 제한, Android 14+ FGS type/permission, Android 15+ boot 이후 FGS 제한을 버전별로 처리한다.
- 5분은 목표 주기이며 서버에는 실제 실행 시각과 지연을 함께 기록한다.
- 사용자의 force-stop, OEM task killer, 배터리 최적화, 전원 종료·공장 초기화까지 일반 앱이 모두 차단한다고 약속하지 않는다. Device Owner 제한과 local enforcement로 우회 범위를 줄이고, 서버의 stale/offline 알림으로 탐지한다.
- 강제 차단은 주기 검사만으로 의존하지 않고 Device Owner 정책을 local last-known-good 상태로 즉시 적용한다.

공식 참고:

- [PeriodicWorkRequest](https://developer.android.com/reference/androidx/work/PeriodicWorkRequest)
- [Restrictions on starting a foreground service from the background](https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start)
- [Launch a foreground service](https://developer.android.com/develop/background-work/services/fgs/launch)
- [DevicePolicyManager](https://developer.android.com/reference/android/app/admin/DevicePolicyManager)
- [DPC security and suspended packages](https://developer.android.com/work/dpc/security)

### 3.3 FCM의 역할

FCM은 신뢰할 수 있는 명령 전달 큐로 사용하지 않는다.

- FCM data message: `command_id`, `event_id`, `policy_version`, `wake_reason` 정도만 전송
- 자녀앱/부모앱은 FCM을 받으면 서버에 HTTPS sync 수행
- 실제 정책·명령 payload는 인증된 HTTPS response로 받음
- 명령은 `delivered`, `acknowledged`, `completed`, `failed`, `expired` 상태를 가짐
- FCM이 누락·지연·순서 변경되어도 periodic sync가 복구
- FCM token은 device/account에 귀속하여 저장하고 invalid token은 폐기

#### QR pairing 완료 알림

QR pairing에서도 FCM은 관계 확정의 증거가 아니라 Parent 앱을 깨우는 hint다.

```text
Parent QR 표시
→ Child가 QR claim
→ 스캔한 기기에서 이름 preview 확인·단일 동의
→ 서버가 mapping/session을 confirmed로 원자적 전환
→ 서버가 FCM wake-up 시도
→ Parent가 인증된 pairing-session status를 조회
→ status=confirmed일 때만 QR 종료
```

권장 최소 payload는 다음과 같다. 이름, device secret, token, 정책 본문과 같은 상세 데이터는 넣지 않는다.

```json
{
  "type": "cpsm_pairing_status",
  "pairing_session_id": "[REDACTED]",
  "status": "confirmed"
}
```

FCM 수신·전달·순서는 보장되지 않으므로 앱은 FCM만으로 QR을 닫거나 관계를 확정하지 않는다. FCM 수신 후에도 `GET /api/parent/pairing-sessions/{sessionId}`의 서버 응답이 authoritative하다.

현재 운영은 `CPSM_FCM_ENABLED=0`이다. 공개 Parent version 19는 임시로 1.5초 상태 polling을 사용해 `confirmed`, `declined`, `expired`에서 QR을 닫는다. 이 polling은 QR 표시 시간이 길어질수록 불필요한 request를 만들 수 있으므로 최종 구현에서는 제거한다.

FCM이 비활성화되거나 유실되는 경우의 fallback은 5분 단일 연결이 아니라 30~45초 단위 Long Polling 재연결이다. 서버는 terminal state가 되면 즉시 응답하고, timeout이면 client가 제한된 횟수로 재연결한다. QR TTL이 2분이므로 전체 재연결 예산도 TTL 안에서 제한한다. 이 endpoint와 Parent handler는 아직 구현·배포 전이다.

FCM 신규 키는 실제 발급 전까지 코드에 넣지 않는다. 임시 설정은 다음 placeholder만 사용한다.

```text
FIREBASE_PROJECT_ID=__CPSM_TEMP_PROJECT_ID__
GOOGLE_APPLICATION_CREDENTIALS=/etc/cpsm/secrets/firebase-adminsdk.json
CPSM_FCM_ENABLED=0
CPSM_FCM_KEY_STATUS=placeholder
```

`firebase-adminsdk.json`은 저장소에 커밋하지 않는다. 사용자가 신규 발급 키를 제공·설치 승인한 뒤 secret store에 넣고, `CPSM_FCM_ENABLED=1`로 전환한다.

### 3.4 신원·인증

정적 공통 enrollment key를 보안 경계로 사용하지 않는다.

정상 제품 흐름은 다음과 같다.

1. 부모 앱이 Android Keystore 공개키와 fingerprint를 생성한다.
2. `/api/parent/auth/auto-enroll`이 fingerprint 일치를 검증하고 Parent profile/family/session을 자동 생성한다.
3. 부모가 자녀 QR을 촬영하거나 자녀가 부모 QR을 촬영한다.
4. QR session은 2분 TTL·1회 사용이며, QR을 표시한 행위와 스캔 후 이름 확인창의 명시적 동의를 합쳐 관계를 확정한다.
5. 스캔한 기기의 확인창에서 부모·자녀 display name을 보여주고, 동의 시 서버가 `parent_consent=true`와 `child_consent=true`를 원자적으로 기록한다.
6. 취소 또는 이름 불일치 의심 시 관계를 확정하지 않고 정책도 제공하지 않는다.
7. bootstrap code는 일반 사용자 입력값이 아니며, 통제된 관리자 복구 경로에만 남긴다.

이 설계는 부모 Google 계정 비밀번호나 서버 bootstrap secret을 CPSM 앱이 수집해야 한다고 가정하지 않는다. 자동 enrollment 자체는 빈 family/profile만 만들 뿐이며, QR claim preview와 스캔 기기의 단일 명시적 confirm이 실제 자녀 접근 경계다.

#### 자녀 Android/Windows device

- 설치 시 device key pair 생성
  - Android: Android Keystore EC P-256
  - Windows: DPAPI 보호 secret 또는 Windows certificate store
- 서버 enrollment는 부모가 표시하는 짧은 승인 코드 또는 QR one-time token으로 수행
- 이후 모든 device API는 다음을 검증한다.
  - device ID
  - request timestamp
  - nonce
  - request body hash
  - device signature
  - replay window
  - policy/device binding
- credential은 local protection storage에만 저장
- 서버는 device revoke/rotate를 지원

#### 부모 Android app

- 부모 계정과 family membership을 서버에서 관리
- 부모 앱은 Keystore key로 device enrollment
- FCM token은 인증된 부모 device에만 등록
- 정책 변경·lock·terminate는 parent authorization과 device credential step-up을 요구
- APK에 공통 비밀키를 삽입하지 않음

#### 서버

- parent/device API와 public health API 분리
- 모든 state-changing API에 authorization
- device는 자기 device path만 접근
- parent는 자신의 family만 접근
- 관리자 API는 별도 admin scope와 네트워크 정책 적용
- rate limit, body size limit, audit log 적용

## 4. 통합 데이터 모델

### 4.1 Device

```json
{
  "id": "device_uuid",
  "family_id": "family_uuid",
  "role": "child",
  "platform": "android|windows",
  "display_name": "민준 휴대폰",
  "installation_id": "random_installation_uuid",
  "public_key_fingerprint": "sha256:...",
  "os_version": "...",
  "app_version": "...",
  "boot_id": "...",
  "booted_at": "2026-...",
  "last_seen_at": "2026-...",
  "last_sync_at": "2026-...",
  "last_local_check_at": "2026-...",
  "protection_state": "protected|degraded|stale|revoked|unknown",
  "capabilities": {
    "device_owner": true,
    "usage_access": true,
    "location": false,
    "package_suspend": true
  }
}
```

`device_id`는 Android의 현재 고정 문자열 `local-android-device`를 제거하고 설치별로 생성한다.

### 4.2 Policy

```json
{
  "policy_id": "family-policy",
  "version": 42,
  "issued_at": "2026-...",
  "expires_at": "2026-...",
  "timezone": "Asia/Seoul",
  "daily_limit_minutes": 120,
  "schedule": {
    "downtime": [{"days":[1,2,3,4,5],"start":"22:00","end":"07:00"}],
    "school_time": []
  },
  "allowed_apps": ["com.android.dialer"],
  "app_rules": [
    {
      "id": "rule-1",
      "platform": "android",
      "package_name": "com.example.game",
      "action": "block",
      "daily_limit_minutes": 30
    }
  ],
  "bonus_time_minutes": 0,
  "signature": "base64(...)"
}
```

- 서버 서명 대상은 canonical JSON이다.
- client는 signature, policy ID, version, expiry, family/device binding을 검사한다.
- 낮은 version은 자동 적용하지 않는다.
- 정책 다운로드 실패 시 last-known-good 정책을 유지한다.
- 너무 오래된 정책은 `stale`로 표시하되, 안전한 local block rule은 유지한다.

### 4.3 Event

```json
{
  "event_id": "uuid",
  "device_id": "device_uuid",
  "sequence": 1042,
  "type": "boot|health_check|app_foreground|app_background|app_blocked|policy_applied|permission_lost|location_update|command_result",
  "event_time": "2026-...",
  "observed_at": "2026-...",
  "payload": {},
  "schema_version": 1
}
```

서버는 `device_id + event_id` 및 sequence로 중복 제거한다. agent는 업로드 ACK가 확인될 때까지 queue를 유지한다.

### 4.4 Command

```json
{
  "command_id": "uuid",
  "family_id": "family_uuid",
  "device_id": "device_uuid",
  "type": "policy.refresh|device.lock|device.unlock|app.block|app.allow_temporary|app.terminate|sync_now",
  "payload": {},
  "status": "queued|delivered|acknowledged|completed|failed|expired",
  "created_at": "2026-...",
  "expires_at": "2026-...",
  "attempt": 0,
  "idempotency_key": "..."
}
```

명령은 여러 번 전달되어도 같은 `idempotency_key`로 한 번만 효과가 발생해야 한다.

## 5. 저장소 및 서버 설계: `cpsm-server`

### 5.1 저장소

현재 `state.json` 단일 파일을 운영 저장소로 사용하지 않는다.

1차 구현은 SQLite로 시작한다.

- `families`
- `parent_accounts`
- `parent_devices`
- `child_devices`
- `device_credentials`
- `policies`
- `policy_assignments`
- `events`
- `commands`
- `approval_requests`
- `fcm_tokens`
- `audit_logs`
- `location_samples` 또는 별도 opt-in table

운영 규모가 커지면 PostgreSQL로 migration한다. JSON export/import 명령은 장애 복구용으로 둔다.

### 5.2 API 그룹

실제 구현 route와 호출 parameter의 authoritative 목록은 [`API_DESIGN.md`](./API_DESIGN.md)다. 이 절은 그룹 요약만 유지한다.

#### Public/bootstrap/update API

- `GET /api/status`
- `POST /api/parent/auth/enroll`
- `GET /api/updates/manifest?platform=...&product=...`
- `GET /api/updates/download?platform=...&product=...`
- `GET /api/updates/android/{cpsm-m|cpsm-p}/manifest.json`
- `GET /api/updates/android/{cpsm-m|cpsm-p}/latest.apk`

#### Device API: `cpsm-m`, `cpsm-c`

- `POST /api/devices/register`
- `GET /api/devices/{deviceId}/registration-status`
- `POST /api/devices/{deviceId}/consent-requests/{requestId}/decision`
- `POST /api/devices/{deviceId}/notification-key`
- `POST /api/devices/{deviceId}/heartbeat`
- `POST /api/devices/{deviceId}/events`
- `POST /api/devices/{deviceId}/sync`
- `GET /api/devices/{deviceId}/policy`
- `GET /api/devices/{deviceId}/updates/manifest?product=...`
- `GET /api/devices/{deviceId}/updates/download?product=...`
- `GET /api/devices/{deviceId}/commands/poll`
- `POST /api/devices/{deviceId}/commands/{commandId}/result`
- 설계/구현 예정: `POST /api/devices/{deviceId}/errors`

#### Parent API: `cpsm-p`

Parent client 기본 prefix `/v1/parent`는 server에서 `/api/parent`로 normalize한다.

- `GET /v1/parent/dashboard`
- `GET /v1/parent/families`
- `GET /v1/parent/children/available`
- `POST /v1/parent/mappings`
- `GET /v1/parent/mappings`
- `POST /v1/parent/mappings/{mappingId}/consent`
- `GET /v1/parent/consent-requests`
- `GET /v1/parent/devices/{deviceId}/health`
- `GET /v1/parent/devices/{deviceId}/timeline`
- `GET /v1/parent/approval-requests`
- `GET /v1/parent/approval-requests/{requestId}`
- `POST /v1/parent/approval-requests/{requestId}/decision`
- `GET /v1/parent/policies/current`
- `PUT /v1/parent/policies/current`
- `POST /v1/parent/devices/fcm-token` (production disabled)
- compatibility: `/api/parent/blocked-apps`, `/api/parent/approval-requests/{id}/allow|terminate`

#### Admin API

- `POST /api/admin/portal-device/token`
- `POST /api/admin/devices/{deviceId}/secret`
- 설계/구현 예정: error review와 App Version change API

모든 protected route는 device proof, parent session, 또는 admin scope를 요구한다. 상세 method/body/response/오류는 `API_DESIGN.md`에서 관리한다.

### 5.3 정책 서명

- 서버 signing key는 환경변수나 파일에 평문으로 저장하지 않고 secret store 사용
- 개발 단계는 테스트 signing key와 명시적인 `CPSM_POLICY_SIGNING_MODE=test`
- Android/Windows agent에는 서버 public key만 포함
- key rotation은 `key_id`와 유효기간으로 처리
- signature 실패·만료·rollback은 정책 적용 금지 및 security event 발생

### 5.4 FCM

`cpsm-server/src/fcm.js`를 다음 방식으로 변경한다.

- FCM disabled/placeholder 모드에서 실제 호출 금지
- service account JSON 경로를 cwd 상대경로에 의존하지 않음
- startup 시 credential schema와 파일 permission 검사
- OAuth/FCM 요청 timeout 적용
- invalid/unregistered token 자동 비활성화
- 한 token 실패가 전체 event request를 실패시키지 않도록 비동기 outbox 사용
- FCM payload에는 최소 식별자만 포함
- 모든 중요한 명령은 FCM 성공을 명령 완료로 간주하지 않음

## 6. Windows 설계: `cpsm-c`

### 6.1 Windows service

현재 Node 프로세스를 `New-Service`에 직접 등록하는 방식은 제거한다.

선택안:

- 권장: WinSW wrapper를 포함한 Windows service
- 대안: NSSM 설치 전제
- 장기안: native service host가 Node agent를 child process로 감시

필수 조건:

- Automatic start
- service recovery: 1분 내 3회 재시작, 이후 backoff
- graceful stop과 queue flush
- working directory 명시
- ProgramData ACL 설정
- service account를 최소 권한으로 분리
- LocalSystem 권한을 기본값으로 사용하지 않음
- 설치/삭제/업그레이드 rollback

### 6.2 프로세스 감시

현재 단순 이름/PID 종료를 다음으로 교체한다.

1. process start event 수집
2. PID, process creation time, executable path를 함께 저장
3. 대상 path가 정책과 일치하는지 검증
4. Authenticode publisher/signature 또는 SHA-256 allow/block 기준 지원
5. 종료 전 PID 재조회와 creation time 비교
6. 정책 범위 밖 프로세스는 종료하지 않음
7. 동일 이름 전체 종료 fallback 제거
8. `block`은 정책 적용 후 즉시 enforcement하고 결과를 기록
9. agent 자체, Windows shell, 통신·긴급전화 관련 필수 프로세스는 protected list
10. 실행 시점 race는 OS event subscription 또는 짧은 주기 polling으로 최소화

### 6.3 로컬 API

현재 TCP localhost HTTP 관리 API는 다음 중 하나로 변경한다.

- 권장: Windows named pipe + ACL
- 대안: loopback TCP + 설치별 random bearer token + HMAC request

API 분리:

- read-only status: 상태 조회만 허용
- policy mutation: 부모 서명 명령 또는 관리자 설치 토큰 필요
- temporary allow: server-issued one-time command만 허용
- raw policy export: production에서 비활성화 또는 redaction

자녀 사용자 프로세스가 정책 변경 endpoint를 호출할 수 없어야 한다.

### 6.4 이벤트 queue

- NDJSON 대신 SQLite 또는 append-only journal + atomic checkpoint
- `event_id`와 sequence를 stable하게 유지
- flush single-flight lock
- server ACK가 확인된 sequence까지만 삭제
- crash recovery와 partial line 복구
- queue 상한과 disk pressure 상태 알림

## 7. Android 자녀 설계: `cpsm-m`

### 7.1 구성요소

추가할 구성요소:

- `CpsmApplication`
- `ProtectionForegroundService`
- `BootCompletedReceiver`
- `PackageChangeReceiver`
- `PolicySyncWorker` (15분 이상 보조 sync)
- `UsageStatsCollector`
- `DeviceHealthCollector`
- `DeviceEnrollmentClient`
- `SignedPolicyStore`
- `CommandProcessor`
- `EventQueue`
- `LocationCollector` (opt-in)

### 7.2 부팅 처리

Manifest에 다음 이벤트와 조건을 추가한다.

- `android.permission.RECEIVE_BOOT_COMPLETED`
- `ACTION_BOOT_COMPLETED`
- `ACTION_LOCKED_BOOT_COMPLETED`
- `ACTION_MY_PACKAGE_REPLACED`
- `PACKAGE_ADDED`
- `PACKAGE_REMOVED`
- `PACKAGE_REPLACED`

`LOCKED_BOOT_COMPLETED` 경로는 receiver/service를 `directBootAware`로 선언하고 device-protected storage에서만 동작시킨다. `PACKAGE_*` receiver에는 package data scheme을 명시하고, 불필요한 exported 상태는 금지한다. 일반 사용자 broadcast를 신뢰하지 않고 부팅 후 실제 device/policy 상태를 다시 조회한다.

부팅 순서:

```text
BOOT_COMPLETED
  → boot_id 저장
  → signed last-known-good policy 로드
  → device owner 상태 확인
  → ProtectionForegroundService 시작
  → local policy apply
  → server sync 시도
  → health_check/boot 이벤트 전송
```

### 7.3 정책 적용

- `LocalPolicyStore`는 JSON 저장만 하지 않고 canonical hash와 signature를 검증
- last-known-good 정책과 pending 정책을 분리
- pending 정책은 검증 성공 후 atomic rename/commit
- `block`: Device Owner `setPackagesSuspended`
- `monitor`: foreground usage/event 기록
- `require_approval`: 앱 접근을 제한하고 parent command 대기
- `allow_temporary`: 서버 command의 만료시각과 대상 package를 검증
- 로컬 clock을 뒤로 돌리는 경우 time anomaly 이벤트 생성
- 정책 만료 후 안전한 기본 block/allowlist 정책 적용

### 7.4 UsageStats 기반 앱 사용량

Android 공개 `UsageStatsManager`와 `PACKAGE_USAGE_STATS`를 사용한다.

- `ACTIVITY_RESUMED`/`ACTIVITY_PAUSED` 또는 usage interval을 기반으로 foreground 구간 계산
- 같은 앱의 겹치는 구간 병합
- 화면이 켜져 있고 앱이 foreground인지 별도 기록
- background service 실행 시간은 foreground screen time과 분리
- Android API/제조사별 누락을 `estimated`로 표시
- 앱별 일일 누적은 timezone과 정책 day boundary를 사용
- local aggregation 결과만 서버에 전송하고 raw event 보존기간을 짧게 둔다

Google 공식 설명도 앱 activity 시간은 앱이 열려 화면에 표시된 시간 기준이며 background 실행은 동일하게 계산하지 않는다고 설명한다. CPSM은 이 범위를 동일한 성격의 측정값으로만 표시한다.

### 7.5 5분 health check

각 check에서 아래를 기록한다.

```json
{
  "check_id": "uuid",
  "checked_at": "2026-...",
  "boot_id": "...",
  "device_owner": true,
  "device_admin": true,
  "usage_access": true,
  "notification_permission": true,
  "policy_signature_valid": true,
  "policy_version": 42,
  "policy_age_ms": 12345,
  "service_process_alive": true,
  "suspended_packages_valid": true,
  "network_available": true,
  "battery_optimization_exempt": false,
  "clock_anomaly": false
}
```

부모 화면에는 `last_check_at`, `check_age`, `protection_state`, `degraded_reason`을 표시한다.

### 7.6 Android 권한과 개인정보

필요한 권한만 요청한다.

- `INTERNET`
- `ACCESS_NETWORK_STATE`
- `RECEIVE_BOOT_COMPLETED`
- `PACKAGE_USAGE_STATS`는 settings grant 필요
- `POST_NOTIFICATIONS`
- 위치 기능을 켠 경우에만 적절한 location permission
- foreground service type과 Android 버전별 권한

AccessibilityService는 기본 설계에서 사용하지 않는다. Device Owner로 충족되지 않는 기능이 있을 때 별도 제품·Play 정책 검토 후 분리한다.

## 8. 부모 앱 설계: `cpsm-p`

### 8.1 정리

- `org.pmoci.kskillauth` namespace와 OTP 클래스/문구를 CPSM domain으로 변경
- `PortalApi`를 `CpsmApiClient`로 교체
- 기존 OTP enrollment와 CPSM parent enrollment를 분리
- 서버 URL은 production allowlist와 HTTPS를 강제
- arbitrary URL 입력은 개발 빌드에서만 허용

### 8.2 대시보드

표시 항목:

- child/device 목록
- online/offline/stale/degraded
- 마지막 boot
- 마지막 local health check
- Device Owner/Usage Access/policy signature 상태
- 오늘 screen time와 앱별 사용량
- 정책 버전과 만료
- 승인 대기
- 최근 block/allow/terminate 이벤트
- 위치 opt-in 시 마지막 위치·정확도·시각

대시보드 API는 앱 시작 즉시 호출하지 않고, parent device authentication과 session validation 이후 호출한다.

### 8.3 승인 흐름

1. server가 approval request 생성
2. 부모 FCM에 최소 payload 발송
3. 부모 앱이 서버에서 최신 request를 fetch
4. 부모 device credential step-up
5. parent scope와 request status/expiry 검증
6. allow/terminate command 생성
7. 부모 앱에는 queued 상태 표시
8. 자녀 device ack/result 수신
9. 완료 또는 실패 상태 표시

알림 payload에 executable path, raw location, 불필요한 개인정보를 직접 넣지 않는다.

### 8.4 QR pairing 상태 UI

부모 QR dialog는 다음 상태만 사용자에게 표시한다.

- `pending`: `스캔 대기 중`
- `claimed`: `QR 인식됨. 자녀 확인을 기다리는 중`
- `confirmed`: `페어링 완료` 후 dialog 종료 및 Family/Dashboard 새로고침
- `declined`: 취소 안내 후 dialog 종료
- TTL 만료: 만료 안내 후 dialog 종료

현재 version 19의 상태 조회는 임시 1.5초 polling으로 구현되어 있다. 최종 sequence는 다음으로 교체한다.

1. QR dialog가 session ID를 보유한다.
2. FCM wake-up을 받으면 해당 session ID인지 확인한다.
3. 일치하면 인증된 status GET을 1회 호출한다.
4. `confirmed`일 때만 QR을 닫고, `declined`/`expired`도 server 응답에 따라 닫는다.
5. FCM이 꺼져 있거나 일정 시간 내 도착하지 않으면 30~45초 Long Polling을 제한적으로 재연결한다.

FCM handler, Long Polling endpoint, reverse-proxy timeout과 physical-device 검증이 끝나기 전에는 이 최종 sequence를 구현 완료로 표현하지 않는다.

## 9. 보안·개인정보 기준

### 필수

- 모든 외부 API HTTPS
- parent/device별 인증과 authorization
- replay protection
- 정책 서명 검증
- command idempotency
- FCM token 폐기
- request body size limit
- rate limit
- 감사 로그
- secret 파일 git 제외 및 권한 0600
- location opt-in 및 보존기간 설정
- child/family 단위 데이터 분리
- 삭제/export 요청 처리

### 기본 보존기간 제안

- health heartbeat: 30일
- raw app foreground event: 30일
- daily aggregate: 1년
- command/audit: 1년
- location samples: 30일, opt-in family만
- FCM token: 마지막 사용 후 30일 또는 invalid 즉시 비활성화

위치 표본 보관은 사용자가 30일로 확정했다. 나머지 데이터 범주의 보존기간은 구현 전 사용자 승인 또는 별도 설정으로 확정한다.

### 하지 않을 것

- 비밀번호·Parent Access Code를 로그에 기록
- FCM private key를 저장소에 커밋
- APK의 공통 key를 인증 경계로 사용
- Family Link private API/DB 접근
- 부모 승인 없는 임시 허용
- 정책 검증 실패 시 새 정책 적용
- FCM 도착만으로 명령 완료 처리
- 자녀가 호출 가능한 무인증 localhost mutation API

## 10. 구현 순서

### Phase 0: 승인·환경

- 이 설계서 승인
- 보존기간과 위치 opt-in 결정
- Android 기기 Device Owner 운영 여부 결정
- FCM 신규 프로젝트/서비스 계정 발급
- FCM은 placeholder/disabled 상태로 개발
- 현재 Linux 서버로 가능한 범위 확인
- pm-office 또는 3060 서버는 리소스 부족이 확인될 때 별도 승인을 받은 후에만 접속

### Phase 1: 서버 보안 기반

- API versioning
- SQLite schema/migration
- parent/device auth
- signature/replay protection
- policy signing
- command state machine
- event idempotency
- request limits/rate limits
- FCM outbox와 placeholder mode

완료 기준:

- 인증 없는 모든 read/write API가 거부됨
- 다른 family/device ID 접근이 거부됨
- policy signature 실패가 적용되지 않음
- command retry가 중복 효과를 만들지 않음

### Phase 2: Android 자녀 보호

- unique device enrollment
- Device Owner provisioning guide
- boot receiver
- foreground service
- 5분 목표 health check
- signed local policy
- package suspend/allowlist
- usage aggregation
- event queue
- FCM invalidate + HTTPS sync

완료 기준:

- 재부팅 후 last-known-good block policy가 자동 적용됨
- 실제 health check 시각이 서버에 남음
- 5분 목표 초과가 stale 상태로 표시됨
- Device Owner 제거/Usage Access 상실이 부모에게 표시됨

### Phase 3: Windows agent

- service wrapper
- service recovery
- named pipe/ACL local control
- signed policy
- signer/path/PID validation
- event queue single-flight
- process block/terminate integration

### Phase 4: 부모 앱

- namespace/domain cleanup
- secure parent enrollment
- dashboard/health/timeline
- FCM minimal wake-up
- authenticated approval flow
- policy editor
- location opt-in UI

### Phase 5: 통합 검증

- Android emulator: 정책·명령·권한 상태
- Device Owner 실기기: 재부팅·잠금·앱 suspend
- Android 12/13/14/15 호환성
- Windows 10/11: service start/restart/reboot
- 네트워크 단절·서버 재시작·FCM 미수신
- duplicate/replay/out-of-order command
- unauthorized API/local IPC 보안 테스트
- 개인정보·로그 redaction 검증

## 11. 테스트와 수용 기준

### 서버

- 모든 route에 auth/authorization test
- malformed JSON/body size test
- invalid signature/expired nonce/replay test
- policy version rollback test
- command retry/duplicate completion test
- database crash/restart recovery test
- FCM disabled placeholder test

### Android

- APK build/lint/signature verification
- Device Owner provisioning
- reboot after policy install
- app killed/restarted
- FGS notification presence
- health check actual interval measurement
- Doze/battery saver/network loss
- Usage Access removed
- Device Owner removed
- system app/allowlist safety
- package suspend/unsuspend
- Android 12–15 behavior

### Windows

- service install/start/stop/recovery
- reboot persistence
- local IPC ACL
- process path/signature/PID reuse
- block and temporary allow expiry
- event queue crash recovery
- server offline queueing

### End-to-end

```text
parent policy update
  → signed server policy
  → FCM wake-up or periodic sync
  → child authenticated sync
  → local policy signature verify
  → Device Owner/app enforcement
  → health/event upload
  → parent dashboard update
```

각 단계에 correlation ID를 남기고, FCM 자체가 아닌 command ACK/result를 최종 성공 기준으로 삼는다.

## 12. 배포 및 리소스 사용 정책

현재 우선 대상은 이 서버의 `/home/ubuntu/web-service-archive/childrens_pc_security_monitoring`이다.

- 소스 검토·설계·단위 테스트는 현재 서버에서 수행
- Android SDK가 필요한 빌드만 현재 서버 환경을 먼저 확인
- pm-office 또는 3060 서버로 소스 복사, 빌드, 서비스 실행, 장기 테스트를 수행하기 전에는 사용자 승인을 받음
- SSH 터널이 열려 있다는 이유만으로 원격 서버를 사용하지 않음
- 원격 사용 승인 시 목적, 예상 CPU/RAM/disk, 예상 시간, 변경 범위를 먼저 제시
- 실제 FCM key 설치·활성화도 별도 승인 후 수행

## 13. 현재 MVP에서 제거·교체할 항목

- `cpsm-c` 무인증 localhost mutation API
- `cpsm-server` 모든 route 무인증 처리
- JSON 단일 파일 state store
- 정적 공통 `ADMIN_DEVICE_ENROLLMENT_KEY`
- Android 고정 `local-android-device`
- FCM을 명령 전달의 신뢰 근거로 사용하는 방식
- `cpsm-m` 수동 sync 버튼 중심 구조
- direct Node process Windows service 등록
- 단순 process name 기반 전체 종료 fallback
- policy hash를 저장만 하고 검증하지 않는 방식
- OTP 원본 namespace와 CPSM 기능이 섞인 parent app 구조

## 14. 승인 이후 변경 원칙

승인 후에도 다음 순서로 작은 단위로 구현한다.

1. 서버 인증·저장소·정책 서명
2. Android device identity·boot/health 기반
3. Android 정책 적용과 명령 처리
4. Windows local IPC/service/queue
5. 부모 앱 API/auth/dashboard
6. FCM 연결
7. 실제 기기 통합 테스트

각 단계마다 변경 후 테스트 결과를 확인하고 다음 단계로 진행한다. FCM 키나 원격 서버 사용처럼 외부 상태를 변경하는 작업은 별도 확인 없이 진행하지 않는다.

## 15. 현재 구현 반영 보충

기존 1.0 설계 이후 실제 구현·검증된 사항은 다음과 같다.

- SQLite가 운영 canonical store이며 `state.json`은 compatibility fallback이다.
- `families`, `parent_profiles`, `child_profiles`, `family_members`, `parent_child_mappings`, `consent_requests`, `device_notification_keys`, `family_policies`, `device_policy_assignments`, `policy_sync_receipts`가 추가되었다.
- Child는 Android Keystore public key와 runtime metadata로 자동 등록한다.
- Parent는 Android Keystore 기반 자동 enrollment 후 short-lived parent session을 사용한다.
- Parent-child 관계는 parent consent와 child consent가 모두 승인되어야 confirmed가 된다.
- confirmed 전에는 Android policy를 server가 내려주지 않는다.
- Child local policy는 canonical hash, signature, expiry, version downgrade를 검증한 뒤에만 commit한다.
- API 26~36 범위와 API 26/27 legacy signer, API 28+ SigningInfo를 구분한다.
- Child/Parent public OTA alias와 query manifest/download route가 제공된다.
- FCM은 production disabled이며 polling/manual refresh가 정상 경로다.
- Parent 자동 enrollment 화면은 Android Keystore와 `/api/parent/auth/auto-enroll`을 사용한다. bootstrap code는 일반 UI에 표시하지 않는다.
- Child 화면의 `canonical_hash_invalid`는 관계가 unpaired인 현재 server state에서 정책을 내려받을 수 없는 것과 별도로, 이전 pending candidate가 남아 표시될 수 있다. 최신 Child 수정본은 정책 delivery가 blocked일 때 stale candidate와 이전 rejection을 정리한다.

상세 path, parameter, auth, response, sequence는 `API_DESIGN.md`를 단일 부속 계약으로 사용한다.

## 16. 오류 telemetry와 App Version 변경 이력 설계

오류를 화면·로그에서 끝내지 않고 다음 계층으로 업로드한다.

```text
cpsm-m/cpsm-c local error
  → authenticated POST /api/devices/{deviceId}/errors
  → device_errors issue aggregate
  → device_error_occurrences occurrence history
  → triage/in_progress
  → app_versions new release
  → app_version_changes added/modified/fixed record
  → error_app_version_links fixed/regressed relation
  → verified resolved
```

필수 설계 원칙:

1. `device_errors.is_fixed`와 `status`를 별도 저장한다. publish만으로 수정 완료로 처리하지 않는다.
2. 실제 발생별 runtime/version/context는 `device_error_occurrences`에 남긴다.
3. 어떤 version에서 어떤 API·class·field가 추가/수정/삭제되었는지는 `app_version_changes`에 기록한다.
4. 오류와 수정 version은 `error_app_version_links`로 연결한다.
5. token, password, private key, bootstrap code, FCM credential, raw authorization header는 업로드·저장하지 않는다.
6. server migration, device error upload API, Android/Windows local queue/retry, admin review와 App Version verification workflow는 구현되었으며 server smoke로 검증한다.

상세 DDL·parameter·상태 전이는 `API_DESIGN.md` 6~8장을 따른다.

## 16-Q. QR 기반 Parent-Child 매핑 UX

Device ID를 수동 입력하지 않도록 `cpsm-m`과 `cpsm-p` 양쪽에 QR 생성·카메라 스캔을 구현했다. Child는 `자녀 매핑 QR 표시`로 `role=child` session을 만들고 Parent는 `QR로 자녀 추가`로 촬영한다. Parent는 `부모 매핑 QR 표시`로 `role=parent` session을 만들고 Child는 `부모 매핑 QR 스캔`으로 촬영한다. payload는 `cpsm://pair?version=3&role=parent|child&session_id=...&pairing_code=...`이며, server가 2분 TTL·1회 사용·issuer/claimant role을 검증한다. 서버에는 pairing code hash만 저장하고 claim 이후 session을 재사용할 수 없게 한다.

QR은 식별 보조 수단일 뿐이다. private key, API key, password, 장기 token은 포함하지 않으며, QR 스캔만으로 관계를 확정하지 않는다. 서버의 parent authentication, child authentication, parent consent, child consent 조건은 그대로 유지된다. Bluetooth는 권한·백그라운드·기기별 동작 차이가 크므로 현재 구현하지 않고, 향후 추가해도 proximity discovery 보조 수단으로만 취급한다.

이 기능의 앱 검증 상태:

- Child/Parent versionCode `11`, versionName `0.1.10-bidirectional-qr` 빌드 성공.
- 두 APK `apksigner verify` 및 기존 signer digest continuity 확인.
- public manifest/download size와 SHA-256 readback 일치.
- server check/smoke에서 Child QR→Parent claim, Parent QR→Child claim, 양방향 1회 사용 거부, 기존 mutual-consent flow 통과.
- 실제 카메라 스캔 및 양쪽 physical device consent는 `adb devices -l`에 기기가 없고 emulator/AVD도 없어 미검증.

## 17. 문서 정합성 검토 기준

이번 2.0 갱신은 다음 대화 요구사항과 실제 상태를 대조했다.

- 최신 `cpsm-m`, `cpsm-p` APK public download 및 OTA 검증.
- Galaxy Note8 API 28, Galaxy S21 API 35, LG V50 API 31, LG Q9 API 26+, Galaxy S26/S22 Ultra API 36+ 대응 방향.
- 두 Android 앱의 OS/API/security patch/model metadata 수집·표시·server compatibility 판정.
- Child의 APK signing mismatch와 Parent의 FCM-disabled startup failure 수정.
- Parent Bootstrap Code 최초 enrollment 화면의 의미와 session 저장 경계.
- Family lifecycle과 양쪽 consent 이후에만 policy를 제공하는 gate.
- FCM disabled 상태에서 server polling/manual refresh를 사용하는 fallback.
- Child 화면에서 관찰된 `registered`, `unpaired`, `policy missing`, `canonical_hash_invalid`의 분리.
- 실제 physical device 설치·Package Installer 승인·Device Owner·Usage Access 검증은 아직 완료로 표시하지 않음.

정합성 검토의 상세 결과와 남은 위험은 `DESIGN_REVIEW.md`의 2차 검토 항목에 기록한다.
