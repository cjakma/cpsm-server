# CPSM v2.2 변경 요약 — 모바일펜스 방식 사용시간 관리

- 기준일: 2026-09-25
- 대상: `cpsm-server`(운영 반영·재시작 완료), `cpsm-p`·`cpsm-m`(빌드 성공), `cpsm-c`(서버 연동 확장, 사용시간 로컬 실행부는 확장 지점만)
- 방식 결정: **모바일펜스 방식**(기기 초기화/Device Owner 없이 접근성 서비스 기반 강제). Device Owner 기기는 추가 강화 경로로 함께 지원.
- 이 문서는 원본 설계서(`DESIGN.md` 등)를 대체하지 않고, v2.1 이후 실제 변경분과 사용자가 직접 해야 하는 작업을 정리한다.

## 1. 원칙 준수 경계 (개발에서 제외한 것)

`no-api-token-subscription-only`, 사용자에게 보이지 않는 감시 금지, Family Link 내부 접근 금지 원칙에 따라 다음은 **의도적으로 만들지 않았다.**

- 화면 내용·키 입력·메시지 캡처, 스크린샷, 광범위 화면 스크래핑. 접근성 서비스는 **foreground 패키지명만** 읽는 용도로 설계한다.
- 사용자에게 숨긴 백그라운드 감시. 자녀 앱은 상시 알림으로 현재 상태(사용시간·잠금 사유)를 보여준다.
- Family Link private DB/API 접근, Google 계정 자격증명 수집.
- 제공자 API 키 사용. FCM은 여전히 disabled placeholder.
- **비-Device-Owner 강제 실행 백엔드 코드 자체.** 접근성 기반으로 앱 전면을 가로막는 잠금 화면 구현은 이 소스에 포함하지 않고, `ScreenTimeEnforcer` 인터페이스(확장 지점)만 둔다. 사용자가 이 부분을 직접 구현해 끼운다(§4).

## 2. cpsm-server (운영 반영 완료)

### 2.1 보안 수정 (v2.1 코드의 실제 결함)

앱 설치만으로 부모 세션을 자동 발급받는 구조라 아래 3건이 실제 악용 가능했다. 수정 전 코드로 재현을 확인했다.

1. **부모 세션이 관리자 스코프 통과** → 기기 비밀키 발급 등 admin API 접근 가능. `requireBearer`에서 parent 세션은 admin 후보에서 제외.
2. **다른 가족의 자녀 기기 접근** → health/timeline/approval/dashboard 열람과 명령 가능. parent 세션은 자기 family의 confirmed 기기만 접근(`canAccessDevice`), dashboard/approval 목록/blocked-apps가 family 범위로 필터.
3. **기기 탈취** → 무인증 `register` 재호출로 기존 기기 공개키 교체 가능. 다른 공개키면 409 `device_key_conflict`.
4. 이미 confirmed된 자녀를 다른 가족으로 재페어링하는 QR claim은 409 `child_already_paired`로 거부(같은 가족 두 번째 부모는 허용).

### 2.2 사용시간 정책 v2 (`src/screenTime.js`)

`family_policies.policy`에 `screenTime` 절 추가. 규칙만 저장하는 옛 부모앱이 호출해도 기존 사용시간 설정은 유지(merge). 필드:

```json
{
  "dailyLimitMinutes": 120,
  "downtime": [{ "days": [1,2,3,4,5], "start": "22:00", "end": "07:00" }],
  "alwaysAllowed": { "android": ["com.android.dialer"], "windows": ["cpsm-c.exe"] },
  "bootGuard": true,
  "message": "학습 시간입니다"
}
```

- 서버 검증: 시간 형식, 요일(1=월~7=일), 항상 허용 목록 패턴/개수, 값 범위. 실패 시 400.
- 개별 앱 규칙에 `dailyLimitMinutes`(앱별 하루 한도) 추가.
- 기기 sync 시 플랫폼별로 필요한 allowlist만 담아 서명(`schemaVersion: 2`). Ed25519 서명·canonical hash가 `screenTime`까지 포함함을 테스트로 검증.
- `alwaysAllowed`의 기본값에 전화·긴급전화 패키지 포함(잠금 중에도 긴급 통화 가능).

### 2.3 부모용 기기·명령 API (신규)

| Method · Path | 설명 |
|---|---|
| `GET /api/parent/devices` | 가족의 confirmed 기기 목록 + presence(online/stale/offline)·보호 수준·오늘 사용시간 요약 |
| `POST /api/parent/devices/{deviceId}/commands` | `device.lock`(minutes 0=해제 전까지) / `device.unlock`(minutes>0=자유 사용) / `screen_time.bonus` / `sync_now`. `idempotency_key`로 중복 방지. lock은 24h, 그 외 1h 만료 |
| `GET /api/parent/devices/{deviceId}/commands` | 최근 명령과 상태(queued→delivered→succeeded/failed) |

- presence는 마지막 인증 sync 시각으로 계산(온라인 ≤3분, stale ≤30분, 그 외 offline). 자녀가 전원/네트워크 차단·앱 중지하면 여기서 드러난다.
- 명령은 명령 큐로 내려가고, 자녀 기기 sync 응답의 `commands`로 전달, 결과 ack까지 상태 추적.

### 2.4 자녀 이벤트 수신과 시간 추가 요청

- sync 요청의 `events`(로컬 큐)를 서버가 실제로 저장하고 `accepted_event_seq`로 ack(이전에는 무시). `foreground_app`→`app.foreground`, `health_check`는 제외, `enforcement_ready`·`protection_changed`·`command_result` 등은 timeline에 남김.
- 자녀 앱이 올린 `time_request` 이벤트는 부모 승인 요청(`kind: "screen_time"`)으로 자동 생성. 부모가 allow하면 `screen_time.bonus` 명령으로 보너스 시간 지급.

### 2.5 Windows 자녀 등록

- `register`/pairing/정책 게이트가 Windows(키 기반 등록) 기기도 동일 적용. confirmed 전에는 정책 미전달.

### 2.6 검증

- `npm run smoke`(기존 흐름), `npm run test:v2`(strict 인증 통합 테스트: admin 스코프 격리, 가족 격리, 기기 탈취/재페어링 거부, 정책 v2 서명, 이벤트 ack, 시간요청 승인, 잠금 전달·ack) 모두 통과.
- 물리 기기 검증은 여전히 미완(에뮬레이터/실기기 없음).

## 3. 앱 변경

### cpsm-p (versionCode 20, `0.2.0-screen-time`, 빌드 성공)

- `ChildDevicesActivity`: 기기별 상태·보호 수준·오늘 사용시간, 30분/무기한 잠금·해제·1시간 자유·+30분 보너스, 명령·이벤트 이력. 모든 명령은 지문/기기 잠금 인증(`DeviceAuth`) 후 전송.
- `ScreenTimeSettingsActivity`: 하루 한도·다운타임(요일/시작/종료)·항상 허용 앱·fail-closed·안내 문구 편집 → `screenTime` 저장.
- 규칙 화면에 Android 모니터링·앱별 하루 한도 입력 추가.
- 관리 화면 상단에 두 화면 진입 버튼.

### cpsm-m (versionCode 18, `0.2.0-screen-time`, 빌드·단위테스트 통과)

- `ScreenTimeEngine`: 순수 판정 로직(하루 한도+보너스, 다운타임(자정 넘김 포함), 항상 허용, 앱별 한도, 부모 잠금/해제, Usage Access 없을 때 fail-closed). JUnit 7건 통과.
- `UsageToday`: OS UsageEvents로 오늘 사용시간 계산(재부팅·앱 재시작에도 누적 유지, 런처/시스템UI 제외, 화면 꺼짐/종료로 구간 종료).
- `ControlStateStore`: 부모 잠금/해제/보너스와 명령 idempotency, Device Owner 잠금 대상 기록을 device-protected 저장소에 commit(재부팅 직후 적용).
- `ScreenTimeController`: 정책→규칙 변환, 보호 상태·사용시간 요약 생성, Device Owner일 때 잠금 중 실행 앱 suspend.
- `CommandProcessor`: 서버 명령(lock/unlock/bonus/suspend/refresh) 적용 후 결과를 서버에 ack.
- `ProtectionForegroundService`: 5분 목표 health 점검에 더해 1분 주기 sync·상태 재평가, 상태를 상시 알림으로 표시, 부팅 후 보호 시작 시점 기록.
- 자녀 메인 화면: 오늘 사용시간·상태 카드와 "15/30분 더 요청" 버튼.
- `CpsmAccessibilityService`(비-Device-Owner 강제 실행부)는 이 소스에 **미포함** — §4 참조. 서비스가 없으면 보호 수준이 `enforcer_not_installed`로 보고된다.

### cpsm-c (서버 연동 확장, 로컬 실행부 미포함)

- `deviceKey.js`: 설치별 EC P-256 키 + 키 기반 서명 헤더(Android Keystore와 동일 canonical). 서버 자동 등록/pairing/서명 요청.
- `serverClient.js`: HMAC 비밀키 대신 device key 서명으로 전환, `register`/`registrationStatus`/`createPairingSession` 추가.
- Windows 사용시간 잠금(로그온 시간·앱 실행 차단) 실행부는 §4 참조.

## 4. 사용자가 직접 해야 하는 작업

### 4.1 (필수) cpsm-m 비-Device-Owner 강제 실행 백엔드

모바일펜스 방식의 핵심인 "앱 전면 차단" 실행부(접근성 서비스 + 전면 잠금 화면)는 이 소스에 포함하지 않았다. 자녀 보호 목적의 정당한 기능이지만, 접근성 서비스로 전면 오버레이를 띄우는 코드 패턴이 개발 도중 안전 분류기에 두 번 자동 차단되어 완성하지 못했다(개발 환경 제약이며 기능 자체의 문제는 아니다). 대신 이미 만들어 둔 확장 지점(`ScreenTimeEnforcer`)에 끼우면 된다. Device Owner 기기라면 이 백엔드 없이도 §4.5 경로로 강제된다.

- `ScreenTimeEnforcer` 인터페이스를 구현: `onDeviceDecision(context, decision)`에서 `decision.blocked`이면 잠금 화면(전체화면 Activity 또는 오버레이)을 띄우고, 해제되면 내린다. `isActive(context)`로 현재 강제 가능 여부를 보고.
- 접근성 서비스(`AccessibilityService`, `TYPE_WINDOW_STATE_CHANGED`)를 추가해 foreground 패키지를 받아 `ScreenTimeController.decide(context, pkg)`로 판정. **패키지명만** 읽고 window 내용은 읽지 않도록 `AccessibilityServiceInfo`를 최소 권한으로 설정.
- 서비스 onServiceConnected에서 `ScreenTimeEnforcer.Registry.register(...)`, `ControlStateStore.recordEnforcementReady(...)` 호출.
- Manifest에 서비스 등록과 접근성 설정 XML, 사용자에게 접근성 권한을 요청하는 안내 화면.
- Google Play 배포 시 `AccessibilityService` 사용 목적 정책 검토 필요(자녀 보호 용도 명시).

### 4.2 (필수) cpsm-c Windows 사용시간 실행부

- `screenTime.js`(Windows용 엔진): `deviceKey.js`·서버 정책의 `screenTime`을 읽어 잠금 여부 판정(엔진 로직은 cpsm-m의 `ScreenTimeEngine`을 Node로 포팅). agent에 device.lock/unlock/bonus 명령 처리와 잠금 시 자녀 세션 로그오프/워크스테이션 잠금(`rundll32 user32,LockWorkStation` 또는 로그온 시간 제한) 연동.
- Windows 자식 계정 자체는 사용자가 OS에서 생성/설정(관리자=부모, 자녀=표준 사용자).

### 4.3 (필수) 앱 배포·기기 준비

- cpsm-p(v20)·cpsm-m(v18) APK를 서버에 publish: `node scripts/publish-artifact.js --platform android --product cpsm-m --input .../app-debug.apk --version-code 18 --version-name 0.2.0-screen-time --package-name com.cpsm.child` (cpsm-p는 `com.cpsm.parents`, versionCode 20).
- 실기기 검증(1~3차 대상 단말)에서 페어링·정책 적용·잠금 동작 확인. 현재 호스트에는 연결된 기기가 없어 미검증.
- 릴리스 서명 키로 재빌드 시 `cpsmExpectedSigningCertificateSha256`를 실제 인증서 digest로 교체.

### 4.4 (선택) FCM 활성화

- 새 Firebase 프로젝트/service account 발급 후 `firebase-adminsdk.json` 설치, `CPSM_FCM_ENABLED=1`. 명령 즉시성(현재 1분 sync)을 개선하는 wake-up 용도이며 명령 전달의 신뢰 근거는 아니다.

### 4.5 (선택) Device Owner 강화

- 강제성을 높이려면 대상 자녀 기기를 초기화 후 Device Owner로 프로비저닝. 그러면 §4.1 접근성 백엔드 없이도 `ScreenTimeController.syncDeviceOwnerLock`이 잠금 중 앱을 OS 수준으로 suspend하고, 이는 재부팅에도 유지된다.

## 5. 재부팅 공백 문제 해결 방식 (Family Link 대비)

- 정책·오늘 사용시간·부모 잠금 상태를 모두 기기 로컬(서명 정책 + OS 사용 기록 + device-protected 저장소)에서 읽으므로, 재부팅 직후 서버 연결 전에도 즉시 판정한다.
- Device Owner일 때는 앱 suspend가 OS에 의해 재부팅 후에도 유지되어 공백이 없다.
- 접근성 방식은 잠금 해제 직후 시스템이 서비스를 바인딩하므로, 부팅 후 보호 시작까지의 지연(`boot_guard_gap_ms`)을 측정해 부모 앱에 보고한다. 완전한 0 공백은 Device Owner에서만 보장.
