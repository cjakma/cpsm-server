# cpsm-m

`cpsm-m`은 자녀 Android 기기에 설치하는 CPSM Child 앱입니다.

- applicationId: `com.cpsm.child`
- Android 구현: Java native
- minSdk: 26
- targetSdk: 35
- 운영 API: `https://pm-oci.duckdns.org/cpsm-api`

## 최신 소스 다운로드

GitHub 저장소의 `main` 브랜치가 최신 소스입니다.

```bash
git clone https://github.com/cjakma/cpsm-m.git
```

ZIP으로 받으려면 다음 주소를 사용합니다.

```text
https://github.com/cjakma/cpsm-m/archive/refs/heads/main.zip
```

현재 저장소에는 다음 구현이 포함되어 있습니다.

- Android Keystore 기반 device identity/authentication
- Child 자동 등록 및 등록 상태 조회
- 양방향 QR pairing session 발급·스캔·claim
- 단기·1회용 pairing code와 role 검증
- QR claim 응답에서 부모·자녀 이름 preview를 받고, 스캔한 기기의 단일 확인창으로 관계 확정
- signed policy sync 및 local policy 검증
- Device Owner/Usage Access 기반 보호 실행 골격
- OTA manifest 조회, APK 다운로드, 크기/SHA-256/package/version/signer 검증
- OTA 오류 진단 및 durable error outbox
- 설정 화면의 `설치 APK 서명 정보 보기`에서 현재 설치 APK의 certificate SHA-256/DN 확인
- 빌드 시 내장한 expected certificate SHA-256과 실제 설치 APK signer 자체 검사
- Android runtime/API/security-patch metadata 수집
- 부팅 후 보호 서비스 복구

## QR 관계 확정과 알림 경계

자녀 앱의 QR 흐름은 다음과 같습니다.

```text
부모 QR 촬영
→ 서버 claim + 부모·자녀 이름 preview
→ 자녀 앱에서 이름 확인창 표시
→ 사용자가 동의
→ 인증된 /confirm 요청
→ 서버가 mapping을 confirmed로 원자적 전환
→ 정책 동기화 대상이 됨
```

QR을 읽은 것만으로 관계를 확정하지 않습니다. QR payload에는 private key, API key, password, 장기 token 또는 raw device secret을 넣지 않으며, 서버의 실제 `confirmed` 상태가 관계 확정의 기준입니다.

FCM은 관계 확정의 증거가 아니라 Parent 앱을 깨우는 알림 힌트로만 사용합니다. FCM이 도착하더라도 Parent 앱은 인증된 pairing-session 상태 API에서 `confirmed`를 다시 확인해야 하며, FCM이 비활성화되거나 유실된 경우를 위한 30~45초 Long Polling fallback은 설계 단계이고 아직 이 앱의 공개 APK에 구현되지 않았습니다.

## 빌드

운영 API를 지정한 debug APK 빌드:

```bash
export ANDROID_HOME=/home/ubuntu/android-sdk
export ANDROID_SDK_ROOT=/home/ubuntu/android-sdk

bash ./gradlew --no-daemon assembleDebug \
  -PcpsmApiBaseUrl=https://pm-oci.duckdns.org/cpsm-api \
  -PcpsmOtaCheckEnabled=true \
  -PcpsmExpectedSigningCertificateSha256=6c28052e2c1eb827cdddaa8931e1d2b30c260cadcd0f237113d30b6d04905d3c \
  -PcpsmVersionCode=17 \
  -PcpsmVersionName=0.1.16-qr-single-confirm \
  -Pandroid.aapt2FromMavenOverride=/home/ubuntu/android-sdk/build-tools/35.0.1/aapt2
```

APK 출력 경로:

```text
app/build/outputs/apk/debug/app-debug.apk
```

개발 서버를 사용할 때는 운영 URL 대신 `-PcpsmApiBaseUrl` 값을 별도로 지정합니다. API URL, 정책 서명 공개키 등은 build property/environment로 주입하며, private key와 서버 secret은 소스 또는 APK에 포함하지 않습니다.

Android Studio에서 실행하는 local/debug 빌드는 운영 APK와 debug signing key가 다를 수 있으므로 OTA 확인이 기본 비활성화됩니다. 운영 OTA를 테스트하는 빌드만 `-PcpsmOtaCheckEnabled=true`를 명시합니다. 서로 다른 signing key로 서명된 APK는 Android가 in-place update할 수 없습니다.

## 최신 운영 APK

```text
https://pm-oci.duckdns.org/cpsm-api/api/updates/android/cpsm-m/latest.apk
```

현재 운영 APK:

```text
versionName: 0.1.16-qr-single-confirm
versionCode: 17
SHA-256: c494f78574b069be060bb0ecf9dfe57cb6c35e1d1c95adaab65af4512263c297
signing certificate SHA-256: 6c28052e2c1eb827cdddaa8931e1d2b30c260cadcd0f237113d30b6d04905d3c
```

## 정책 동기화 lifecycle

```text
UNREGISTERED
→ CHILD_REGISTERED_UNPAIRED
→ PARENT_MAPPED_PENDING_CONSENT
→ PARENT_CHILD_CONFIRMED
→ POLICY_SYNCED
→ PROTECTED_RUNNING
```

QR claim은 서버에 이름 preview와 `pending_consent` mapping을 만들고, 스캔한 기기에서 단일 확인창을 표시합니다. 사용자가 동의하면 `/api/.../pairing-sessions/{sessionId}/confirm`이 부모·자녀 동의를 원자적으로 승인하고 관계를 `confirmed`로 전환합니다. 취소하면 mapping은 `declined`가 되며 정책은 제공되지 않습니다.

## 검증

Android 빌드 후 다음을 실행합니다.

```bash
/home/ubuntu/android-sdk/cmdline-tools/latest/bin/apkanalyzer manifest application-id app/build/outputs/apk/debug/app-debug.apk
/home/ubuntu/android-sdk/cmdline-tools/latest/bin/apkanalyzer manifest min-sdk app/build/outputs/apk/debug/app-debug.apk
/home/ubuntu/android-sdk/cmdline-tools/latest/bin/apkanalyzer manifest target-sdk app/build/outputs/apk/debug/app-debug.apk
/home/ubuntu/android-sdk/build-tools/35.0.1/apksigner verify --verbose --print-certs app/build/outputs/apk/debug/app-debug.apk
sha256sum app/build/outputs/apk/debug/app-debug.apk
```

실제 카메라 촬영, Package Installer 승인, Device Owner 설정은 연결된 Android 기기에서 별도로 검증해야 합니다.

## Device Owner 테스트

테스트 기기는 초기화 상태이거나 Device Owner를 설정할 수 있는 상태여야 합니다.

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
adb shell dpm set-device-owner com.cpsm.child/.CpsmDeviceAdminReceiver
```

이미 다른 Device Owner가 있으면 설정이 실패할 수 있습니다.

---

## v2.2 (0.2.0-screen-time, versionCode 18)

모바일펜스 방식 사용시간 관리를 추가했습니다. 전체 내용과 사용자 작업은 [CHANGES_v2.2.md](CHANGES_v2.2.md).

### 새 구성요소

- `ScreenTimeEngine`: 하루 한도(+보너스), 다운타임(자정 넘김 포함), 항상 허용 앱, 앱별 한도, 부모 잠금/해제, Usage Access 없을 때 fail-closed를 판정하는 순수 로직. `src/test`에 JUnit 7건.
- `UsageToday`: OS UsageEvents 기반 오늘 사용시간(재부팅·앱 재시작에도 누적, 런처/시스템UI 제외).
- `ControlStateStore`: 부모 잠금·해제·보너스, 명령 idempotency를 device-protected 저장소에 commit.
- `ScreenTimeController`: 서명 정책→규칙 변환, 보호/사용시간 요약, Device Owner 잠금 시 앱 suspend.
- `CommandProcessor`: `device.lock`·`device.unlock`·`screen_time.bonus`·suspend/refresh 처리 후 서버에 결과 ack.
- `ProtectionForegroundService`: 1분 주기 sync·상태 재평가, 상시 알림에 현재 상태 표시, 부팅 후 보호 시작 시점 기록.
- 메인 화면: 오늘 사용시간·상태 카드, "15/30분 더 요청" 버튼(부모 승인 요청 생성).

### 강제 실행 백엔드는 별도 구현 필요

접근성 서비스 기반 앱 전면 차단(`CpsmAccessibilityService`)은 이 소스에 포함하지 않았습니다. `ScreenTimeEnforcer` 인터페이스를 구현해 `ScreenTimeEnforcer.Registry.register(...)`로 등록하세요. 미등록 시 보호 수준은 `enforcer_not_installed`로 보고됩니다. Device Owner 기기는 백엔드 없이도 `syncDeviceOwnerLock`이 앱을 suspend합니다.

### 빌드

```bash
ANDROID_HOME=/home/ubuntu/android-sdk bash ./gradlew --no-daemon assembleDebug testDebugUnitTest \
  -PcpsmOtaCheckEnabled=true \
  -Pandroid.aapt2FromMavenOverride=/home/ubuntu/android-sdk/build-tools/35.0.1/aapt2
```
