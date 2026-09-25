# cpsm-p

`cpsm-p`는 부모가 사용하는 Android 모니터링, 관리, 승인 앱입니다. 기존 Android 앱 `pm-oci-otp`를 복사해 CPSM 부모앱으로 커스터마이징한 프로젝트입니다.

원본 프로젝트:

```text
C:\env\workspace_AndroidStudioProjects\pm-oci-otp
https://github.com/cjakma/oci_otp
```

## 현재 구현 상태

- 프로젝트 디렉터리명을 `cpsm-p`로 정리
- Gradle root project name: `CPSMParents`
- Android applicationId: `com.cpsm.parents`
- 앱 표시명: `CPSM Parents`
- versionName: `0.1.18-parent-qr-auto-close` / versionCode `19`
- CPSM API base URL을 BuildConfig로 주입
- Firebase Android app 설정 파일 적용
- FCM service에서 CPSM 앱 승인 요청 payload 처리
- 서버 dashboard 조회 기반 메인 상태 화면 구현
- 자녀 앱 실행 승인/종료 화면 추가
- 정책 관리 화면 추가
- 정책 규칙 조회, 추가, 1시간 제외 UI 추가
- 정책 action 선택 UI 추가
  - `monitor`
  - `require_approval`
  - `block`
- Android Material Design 3 방향의 UI 정리
- Parent QR session 상태 조회와 `confirmed`/`declined`/`expired` 자동 종료
- QR claim preview 기반 단일 이름 확인·동의 UX

아직 남아있는 정리:

- Java package namespace는 아직 `org.pmoci.kskillauth`입니다.
- 일부 기존 OTP 클래스와 enrollment 이름이 남아 있습니다.
- 추후 CPSM 도메인에 맞춰 클래스명과 flow를 정리해야 합니다.

## 일반 사용자 초기화 흐름

일반 사용자는 bootstrap code, Parent session, Device-ID를 확인하거나 입력하지 않습니다.

```text
앱 설치
→ 부모 기기 자동 준비(Android Keystore)
→ 부모가 자녀 QR 촬영 또는 자녀가 부모 QR 촬영
→ 서버 one-time pairing claim + 이름 preview
→ 스캔한 기기에서 단일 확인창
→ 확인 시 부모·자녀 관계 확정
→ 정책 동기화
→ cpsm-m / cpsm-c 모니터링·차단
```

부모 앱은 최초 실행 시 `/api/parent/auth/auto-enroll`을 호출하고, 반환된 session을 Android Keystore로 보호된 로컬 저장소에 저장합니다. bootstrap code는 일반 사용자 UI에서 제거되었고, 통제된 관리자 복구 경로에만 남아 있습니다.

자동 준비 화면과 메인 화면 하단의 `서명 정보` 버튼에서 현재 설치 APK의 package, version, signer count, certificate SHA-256 fingerprint, certificate DN을 확인할 수 있습니다. 앱 시작 시 빌드에 내장한 expected certificate SHA-256과 실제 설치 signer도 자체 비교합니다. private signing key는 앱에서 읽거나 표시하지 않습니다.

### Parent QR 자동 종료 상태

현재 공개된 version `19`는 Parent가 표시한 QR session의 상태를 인증된 `GET /api/parent/pairing-sessions/{id}`로 확인해 다음 상태에서 QR을 닫습니다.

- `confirmed`: 자녀 기기와 페어링 완료
- `declined`: 자녀 기기에서 취소
- `expired`: 2분 TTL 만료

version 19의 구현은 임시로 1.5초 간격 상태 polling을 사용합니다. QR을 오래 표시할 때 불필요한 요청을 만들 수 있으므로 최종 구조는 다음과 같이 분리합니다.

```text
FCM wake-up 수신
→ 인증된 pairing-session 상태 GET 1회
→ 서버가 confirmed일 때만 QR 종료

FCM 비활성화·유실
→ 30~45초 Long Polling 재연결
→ timeout 또는 terminal state 응답
```

FCM 수신 자체는 관계 확정의 증거가 아닙니다. FCM payload에는 최소한의 `type`, `pairing_session_id`, `status`만 사용하고, 실제 관계 상태는 서버 응답을 기준으로 합니다. FCM wake-up handler와 Long Polling endpoint는 아직 구현·배포·실기기 검증 전입니다.

## 최신 운영 APK

```text
https://pm-oci.duckdns.org/cpsm-api/api/updates/android/cpsm-p/latest.apk
```

```text
versionName: 0.1.18-parent-qr-auto-close
versionCode: 19
SHA-256: 91f1015a4df0c27b5ba843f95abc2060c888f33e2b2cdd848e363ce9a3d7153f
signing certificate SHA-256: 6c28052e2c1eb827cdddaa8931e1d2b30c260cadcd0f237113d30b6d04905d3c
```

## Firebase 설정

FCM을 별도로 활성화하는 경우에만 `app/google-services.json`을 로컬에 주입합니다. 실제 Firebase credential는 GitHub에 저장하지 않으며, 저장소에는 placeholder만 있는 `app/google-services.json.example`만 둡니다.

```text
project_id: childrens-pc-sec-monit
project_number: 497830851944
package_name: com.cpsm.parents
mobilesdk_app_id: 1:497830851944:android:fd62958440a746d1f112dd
```

현재 운영 배포의 `CPSM_FCM_ENABLED`는 `false`입니다. 비활성화 상태에서는 부모 앱이 FCM token을 조회·등록하지 않으며, QR 자동 종료는 version 19의 임시 상태 polling 경로를 사용합니다. FCM을 활성화할 때도 FCM은 wake-up/hint로만 사용하고, 인증된 pairing-session 상태 조회를 생략하지 않습니다.

## 정책 작성 흐름

부모는 `cpsm-p`에서 Steam뿐 아니라 Epic Games, KakaoTalk, Android package 등 대상 앱을 규칙으로 등록합니다.

정책 action:

```text
monitor           실행 허용 + 부모 알림
require_approval  부모에게 허락/종료 선택 요청
block             즉시 차단
```

현재 관리 화면 버튼:

```text
모니터링       windows + monitor
승인 필요      windows + require_approval
PC 차단        windows + block
Android 차단   android + block
```

정책을 저장하면 `cpsm-server`가 정책 버전을 올립니다. 이후 `cpsm-c`와 `cpsm-m`이 `/sync`로 새 버전을 확인해 로컬 정책을 갱신합니다.

## 승인/종료 흐름

1. 자녀 PC 또는 Android 기기에서 정책 대상 앱이 실행됩니다.
2. 자녀 기기가 서버로 이벤트를 업로드합니다.
3. 서버가 부모 기기로 FCM data message를 보냅니다.
4. 부모가 알림을 누르면 `ChildAppApprovalActivity`가 열립니다.
5. 부모가 `허락`을 누르면 서버가 `app.allow.temporary` 명령을 큐에 넣습니다.
6. 부모가 `종료`를 누르면 서버가 `app.terminate` 명령을 큐에 넣습니다.
7. 자녀 기기는 다음 `/sync` 또는 command poll에서 명령을 받아 실행합니다.

## 메인 대시보드

`MainActivity`는 앱 실행/복귀 시 `GET /api/parent/dashboard`를 호출해 부모가 즉시 확인해야 하는 상태를 보여줍니다.

현재 표시 항목:

```text
기기 온라인/전체 수
정책 버전
정책 규칙 수
대기 승인 요청 수
최근 이벤트 수
가장 최근 승인 요청
가장 최근 앱 이벤트
```

대기 승인 요청이 있으면 메인 화면의 `요청 열기` 버튼으로 바로 `ChildAppApprovalActivity`를 열 수 있습니다.

## 주요 클래스

```text
MainActivity                  부모앱 메인 화면
MyFirebaseMessagingService    FCM payload 수신
ChildAppApprovalActivity      자녀 앱 실행 허락/종료 화면
CpsmManagementActivity        정책 규칙 관리 화면
PortalApi                     CPSM 서버 API client
AppPrefs                      로컬 설정 저장
UiKit                         공통 UI 스타일 helper
```

## 빌드

```powershell
cd C:\env\workspace\childrens_pc_security_monitoring\cpsm-p
.\gradlew.bat assembleDebug
```

API 주소는 Gradle property 또는 환경 변수로 지정할 수 있습니다.

```powershell
.\gradlew.bat assembleDebug -PcpsmApiBaseUrl=https://your-cpsm-server.example.com
```

또는:

```powershell
$env:CPSM_API_BASE_URL='https://your-cpsm-server.example.com'
$env:CPSM_PARENT_DEVICE_ENROLLMENT_KEY='dev-parent-device-key'
.\gradlew.bat assembleDebug
```

현재 로컬 빌드는 `local.properties`의 SDK 경로를 사용합니다. `local.properties`와 실제 Firebase credential는 GitHub에 저장하지 않습니다.

```text
sdk.dir=C\:\\Users\\cjakm\\AppData\\Local\\Android\\Sdk
```

## 다음 작업

1. 부모 FCM token 실제 등록 flow 연결
2. `PortalApi`의 기존 OTP 용어 제거
3. Java namespace를 `com.cpsm.parents`로 정리
4. dashboard API와 연동한 실시간 상태 화면 강화
5. 정책 규칙 삭제, 수정, device별 적용 범위 UI 추가
6. Parent QR 1.5초 polling을 FCM wake-up + 인증된 상태 GET으로 교체
7. FCM 비활성화·유실 fallback으로 30~45초 Long Polling endpoint와 재연결 제한 구현
8. FCM/Long Polling을 포함한 Parent QR 자동 종료를 실기기에서 검증

---

## v2.2 (0.2.0-screen-time, versionCode 20)

사용시간 관리와 자녀 기기 원격 제어 화면을 추가했습니다. 전체 내용은 [CHANGES_v2.2.md](CHANGES_v2.2.md).

- `ChildDevicesActivity`: 가족 기기별 연결 상태(online/stale/offline)·보호 수준·오늘 사용시간과 30분/무기한 잠금·해제·1시간 자유 사용·+30분 보너스, 명령·이벤트 이력. 모든 명령은 지문/기기 잠금 인증 후 전송.
- `ScreenTimeSettingsActivity`: 하루 한도·다운타임(요일/시작/종료)·항상 허용 앱·fail-closed·안내 문구 편집.
- 규칙 관리: Android 모니터링, 앱별 하루 한도 입력 추가. 관리 화면 상단에 두 신규 화면 진입 버튼.
- 정책 저장은 `/v1/parent/policies/current`에 규칙+`screenTime`를 함께 PUT하며, 규칙만 저장해도 사용시간 설정은 서버에서 유지됩니다.

### 빌드

```bash
ANDROID_HOME=/home/ubuntu/android-sdk bash ./gradlew --no-daemon assembleDebug \
  -PcpsmOtaCheckEnabled=true \
  -Pandroid.aapt2FromMavenOverride=/home/ubuntu/android-sdk/build-tools/35.0.1/aapt2
```
