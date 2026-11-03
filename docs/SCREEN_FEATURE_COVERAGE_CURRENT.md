# CPSM 화면 기능 커버리지 — 현재 코드/검증 증거

기준: `CPSM_UI_IMPLEMENTATION_SCOPE.md`와 현재 `cpsm-p`, `cpsm-m`, `cpsm-server` 작업 트리. 상태 표기는 소스 존재와 실행 증거를 구분한다. 원본 `CPSM_p_v0.2.zip` / `CPSM_m_v0.1.zip` 화면 시안은 archive에서 찾지 못해, 시각적 픽셀 대조가 아니라 scope 문서와 실제 native Activity/API/Manifest를 기준으로 검사했다. 이 문서는 운영 배포 검증이 아니다.

- **구현**: source에 해당 경로가 있고 자동화 테스트에서 일부를 실행.
- **부분**: 화면/API가 있으나 요구사항의 일부 하위 흐름이나 데이터 표시는 빠짐.
- **미구현**: 요구된 구현 파일/API가 확인되지 않음.
- **실기기 미검증**: 코드 경로는 있어도 Android OS·OEM·실제 서버 장치 동작을 확인하지 않음.

## Parent (`cpsm-p`)

| 화면 요구 | 상태 | 근거 및 남은 범위 |
|---|---|---|
| 홈·자녀별 상태, 최근 이벤트, 사용량 | 부분 | `MainActivity.java`는 가족 dashboard/device API로 상태 요약을 표시하지만, 최근 이벤트는 제한된 요약이고 실제 위치 표본이 있어도 홈 위치 요약은 표시하지 않는다. 상세 카드의 미보고/미확인 사용량·플랫폼 상태는 기본 0/Windows로 추정하지 않도록 보완했다. |
| 자녀 기기 목록·상세, 보호 상태·부모 명령 | 부분 | `ChildDevicesActivity.java`에 가족 기기, 보호/연결 상태, 잠금/해제/보너스/이력이 있다. 미보고 사용시간·한도는 unavailable로, 미확인 플랫폼/상태는 추정하지 않고 표시한다. 웨어러블/태그를 연결된 기기로 꾸며 표시하지 않는 것은 준수한다. 실제 명령 적용은 기기 미검증이다. |
| 사용시간·앱 제어 | 부분 | `ScreenTimeSettingsActivity.java`는 가족 정책의 사용시간을 편집한다. `CpsmManagementActivity.java`에는 가족 전체/개별 자녀 기기 선택을 추가했고, 선택된 기기만 대상으로 하는 규칙을 서버가 저장·검증·서명한다. 앱별 집행의 실기기 동작은 미검증이다. |
| 위치 동의·안심구역·이동 이력 | 부분 | `GeofenceSettingsActivity.java`에서 원형 구역 CRUD, `LocationHistoryActivity.java`에서 동의·일회 요청·timeline을 제공한다. SDK 미선택 상태의 좌표 입력/외부 지도 fallback은 scope에서 허용한다. 시간순 samples/transitions는 조회되나 합쳐진 이동 이벤트 timeline은 미흡하다. OS 권한·GPS·백그라운드 동작은 실기기 미검증이다. |
| 활동·건강(Health Connect/웨어러블) | 미구현 | Parent manifest/dependencies/API 호출에서 Health Connect read·동의·건강 샘플 UI가 확인되지 않았다. `PortalApi.getDeviceHealth()`는 선언돼 있지만 호출처가 없다. |
| 더보기·설정·알림·개인정보 상태 | 부분 | `SettingsActivity.java`에 서버/userKey/이미지 설정을 두고, 앱 알림 허용 상태 및 Android 시스템 채널 설정 shortcut을 추가했다. 가족 구성원 권한 관리와 가족별 개인정보/동의 전체 관리 화면은 아직 없다. 위치 동의는 `LocationHistoryActivity.java`에서 관리한다. |
| 가족 다중 부모 계정·초대/철회 | 미구현 / 도메인 확정 | 시스템 `admin`은 별도 운영자다. 가족은 자녀와 여러 `parent` 계정을 가지며 `guardian` 역할은 없다. 아빠/엄마/할아버지/외할머니/삼촌 등은 관계 표시명이지 별도 권한 역할이 아니다. 현재 `ensureParentProfile`은 등록 지문별로 family를 생성하고 `owner`를 부여하며 부모 초대·가족 간 합류 API/UI가 없다. 부모 간 관리 권한은 결정 대기. |
| 미션 생성·검토·보상 | 부분 | `FamilyMissionsActivity.java`와 `PortalApi.java`에서 생성/취소/검토/멱등 생성 요청이 구현됐다. 자녀 연결 전제에서 동작한다. 실제 부모 알림/실기기 보너스 적용은 별도 검증이며 Parent 테스트는 request-ID helper 중심이다. |
| 앱 설치 허가 요청 | 구현(소스/서버) | `AppInstallRequestsActivity.java`와 family-scoped 서버 API가 별도 요청/결정 흐름을 제공한다. 승인 후 Android 설치 확인은 실제 기기에서 미검증이며, 자동/원격 설치하지 않는다. |

## Child (`cpsm-m`)

| 화면 요구 | 상태 | 근거 및 남은 범위 |
|---|---|---|
| 오늘 사용량·한도·연장 요청·보호 상태 | 부분 | `MainActivity.java`, `UsageToday.java`, `ScreenTimeController.java`, `ScreenTimeEngine.java`에서 local usage/정책/15·30분 요청을 표시한다. 앱별 표시가 실제 앱 사용시간인지 정책 규칙인지 분리해 개선할 필요가 있다. |
| 앱 설치 요청·부모 결정 후 Play Store handoff | 구현(소스/서버) | `AppInstallRequestActivity.java`, `DeviceRegistrationClient.java`에서 요청/전체 이력/취소 및 승인 후 store handoff가 있다. Package Installer의 자녀 확인은 실기기 미검증이다. |
| 위치 동의·권한/기기 위치 수집·전송 | 부분 | `LocationConsentStore.java`, `LocationCaptureWorker.java`, `DeviceRegistrationClient.java`, `ProtectionForegroundService.java`에 자녀 동의·권한 보고·일회 worker 업로드가 있다. Child 앱에는 안심구역 및 위치 이력 화면이 확인되지 않는다. |
| 부모 위치 요청 처리, durable retry, 만료 | 구현(코드) / 실기기 미검증 | FCM은 wake-up 힌트 후 signed sync queue를 조회하고 WorkManager가 동의/권한/배터리/provider를 확인한다. 실제 FCM, Doze/OEM 실행과 lost-response retry는 장치에서 검증되지 않았다. Server는 active 요청을 재사용하고 terminal 결과 후 기기당 60분 cooldown을 적용한다. |
| SOS 오디오(자녀가 foreground에서 직접 시작, 별도 확인) | 미구현 | `MediaRecorder`, `AudioRecord`, 마이크 권한·recording UI를 찾지 못했다. 원격 녹음 요청은 만들지 않는다. 저장/부모 공유/삭제 조건도 미결정이다. |
| 다운타임·앱별 제한·보호상태 | 부분 | UsageStats/정책 계산과 enforcement 후보가 있다. Device Owner/Accessibility/OEM/재부팅 중 실제 차단 신뢰도는 실기기 미검증이다. |
| 미션 목록·텍스트 제출·보상 | 부분 | `ChildMissionsActivity.java`는 서버 미션·텍스트 제출과 별도 보상 원장 API를 표시한다. 원장에 기록된 분량과 command state를 구분하며, `delivered`를 실제 적용으로 주장하지 않는다. 배지/누적 칭찬 UI와 실제 기기 적용은 남아 있다. |
| 가족 프로필·연결 기기/역할 | 부분 | 등록 상태·QR pairing·관계 확인 경로가 있다. 가족 구성원/guardian 역할 관리 화면은 없다. |
| Health Connect·웨어러블 | 미구현 | `HealthStore`는 보호/부팅 상태 저장소이며 건강 기록 저장소가 아니다. Health Connect dependency/provider, record type 권한, 건강 이력 화면과 제조사 adapter가 없다. API 26–27은 Health Connect provider 지원 대상이 아니다. |

## Server/API 및 공통 데이터 흐름

| 영역 | 상태 | 근거 및 제한 |
|---|---|---|
| 등록·QR 관계·정책 게이트 | 구현(코드/isolated tests) | `src/index.js`, `src/store.js`; signed device proof, Family scope, QR scanner의 명시적 confirm, policy assignment/receipt가 있다. 실 FCM은 꺼져 있다. |
| 화면시간·승인·명령 queue | 구현(코드/isolated tests) | `/api/devices/*/sync`, `/commands/poll`, parent approval/command routes, SQLite persistence. Child OS 집행은 실기기 검증 전이다. |
| 가족/기기 범위 앱 규칙 | 구현(서버 통합 테스트) | 정책 규칙은 optional `device_id`로 가족 전체 또는 특정 confirmed device에 적용된다. 부모 세션은 다른 가족/미확인 device를 지정할 수 없고, signed policy는 해당 기기 규칙만 포함한다. Parent selector와 연동했다. |
| 위치·안심구역·timeline·보관 | 구현(코드/SQLite tests) | `src/location.js`, `src/store.js`; dual consent, permission report, 30일 retention, 최대 60분 request TTL, active request reuse, terminal 후 per-device 60분 cooldown/429, geofence baseline/deduplication이 있다. |
| 미션·보상·audit·생성 멱등성 | 구현(서버 통합 테스트) | mission request UUID + scoped fingerprint, reward ledger/command idempotency, text-free lifecycle audit가 SQLite와 JSON fallback에서 검사됐다. |
| 앱 설치 요청 | 구현(서버 통합 테스트) | 가족 scope, expiry, pending dedupe, no-install-command, JSON/SQLite persistence. |
| 가족 역할/초대·권한관리 | 미구현 | table에 role field는 있으나 member invite/role change/revoke API와 permission matrix가 없다. |
| Health Connect/건강 기록 | 미구현 | 건강 consent/sample tables/API/UI/provider가 없다. `devices.health`는 기기 상태 JSON이며 건강 기록 schema가 아니다. |
| 위치 요청 빈도 정책 | 구현(서버/Parent UI) | terminal outcome 후 같은 기기에 새 요청을 60분 동안 제한한다. active queued/deferred request는 재사용하며, 429에 retry delay를 반환하고 Parent는 남은 시간을 표시한다. |
| SOS audio | 미구현 | 서버 audio upload/storage/retention API 없음. 기획상 원격 capture 금지, 자녀 시작과 명시적 공유만 검토 가능. |

## Parent client/server route divergence

`cpsm-p` `PortalApi.java` retains legacy admin OTP wrappers that call `/api/admin/portal-enroll` and, when no gateway base URL is configured, `/api/submit`. Neither path is present in the current CPSM server route matcher. They are outside this server API contract and require a separately verified legacy gateway; do not infer successful behavior from the client wrapper alone.

## 코드 및 자동 테스트 증거

- Server: latest `npm run check`, `npm run test:location`, and `npm run test:v2` (143 assertions) passed using isolated data; v2 includes HTTP cooldown, active-request reuse, and `Retry-After` checks. `test:missions` (105 assertions), `test:app-install-requests` (106 assertions), and `smoke` passed in earlier runs; no mission/app-install code changed after those runs.
- Parent: latest `:app:testDebugUnitTest` 16 tests and `:app:assembleDebug` passed before the current cooldown-UI edit; rebuild/retest after that edit is still required.
- Child: `:app:testDebugUnitTest` 24 tests and `:app:assembleDebug` passed before the current cooldown disclosure/BuildConfig edit; rebuild/retest after that edit is still required.
- `adb devices -l` showed no connected devices. Therefore camera QR, actual location/Health Connect, FCM, usage/event producer, Package Installer, reboot/Device Owner enforcement are not verified.
- Original screen mockup ZIP was not found in the project archive search, so visual mockup comparison was not performed. This matrix is based on scope Markdown and native code/API/schema/test evidence.

## 사용자 확정 기준과 미완료 구현

- Location: terminal outcome 후 같은 기기에 새 요청은 60분 간격; active queued/deferred request는 재사용한다. 구현·자동 검증 완료.
- Screen time: 가족 기본 한도/다운타임에 자녀별 override를 더하고, override가 우선한다. 현재 구현은 가족 공통이므로 서버/API/Parent UI 확장이 남았다.
- Family roles: owner/admin만 구성원 초대·역할 변경·철회; guardian은 조회·요청 승인·자녀 명령; child는 본인 데이터·동의만. server authorization/audit/UI는 미구현이다.
- Health Connect: Health Connect only; steps + sleep; 30일 보관; consent revoke 시 CPSM copy 삭제; 제조사별 adapter 제외. Android provider + consent + sync/retention/server/Parent display는 미구현이다.
- SOS audio: child-started foreground recording plus explicit share is requested, but storage, sharing recipient/authorization, retention, and deletion behavior are not specified. Do not implement/upload audio until those data-handling rules are approved.

## 차단 정책 세부사항

SOS audio를 포함한다면 저장 위치(기기/서버), 전송 암호화, 자녀가 공유를 승인하는 시점과 수신자, 부모/자녀의 삭제 권한, 보관기간 및 동의 철회 시 삭제 방식을 확정해야 한다. Until specified, the audio slice remains blocked; no remote capture behavior will be added.

원본 화면 시안 ZIP 부재, 기기 미연결, and the above outstanding code/policy work mean this is not yet at “physical device install testing only.”
