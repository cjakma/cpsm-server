# CPSM 통합 재설계서 자체 검토 결과

- 문서 버전: 2.1
- 기준일: 2026-09-25
- 대상 문서: `DESIGN.md`, `API_DESIGN.md`, 운영 `cpsm-server/SCHEMA.md`
- 검토 방식: Slack 대화에 확정된 요구사항, 현재 Android/server source, production SQLite status, public artifact readback, server check/smoke 결과 대조
- 검토 횟수: 3회차
- 결론: **단일 확인 QR의 서버/API 구현과 공개 artifact readback은 정합; Parent QR 통지 최종 구조와 physical-device 검증은 남음**

## 1. 대조 결과

### 기존 코드 검토사항 반영

| 검토사항 | 설계 반영 위치 | 결과 |
|---|---|---|
| `cpsm-server` 전체 API 무인증 | 3.4, 5.2, 9, Phase 1 | 반영 |
| `cpsm-c` localhost mutation API 무인증 | 6.3, 13 | 반영 |
| Android 자녀앱이 수동 sync/테스트 골격뿐 | 7 전체, Phase 2 | 반영 |
| Android 고정 device ID | 4.1, 10 Phase 2, 13 | 반영 |
| 정책 hash 저장만 하고 검증하지 않음 | 4.2, 5.3, 7.3, 13 | 반영 |
| FCM을 명령 전달의 신뢰 근거로 사용 | 3.3, 4.4, 8.3, 13 | 반영 |
| FCM token/서비스 계정 운영 위험 | 3.3, 5.4, 9, 12 | 반영 |
| command queue가 `sent` 후 유실 가능 | 3.3, 4.4, 5.4, 11 | 반영 |
| event flush 동시성/queue 삭제 문제 | 6.4, 11 | 반영 |
| Windows process name/PID 종료 우회 | 6.2 | 반영 |
| Windows Node 직접 service 등록 | 6.1, 13 | 반영 |
| JSON 단일 state 파일의 손상/동시성 문제 | 5.1, 13 | 반영 |
| parent approval 재처리/만료 문제 | 4.4, 5.2, 8.3, 11 | 반영 |
| Android boot receiver/5분 health check 부재 | 3.2, 7.2, 7.5, Phase 2 | 반영 |
| Android Device Owner와 일반 Device Admin 혼동 | 3.1, 7.2, Phase 2 | 반영 |

## 2. Family Link 범위 검토

공식 Google 문서에서 확인 가능한 부모 기능을 다음과 같이 반영했다.

- screen time와 app activity
- daily limit, app limit
- Downtime/School time
- app block/allow/Unlimited time
- Play 앱·구매 승인과 권한 관리 범주
- 기기 위치와 정확도
- family place 도착/이탈 알림 범주
- 기기 lock/unlock 및 bonus time
- Family Link notification 범주

다음은 공식 Family Link 내부 데이터로 가장하지 않고 제외했다.

- Family Link private DB/API/RPC
- Parent Access Code와 Google credential
- Google 내부 screen-time ledger
- Google Maps/Family Link raw location history
- 다른 앱의 콘텐츠·키 입력·화면 캡처

이 구분은 설계서의 `2.1~2.3`과 일치한다.

## 3. Android 실행 가능성 검토

설계서의 5분 점검은 `WorkManager`로 구현한다고 쓰지 않고, 다음과 같이 제한을 반영했다.

- WorkManager periodic minimum 15분
- 5분은 목표 주기이지 OS가 보장하는 exact interval이 아님
- foreground service와 Device Owner local enforcement를 조합
- Android 12/14/15 background FGS 제한을 버전별 검증
- 실제 간격을 기록하고 `stale`로 표시
- force-stop, OEM task killer, 배터리 최적화, 전원 종료, 공장 초기화를 완전 차단한다고 약속하지 않음

자체 검토 중 빠져 있던 실제 Android 조건도 수정했다.

- `RECEIVE_BOOT_COMPLETED`
- `directBootAware`
- `PACKAGE_*` receiver의 package data scheme
- Device Owner 초기화/QR provisioning 전제
- 부모 bootstrap enrollment의 one-time/TTL/revoke 흐름

## 4. FCM 임시값 검토

사용자가 신규 FCM 자격증명을 나중에 할당한다는 조건을 반영했다.

문서에 명시된 임시 상태:

```text
FIREBASE_PROJECT_ID=__CPSM_TEMP_PROJECT_ID__
CPSM_FCM_ENABLED=0
CPSM_FCM_KEY_STATUS=placeholder
```

검토 결과:

- 실제 private key를 문서·소스·Git에 넣지 않음
- FCM 호출은 disabled 상태로 유지
- 실제 키 설치·활성화는 별도 승인 후 수행
- FCM은 wake-up이며 명령 완료 근거가 아님

여기서 “FCM 키”는 legacy server key를 APK에 넣는 방식이 아니라, 서버 전용 Firebase service-account credential 또는 해당 프로젝트의 공식 FCM 인증 설정을 의미하도록 설계했다.

## 5. 원격 리소스 사용 조건 검토

사용자가 허용한 `pm-office`와 `3060` 서버는 설계·문서 단계에서 사용하지 않았다.

문서에는 다음 조건이 들어 있다.

- 현재 서버에서 먼저 작업
- 리소스 부족 확인 후 목적·예상 자원·시간·변경 범위를 제시
- 사용자 승인 전 SSH 접속·소스 복사·빌드·서비스 실행·장기 테스트 금지
- FCM key 설치·활성화도 별도 승인

현재 단계에서 이 조건과 충돌하는 작업은 없었다.

## 6. 남은 설계 결정

다음은 문서 결함이 아니라 구현 전에 사용자가 결정해야 하는 항목이다.

1. Android 자녀 기기를 실제 Device Owner로 초기화·프로비저닝할 수 있는지
2. 기존 개인용 기기에서 Device Owner 전환을 허용할지
3. 위치 기능을 사용할지와 보존기간
4. 부모 로그인 방식을 bootstrap code + Keystore로 고정할지, 별도 계정 연동을 추가할지
5. 기본 screen-time/app-limit 정책과 필수 allowlist
6. 데이터 보존기간의 최종값
7. FCM 신규 Firebase 프로젝트/service account 발급 범위

## 7. 1차 검토 판정

1차 검토 기준에서는 설계서가 확인된 코드 문제와 원래 요구사항을 반영했지만, 실제 구현 전 문서였으므로 구현 승인 대기 상태였다. 2차 검토에서 현재 source·production state·실행 증거와 API_DESIGN을 다시 대조한 결과는 다음 8장에서 갱신한다.

## 8. 2차 검토 — 최신 Slack 문맥과 실제 상태 대조

### 8.1 요구사항 대조

| 최신 요구/관찰 | 문서 반영 | 판정 |
|---|---|---|
| `cpsm-m`, `cpsm-p` 최신 APK public download | `DESIGN.md` 15, `API_DESIGN.md` M-09/P-11 | 반영 |
| Note8 API 28, S21 API 35, V50 API 31, Q9 API 26+, S22/S26 API 36+ | `androidCompatibility`, API metadata, API_DESIGN 3장 | 반영 |
| 앱 실행 시 OS/API/security patch/model 읽기 | M-01, P-01 metadata contract | 구현·반영 |
| Parent Bootstrap Code 화면 | P-01, 8.2 sequence | 정상 최초 enrollment branch로 정리 |
| Child 화면 `registered`, `unpaired`, `policy missing` | M-02/M-05, lifecycle | 상태를 혼동하지 않도록 분리 |
| Child `canonical_hash_invalid` | `DESIGN.md` 15, stale candidate cleanup 기록 | 과거 후보와 현재 policy gate를 분리 |
| FCM disabled | 공통 auth/FCM 규약, Parent QR 임시 polling과 최종 wake-up/fallback 구분 | 반영 |
| parent+child 양쪽 consent | 8.3 sequence, lifecycle invariant | 반영 |
| 오류값 서버 업로드와 수정 여부 | `API_DESIGN.md` 6~8, SCHEMA 보충 | 구현·운영 migration readback 검증 |

### 8.2 실제 코드와 API 문서 대조

- `cpsm-server/src/index.js`의 route matcher와 `API_DESIGN.md` catalog를 대조했다.
- `cpsm-m/DeviceRegistrationClient.java`와 `PolicySyncClient.java`의 register/status/consent/sync/policy 호출 parameter를 대조했다.
- `cpsm-p/PortalApi.java`의 `/v1/parent` prefix, enrollment, family, mapping, consent, dashboard, approval, policy API를 대조했다.
- `cpsm-c/src/serverClient.js`와 `localApi.js`의 server API·local mutation API를 분리해 기록했다.
- 실제 server의 parent route는 `/v1/parent`를 `/api/parent`로 normalize하므로 문서에 두 경로를 함께 기록했다.
- 예전 설계서의 미구현 `/v1/devices/enroll/start`, `/v1/devices/enroll/complete`, `/v1/parent/devices/{id}/commands` 목록은 실제 contract에서 제거하고 `API_DESIGN.md` 기반으로 교체했다.

### 8.3 DB 대조

현재 production SQLite에 확인된 canonical table:

- `devices`
- `families`
- `parent_profiles`
- `child_profiles`
- `family_members`
- `parent_child_mappings`
- `consent_requests`
- `device_notification_keys`
- `family_policies`
- `device_policy_assignments`
- `policy_sync_receipts`
- `app_versions`
- `events`
- `commands`
- `approval_requests`
- `parent_sessions`
- `audit_log`
- `request_nonces`

문서에 추가한 `device_errors`, `device_error_occurrences`, `app_version_changes`, `error_app_version_links`는 운영 PM2 재시작 후 모두 생성되었고, 각 table column readback까지 확인했다.

### 8.4 실제 실행 증거와 문서 표현 대조

- `npm run check`: 통과.
- `npm run smoke`: 통과.
- PM2 `cpsm-server`: online.
- 운영 `/api/status`: HTTP 200, SQLite, FCM disabled.
- Child v8 manifest/download: HTTP 200, manifest size/SHA-256와 다운로드 bytes 일치.
- Child v7→v8 실제 APK signer digest continuity: 통과.
- Parent dummy bootstrap code: HTTP 401 `invalid_bootstrap_code`; configured route로 확인.
- production Note8: `registered_unpaired`, `policyReady=false`; 따라서 policy withheld는 정상.

이 증거로 문서에는 다음 표현만 허용한다.

- 서버·API lifecycle: `구현 및 smoke 검증`
- APK public route/integrity: `운영 readback 검증`
- 실제 Android 설치·Package Installer 승인·policy commit: `미검증`
- 오류 telemetry tables/API: `구현 및 운영 readback 검증`

### 8.4-Q QR 매핑 기능 검토

- `cpsm-m`의 QR 생성·카메라 스캔과 `cpsm-p`의 QR 생성·카메라 스캔 코드를 source 대조했다.
- QR payload는 `cpsm://pair`, version `3`, role, 단기 session ID와 pairing code로 구성되며 private key·장기 token·password를 담지 않는다. server에는 code hash만 저장한다.
- Child QR→Parent claim과 Parent QR→Child claim 모두 issuer/claimant role 및 device/parent 인증을 통과해야 한다.
- 스캔 후 claim response에 부모·자녀 이름 preview가 포함되고, 스캔한 기기의 단일 확인창에서 명시적 동의를 받는다.
- 확인 시 server가 부모·자녀 consent를 원자적으로 처리해 relationship을 확정하며, QR이 server lifecycle gate를 우회하지 않는다.
- Child/Parent 최신 QR single-confirm APK는 build/sign/public manifest readback을 별도로 검증한다.
- server smoke에서 양방향 claim, preview, 단일 confirm, 1회 사용 거부를 검증했다.
- 카메라 권한 승인, 실제 QR 인식, physical device 간 confirm은 `adb devices -l`에 기기가 없어 미검증이다.

### 8.5-Q QR 완료 통지 설계 검토

- Parent version 19는 `GET /api/parent/pairing-sessions/{id}`를 1.5초 간격으로 호출해 `confirmed`/`declined`/`expired`에서 QR을 닫는다.
- 이 구현은 서버 smoke와 코드 대조에는 정합하지만, QR 표시 시간이 길어질수록 request가 누적되는 부하 문제가 있어 최종 구조로 승인하지 않는다.
- FCM은 `type`, `pairing_session_id`, `status` 정도의 최소 wake-up payload만 전달하고, Parent는 수신 후 인증된 status GET으로 서버 상태를 재검증해야 한다.
- FCM disabled/유실 fallback은 30~45초 Long Polling 재연결로 설계하며, 5분 단일 연결은 reverse-proxy timeout과 QR TTL을 고려해 채택하지 않는다.
- FCM pairing handler, Long Polling endpoint, proxy timeout, Parent/Child physical-device 흐름은 아직 구현·검증되지 않았다.

### 8.6 3차 검토에서 남은 위험

1. Parent 자동 enrollment/session 발급은 server smoke와 public endpoint로 검증했지만, 실제 Android physical device에서 첫 실행→QR→양쪽 consent를 아직 재현하지 않았다.
2. 실제 Child/Parent physical device에서 update approval과 post-update startup을 확인하지 않았다.
3. API 26/31/35/36 기기 matrix는 source compatibility classification만 검증되었고, 각 실기기 runtime evidence는 없다.
4. confirmed relationship 이후 Android policy의 실제 signature/hash commit은 physical device에서 재현해야 한다.
5. error telemetry raw stack/context redaction, client queue retry and public upload were tested; physical Android/Windows runtime upload remains unverified.
6. `is_fixed`는 release publish가 아니라 재현·수정 version·검증 결과를 연결한 뒤에만 true로 설정해야 한다.

### 8.7 검토 결론

이번 갱신으로 문서와 현재 코드·운영 상태 사이의 주요 경로 불일치를 제거했다. 특히 API 목록, parameter, Parent/Child/Server 역할 분리, lifecycle sequence, OTA 경계, 오류·App Version 변경 이력 관계를 상세 문서로 고정했다.

다음 검증 단위는 physical runtime 환경에 한정한다.

1. 실제 Android 기기 연결 후 offline queue → 재연결 → error upload
2. Windows Service 설치 환경에서 `cpsm-c` network upload
3. Android API 26/31/35/36 device matrix와 Package Installer approval

실제 Android/Windows runtime이 없는 현재 host에서는 위 항목을 완료된 기능으로 보고하지 않는다.
