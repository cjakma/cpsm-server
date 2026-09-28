# CPSM 위치 기능 구현 — 동의·요청·이력·안심구역

## 범위

서버에는 가족별 안심구역 CRUD, 양측 위치 동의, durable `location.refresh` 요청, 표본 업로드, 타임라인과 안심구역 전이 API가 추가됐다. CPSM-m에는 자녀 동의/철회 UI, Android 권한 보고, 30% 배터리 조건의 WorkManager 1회 GPS 캡처·재시도, FCM wake-up handler가 구현됐고, 부모 앱에는 동의/요청/이력 화면이 추가됐다. 앱 빌드와 서버 격리 테스트는 통과했지만 실제 기기 동작은 검증되지 않았다.

로컬 앱 모듈에는 각 패키지와 일치하는 Firebase Android 설정 파일이 권한 600으로 배치되고 Git에서 제외된다. Google Services plugin/BOM 설정에 따라 두 Android debug build는 FCM token 등록·수신 코드를 활성화한다. 실제 서비스의 FCM 발송은 별도 Firebase Admin SDK service-account credential과 `CPSM_FCM_ENABLED=1`이 필요하므로 운영 서버는 이 작업에서 활성화하지 않았다. 새 위치 API도 운영 서버에는 배포하지 않았다.

## API

모든 경로는 parent session bearer 인증과 session family scope를 요구한다.

- `GET /api/parent/geofences` — 현재 family의 geofence 목록
- `POST /api/parent/geofences` — `{name, latitude, longitude, radius_m, enabled?}` 생성
- `PUT /api/parent/geofences/{geofenceId}` — 같은 family geofence 수정
- `DELETE /api/parent/geofences/{geofenceId}` — 같은 family geofence 삭제
- `GET /api/parent/devices/{deviceId}/location-consent` — 두 동의/권한 상태
- `POST /api/parent/devices/{deviceId}/location-consent` — 부모 측 위치 동의
- `POST /api/devices/{deviceId}/location-consent` — 자녀 동의와 현재 OS permission 상태
- `POST /api/parent/devices/{deviceId}/location-requests` — 두 동의 및 위치 권한 보고가 모두 유효할 때 durable `location.refresh` queue + FCM wake-up 시도
- `POST /api/devices/{deviceId}/location-requests/{requestId}/result` — 저전력/권한/위치 provider 실패 시 defer/failure 결과 보고
- `POST /api/devices/{deviceId}/location-samples` — 요청에 응답하는 인증된 GPS 표본 업로드
- `GET /api/parent/devices/{deviceId}/location-timeline?limit=N` — 가족 범위의 timestamp순 표본/안심구역 전이 조회

검증:

- `name`: 공백 제거 후 1~80자
- `latitude`: JSON number, -90~90
- `longitude`: JSON number, -180~180
- `radius_m`: 정수 1000~20000 미터
- `enabled`: boolean, 생략하면 true
- 권한 없는/타 가족 ID는 존재 여부를 노출하지 않고 404 처리
- 각 변경은 audit log에 기록

SQLite에는 `geofences` 테이블을 additive하게 생성한다. 저장은 family ID, 중심 좌표, 반경, enabled, 생성/수정시각과 생성 parent ID로 구성된다.

위치 저장에는 `location_consents`, `location_requests`, `location_samples`, `geofence_states`, `location_transitions`를 추가했다. 위치 표본은 sample ID로 중복 제거하며, 지오펜스 최초 표본은 기준 상태만 저장하고 enter/exit를 만들지 않는다. 정확도 원이 경계와 겹치는 표본은 `uncertain`으로 보고 상태 전이를 발생시키지 않는다. 타임라인은 수집 timestamp 순이며 두 표본 사이의 실제 경로로 보간하지 않는다.

기본값은 최소 배터리 `30%` 또는 충전 중 허용, 위치 이력 보관 `30일`이다. 각각 `CPSM_LOCATION_MIN_BATTERY_PERCENT`, `CPSM_LOCATION_RETENTION_DAYS`로 조정 가능하고 보관 설정은 1~90일로 제한한다. 서버는 시작 시와 매시간 만료 데이터를 정리하며, 읽기/표본 수신 시에도 정리한다. 위치 표본·전이·완료 요청·location.refresh command 및 관련 요청/표본 audit는 30일 뒤 삭제한다. 자녀/부모 동의 변경 audit는 좌표를 포함하지 않고 별도로 유지한다. 요청 만료는 최대 60분이다. 실기기 전력·권한 동작 검증은 별도다.

## 부모 앱

자녀별 `위치 · 안심구역 이력`에서 부모 동의 설정, 1회 요청, 요청 상태와 timestamp 기반 위치/전이 기록을 조회한다. 각 표본의 `geo:` 링크는 설치된 지도 앱으로 넘긴다. Google/Naver 임베디드 지도 SDK/key는 아직 연결하지 않았다. `정책 관리 → 가족 안심구역 설정`에서는 구역 CRUD만 처리하며, 구역 저장만으로 위치 수집이 켜지지 않는다.

## 아직 남은 단계와 경계

- Google/Naver 임베디드 지도 SDK/key 선정 및 실제 지도 렌더링
- 자녀 FCM 설정/토큰 등록/발송의 실기기 검증과 배터리·위치 권한별 WorkManager 재시도 검증
- 새 API 운영 배포 및 public-service readback (별도 승인 필요)
- Android API 26–36 대상 실기기 위치·권한·재부팅 검증
- 위치정보 보관/동의 정책의 출시 전 개인정보·위치정보 법률 검토
