# cpsm-c

`cpsm-c`는 자녀가 사용하는 Windows 10 이상 PC에 설치하는 CPSM Windows 에이전트입니다. 현재는 Electron shell을 포함한 Node.js 기반 MVP이며, Windows 프로세스를 주기적으로 감시하고 서버 정책에 따라 모니터링, 차단, 부모 승인 요청 이벤트를 생성합니다.

## 현재 구현 상태

- 프로젝트 이름과 패키지명을 `cpsm-c`로 정리
- Node.js 기반 child agent 구현
- Windows 프로세스 polling 감시 구현
- 로컬 정책 엔진 구현
- 이벤트 큐와 서버 업로드 구현
- 로컬 관리 API와 상태 UI 구현
- Electron shell 진입점 추가
- Windows Service 등록/제거용 PowerShell 스크립트 추가
- 서버 명령 처리 구현
  - `app.terminate`
  - `app.allow.temporary`
  - `policy.refresh`
- `/sync` 기반 정책 버전 확인과 원격 정책 다운로드 구현
- timestamp/nonce/body hash 기반 device request 서명과 replay 방지
- 원격 정책의 version/expiry/hash/signature/key-id 검증 및 last-known-good 복구
- bounded event/error queue, atomic file write, redacted error outbox와 retry/dead-letter 처리
- loopback local API와 mutation bearer/local-control-token 인증
- Windows OTA manifest 조회, artifact size/SHA-256 검증, 명시적 apply 승인과 PowerShell 적용 진입점
- `monitor`, `block`, `require_approval`, `allow` action 처리 구현

## 정책 동기화

`cpsm-c`는 서버와 항상 연결되어 있지 않아도 동작해야 하므로 로컬 정책을 보관합니다.

동작 방식:

1. 주기적으로 `POST /api/devices/{deviceId}/sync`를 호출합니다.
2. 서버 응답의 `policy.changed`가 `true`이면 `/policy`를 다운로드합니다.
3. 다운로드한 정책을 로컬 `policy.json`에 저장합니다.
4. 앱 실행 감시는 로컬 정책으로 즉시 판단합니다.
5. `monitor`, `block`, `require_approval` 이벤트는 바로 서버로 flush합니다.
6. 서버가 내려준 명령이 있으면 같은 sync 응답에서 받아 실행합니다.

지원 action:

```text
monitor           앱 실행 허용, 이벤트와 부모 알림 생성
block             앱 실행 차단, 이벤트와 부모 알림 생성
require_approval  부모 승인 요청 생성
allow             명시 허용
```

## 서버 연동 설정

개발 모드 정책 파일:

```text
cpsm-c\.data\config\policy.json
```

기본 정책 템플릿:

```text
cpsm-c\config\default-policy.json
```

서버 동기화를 테스트하려면 정책 파일의 `server` 값을 설정합니다.

```json
{
  "server": {
    "baseUrl": "http://127.0.0.1:18732",
    "deviceId": "local-device",
    "deviceSecret": "dev-secret"
  }
}
```

서버의 Windows device secret 또는 향후 public-key enrollment 결과는 설치별 로컬 정책에 주입합니다. device secret, local-control token, 정책 public key, 운영 credential는 저장소·로그·업데이트 artifact에 포함하지 않습니다.

운영 서버의 정책 API는 만료·hash·signature·key-id가 포함된 정책 envelope를 반환해야 하며, 검증에 실패한 원격 정책은 적용하지 않고 기존 last-known-good 정책을 유지합니다.

## 실행

```powershell
cd C:\env\workspace\childrens_pc_security_monitoring\cpsm-c
npm run dev
```

또는:

```powershell
.\scripts\start-dev.ps1 -Port 18731
```

개발 UI:

```text
http://127.0.0.1:18731
```

## 로컬 API

```http
GET  /api/status
GET  /api/events?limit=80
GET  /api/policy
POST /api/policy
POST /api/policy/reload
POST /api/allow-temporary
```

임시 허용 예시:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:18731/api/allow-temporary `
  -ContentType application/json `
  -Body '{"processName":"notepad.exe","minutes":15}'
```

## Windows Service

관리자 PowerShell에서 실행합니다.

```powershell
cd C:\env\workspace\childrens_pc_security_monitoring\cpsm-c
.\scripts\install-service.ps1
```

제거:

```powershell
.\scripts\uninstall-service.ps1
```

현재 스크립트는 개발 검증용입니다. 실제 배포 단계에서는 코드 서명, 설치 관리자, 서비스 복구 옵션, 자녀 일반 계정을 추가 검증해야 합니다. 정책 복원과 OTA 적용은 코드 경로가 있으나 Windows 실기기·서비스 권한 검증은 아직 남아 있습니다.

## 데이터 위치

개발 모드:

```text
cpsm-c\.data\
```

서비스 모드:

```text
C:\ProgramData\CPSM\cpsm-c\
```

개발 스크립트 기본 데이터:

```text
C:\tmp\cpsm-c-dev\
```

## 현재 한계와 검증 경계

- AppLocker/Windows Defender Application Control 적용은 아직 구현 전입니다.
- 현재 차단은 polling 후 `Stop-Process`를 호출하는 보조 방식입니다.
- 관리자 권한 보호, 코드 서명, tamper protection은 아직 없습니다.
- enrollment와 device secret 발급은 중앙 서버의 운영 설정과 함께 검증해야 합니다.
- Electron packaging은 아직 완료 전입니다.
- Windows 실기기에서 PowerShell process identity 검증, 서비스 권한, OTA apply, code signing은 아직 검증하지 않았습니다.
- 현재 smoke/test는 Linux host에서도 실행되도록 Windows process API를 건너뛰며, 실제 Windows enforcement 증거가 아닙니다.

## 검증

```powershell
npm run check
npm test
npm run smoke
```

현재 host에서 확인된 결과:

- `npm run check`: 통과
- `npm test`: 5개 통과
- `npm run smoke`: 통과

---

## v2.2 (서버 연동 확장)

- `src/deviceKey.js`: 설치별 EC P-256 키와 키 기반 서명 헤더(Android Keystore와 동일 canonical). 서버 자동 등록·QR pairing·서명 요청.
- `src/serverClient.js`: 관리자 발급 HMAC 비밀키 대신 device key 서명으로 전환. `register`·`registrationStatus`·`createPairingSession` 추가. confirmed 전에는 서버가 정책을 내려주지 않습니다.

### 사용자가 구현할 부분 (모바일펜스 방식)

Windows 사용시간 실행부(`screenTime.js` 엔진 포팅 + `device.lock`/`unlock`/`bonus` 명령 처리 + 잠금 시 워크스테이션 잠금/로그오프)는 미포함입니다. cpsm-m의 `ScreenTimeEngine`을 Node로 포팅하고 agent에 연결하세요. 자녀 표준 사용자 계정은 OS에서 직접 생성합니다. 자세한 내용은 [CHANGES_v2.2.md](CHANGES_v2.2.md) §4.2.
