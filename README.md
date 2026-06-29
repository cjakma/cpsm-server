# cpsm-server

`cpsm-server`는 CPSM의 중앙 서버입니다. 지금 단계에서는 동시 접속자 4명 수준을 전제로 단일 Node.js 프로세스와 파일 저장소를 사용하지만, 프로토콜은 이후 동접 5만 명 규모로 PostgreSQL, Redis, Queue, WebSocket Gateway를 분리하기 쉬운 형태로 잡았습니다.

## 역할

- `cpsm-c` Windows 자녀 PC 에이전트 이벤트 수신
- `cpsm-m` Android 자녀 앱 이벤트와 상태 수신
- 부모앱 `cpsm-p`에서 작성한 정책 규칙 저장 및 버전 관리
- 자녀 기기의 `/sync` 요청에 정책 변경 여부와 명령 큐 반환
- `monitor`, `block`, `require_approval` 이벤트 처리
- 부모 기기로 FCM data message 발송
- 부모의 허락/종료 결정을 자녀 기기 명령으로 변환

## 현재 설계

정책 원본은 서버에 있습니다. 부모앱이 규칙을 작성하면 서버는 정책 버전을 증가시키고, 자녀 기기(`cpsm-c`, `cpsm-m`)는 주기적으로 `/sync`를 호출해 새 버전이 있는지 확인합니다.

현재는 HTTP polling을 사용합니다. 동접 5만 명으로 커질 때도 이 프로토콜은 유지할 수 있고, 내부 구현만 다음처럼 분리하면 됩니다.

```text
현재 MVP:
cpsm-c/cpsm-m -> cpsm-server(Node) -> file store + FCM

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
```

`/api/parent/blocked-apps`는 기존 부모앱 UI 호환을 위해 이름을 유지합니다. 현재 응답 내용은 차단 목록만이 아니라 `monitor`, `block`, `require_approval` 전체 정책 규칙입니다.

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

## FCM 설정

Firebase Admin SDK service account 파일은 아래 경로를 기본으로 사용합니다.

```text
cpsm-server\secrets\firebase-adminsdk.json
```

현재 적용된 Firebase project:

```text
project_id: childrens-pc-sec-monit
client_email: firebase-adminsdk-fbsvc@childrens-pc-sec-monit.iam.gserviceaccount.com
```

다른 경로를 쓰려면 환경 변수를 설정합니다.

```powershell
$env:GOOGLE_APPLICATION_CREDENTIALS='C:\path\firebase-service-account.json'
$env:FIREBASE_PROJECT_ID='your-firebase-project-id'
```

FCM service account가 없거나 부모 FCM token이 등록되지 않으면 실제 발송 대신 `data\notifications.ndjson`에 fallback payload를 기록합니다.

## 이벤트 흐름

1. 부모가 `cpsm-p`에서 앱 규칙을 작성합니다.
2. 서버가 정책 버전을 증가시킵니다.
3. `cpsm-c` 또는 `cpsm-m`이 `/sync`에서 새 정책 버전을 확인합니다.
4. 자녀 기기가 `/policy`를 다운로드해 로컬에 저장합니다.
5. 자녀 기기에서 정책 대상 앱이 실행되면 action에 따라 이벤트를 서버로 보냅니다.
6. 서버는 부모에게 FCM data message를 보냅니다.
7. `require_approval`이면 부모가 허락 또는 종료를 선택합니다.
8. 서버는 `app.allow.temporary` 또는 `app.terminate` 명령을 자녀 기기 큐에 넣습니다.
9. 자녀 기기가 다음 `/sync` 또는 command poll에서 명령을 받아 실행합니다.

## 검증

```powershell
npm run check
npm run smoke
```
