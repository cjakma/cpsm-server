# CPSM API 연동 규격서 — 현재 코드 기준

## 범위와 근거

이 문서는 archive server의 실제 `src/index.js` route matcher, `src/auth.js`, `src/location.js`, `src/screenTime.js`, `src/store.js`를 기준으로 작성했다. 배포된 서비스가 archive와 일치한다는 뜻은 아니며, API 존재를 실기기 실행이나 실 FCM 전달의 증거로 해석하지 않는다. 자세한 legacy 설계 이력은 [`../API_DESIGN.md`](../../API_DESIGN.md), 저장 스키마는 [`SCHEMA.md`](SCHEMA.md), Mermaid ERD는 [`ERD_CURRENT.md`](ERD_CURRENT.md)를 본다.

Canonical server paths are `/api/...`. Reverse proxy may prepend `/cpsm-api`; the parent compatibility prefix `/v1/parent/...` is normalized to `/api/parent/...`. Device signatures bind the actual request path including `x-forwarded-prefix`, method, timestamp, nonce, and raw body. `cpsm-p` also contains legacy admin OTP wrappers for `/api/admin/portal-enroll` and `/api/submit`; these are not server routes in this archive and are not specified as supported CPSM APIs here.

## Authentication

| Security scheme | Required headers / rule | Applies to |
|---|---|---|
| Public bootstrap | No bearer; registration accepts a device public key, never a private key. Parent auto-enrollment validates the public-key fingerprint. | `/api/devices/register`, `/api/parent/auth/auto-enroll`, `/api/parent/auth/enroll`, public OTA manifest/download, `/api/status` |
| Device HMAC | `X-CPSM-Device-Id`, `X-CPSM-Timestamp`, `X-CPSM-Nonce`, `X-CPSM-Signature`; HMAC-SHA256 over `METHOD\nrequestPath\ntimestamp\nnonce\nsha256hex(rawBody)`. | Device routes |
| Device public-key signature | `X-CPSM-Device-Id`, `X-CPSM-Timestamp`, `X-CPSM-Nonce`, `X-CPSM-Device-Public-Key`, `X-CPSM-Device-Signature`; signature binds `METHOD\nrequestPath\ntimestamp\nnonce\nbase64(rawBody)`. | Enrolled Android/Windows device routes |
| Parent bearer | `Authorization: Bearer <session>` or configured parent/operator token. Parent sessions are family-scoped; self-enrolled parent sessions require a parent profile for profile operations. | `/api/parent/*`, except the public enrollment endpoints above |
| Admin bearer | `Authorization: Bearer <admin token>`; parent session is not admin authority. | `/api/admin/*` |

Device auth defaults to strict. Disabled auth is permitted only in local/test mode. `request_nonces` blocks replay; stale timestamp, mismatched device ID, invalid signature, and replay are rejected.

## Endpoint inventory

All paths below are canonical. `{deviceId}` is a server device ID; `{sessionId}`, `{mappingId}`, `{missionId}`, `{submissionId}`, `{requestId}`, `{commandId}`, `{geofenceId}`, `{errorId}`, and `{changeId}` are opaque IDs unless a selector schema says otherwise.

### Public and bootstrap

| Method | Path | Auth | Contract |
|---|---|---|---|
| GET | `/api/status` | Public | Server/storage/auth/FCM status; no secrets. |
| GET | `/api/updates/manifest?platform=&product=` | Public, read-only | Bootstrap OTA manifest. Product/platform are validated by the artifact service. |
| GET | `/api/updates/download?platform=&product=` | Public, read-only | Bootstrap artifact bytes. |
| GET | `/api/updates/android/{product}/manifest.json` | Public, read-only | Stable Android alias; product is `cpsm-m` or `cpsm-p`. |
| GET | `/api/updates/android/{product}/latest.apk` | Public, read-only | Stable Android artifact alias. |
| POST | `/api/devices/register` | Public bootstrap | Enroll/update device metadata and public key; same key preserves paired state, key rotation conflicts. Returns `201`. |
| POST | `/api/parent/auth/auto-enroll` | Public bootstrap | Parent public key + SHA-256 fingerprint + display/approved metadata; creates family/profile/session. Returns `201`. |
| POST | `/api/parent/auth/enroll` | Bootstrap code | Legacy/recovery enrollment; `CPSM_BOOTSTRAP_CODE` must be configured. Returns session. |

### Device-authenticated routes

| Method | Path | Purpose / side effect |
|---|---|---|
| GET | `/api/devices/{deviceId}/registration-status` | Registration, relationship, consent requests, policy assignment/receipt and compatibility state. |
| POST | `/api/devices/{deviceId}/heartbeat` | Device status/current app/health metadata update. |
| POST | `/api/devices/{deviceId}/sync` | Update device state, accept sequenced events, acknowledge event sequence, poll queued commands, write policy receipt, return signed-policy availability only when relationship gate passes. |
| GET | `/api/devices/{deviceId}/policy` | Signed policy; `409 policy_not_ready` while required relationship/consent gate is unmet. |
| POST | `/api/devices/{deviceId}/events` | Store deduplicated events and create approval requests/notifications for applicable actions. |
| POST | `/api/devices/{deviceId}/errors` | Bounded/redacted telemetry upload; `202`, acknowledged client IDs support durable client outbox. |
| POST | `/api/devices/{deviceId}/notification-key` | Register notification provider token; response does not echo the secret token. |
| GET | `/api/devices/{deviceId}/commands/poll` | Lease queued commands to this device. |
| POST | `/api/devices/{deviceId}/commands/{commandId}/result` | Store command result/acknowledgement. |
| GET | `/api/devices/{deviceId}/updates/manifest?product=` | Authenticated device OTA manifest; product must match platform. |
| GET | `/api/devices/{deviceId}/updates/download?product=` | Authenticated device OTA artifact. |
| POST | `/api/devices/{deviceId}/pairing-sessions` | Child issues one-time pairing session/code; response includes role and expiry. |
| POST | `/api/devices/{deviceId}/pairing-sessions/{sessionId}/claim` | Child claims parent-issued pairing code; returns name preview. |
| POST | `/api/devices/{deviceId}/pairing-sessions/{sessionId}/confirm` | Scanner explicitly confirms/declines; server records relationship state. |
| POST | `/api/devices/{deviceId}/consent-requests/{requestId}/decision` | Child independently records relationship consent. |
| GET | `/api/devices/{deviceId}/missions?status=all\|active` | List only the authenticated child's current-family missions. |
| GET | `/api/devices/{deviceId}/mission-rewards?limit=` | Read the authenticated child's reward ledger only; default 50, maximum 100; confirmed relationship required. |
| POST | `/api/devices/{deviceId}/missions/{missionId}/submissions` | Text-only mission submission; returns `201`, no media. |
| GET/POST | `/api/devices/{deviceId}/app-install-requests?status=` | Child's own family-scoped app-install request list/create; status defaults to `pending`. |
| POST | `/api/devices/{deviceId}/app-install-requests/{requestId}/cancel` | Cancel a pending request owned by the authenticated child. |
| GET | `/api/devices/{deviceId}/location-consent` | Signed child read of current family-scoped parent/child consent and OS permission; used immediately before scheduled capture. |
| POST | `/api/devices/{deviceId}/location-consent` | Child consent/current permission report. |
| POST | `/api/devices/{deviceId}/location-requests/{requestId}/result` | Report deferred/failure outcome for an owned one-shot parent request. |
| POST | `/api/devices/{deviceId}/location-samples` | Upload one validated sample. `capture_type=parent_request` requires a valid request ID; `capture_type=scheduled` is periodic and has no request ID. Duplicate sample is idempotent (`200`), new sample `201`; accepted new samples trigger a family-scoped data-only parent refresh attempt. |

### Parent routes

| Method | Path | Purpose / side effect |
|---|---|---|
| GET | `/api/parent/dashboard` | Family-scoped dashboard summary. |
| GET | `/api/parent/devices` | Family-scoped connected devices. |
| GET | `/api/parent/families` | Current parent family. |
| GET | `/api/parent/children/available` | Unpaired child discovery; excludes already-confirmed relationships. |
| GET/POST | `/api/parent/mappings` | List/create legacy parent-child mapping. |
| POST | `/api/parent/mappings/{mappingId}/consent` | Parent consent decision. |
| GET | `/api/parent/consent-requests` | Parent's consent request history. |
| POST | `/api/parent/pairing-sessions` | Parent issues one-time QR session/code. |
| GET | `/api/parent/pairing-sessions/{sessionId}` | Issuer-scoped authoritative QR status. |
| POST | `/api/parent/pairing-sessions/{sessionId}/claim` | Claim child-issued code and receive parent/child name preview. |
| POST | `/api/parent/pairing-sessions/{sessionId}/confirm` | Explicit parent-side scanner confirmation/decline. |
| GET | `/api/parent/devices/{deviceId}/health` | Current device summary, family-scoped. |
| GET | `/api/parent/devices/{deviceId}/timeline` | Latest device events, family-scoped. |
| GET | `/api/parent/approval-requests` | Family-visible app-launch/time requests. |
| GET | `/api/parent/approval-requests/{requestId}` | Read one family-visible request. |
| POST | `/api/parent/approval-requests/{requestId}/decision` | `allow` or `terminate`; queues matching command. |
| POST | `/api/parent/approval-requests/{requestId}/allow` or `/terminate` | Compatibility decision aliases. |
| GET | `/api/parent/policies/current` | Current family policy (or legacy/global operator policy). |
| POST | `/api/parent/policies` | Legacy policy write; body `rules` plus optional `screenTime`. |
| PUT | `/api/parent/policies/current` | Replace family policy; increments version and queues policy refresh. |
| GET/POST | `/api/parent/blocked-apps` | Read/add a policy rule; legacy global route is separate from family session behavior. |
| GET/POST | `/api/parent/devices/{deviceId}/commands` | List/queue supported device commands; parent session must access the device's current family. |
| GET | `/api/parent/app-install-requests?status=pending\|all` | Family-scoped app-install request review queue. |
| POST | `/api/parent/app-install-requests/{requestId}/decision` | `approve`/`deny`; records permission, never queues silent install. |
| GET | `/api/parent/missions?status=all\|active\|pending_review\|completed\|cancelled` | Current-family mission history. |
| POST | `/api/parent/missions` | Create one confirmed Android child mission; request UUID is idempotency key. |
| POST | `/api/parent/missions/{missionId}/cancel` | Cancel an active mission. |
| POST | `/api/parent/missions/{missionId}/review` | Approve/reject one pending submission; positive approval writes reward ledger + bonus command atomically. |
| GET/POST | `/api/parent/geofences` | List/create family geofences. |
| PUT/DELETE | `/api/parent/geofences/{geofenceId}` | Update/delete a family geofence. |
| GET/POST | `/api/parent/devices/{deviceId}/location-consent` | Read/set parent consent; separate from child consent and OS permission. |
| POST | `/api/parent/devices/{deviceId}/location-requests` | Create/reuse one active on-demand request and queue one-shot location refresh. No cooldown follows captured/failed/expired; once no active request remains the parent may request again. Response reports child FCM attempt counts. |
| GET | `/api/parent/devices/{deviceId}/location-timeline?limit=` | Read consent, 30-day retention, timestamped requested/scheduled samples, transitions, request outcomes, and configured target `sample_interval_ms` (60 minutes by default; Android execution is best-effort). |
| POST | `/api/parent/devices/fcm-token` | Register parent notification token (optional integration). |
| GET | `/api/parent/updates/manifest?product=cpsm-p` | Parent OTA manifest; protected by parent bearer route guard. |
| GET | `/api/parent/updates/download?product=cpsm-p` | Parent OTA artifact; protected by parent bearer route guard. |

### Admin routes

| Method | Path | Purpose / side effect |
|---|---|---|
| POST | `/api/admin/portal-device/token` | Register legacy portal notification token. |
| POST | `/api/admin/devices/{deviceId}/secret` | Set device HMAC secret and/or public key. Never return credential material. |
| GET/POST | `/api/admin/app-versions` | List/register immutable app release metadata. |
| GET/POST | `/api/admin/app-versions/{platform}/{product}/{versionCode}/changes` | List/create release change records. |
| PATCH | `/api/admin/app-versions/{platform}/{product}/{versionCode}/changes/{changeId}` | Verify release change with explicit note. |
| GET | `/api/admin/errors?product=&status=&limit=&cursor=` | Paginated issue aggregates. |
| GET/PATCH | `/api/admin/errors/{errorId}` | Read issue/occurrences/links or update status; resolving/fixed requires verified release link. |

## Request/response contracts for current cross-app features

### Registration and policy gate

`POST /api/devices/register` accepts `device_id`, `public_key`, optional `platform`, names, `auth_mode`, and allowlisted non-secret `metadata`; it never accepts a private key. A new device returns `registered_unpaired`. Re-registering the same key preserves `registered_paired`; changed key conflicts. `GET /api/devices/{deviceId}/registration-status` requires device proof and exposes relationship, consent and policy receipt/assignment state. `POST /api/devices/{deviceId}/sync` is the signed pull path and is authoritative for commands and policy readiness; FCM is only a wake-up hint.

### QR relationship

The issuer creates a short-lived one-time pairing session, the opposite role claims the code, and the scanning device receives the name preview. Only the scanner's explicit `confirm` records both compatibility consent flags and sets the relationship confirmed; `consent:false` declines. Claim/FCM is not confirmation. Parent and child route families mirror one another.

### Family mission

Create body:

```json
{"request_id":"550e8400-e29b-41d4-a716-446655440000","device_id":"child-device","title":"책상 정리","instructions":"정리 후 메시지를 남겨 주세요.","bonus_minutes":15}
```

`request_id` is required UUID; idempotency scope is `(family_id,parent_id,request_id)`. Same key + same trimmed payload returns the original mission with HTTP `200`; same key + different payload is `409 mission_request_id_conflict`. `title` 1–80 chars, `instructions` 1–1000, `bonus_minutes` explicit integer 0–240. Child submission body is `{ "message": "..." }` (1–2000 chars). Parent review body is `{ "submission_id": "...", "decision": "approve|reject", "note": "..." }` (note 0–500 chars). Attachments/media are rejected. Approval/rejection retries for the same submission/decision return the existing review. Positive bonus creates one `mission_rewards` row and one `screen_time.bonus` command keyed `mission-reward:<submission_id>`; zero minutes creates a praise-only ledger row and no command.

`GET /api/devices/{deviceId}/mission-rewards?limit=50` requires device proof and an active confirmed parent-child relationship, returns only that child's current-family ledger entries, and bounds `limit` to 1–100. Each entry includes `reward_id`, `mission_id`, `mission_title`, `submission_id`, `bonus_minutes`, `granted_at`, and `command_state` (`queued`, `delivered`, `succeeded`, `acked`, `failed`, `expired`, `praise_only`, or `unknown`). It does not return submission text. `delivered` means queued command was delivered to the device poll path; it does not alone prove the device applied the bonus.

### App-install request

Child create body: `{ "package_name": "com.example.reader", "display_name": "Reader", "request_note": "Needed for school" }`. Parent decision body: `{ "decision": "approve|deny", "decision_note": "..." }`. Only pending/unexpired requests can be decided. Approval stores permission only; child must complete Play Store/Android Package Installer confirmation. It never queues an install command.

### Location and geofence

Parent geofence body: `{ "name": "집", "latitude": 37.5, "longitude": 127, "radius_m": 1000, "enabled": true }`; radius is 1,000–20,000m. Consent body requires boolean `consent`; child may additionally send `permission_granted`. A location sample requires `sample_id`, `captured_at`, latitude/longitude, `accuracy_m`, `provider`, `battery_pct`, and boolean `charging`. `capture_type` is `parent_request` by default and requires `request_id`; `scheduled` is for the periodic 60-minute target and has no `request_id`. Supported providers: `gps|network|fused|passive|unknown`. Parent on-demand request body is empty, TTL-bound, and deduplicated only while active; no post-completion 60-minute throttle applies. Child schedules periodic WorkManager uploads separately. The server returns the target cadence in the timeline and sends a family-scoped data-only FCM refresh attempt to parent tokens after a new accepted sample. FCM is best-effort; Android background scheduling is not exact-time guaranteed. A first valid sample only establishes the geofence baseline; later in-order, accuracy-resolving samples may create transitions. No route interpolation is performed.

### Screen-time and device command

Parent command body uses a supported `type` (`device.lock`, `device.unlock`, `screen_time.bonus`, `sync_now`), optional type-specific `minutes`, optional `reason`, and optional `idempotency_key`. Lock `minutes=0` is indefinite. Unlock `minutes=0` clears manual lock; positive values grant temporary free use while explicit app bans remain. Bonus is bounded to 1–240. Commands are leased by device poll; a queued never-delivered mission reward whose TTL expired is renewed on the next poll without changing its command ID or idempotency key.

Policy rules accepted by `PUT /api/parent/policies/current` may include optional `device_id` or `deviceId`. An omitted/empty value means family-wide; a non-empty value targets exactly that device. Parent-session writes are rejected with `403 policy_rule_device_not_in_family` unless the target is a confirmed device in that parent's family. `GET /api/devices/{deviceId}/policy` signs only family-wide rules plus rules targeted to that exact device; sibling devices do not receive the targeted rule. This field is part of `family_policies.policy_json.rules[]`, not a separate table.

## Shared errors and lifecycle codes

Errors are JSON `{ "ok": false, "error": "<stable_code>" }`; common statuses are `400` invalid input, `401` missing/invalid auth, `403` authenticated but not authorized, `404` missing/out-of-scope resource, `409` state/relationship/idempotency conflict, `410` expired request, `503` unavailable bootstrap/auth configuration, and `500 internal_error`. Endpoint-specific codes are defined in route/store validators and the detailed existing API design.

The contract only describes routes present in the current source. It does not claim that every screen feature has an Android caller, that the API is deployed, or that physical-device behavior/FCM delivery passed acceptance.
