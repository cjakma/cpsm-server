# CPSM server data model

The server uses SQLite at `data/cpsm.sqlite`. `state.json` remains a compatibility fallback when the Node SQLite runtime is unavailable. The private policy-signing key is stored beside the database and is not part of an archive or API response.

## Identity and membership

- `devices`: canonical physical-device identity, public key, platform, registration state, and auxiliary metadata. Android metadata includes API level, OS release, security patch, manufacturer, model, device/product, and app version. A Wi-Fi address or phone number is not identity.
- `parent_profiles`: logical parent profile linked to a family and a parent-device fingerprint; Android enrollment metadata is stored for compatibility diagnostics.
- `child_profiles`: logical child profile linked to exactly one device.
- `families`: family grouping unit.
- `family_members`: many-to-many membership between a family and parent/child profiles.
- `parent_child_mappings`: explicit parent-to-child relationship in a family. `confirmed` is derived from the QR preview confirmation or the legacy consent endpoint; the QR confirmation atomically records both consent flags. QR scanning without the confirmation dialog never enables policy delivery.
- `consent_requests`: independently auditable compatibility records. The QR confirmation updates both records atomically; FCM is only a wake-up/notification transport and the server remains authoritative.
- `device_notification_keys`: provider tokens associated with a logical device. Real FCM credentials remain disabled in this deployment.

## Policy and delivery

- `policies`: legacy/global policy document used by Windows and compatibility paths.
- `family_policies`: versioned policy snapshot owned by a Family.
- `device_policy_assignments`: assignment of a Family policy version to a confirmed child device; tracks `pending`, `applied`, and `rejected`.
- `policy_sync_receipts`: latest child-reported local policy state, version, hash/signature status, and whether the assignment was accepted.

A confirmed relationship makes a policy assignment eligible; it does not claim that the device stored the policy. The assignment becomes `applied` only after a later authenticated child sync reports a fresh, accepted policy.

## Operations and release data

- `app_versions`: normalized release metadata; artifact bytes and public bootstrap manifests remain in the artifact store.
- Public latest Android download aliases are `/api/updates/android/cpsm-m/latest.apk` and `/api/updates/android/cpsm-p/latest.apk`; their read-only manifest aliases end in `/manifest.json`.
- `events`: child events and health observations.
- `commands`: parent-to-child commands and acknowledgements.
- `approval_requests`: app-launch approval workflow.
- `parent_sessions`: short-lived parent bearer-session hashes.
- `pairing_sessions`: short-lived, one-time bidirectional pairing sessions issued by either parent or child. Stores issuer type/id, pairing-code hash, claimed mapping ID, and confirmation status; the authenticated opposite role must claim it before the preview confirmation can finalize the mapping.
- `parent_tokens`: legacy/global parent notification-token compatibility.
- `audit_log`: lifecycle and administrative audit events.
- `request_nonces`: replay protection for device-signed requests.
- `storage_meta`: migration/initialization marker.

## Lifecycle

```text
registered_unpaired
  -> pending_consent
  -> confirmed / registered_paired
  -> policy assignment pending
  -> policy assignment applied
  -> permission onboarding and enforcement
```

Automatic registration never creates a parent relationship. Legacy manual mapping creates two consent-request records. QR mapping creates a preview and the scanner's single explicit confirmation atomically approves both compatibility consent records. A QR claim or a declined confirmation never enables policy delivery; a policy assignment is insufficient to claim local policy storage.

### Pairing status notification boundary

`pairing_sessions.status` is authoritative for the Parent QR lifecycle. The current authenticated status route is:

```http
GET /api/parent/pairing-sessions/{sessionId}
```

The route is scoped to the issuing parent session and returns `pending`, `claimed`, `confirmed`, `declined`, or an effective `expired` status when the TTL has elapsed. `mapping_id` links the session to the relationship row and `confirmed_at` records the terminal confirmation time.

FCM does not change this authority boundary. If enabled, the server may send a minimal wake-up containing `type`, `pairing_session_id`, and `status`; the Parent client must re-read the authenticated status route before closing the QR or treating the relationship as confirmed. In the current deployment FCM is disabled and Parent version 19 uses temporary 1.5-second polling. A 30–45-second long-poll fallback is designed but the endpoint and client reconnect logic are not yet implemented.

## Error telemetry and release-change schema (implemented)

The SQLite migration creates the error telemetry tables with `CREATE TABLE IF NOT EXISTS` and persists them through the canonical store. Existing databases are upgraded on server startup without dropping lifecycle data:

- `device_errors`: deduplicated issue aggregate with `fingerprint`, product/version, severity, status, `is_fixed`, `fixed_in_version_code`, and resolution metadata.
- `device_error_occurrences`: one row per uploaded occurrence with `client_error_id`, device/request/correlation IDs, runtime/context JSON, redacted message and stack trace.
- `app_version_changes`: release subtable linked to `(platform, product, version_code)`; records added/modified/fixed/removed/security/compatibility changes, component, change key, issue ID, verification note and timestamp.
- `error_app_version_links`: connects an error to observed, introduced, fixed, regressed, or not-reproduced versions and records verification.

The authenticated device endpoint is:

```http
POST /api/devices/{deviceId}/errors
```

The admin review/version endpoints are:

```http
GET    /api/admin/errors
GET    /api/admin/errors/{errorId}
PATCH  /api/admin/errors/{errorId}
GET    /api/admin/app-versions
POST   /api/admin/app-versions
GET    /api/admin/app-versions/{platform}/{product}/{versionCode}/changes
POST   /api/admin/app-versions/{platform}/{product}/{versionCode}/changes
PATCH  /api/admin/app-versions/{platform}/{product}/{versionCode}/changes/{changeId}
```

`is_fixed=1` is accepted only after a fixed change is linked to an existing immutable App Version and that change has been explicitly verified with a verification note. Publishing a new APK alone does not close an issue. See `API_DESIGN.md` for the full DDL, parameters, status transitions, and upload sequence.

## Verification boundary

Implemented and verified at the server/API level: SQLite lifecycle storage, bidirectional short-lived QR pairing sessions with issuer/claimant role checks, preview confirmation, registration, parent enrollment, mapping, policy assignment/receipt, device/parent API routes, Android runtime compatibility metadata, public Android OTA aliases, and the FCM-disabled status-polling compatibility path. The FCM wake-up and long-poll implementation is not included in this verification claim.

Not yet physically verified: Note8/S21 package-installer approval, Android API 26/31/35/36 device matrix, Device Owner provisioning, Usage Access onboarding, and end-to-end policy commit on a confirmed real-device relationship. Error telemetry upload over a physical Android device and Windows production service deployment remain environment-level verification items.
