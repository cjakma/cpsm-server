# Android app-install request API

This API records a child's request for a parent to review. It is separate from app-launch approval. The server only records the parent's informational decision; it never installs an app, queues an install command, or bypasses Android's consent UI.

After approval, the child must still open Google Play Store and complete the installation with Android's user-controlled installer / Package Installer confirmation. Clients must honor `requires_user_installer_confirmation: true`; approval is not proof that an app was installed.

## Authorization and relationship gate

- Child routes require the device's authenticated CPSM signature (`x-cpsm-device-id` and the configured device-signature headers), bound to the exact HTTP method, URL path, and request body.
- Parent routes require an authenticated parent session with a parent profile. The request must belong to a device currently confirmed into that session's family. Other families receive `404` and do not learn whether a request exists.
- The child device must be registered as Android and currently have a confirmed parent-child relationship. Pending/unpaired relationships and non-Android devices cannot create, list, or cancel app-install requests.
- The server returns only its persisted request fields. Client-supplied status, IDs, family, decision, timestamps, or command data are ignored.

## Routes

### Create — child

`POST /api/devices/{deviceId}/app-install-requests`

Body:

```json
{
  "package_name": "com.example.reader",
  "display_name": "Reader",
  "request_note": "Needed for school"
}
```

All three values are required. Package names must be 2+ dot-separated lowercase Android-style identifiers (`[a-z][a-z0-9_]*`) and at most 255 characters. Display name is trimmed, non-empty, and at most 120 characters. Request note is trimmed, non-empty, and at most 500 characters. A child may have only one pending request per package; a terminal or expired request does not block a new request.

Success (`201`):

```json
{
  "ok": true,
  "request": {
    "request_id": "server-generated-id",
    "device_id": "child-device-id",
    "child_name": "Child",
    "package_name": "com.example.reader",
    "display_name": "Reader",
    "request_note": "Needed for school",
    "status": "pending",
    "created_at": "2026-01-01T00:00:00.000Z",
    "expires_at": "2026-01-02T00:00:00.000Z",
    "decided_at": null,
    "decision_note": null
  },
  "requires_user_installer_confirmation": true
}
```

Requests expire 24 hours after server creation. Expired pending requests transition to `expired` when request state is read or changed.

### List — child

`GET /api/devices/{deviceId}/app-install-requests`

Returns `{ "requests": [<request>] }` for that authenticated child. By default only pending requests are returned; `?status=all` returns that child's complete request history.

### Cancel — child

`POST /api/devices/{deviceId}/app-install-requests/{requestId}/cancel`

Only the owning child can cancel a pending request. Success is `{ "ok": true, "request": <request> }` with `status: "cancelled"`. Repeated cancellation and cancellation after another terminal transition return `409`.

### List — parent

`GET /api/parent/app-install-requests?status=pending|all`

Parent session/profile authentication is required. `status` defaults to `pending`; `all` includes terminal and expired requests. Success is `{ "requests": [<request>] }`, scoped to currently confirmed children in the parent's family.

### Approve or deny — parent

`POST /api/parent/app-install-requests/{requestId}/decision`

Body:

```json
{ "decision": "approve", "decision_note": "Approved for school" }
```

`decision` must be exactly `approve` or `deny`. `decision_note` is optional, trimmed, and limited to 500 characters.

Success:

```json
{
  "ok": true,
  "request": {
    "request_id": "server-generated-id",
    "device_id": "child-device-id",
    "child_name": "Child",
    "package_name": "com.example.reader",
    "display_name": "Reader",
    "request_note": "Needed for school",
    "status": "approved",
    "created_at": "2026-01-01T00:00:00.000Z",
    "expires_at": "2026-01-02T00:00:00.000Z",
    "decided_at": "2026-01-01T01:00:00.000Z",
    "decision_note": "Approved for school"
  },
  "requires_user_installer_confirmation": true
}
```

The `request` object in this response has the same complete field set as the create/list contract above. Only a pending request can transition to `approved` or `denied`; the server sets the decision timestamp and note, audits the decision, and does not enqueue any command. Expired or already-decided requests return `409`; a missing or out-of-family request returns `404`.

## Statuses and errors

Request statuses are `pending`, `approved`, `denied`, `cancelled`, and `expired`. Invalid fields/status filters/decisions return `400`; unauthenticated requests return `401`; unconfirmed relationships and non-Android devices return `409`; duplicate pending package requests return `409`; out-of-scope or missing requests return `404`.

## Persistence

SQLite is canonical, with an additive `app_install_requests` table and a partial unique index for pending `(device_id, package_name)`. The existing JSON fallback stores the same request state and app-install audit entries for installations where SQLite is unavailable.
