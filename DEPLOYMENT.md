# CPSM server integration deployment

- Runtime directory: `/home/ubuntu/web-service/cpsm-server`
- PM2 process: `cpsm-server`
- Local listener: `172.18.0.1:18732`
- Public HTTPS base URL: `https://pm-oci.duckdns.org/cpsm-api`
- PM2 startup file: `/home/ubuntu/web-service/cpsm-server/ecosystem.config.cjs`
- Runtime environment: `/home/ubuntu/web-service/cpsm-server/.env` (mode 0600; do not copy or commit)
- Persistent SQLite data: `/home/ubuntu/web-service/cpsm-server/data`
- Published artifacts: `/home/ubuntu/web-service/cpsm-server/artifacts`

The public route is mounted through the existing NPM/blacklist-guard path. The server reconstructs `/cpsm-api` from `X-Forwarded-Prefix` before verifying signed device requests, so Android child and Windows device signatures remain valid through the path prefix.

Current integration artifacts are:

- `cpsm-m`: `0.1.16-qr-single-confirm` / versionCode `17`
- `cpsm-p`: `0.1.18-parent-qr-auto-close` / versionCode `19`
- `cpsm-c`: `0.1.2-bootstrap-update` / versionCode `3`

The latest published Android artifacts were read back from the public manifest and download routes. The Child artifact is versionCode `17` with SHA-256 `c494f78574b069be060bb0ecf9dfe57cb6c35e1d1c95adaab65af4512263c297`; the Parent artifact is versionCode `19` with SHA-256 `91f1015a4df0c27b5ba843f95abc2060c888f33e2b2cdd848e363ce9a3d7153f`. Both use the expected signing certificate digest `6c28052e2c1eb827cdddaa8931e1d2b30c260cadcd0f237113d30b6d04905d3c`.

All clients use:

```text
https://pm-oci.duckdns.org/cpsm-api
```

Fresh installs use these read-only bootstrap update endpoints before device enrollment:

```text
GET /api/updates/manifest?platform=android&product=cpsm-m
GET /api/updates/download?platform=android&product=cpsm-m
GET /api/updates/manifest?platform=android&product=cpsm-p
GET /api/updates/download?platform=android&product=cpsm-p
GET /api/updates/manifest?platform=windows&product=cpsm-c
GET /api/updates/download?platform=windows&product=cpsm-c
```

The manifest is compared by numeric `versionCode`. Clients download only when the server version is newer, then verify size, SHA-256, package identity, and signing certificate. Android hands the verified APK to the system Package Installer, so the user must approve installation. Registered devices retain the authenticated device/parent update routes.

FCM is intentionally disabled. Normal Parent enrollment is automatic: `cpsm-p` generates an Android Keystore public key, calls `/api/parent/auth/auto-enroll`, and stores only the returned short-lived session encrypted with Android Keystore. The `.env` bootstrap code remains only for controlled legacy/admin recovery and must never be exposed to normal users, APKs, QR payloads, chat, or source files.

For Parent QR completion, version 19 currently uses the authenticated pairing-session status route as a temporary 1.5-second polling path. The approved final design is an FCM wake-up followed by one authenticated status read, with a 30–45-second Long Polling fallback when FCM is disabled or lost. FCM is never authoritative, and the Long Polling endpoint/client handler are not deployed yet.

For a Windows child device, create a device secret through the authenticated admin endpoint, then place the same secret only in the Windows agent's local policy. Do not include it in a ZIP or source archive.
