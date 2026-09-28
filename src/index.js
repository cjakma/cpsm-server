const http = require("http");
const path = require("path");
const crypto = require("crypto");
const { Store, StoreError } = require("./store");
const { FcmSender } = require("./fcm");
const { Authenticator, AuthError } = require("./auth");
const { ArtifactStore, ArtifactError } = require("./artifacts");
const { ScreenTimeError, sanitizeDeviceCommand, sanitizeScreenTime } = require("./screenTime");
const { LocationError, sanitizeGeofence, sanitizeLocationConsent, sanitizeLocationSample } = require("./location");

const ONLINE_WINDOW_MS = 3 * 60 * 1000;
const STALE_WINDOW_MS = 30 * 60 * 1000;

const MAX_BODY_BYTES = Number(process.env.CPSM_MAX_BODY_BYTES || 512 * 1024);

function parseArgs(args) {
  const parsed = {
    port: Number(process.env.PORT || 18732),
    host: process.env.CPSM_SERVER_HOST || "127.0.0.1",
    dataDir: process.env.CPSM_SERVER_DATA_DIR || path.join(process.cwd(), "data"),
    dev: false
  };
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--port") {
      parsed.port = Number(args[index + 1]);
      index += 1;
    } else if (args[index] === "--host") {
      parsed.host = args[index + 1] || parsed.host;
      index += 1;
    } else if (args[index] === "--data-dir") {
      parsed.dataDir = args[index + 1];
      index += 1;
    } else if (args[index] === "--dev") {
      parsed.dev = true;
    }
  }
  if (!Number.isInteger(parsed.port) || parsed.port < 1 || parsed.port > 65535) {
    throw new Error("invalid_port");
  }
  return parsed;
}

function logger() {
  return {
    info: (event, payload = {}) => console.log(JSON.stringify({ level: "info", event, payload })),
    warn: (event, payload = {}) => console.warn(JSON.stringify({ level: "warn", event, payload })),
    error: (event, payload = {}) => console.error(JSON.stringify({ level: "error", event, payload }))
  };
}

function sendJson(res, status, body) {
  if (res.headersSent) {
    res.end();
    return;
  }
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    let rejected = false;
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      if (rejected) return;
      data += chunk;
      if (Buffer.byteLength(data, "utf8") > MAX_BODY_BYTES) {
        rejected = true;
        reject(new StoreError("request_body_too_large", 413));
        req.resume();
      }
    });
    req.on("end", () => {
      if (rejected) return;
      if (!data) {
        resolve({ raw: "", value: {} });
        return;
      }
      try {
        resolve({ raw: data, value: JSON.parse(data) });
      } catch (_) {
        reject(new StoreError("invalid_json", 400));
      }
    });
    req.on("error", (error) => {
      if (!rejected) reject(error);
    });
  });
}

function bodyObject(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new StoreError("invalid_body", 400);
  }
  return body;
}

function androidCompatibility(metadata = {}) {
  const apiLevel = Number(metadata.android_api_level || 0);
  if (!apiLevel) return { status: "unknown", apiLevel: 0, minSupportedApi: 26, testedThroughApi: 36 };
  return {
    status: apiLevel < 26 ? "unsupported" : (apiLevel <= 36 ? "supported" : "review_required"),
    apiLevel,
    minSupportedApi: 26,
    testedThroughApi: 36,
    updateVerifier: apiLevel < 28 ? "legacy_signatures" : "signing_info"
  };
}

function publicKeyPem(store) {
  return store.publicKey && store.publicKey.export({ type: "spki", format: "pem" });
}

function sanitizeRules(rules) {
  if (!Array.isArray(rules) || rules.length > 500) {
    throw new StoreError("invalid_rules", 400);
  }
  return rules.map((rule) => {
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) {
      throw new StoreError("invalid_rule", 400);
    }
    const platform = rule.platform === "android" ? "android" : "windows";
    const match = rule.match && typeof rule.match === "object" ? rule.match : {
      type: platform === "android" ? "package" : "processName",
      ...(platform === "android"
        ? { packageName: String(rule.packageName || rule.processName || "") }
        : { processName: String(rule.processName || rule.name || "") })
    };
    const action = ["monitor", "block", "require_approval", "allow"].includes(rule.action)
      ? rule.action
      : "monitor";
    const name = String(rule.name || rule.processName || rule.packageName || "rule").slice(0, 256);
    if (!name.trim()) throw new StoreError("rule_name_required", 400);
    const dailyLimitMinutes = Number(rule.dailyLimitMinutes || rule.daily_limit_minutes || 0);
    if (!Number.isInteger(dailyLimitMinutes) || dailyLimitMinutes < 0 || dailyLimitMinutes > 1440) {
      throw new StoreError("invalid_rule_daily_limit", 400);
    }
    return {
      id: String(rule.id || crypto.randomUUID()).slice(0, 128),
      name,
      platform,
      match,
      action,
      ...(dailyLimitMinutes > 0 ? { dailyLimitMinutes } : {}),
      excludedUntil: String(rule.excludedUntil || "").slice(0, 64),
      reason: String(rule.reason || "parent_policy").slice(0, 256)
    };
  });
}

function normalizeDeviceId(value) {
  const deviceId = decodeURIComponent(String(value || ""));
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(deviceId)) {
    throw new StoreError("invalid_device_id", 400);
  }
  return deviceId;
}

function publicUpdateSelector(requestUrl) {
  const platform = String(requestUrl.searchParams.get("platform") || "");
  const product = String(requestUrl.searchParams.get("product") || "");
  const expectedPlatform = {
    "android:cpsm-m": "android",
    "android:cpsm-p": "android",
    "windows:cpsm-c": "windows"
  }[`${platform}:${product}`];
  if (!expectedPlatform || expectedPlatform !== platform) {
    throw new ArtifactError("invalid_update_selector", 400);
  }
  return { platform, product };
}

function bootstrapMatches(value) {
  const expected = String(process.env.CPSM_BOOTSTRAP_CODE || "");
  const supplied = String(value || "");
  if (!expected || supplied.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(supplied, "utf8"), Buffer.from(expected, "utf8"));
}

async function notifyParentForEvent(fcm, event, request) {
  const payload = event.payload || {};
  const childName = request ? request.childName : event.childName;
  const appName = request ? request.appName : (payload.appName || "앱");
  return fcm.sendToParents({
    type: request ? "cpsm_app_launch_request" : "cpsm_app_event",
    request_id: request ? request.id : "",
    event_id: event.id || event.eventId,
    device_id: event.deviceId,
    child_name: childName || "자녀",
    device_name: request ? request.deviceName : "",
    app_name: appName,
    action: payload.action || "",
    matched_rule_id: payload.matchedRuleId || payload.ruleId || "",
    pid: String(payload.pid || "")
  }, {
    title: `${childName || "자녀"} 앱 이벤트`,
    body: `${childName || "자녀"}가 ${appName}을 실행했습니다.`
  });
}

// Screen-time requests are answered with bonus minutes; app-launch requests keep the
// original temporary-allow / terminate commands.
function approvalAllowCommand(store, request, idempotencyKey) {
  if (request.kind === "screen_time") {
    return store.queueCommand(request.deviceId, "screen_time.bonus", { minutes: Number(request.requestedMinutes || 30), requestId: request.id, issuedAt: new Date().toISOString() }, { idempotencyKey, expiryMs: 60 * 60 * 1000 });
  }
  return store.queueCommand(request.deviceId, "app.allow.temporary", { processName: request.appName, minutes: 120, requestId: request.id }, { idempotencyKey });
}

function approvalDenyCommand(store, request, idempotencyKey) {
  if (request.kind === "screen_time") return null;
  return store.queueCommand(request.deviceId, "app.terminate", { pid: request.pid, processName: request.appName, requestId: request.id }, { idempotencyKey });
}

// Parent-facing summary. Presence is derived from the last authenticated sync so a child
// that powers off, loses network or kills the agent shows up as stale/offline.
function deviceSummary(store, deviceId) {
  const device = store.state.devices[deviceId] || {};
  const health = device.health && typeof device.health === "object" ? device.health : {};
  const lastSeenMs = Date.parse(device.lastSeenAt || "") || 0;
  const ageMs = lastSeenMs ? Date.now() - lastSeenMs : null;
  const presence = ageMs === null ? "unknown" : (ageMs <= ONLINE_WINDOW_MS ? "online" : (ageMs <= STALE_WINDOW_MS ? "stale" : "offline"));
  const protection = health.protection && typeof health.protection === "object" ? health.protection : {};
  return {
    device_id: deviceId,
    platform: device.platform || "unknown",
    device_name: device.deviceName || deviceId,
    child_name: device.childName || "",
    presence,
    last_seen_at: device.lastSeenAt || null,
    last_seen_age_ms: ageMs,
    local_policy_version: Number(device.localPolicyVersion || 0),
    current_app: device.currentApp || "",
    screen_time: health.screen_time && typeof health.screen_time === "object" ? health.screen_time : null,
    protection: {
      level: String(protection.level || "unknown"),
      reasons: Array.isArray(protection.reasons) ? protection.reasons.slice(0, 10) : [],
      accessibility: typeof protection.accessibility === "boolean" ? protection.accessibility : null,
      enforcer: typeof protection.enforcer === "string" ? protection.enforcer : null,
      boot_id: typeof protection.boot_id === "string" ? protection.boot_id : null,
      uptime_ms: Number.isSafeInteger(protection.uptime_ms) && protection.uptime_ms >= 0 ? protection.uptime_ms : null,
      device_owner: health.device_owner === undefined ? null : Boolean(health.device_owner),
      usage_access: health.usage_access === undefined ? null : Boolean(health.usage_access),
      // Null means readiness has not been measured, never a zero-ms success.
      boot_guard_gap_ms: Number.isSafeInteger(protection.boot_guard_gap_ms) && protection.boot_guard_gap_ms >= 0
        ? protection.boot_guard_gap_ms : null
    },
    compatibility: device.platform === "android" ? androidCompatibility(device.metadata || {}) : null,
    metadata: device.metadata || {}
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const log = logger();
  const store = new Store(path.resolve(options.dataDir));
  const locationRetentionTimer = setInterval(() => {
    try {
      if (store.purgeLocationData()) store.save();
    } catch (error) {
      log.warn("location.retention_prune_failed", { code: String(error && error.code || "storage_error") });
    }
  }, 60 * 60 * 1000);
  if (typeof locationRetentionTimer.unref === "function") locationRetentionTimer.unref();
  const fcm = new FcmSender(store, log);
  const auth = new Authenticator({ store, dev: options.dev });
  const artifacts = new ArtifactStore(
    process.env.CPSM_ARTIFACTS_DIR || path.join(process.cwd(), "artifacts")
  );

  const server = http.createServer(async (req, res) => {
    const requestUrl = new URL(req.url, "http://localhost");
    const rawPathname = requestUrl.pathname;
    const pathname = rawPathname.startsWith("/v1/parent")
      ? `/api/parent${rawPathname.slice("/v1/parent".length)}`
      : rawPathname;
    const requestPathPrefix = String(req.headers["x-forwarded-prefix"] || "").trim().replace(/\/$/, "");
    const requestPath = `${requestPathPrefix}${rawPathname}${requestUrl.search}`;
    let body = { raw: "", value: {} };
    try {
      if (["POST", "PUT", "PATCH"].includes(req.method)) body = await readBody(req);
      const value = bodyObject(body.value);

      if (req.method === "GET" && pathname === "/api/status") {
        sendJson(res, 200, {
          ok: true,
          service: "cpsm-server",
          storage: store.storageMode(),
          devices: Object.keys(store.state.devices).length,
          pendingCommands: store.state.commands.filter((command) => ["queued", "delivered"].includes(command.state)).length,
          policyVersion: store.state.policy.version,
          fcmEnabled: fcm.enabled(),
          authMode: auth.mode
        });
        return;
      }

      // Bootstrap update endpoints are deliberately read-only and unauthenticated. They allow a
      // freshly installed client to compare/download a signed artifact before its device key has
      // been enrolled. Registered clients continue to use the authenticated device/parent routes.
      const stableAndroidUpdate = pathname.match(/^\/api\/updates\/android\/(cpsm-m|cpsm-p)\/(manifest\.json|latest\.apk)$/);
      if (req.method === "GET" && stableAndroidUpdate) {
        const product = stableAndroidUpdate[1];
        const resource = stableAndroidUpdate[2];
        if (resource === "manifest.json") {
          artifacts.sendManifest(res, "android", product, `/api/updates/android/${product}/latest.apk`);
        } else {
          artifacts.sendArtifact(res, "android", product);
        }
        return;
      }

      if (req.method === "GET" && pathname === "/api/updates/manifest") {
        const { platform, product } = publicUpdateSelector(requestUrl);
        artifacts.sendManifest(
          res,
          platform,
          product,
          `/api/updates/download?platform=${encodeURIComponent(platform)}&product=${encodeURIComponent(product)}`
        );
        return;
      }

      if (req.method === "GET" && pathname === "/api/updates/download") {
        const { platform, product } = publicUpdateSelector(requestUrl);
        artifacts.sendArtifact(res, platform, product);
        return;
      }

      if (req.method === "POST" && pathname === "/api/admin/portal-device/token") {
        auth.requireAdmin(req);
        store.registerParentToken(value.fcm_token || value.token);
        sendJson(res, 200, { ok: true, registered: true });
        return;
      }

      if (pathname === "/api/admin/app-versions" && req.method === "GET") {
        auth.requireAdmin(req);
        const versions = store.listAppVersions({
          platform: requestUrl.searchParams.get("platform") || "",
          product: requestUrl.searchParams.get("product") || "",
          limit: requestUrl.searchParams.get("limit") || 100
        });
        sendJson(res, 200, { ok: true, versions });
        return;
      }
      if (pathname === "/api/admin/app-versions" && req.method === "POST") {
        auth.requireAdmin(req);
        const version = store.registerAppVersion(value);
        sendJson(res, 201, { ok: true, version });
        return;
      }

      if (pathname === "/api/admin/errors" && req.method === "GET") {
        auth.requireAdmin(req);
        const result = store.listDeviceErrors({
          status: requestUrl.searchParams.get("status") || "",
          product: requestUrl.searchParams.get("product") || "",
          limit: requestUrl.searchParams.get("limit") || 100,
          cursor: requestUrl.searchParams.get("cursor") || ""
        });
        sendJson(res, 200, { ok: true, errors: result.errors, next_cursor: result.nextCursor, total: result.total });
        return;
      }
      const adminError = pathname.match(/^\/api\/admin\/errors\/([^/]+)$/);
      if (adminError && req.method === "GET") {
        auth.requireAdmin(req);
        const error = store.getDeviceError(decodeURIComponent(adminError[1]));
        if (!error) {
          sendJson(res, 404, { ok: false, error: "error_not_found" });
          return;
        }
        sendJson(res, 200, { ok: true, error });
        return;
      }
      if (adminError && req.method === "PATCH") {
        auth.requireAdmin(req);
        sendJson(res, 200, { ok: true, error: store.updateDeviceError(decodeURIComponent(adminError[1]), value) });
        return;
      }

      const versionChanges = pathname.match(/^\/api\/admin\/app-versions\/([^/]+)\/([^/]+)\/(\d+)\/changes$/);
      if (versionChanges && req.method === "GET") {
        auth.requireAdmin(req);
        sendJson(res, 200, {
          ok: true,
          changes: store.listAppVersionChanges({ platform: decodeURIComponent(versionChanges[1]), product: decodeURIComponent(versionChanges[2]), versionCode: Number(versionChanges[3]) })
        });
        return;
      }
      if (versionChanges && req.method === "POST") {
        auth.requireAdmin(req);
        const change = store.createAppVersionChange({ ...value, platform: decodeURIComponent(versionChanges[1]), product: decodeURIComponent(versionChanges[2]), version_code: Number(versionChanges[3]) });
        sendJson(res, 201, { ok: true, change });
        return;
      }
      const versionChange = pathname.match(/^\/api\/admin\/app-versions\/([^/]+)\/([^/]+)\/(\d+)\/changes\/([^/]+)$/);
      if (versionChange && req.method === "PATCH") {
        auth.requireAdmin(req);
        const change = store.verifyAppVersionChange(decodeURIComponent(versionChange[4]), {
          verified: value.is_verified === true || value.verified === true,
          verificationNote: value.verification_note || value.verificationNote || ""
        });
        sendJson(res, 200, { ok: true, change });
        return;
      }

      if (req.method === "POST" && pathname === "/api/parent/auth/enroll") {
        if (!process.env.CPSM_BOOTSTRAP_CODE) throw new AuthError("bootstrap_not_configured", 503);
        if (!bootstrapMatches(value.bootstrap_code)) throw new AuthError("invalid_bootstrap_code", 401);
        const familyId = String(value.family_id || `family-${String(value.device_fingerprint || "default").slice(0, 64)}`);
        const metadata = value.metadata && typeof value.metadata === "object" ? value.metadata : {};
        const parent = store.ensureParentProfile({
          familyId,
          deviceFingerprint: String(value.device_fingerprint || ""),
          publicKey: String(value.device_pubkey || ""),
          displayName: String(value.parent_name || "부모").slice(0, 256),
          metadata: {
            android_api_level: Number(metadata.android_api_level || 0) || 0,
            os_release: String(metadata.os_release || "").slice(0, 64),
            security_patch: String(metadata.security_patch || "").slice(0, 64),
            manufacturer: String(metadata.manufacturer || "").slice(0, 128),
            model: String(metadata.model || "").slice(0, 128),
            device: String(metadata.device || "").slice(0, 128),
            product: String(metadata.product || "").slice(0, 128),
            app_version_code: Number(metadata.app_version_code || 0) || 0,
            app_version_name: String(metadata.app_version_name || "").slice(0, 128)
          }
        });
        const session = store.issueParentSession(
          familyId,
          Number(process.env.CPSM_PARENT_SESSION_TTL_MS || 3600000),
          parent.parentId
        );
        store.audit("parent", session.familyId, "parent_session_enrolled", null, {
          platform: String(value.platform || "unknown"),
          deviceFingerprint: String(value.device_fingerprint || "").slice(0, 256)
        });
        sendJson(res, 200, {
          ok: true,
          session: {
            session_token: session.token,
            family_id: session.familyId,
            parent_id: parent.parentId,
            expires_at: session.expiresAt,
            device_compatibility: androidCompatibility(parent.metadata || {})
          }
        });
        return;
      }

      if (req.method === "POST" && pathname === "/api/devices/register") {
        const deviceId = normalizeDeviceId(value.device_id || value.deviceId);
        const metadata = value.metadata && typeof value.metadata === "object" ? value.metadata : {};
        const registration = store.registerChildDevice({
          deviceId,
          publicKey: String(value.public_key || value.publicKey || ""),
          authMode: value.auth_mode,
          deviceName: value.device_name || value.deviceName,
          childName: value.child_name || value.childName,
          platform: value.platform === "windows" ? "windows" : "android",
          metadata: {
            wifi_ip: String(metadata.wifi_ip || metadata.requested_wifi_ip || "").slice(0, 64),
            phone_number: String(metadata.phone_number || "").slice(0, 64),
            model: String(metadata.model || "").slice(0, 128),
            manufacturer: String(metadata.manufacturer || "").slice(0, 128),
            device: String(metadata.device || "").slice(0, 128),
            product: String(metadata.product || "").slice(0, 128),
            android_api_level: Number(metadata.android_api_level || 0) || 0,
            os_release: String(metadata.os_release || "").slice(0, 64),
            security_patch: String(metadata.security_patch || "").slice(0, 64),
            app_version_code: Number(metadata.app_version_code || 0) || 0,
            app_version_name: String(metadata.app_version_name || "").slice(0, 128),
            windows_release: String(metadata.windows_release || "").slice(0, 64),
            windows_build: String(metadata.windows_build || "").slice(0, 64),
            hostname: String(metadata.hostname || "").slice(0, 128)
          }
        });
        store.audit("child", deviceId, "child_device_registered", req.headers["x-request-id"] || null, { registrationStatus: registration.registrationStatus });
        sendJson(res, 201, { ok: true, device_id: deviceId, registration_status: registration.registrationStatus, relationship_status: "unpaired", policy_ready: false });
        return;
      }

      const adminDevice = pathname.match(/^\/api\/admin\/devices\/([^/]+)\/secret$/);
      if (req.method === "POST" && adminDevice) {
        auth.requireAdmin(req);
        const deviceId = normalizeDeviceId(adminDevice[1]);
        const hasSecret = typeof value.secret === "string" && value.secret.length >= 32 && value.secret.length <= 4096;
        const hasPublicKey = typeof value.publicKey === "string" && value.publicKey.length >= 32 && value.publicKey.length <= 8192;
        if (!hasSecret && !hasPublicKey) {
          throw new StoreError("invalid_device_credential", 400);
        }
        const patch = {
          platform: value.platform === "android" ? "android" : "windows",
          deviceName: String(value.deviceName || deviceId).slice(0, 256),
          childName: String(value.childName || "자녀").slice(0, 256)
        };
        if (hasSecret) patch.hmacSecret = value.secret;
        if (hasPublicKey) patch.publicKey = value.publicKey;
        store.upsertDevice(deviceId, patch);
        sendJson(res, 200, { ok: true, deviceId });
        return;
      }

      const registrationStatus = pathname.match(/^\/api\/devices\/([^/]+)\/registration-status$/);
      if (req.method === "GET" && registrationStatus) {
        const deviceId = normalizeDeviceId(registrationStatus[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const status = store.getRegistrationStatus(deviceId);
        sendJson(res, status.device ? 200 : 404, status.device ? {
          ok: true,
          device_id: deviceId,
          registration_status: status.registrationStatus,
          relationship_status: status.relationshipStatus,
          policy_ready: status.policyReady,
          policy_assignment: status.policyAssignment ? { assignment_id: status.policyAssignment.assignmentId, version: status.policyAssignment.version, status: status.policyAssignment.status, rejection_reason: status.policyAssignment.rejectionReason } : null,
          policy_receipt: status.policyReceipt ? { version: status.policyReceipt.version, status: status.policyReceipt.accepted ? "applied" : "pending_or_rejected", local_state: status.policyReceipt.localState, signature_status: status.policyReceipt.signatureStatus } : null,
          device_compatibility: status.device ? {
            ...androidCompatibility(status.device.metadata || {}),
            os_release: String((status.device.metadata || {}).os_release || ""),
            security_patch: String((status.device.metadata || {}).security_patch || ""),
            manufacturer: String((status.device.metadata || {}).manufacturer || ""),
            model: String((status.device.metadata || {}).model || ""),
            device: String((status.device.metadata || {}).device || ""),
            product: String((status.device.metadata || {}).product || "")
          } : null,
          consent_requests: status.consentRequests.map((item) => ({ request_id: item.requestId, mapping_id: item.mappingId, status: item.status, created_at: item.createdAt, expires_at: item.expiresAt })),
          mappings: status.mappings.map((item) => ({ mapping_id: item.mappingId, family_id: item.familyId, status: item.status, parent_consent: item.parentConsent, child_consent: item.childConsent }))
        } : { ok: false, error: "device_not_registered" });
        return;
      }

      const childConsent = pathname.match(/^\/api\/devices\/([^/]+)\/consent-requests\/([^/]+)\/decision$/);
      if (req.method === "POST" && childConsent) {
        const deviceId = normalizeDeviceId(childConsent[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const child = Object.values(store.state.childProfiles).find((item) => item.deviceId === deviceId);
        if (!child) throw new StoreError("child_profile_not_found", 404);
        const requestId = decodeURIComponent(childConsent[2]);
        const consentRequest = store.state.consentRequests[requestId];
        if (!consentRequest || consentRequest.recipientType !== "child" || consentRequest.recipientId !== child.childId) throw new StoreError("consent_request_not_found", 404);
        const mapping = store.setRelationshipConsent({ mappingId: consentRequest.mappingId, recipientType: "child", recipientId: child.childId, consent: value.consent === true || value.decision === "accept" || value.decision === "approve" });
        await fcm.sendToDeviceIds([mapping.parentId], { type: "cpsm_relationship_consent", mapping_id: mapping.mappingId, relationship_status: mapping.status, child_consent: String(mapping.childConsent) }, { title: "CPSM 자녀 동의 상태", body: mapping.status === "confirmed" ? "부모-자녀 관계가 확정되었습니다." : "자녀 동의가 저장되었습니다." });
        sendJson(res, 200, { ok: true, mapping_id: mapping.mappingId, status: mapping.status, parent_consent: mapping.parentConsent, child_consent: mapping.childConsent, policy_ready: mapping.status === "confirmed" });
        return;
      }

      const childLocationConsent = pathname.match(/^\/api\/devices\/([^/]+)\/location-consent$/);
      if (req.method === "POST" && childLocationConsent) {
        const deviceId = normalizeDeviceId(childLocationConsent[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const input = sanitizeLocationConsent(value);
        const prior = store.state.locationConsents[deviceId];
        const familyId = store.familyIdForDevice(deviceId) || (prior && prior.familyId) || "";
        if (!familyId) throw new StoreError("parent_mapping_required", 409);
        const consent = store.setLocationConsent({
          deviceId, familyId, actorType: "child", consent: input.consent,
          permissionGranted: input.permissionGranted, actorId: deviceId,
          requestId: req.headers["x-request-id"] || null
        });
        sendJson(res, 200, { ok: true, location_consent: consent });
        return;
      }

      const childLocationResult = pathname.match(/^\/api\/devices\/([^/]+)\/location-requests\/([^/]+)\/result$/);
      if (req.method === "POST" && childLocationResult) {
        const deviceId = normalizeDeviceId(childLocationResult[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const request = store.reportLocationRequestResult({
          deviceId, requestId: decodeURIComponent(childLocationResult[2]),
          status: value.status, code: value.code
        });
        sendJson(res, 200, { ok: true, request });
        return;
      }

      const childLocationSample = pathname.match(/^\/api\/devices\/([^/]+)\/location-samples$/);
      if (req.method === "POST" && childLocationSample) {
        const deviceId = normalizeDeviceId(childLocationSample[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const sample = sanitizeLocationSample(value);
        const result = store.recordLocationSample({ deviceId, sample });
        sendJson(res, result.duplicate ? 200 : 201, {
          ok: true, duplicate: result.duplicate, sample_id: result.sample.sampleId,
          captured_at: result.sample.capturedAt, transitions: result.transitions
        });
        return;
      }

      const notificationKey = pathname.match(/^\/api\/devices\/([^/]+)\/notification-key$/);
      if (req.method === "POST" && notificationKey) {
        const deviceId = normalizeDeviceId(notificationKey[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const result = store.addNotificationKey({ deviceId, provider: String(value.provider || "fcm"), token: String(value.token || value.fcm_token || "") });
        sendJson(res, 200, { ok: true, ...result });
        return;
      }

      const deviceEvents = pathname.match(/^\/api\/devices\/([^/]+)\/events$/);
      if (req.method === "POST" && deviceEvents) {
        const deviceId = normalizeDeviceId(deviceEvents[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const stored = store.addEvents(deviceId, value.events || []);
        for (const event of stored) {
          const action = event.payload && event.payload.action;
          if (action === "require_approval" && !store.pendingRequestForPid(deviceId, event.payload.pid)) {
            const request = store.createApprovalRequest(deviceId, event);
            await notifyParentForEvent(fcm, event, request);
          } else if (["monitor", "block"].includes(action)) {
            await notifyParentForEvent(fcm, event, null);
          }
        }
        sendJson(res, 200, {
          ok: true,
          received: stored.length,
          acknowledgedEventIds: stored.map((event) => event.eventId),
          acknowledgedSequences: stored.map((event) => event.sequence).filter((sequence) => sequence != null)
        });
        return;
      }

      const deviceErrors = pathname.match(/^\/api\/devices\/([^/]+)\/errors$/);
      if (req.method === "POST" && deviceErrors) {
        const deviceId = normalizeDeviceId(deviceErrors[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const result = store.recordDeviceErrors({
          deviceId,
          payload: value,
          requestId: req.headers["x-request-id"] || value.client_request_id || null
        });
        sendJson(res, 202, { ok: true, ...result, next_retry_after_ms: 0 });
        return;
      }

      const heartbeat = pathname.match(/^\/api\/devices\/([^/]+)\/heartbeat$/);
      if (req.method === "POST" && heartbeat) {
        const deviceId = normalizeDeviceId(heartbeat[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        store.upsertDevice(deviceId, {
          deviceName: String(value.hostname || value.deviceName || deviceId).slice(0, 256),
          childName: String(value.childName || "자녀").slice(0, 256),
          platform: value.platform === "android" ? "android" : "windows",
          status: String(value.status || "running").slice(0, 64),
          currentApp: String(value.currentApp || value.current_app || "").slice(0, 256),
          health: value.health && typeof value.health === "object" ? value.health : {}
        });
        sendJson(res, 200, { ok: true });
        return;
      }

      const sync = pathname.match(/^\/api\/devices\/([^/]+)\/sync$/);
      if (req.method === "POST" && sync) {
        const deviceId = normalizeDeviceId(sync[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const status = value.status && typeof value.status === "object" ? value.status : {};
        const device = store.upsertDevice(deviceId, {
          deviceName: String(value.deviceName || value.hostname || deviceId).slice(0, 256),
          childName: String(value.childName || "자녀").slice(0, 256),
          platform: value.platform === "android" ? "android" : "windows",
          status: String(status.status || "running").slice(0, 64),
          currentApp: String(status.current_app || status.currentApp || "").slice(0, 256),
          localPolicyVersion: Number(value.local_policy_version || 0),
          lastEventSeq: Number(value.last_event_seq || 0),
          health: status.health && typeof status.health === "object" ? status.health : {}
        });
        // Android queues events locally and uploads them with sync; ack the highest sequence seen.
        let acceptedEventSeq = -1;
        if (Array.isArray(value.events) && value.events.length) {
          const mapped = [];
          for (const event of value.events.slice(0, 100)) {
            const seq = Number(event && event.seq);
            if (!Number.isInteger(seq) || seq <= 0) continue;
            acceptedEventSeq = Math.max(acceptedEventSeq, seq);
            const type = String(event.type || "unknown").slice(0, 64);
            if (type === "health_check") continue; // current health travels in status.health
            const timestamp = Number(event.timestamp_ms);
            mapped.push({
              eventId: `seq-${seq}`,
              sequence: seq,
              type: type === "foreground_app" ? "app.foreground" : type,
              eventTime: new Date(Number.isFinite(timestamp) && timestamp > 0 ? timestamp : Date.now()).toISOString(),
              payload: type === "foreground_app"
                ? { packageName: String(event.package_name || "").slice(0, 256) }
                : (event.details && typeof event.details === "object" && !Array.isArray(event.details) ? event.details : {})
            });
          }
          const stored = mapped.length ? store.addEvents(deviceId, mapped) : [];
          // A child's "more time" request becomes a parent approval request (deduplicated by event id).
          for (const event of stored.filter((item) => item.type === "time_request")) {
            if (!store.state.approvalRequests.some((request) => request.eventId === event.eventId && request.deviceId === deviceId)) {
              store.createApprovalRequest(deviceId, { ...event, payload: { ...event.payload, appName: "추가 사용시간" } });
            }
          }
        }
        const commands = store.pollCommands(deviceId);
        const registration = store.getRegistrationStatus(deviceId);
        const policyReceipt = store.recordPolicySyncReceipt(deviceId, status.policy && typeof status.policy === "object" ? status.policy : {});
        // Self-registered (key-based) children of any platform stay gated until the relationship is confirmed.
        const androidPolicyBlocked = (device.platform === "android" || Boolean(registration.child)) && !registration.policyReady;
        const signedPolicy = androidPolicyBlocked ? null : store.getSignedPolicy(deviceId);
        sendJson(res, 200, {
          ok: true,
          server_time: new Date().toISOString(),
          device,
          registration: {
            status: registration.registrationStatus,
            relationship_status: registration.relationshipStatus,
            policy_ready: registration.policyReady
          },
          policy_receipt: { status: policyReceipt.accepted ? "applied" : "pending_or_rejected", version: policyReceipt.version, local_state: policyReceipt.localState, signature_status: policyReceipt.signatureStatus },
          policy: androidPolicyBlocked ? {
            available: false,
            changed: false,
            version: 0,
            hash: "",
            canonical_hash: "",
            reason: registration.relationshipStatus === "unpaired" ? "parent_mapping_required" : "mutual_consent_required"
          } : {
            available: true,
            changed: Number(value.local_policy_version || 0) < Number(signedPolicy.version || 0),
            version: signedPolicy.version,
            hash: signedPolicy.canonicalHash,
            canonical_hash: signedPolicy.canonicalHash,
            download_url: `/api/devices/${encodeURIComponent(deviceId)}/policy?version=${signedPolicy.version}`
          },
          commands,
          accepted_event_seq: acceptedEventSeq,
          next_sync_after_ms: 30000 + Math.floor(Math.random() * 15000)
        });
        return;
      }

      const policy = pathname.match(/^\/api\/devices\/([^/]+)\/policy$/);
      if (req.method === "GET" && policy) {
        const deviceId = normalizeDeviceId(policy[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const registration = store.getRegistrationStatus(deviceId);
        const device = store.state.devices[deviceId];
        if (device && (device.platform === "android" || registration.child) && !registration.policyReady) {
          sendJson(res, 409, { ok: false, error: "policy_not_ready", reason: registration.relationshipStatus === "unpaired" ? "parent_mapping_required" : "mutual_consent_required" });
          return;
        }
        sendJson(res, 200, { ...store.getSignedPolicy(deviceId) });
        return;
      }

      const updateManifest = pathname.match(/^\/api\/devices\/([^/]+)\/updates\/manifest$/);
      if (req.method === "GET" && updateManifest) {
        const deviceId = normalizeDeviceId(updateManifest[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const product = String(requestUrl.searchParams.get("product") || "");
        const device = store.state.devices[deviceId];
        const expectedProduct = device && device.platform === "android" ? "cpsm-m" : "cpsm-c";
        if (product !== expectedProduct) throw new ArtifactError("artifact_product_not_for_device", 403);
        artifacts.sendManifest(
          res,
          expectedProduct === "cpsm-m" ? "android" : "windows",
          product,
          `/api/devices/${encodeURIComponent(deviceId)}/updates/download?product=${encodeURIComponent(product)}`
        );
        return;
      }

      const updateDownload = pathname.match(/^\/api\/devices\/([^/]+)\/updates\/download$/);
      if (req.method === "GET" && updateDownload) {
        const deviceId = normalizeDeviceId(updateDownload[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const product = String(requestUrl.searchParams.get("product") || "");
        const device = store.state.devices[deviceId];
        const expectedProduct = device && device.platform === "android" ? "cpsm-m" : "cpsm-c";
        if (product !== expectedProduct) throw new ArtifactError("artifact_product_not_for_device", 403);
        artifacts.sendArtifact(res, expectedProduct === "cpsm-m" ? "android" : "windows", product);
        return;
      }

      const pollCommands = pathname.match(/^\/api\/devices\/([^/]+)\/commands\/poll$/);
      if (req.method === "GET" && pollCommands) {
        const deviceId = normalizeDeviceId(pollCommands[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        sendJson(res, 200, { commands: store.pollCommands(deviceId) });
        return;
      }

      const commandResult = pathname.match(/^\/api\/devices\/([^/]+)\/commands\/([^/]+)\/result$/);
      if (req.method === "POST" && commandResult) {
        const deviceId = normalizeDeviceId(commandResult[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const commandId = decodeURIComponent(commandResult[2]);
        const command = store.completeCommand(deviceId, commandId, value);
        if (!command) {
          sendJson(res, 404, { ok: false, error: "command_not_found" });
          return;
        }
        sendJson(res, 200, { ok: true, command });
        return;
      }

      const devicePairingClaim = pathname.match(/^\/api\/devices\/([^/]+)\/pairing-sessions\/([^/]+)\/claim$/);
      if (req.method === "POST" && devicePairingClaim) {
        const deviceId = normalizeDeviceId(devicePairingClaim[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const claimed = store.claimPairingSession({
          sessionId: decodeURIComponent(devicePairingClaim[2]),
          pairingCode: value.pairing_code || value.pairingCode,
          claimantType: "child",
          childDeviceId: deviceId
        });
        const preview = store.pairingPreview(claimed.mapping.mappingId);
        sendJson(res, 201, { ok: true, pairing_session_id: claimed.sessionId, mapping: claimed.mapping, preview });
        return;
      }
      const devicePairingConfirm = pathname.match(/^\/api\/devices\/([^/]+)\/pairing-sessions\/([^/]+)\/confirm$/);
      if (req.method === "POST" && devicePairingConfirm) {
        const deviceId = normalizeDeviceId(devicePairingConfirm[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const confirmed = store.confirmPairingSession({
          sessionId: decodeURIComponent(devicePairingConfirm[2]),
          claimantType: "child",
          childDeviceId: deviceId,
          consent: value.consent === true
        });
        store.audit("device", deviceId, value.consent === true ? "pairing_confirmed" : "pairing_declined", req.headers["x-request-id"] || null, { sessionId: confirmed.sessionId, mappingId: confirmed.mapping.mappingId });
        sendJson(res, 200, { ok: true, pairing_session_id: confirmed.sessionId, mapping: confirmed.mapping, status: confirmed.status, policy_ready: confirmed.status === "confirmed" });
        return;
      }
      const devicePairingSession = pathname.match(/^\/api\/devices\/([^/]+)\/pairing-sessions$/);
      if (req.method === "POST" && devicePairingSession) {
        const deviceId = normalizeDeviceId(devicePairingSession[1]);
        auth.requireDevice(req, deviceId, requestPath, body.raw);
        const session = store.createPairingSession({ issuerType: "child", issuerId: deviceId, childDeviceId: deviceId });
        store.audit("device", deviceId, "pairing_session_created", req.headers["x-request-id"] || null, { sessionId: session.sessionId, expiresAt: session.expiresAt });
        sendJson(res, 201, { ok: true, pairing_session_id: session.sessionId, pairing_code: session.pairingCode, expires_at: session.expiresAt });
        return;
      }

      // Normal Parent users must never handle the server bootstrap secret. The
      // Android app generates a Keystore key on first launch and self-enrolls
      // into an isolated family. Child/Parent QR pairing remains the consent
      // boundary for accessing a child device.
      if (req.method === "POST" && pathname === "/api/parent/auth/auto-enroll") {
        const publicKey = String(value.device_pubkey || value.public_key || "");
        const fingerprint = String(value.device_fingerprint || "").trim().toLowerCase();
        if (publicKey.length < 32 || publicKey.length > 8192) throw new AuthError("invalid_parent_device_public_key", 400);
        if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new AuthError("invalid_parent_device_fingerprint", 400);
        let publicKeyBytes;
        try {
          publicKeyBytes = Buffer.from(publicKey, "base64");
          crypto.createPublicKey({ key: publicKeyBytes, format: "der", type: "spki" });
        } catch (_) {
          throw new AuthError("invalid_parent_device_public_key", 400);
        }
        const derivedFingerprint = crypto.createHash("sha256").update(publicKeyBytes).digest("hex");
        if (derivedFingerprint !== fingerprint) throw new AuthError("parent_device_fingerprint_mismatch", 400);
        const existingParent = Object.values(store.state.parentProfiles || {}).find((item) => item.deviceFingerprint === fingerprint);
        const familyId = existingParent && existingParent.familyId
          ? existingParent.familyId
          : `family-${crypto.createHash("sha256").update(fingerprint, "utf8").digest("hex").slice(0, 24)}`;
        const parent = store.ensureParentProfile({
          familyId,
          deviceFingerprint: fingerprint,
          publicKey,
          displayName: value.display_name || "부모",
          metadata: value.metadata || {}
        });
        const session = store.issueParentSession(parent.familyId, 3600000, parent.parentId);
        store.audit("parent", parent.parentId, "parent_auto_enrolled", req.headers["x-request-id"] || null, {
          familyId: parent.familyId,
          enrollment: "qr_pairing_ready"
        });
        sendJson(res, 201, {
          ok: true,
          enrollment: "automatic",
          parent: { parent_id: parent.parentId, family_id: parent.familyId, display_name: parent.displayName },
          session: {
            session_token: session.token,
            expires_at: session.expiresAt,
            family_id: session.familyId,
            parent_id: session.parentId,
            device_compatibility: androidCompatibility(value.metadata || {})
          }
        });
        return;
      }

      if (pathname.startsWith("/api/parent/")) auth.requireParent(req);

      if (req.method === "GET" && pathname === "/api/parent/updates/manifest") {
        const product = String(requestUrl.searchParams.get("product") || "cpsm-p");
        if (product !== "cpsm-p") throw new ArtifactError("artifact_product_not_for_parent", 403);
        artifacts.sendManifest(res, "android", product, "/api/parent/updates/download?product=cpsm-p");
        return;
      }

      if (req.method === "GET" && pathname === "/api/parent/updates/download") {
        const product = String(requestUrl.searchParams.get("product") || "cpsm-p");
        if (product !== "cpsm-p") throw new ArtifactError("artifact_product_not_for_parent", 403);
        artifacts.sendArtifact(res, "android", product);
        return;
      }

      if (req.method === "POST" && pathname === "/api/parent/devices/fcm-token") {
        const token = value.fcm_token || value.token;
        store.registerParentToken(token);
        const sessionForToken = store.getParentSession(auth.bearerToken(req));
        if (sessionForToken && sessionForToken.parent_id) {
          store.addNotificationKey({ deviceId: sessionForToken.parent_id, provider: "fcm", token });
        }
        sendJson(res, 200, { ok: true, registered: true });
        return;
      }

      const parentSession = store.getParentSession(auth.bearerToken(req));
      const requireParentProfile = () => {
        if (!parentSession || !parentSession.parent_id) throw new StoreError("parent_session_profile_required", 403);
        return parentSession;
      };
      // A self-enrolled parent session only reaches devices confirmed into its own family.
      // Static operator tokens (no session) keep the legacy global view.
      const canAccessDevice = (deviceId) => !parentSession
        || Boolean(parentSession.family_id && store.familyIdForDevice(deviceId) === parentSession.family_id);
      const requireDeviceAccess = (deviceId) => {
        if (!store.state.devices[deviceId] || !canAccessDevice(deviceId)) throw new StoreError("device_not_found", 404);
      };
      const familyScope = parentSession && parentSession.family_id ? parentSession.family_id : null;
      const geofenceRoute = pathname.match(/^\/api\/parent\/geofences(?:\/([^/]+))?$/);
      if (geofenceRoute && req.method === "GET" && !geofenceRoute[1]) {
        const session = requireParentProfile();
        sendJson(res, 200, { geofences: store.listGeofences(session.family_id) });
        return;
      }
      if (geofenceRoute && req.method === "POST" && !geofenceRoute[1]) {
        const session = requireParentProfile();
        const geofence = store.upsertGeofence({
          ...sanitizeGeofence(value), familyId: session.family_id, parentId: session.parent_id,
          requestId: req.headers["x-request-id"] || null
        });
        sendJson(res, 201, { ok: true, geofence });
        return;
      }
      if (geofenceRoute && req.method === "PUT" && geofenceRoute[1]) {
        const session = requireParentProfile();
        const geofenceId = decodeURIComponent(geofenceRoute[1]);
        if (!store.getGeofence(session.family_id, geofenceId)) throw new StoreError("geofence_not_found", 404);
        const geofence = store.upsertGeofence({
          ...sanitizeGeofence(value), geofenceId, familyId: session.family_id, parentId: session.parent_id,
          requestId: req.headers["x-request-id"] || null
        });
        sendJson(res, 200, { ok: true, geofence });
        return;
      }
      if (geofenceRoute && req.method === "DELETE" && geofenceRoute[1]) {
        const session = requireParentProfile();
        const geofenceId = decodeURIComponent(geofenceRoute[1]);
        if (!store.deleteGeofence(session.family_id, geofenceId, session.parent_id, req.headers["x-request-id"] || null)) {
          throw new StoreError("geofence_not_found", 404);
        }
        sendJson(res, 200, { ok: true, deleted: true, geofence_id: geofenceId });
        return;
      }
      const parentLocationConsent = pathname.match(/^\/api\/parent\/devices\/([^/]+)\/location-consent$/);
      if (parentLocationConsent && ["GET", "POST"].includes(req.method)) {
        const session = requireParentProfile();
        const deviceId = normalizeDeviceId(parentLocationConsent[1]);
        requireDeviceAccess(deviceId);
        const consent = store.getLocationConsent(deviceId, session.family_id);
        if (req.method === "GET") {
          sendJson(res, 200, { ok: true, location_consent: consent });
          return;
        }
        const input = sanitizeLocationConsent(value);
        const updated = store.setLocationConsent({
          deviceId, familyId: session.family_id, actorType: "parent", consent: input.consent,
          actorId: session.parent_id, requestId: req.headers["x-request-id"] || null
        });
        sendJson(res, 200, { ok: true, location_consent: updated });
        return;
      }
      const parentLocationRequest = pathname.match(/^\/api\/parent\/devices\/([^/]+)\/location-requests$/);
      if (req.method === "POST" && parentLocationRequest) {
        const session = requireParentProfile();
        const deviceId = normalizeDeviceId(parentLocationRequest[1]);
        requireDeviceAccess(deviceId);
        const created = store.createLocationRequest({ deviceId, familyId: session.family_id, parentId: session.parent_id });
        const fcmResult = await fcm.sendToDeviceIds([deviceId], {
          type: "cpsm_location_refresh"
        }, undefined, { priority: "high" });
        sendJson(res, created.reused ? 200 : 202, {
          ok: true, request: created.request, command_id: created.command.id,
          reused: created.reused, fcm: { sent: Number(fcmResult.sent || 0), skipped: Number(fcmResult.skipped || 0), failed: Number(fcmResult.failed || 0) }
        });
        return;
      }
      const parentLocationTimeline = pathname.match(/^\/api\/parent\/devices\/([^/]+)\/location-timeline$/);
      if (req.method === "GET" && parentLocationTimeline) {
        const session = requireParentProfile();
        const deviceId = normalizeDeviceId(parentLocationTimeline[1]);
        requireDeviceAccess(deviceId);
        const limit = Number(requestUrl.searchParams.get("limit") || 100);
        if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new LocationError("invalid_location_timeline_limit", 400);
        const timeline = store.listLocationTimeline(deviceId, session.family_id, limit);
        sendJson(res, 200, {
          ok: true, device_id: deviceId, location_consent: store.getLocationConsent(deviceId, session.family_id),
          retention_days: timeline.retentionDays, samples: timeline.samples, transitions: timeline.transitions, requests: timeline.requests
        });
        return;
      }
      if (req.method === "POST" && pathname === "/api/parent/pairing-sessions") {
        const session = requireParentProfile();
        const pairing = store.createPairingSession({ issuerType: "parent", issuerId: session.parent_id, familyId: session.family_id });
        store.audit("parent", session.parent_id, "pairing_session_created", req.headers["x-request-id"] || null, { sessionId: pairing.sessionId, expiresAt: pairing.expiresAt });
        sendJson(res, 201, { ok: true, pairing_session_id: pairing.sessionId, pairing_code: pairing.pairingCode, expires_at: pairing.expiresAt, role: "parent" });
        return;
      }
      if (req.method === "GET" && pathname === "/api/parent/families") {
        const session = requireParentProfile();
        sendJson(res, 200, { families: Object.values(store.state.families).filter((family) => family.familyId === session.family_id) });
        return;
      }
      if (req.method === "GET" && pathname === "/api/parent/children/available") {
        requireParentProfile();
        sendJson(res, 200, { children: store.listAvailableChildren(parentSession.family_id).map((item) => ({ child_id: item.child.childId, device_id: item.device.deviceId, display_name: item.child.displayName, device_name: item.device.deviceName, registration_status: item.device.registrationStatus, relationship_status: item.relationshipStatus, compatibility: androidCompatibility(item.device.metadata || {}), metadata: item.device.metadata || {} })) });
        return;
      }
      const parentPairingStatus = pathname.match(/^\/api\/parent\/pairing-sessions\/([^/]+)$/);
      if (req.method === "GET" && parentPairingStatus) {
        const session = requireParentProfile();
        const pairingSessionId = decodeURIComponent(parentPairingStatus[1]);
        const pairing = store.state.pairingSessions[pairingSessionId];
        if (!pairing || pairing.issuerType !== "parent" || pairing.issuerId !== session.parent_id) {
          throw new StoreError("pairing_session_not_found", 404);
        }
        const expired = Number(pairing.expiresAt) <= Date.now()
          && ["pending", "claimed"].includes(pairing.status);
        const mapping = pairing.mappingId ? store.state.parentChildMappings[pairing.mappingId] || null : null;
        sendJson(res, 200, {
          ok: true,
          pairing_session_id: pairingSessionId,
          status: expired ? "expired" : pairing.status,
          expires_at: new Date(Number(pairing.expiresAt)).toISOString(),
          mapping
        });
        return;
      }
      const parentPairingClaim = pathname.match(/^\/api\/parent\/pairing-sessions\/([^/]+)\/claim$/);
      if (req.method === "POST" && parentPairingClaim) {
        const session = requireParentProfile();
        const pairingSessionId = decodeURIComponent(parentPairingClaim[1]);
        const claimed = store.claimPairingSession({
          sessionId: pairingSessionId,
          pairingCode: value.pairing_code || value.pairingCode,
          claimantType: "parent",
          familyId: session.family_id,
          parentId: session.parent_id
        });
        const preview = store.pairingPreview(claimed.mapping.mappingId);
        store.audit("parent", session.parent_id, "parent_pairing_session_claimed", req.headers["x-request-id"] || null, { pairingSessionId, mappingId: claimed.mapping.mappingId });
        sendJson(res, 201, { ok: true, pairing_session_id: pairingSessionId, mapping: claimed.mapping, preview });
        return;
      }
      const parentPairingConfirm = pathname.match(/^\/api\/parent\/pairing-sessions\/([^/]+)\/confirm$/);
      if (req.method === "POST" && parentPairingConfirm) {
        const session = requireParentProfile();
        const pairingSessionId = decodeURIComponent(parentPairingConfirm[1]);
        const confirmed = store.confirmPairingSession({
          sessionId: pairingSessionId,
          claimantType: "parent",
          familyId: session.family_id,
          parentId: session.parent_id,
          consent: value.consent === true
        });
        store.audit("parent", session.parent_id, value.consent === true ? "pairing_confirmed" : "pairing_declined", req.headers["x-request-id"] || null, { sessionId: confirmed.sessionId, mappingId: confirmed.mapping.mappingId });
        sendJson(res, 200, { ok: true, pairing_session_id: confirmed.sessionId, mapping: confirmed.mapping, status: confirmed.status, policy_ready: confirmed.status === "confirmed" });
        return;
      }
      if (req.method === "POST" && pathname === "/api/parent/mappings") {
        const session = requireParentProfile();
        const childDeviceId = normalizeDeviceId(value.child_device_id || value.device_id);
        const mapping = store.createParentChildMapping({ familyId: session.family_id, parentId: session.parent_id, childDeviceId });
        const childProfile = store.state.childProfiles[mapping.childId];
        await fcm.sendToDeviceIds([session.parent_id, childProfile ? childProfile.deviceId : ""], {
          type: "cpsm_relationship_consent",
          mapping_id: mapping.mappingId,
          relationship_status: mapping.status
        }, { title: "CPSM 부모-자녀 연결 동의", body: "관계 동의 요청을 확인하세요." });
        store.audit("parent", session.parent_id, "parent_child_mapping_requested", req.headers["x-request-id"] || null, { mappingId: mapping.mappingId, childDeviceId });
        sendJson(res, 201, { ok: true, mapping });
        return;
      }
      if (req.method === "GET" && pathname === "/api/parent/mappings") {
        const session = requireParentProfile();
        const mappings = Object.values(store.state.parentChildMappings).filter((mapping) => mapping.familyId === session.family_id && mapping.parentId === session.parent_id);
        sendJson(res, 200, { mappings });
        return;
      }
      const parentConsent = pathname.match(/^\/api\/parent\/mappings\/([^/]+)\/consent$/);
      if (req.method === "POST" && parentConsent) {
        const session = requireParentProfile();
        const mappingId = decodeURIComponent(parentConsent[1]);
        const mapping = store.state.parentChildMappings[mappingId];
        if (!mapping || mapping.familyId !== session.family_id || mapping.parentId !== session.parent_id) throw new StoreError("mapping_not_found", 404);
        const updated = store.setRelationshipConsent({ mappingId, recipientType: "parent", recipientId: session.parent_id, consent: value.consent === true || value.decision === "accept" || value.decision === "approve" });
        sendJson(res, 200, { ok: true, mapping: updated, policy_ready: updated.status === "confirmed" });
        return;
      }
      if (req.method === "GET" && pathname === "/api/parent/consent-requests") {
        const session = requireParentProfile();
        const requests = Object.values(store.state.consentRequests).filter((request) => request.recipientType === "parent" && request.recipientId === session.parent_id);
        sendJson(res, 200, { requests });
        return;
      }

      const parentDevice = pathname.match(/^\/api\/parent\/devices\/([^/]+)\/(health|timeline)$/);
      if (req.method === "GET" && parentDevice) {
        const deviceId = normalizeDeviceId(parentDevice[1]);
        requireDeviceAccess(deviceId);
        if (parentDevice[2] === "health") {
          sendJson(res, 200, { device: store.state.devices[deviceId] || null });
        } else {
          sendJson(res, 200, { events: store.state.events.filter((event) => event.deviceId === deviceId).slice(-200).reverse() });
        }
        return;
      }

      const approvalRead = pathname.match(/^\/api\/parent\/approval-requests\/([^/]+)$/);
      if (req.method === "GET" && approvalRead) {
        const request = store.state.approvalRequests.find((item) => item.id === decodeURIComponent(approvalRead[1]));
        const visible = request && canAccessDevice(request.deviceId);
        sendJson(res, visible ? 200 : 404, visible ? request : { ok: false, error: "request_not_found" });
        return;
      }

      const approvalDecision = pathname.match(/^\/api\/parent\/approval-requests\/([^/]+)\/decision$/);
      if (req.method === "POST" && approvalDecision) {
        const requestId = decodeURIComponent(approvalDecision[1]);
        const decision = value.decision === "allow" ? "allow" : (value.decision === "terminate" ? "terminate" : "");
        if (!decision) throw new StoreError("invalid_decision", 400);
        const target = store.state.approvalRequests.find((item) => item.id === requestId);
        if (!target || !canAccessDevice(target.deviceId)) throw new StoreError("request_not_found", 404);
        const request = store.decideApprovalRequest(requestId, decision);
        if (!request) {
          sendJson(res, 404, { ok: false, error: "request_not_found" });
          return;
        }
        const command = decision === "allow"
          ? approvalAllowCommand(store, request, String(value.idempotency_key || requestId))
          : approvalDenyCommand(store, request, String(value.idempotency_key || requestId));
        sendJson(res, 200, { ok: true, request, command });
        return;
      }
      if (req.method === "GET" && pathname === "/api/parent/approval-requests") {
        sendJson(res, 200, { requests: store.state.approvalRequests.filter((request) => canAccessDevice(request.deviceId)).reverse() });
        return;
      }
      if (req.method === "GET" && pathname === "/api/parent/dashboard") {
        sendJson(res, 200, parentSession ? store.dashboardForFamily(familyScope || "") : store.dashboard());
        return;
      }
      if (req.method === "GET" && pathname === "/api/parent/policies/current") {
        const familyPolicy = parentSession && parentSession.family_id ? store.getFamilyPolicy(parentSession.family_id) : null;
        const policy = familyPolicy && familyPolicy.policy ? familyPolicy.policy : store.state.policy;
        sendJson(res, 200, { ...policy, family_id: familyPolicy ? familyPolicy.familyId : null, publicKey: publicKeyPem(store) });
        return;
      }
      if ((req.method === "POST" && pathname === "/api/parent/policies")
          || (req.method === "PUT" && pathname === "/api/parent/policies/current")) {
        const rules = sanitizeRules(value.rules || []);
        const screenTime = sanitizeScreenTime(value.screenTime !== undefined ? value.screenTime : value.screen_time);
        if (parentSession && !(parentSession.family_id && parentSession.parent_id)) throw new StoreError("parent_session_profile_required", 403);
        const familyPolicy = parentSession
          ? store.replaceFamilyPolicyRules(parentSession.family_id, rules, screenTime) : null;
        if (!familyPolicy) store.replacePolicyRules(rules);
        const policyRefreshVersion = familyPolicy ? familyPolicy.version : store.state.policy.version;
        const refreshTargets = familyPolicy ? store.familyDeviceIds(familyPolicy.familyId) : Object.keys(store.state.devices);
        for (const deviceId of refreshTargets) {
          store.queueCommand(deviceId, "policy.refresh", {}, { idempotencyKey: `policy-${policyRefreshVersion}-${deviceId}` });
        }
        const policy = familyPolicy && familyPolicy.policy ? familyPolicy.policy : store.state.policy;
        sendJson(res, 200, { ok: true, policy: { ...policy, family_id: familyPolicy ? familyPolicy.familyId : null, publicKey: publicKeyPem(store) } });
        return;
      }

      const approvalAction = pathname.match(/^\/api\/parent\/approval-requests\/([^/]+)\/(allow|terminate)$/);
      if (req.method === "POST" && approvalAction) {
        const requestId = decodeURIComponent(approvalAction[1]);
        const action = approvalAction[2];
        const target = store.state.approvalRequests.find((item) => item.id === requestId);
        if (!target || !canAccessDevice(target.deviceId)) throw new StoreError("request_not_found", 404);
        const request = store.decideApprovalRequest(requestId, action);
        if (!request) {
          sendJson(res, 404, { ok: false, error: "request_not_found" });
          return;
        }
        const command = action === "allow"
          ? approvalAllowCommand(store, request, requestId)
          : approvalDenyCommand(store, request, requestId);
        sendJson(res, 200, { ok: true, request, command });
        return;
      }
      if (req.method === "GET" && pathname === "/api/parent/blocked-apps") {
        const familyPolicy = familyScope ? store.getFamilyPolicy(familyScope) : null;
        sendJson(res, 200, { blockedApps: parentSession ? ((familyPolicy && familyPolicy.policy.rules) || []) : store.state.policy.rules });
        return;
      }
      if (req.method === "POST" && pathname === "/api/parent/blocked-apps" && parentSession) {
        const session = requireParentProfile();
        const rule = sanitizeRules([{ ...value, id: value.id || crypto.randomUUID() }])[0];
        const current = store.getFamilyPolicy(session.family_id);
        const rules = ((current && current.policy.rules) || []).filter((item) => item.id !== rule.id).concat([rule]);
        const familyPolicy = store.replaceFamilyPolicyRules(session.family_id, rules);
        for (const deviceId of store.familyDeviceIds(session.family_id)) {
          store.queueCommand(deviceId, "policy.refresh", {}, { idempotencyKey: `policy-${familyPolicy.version}-${deviceId}` });
        }
        sendJson(res, 200, { ok: true, rule });
        return;
      }
      if (req.method === "GET" && pathname === "/api/parent/devices") {
        const deviceIds = familyScope ? store.familyDeviceIds(familyScope) : (parentSession ? [] : Object.keys(store.state.devices));
        sendJson(res, 200, { devices: deviceIds.map((deviceId) => deviceSummary(store, deviceId)) });
        return;
      }
      const parentDeviceCommands = pathname.match(/^\/api\/parent\/devices\/([^/]+)\/commands$/);
      if (parentDeviceCommands && req.method === "POST") {
        const deviceId = normalizeDeviceId(parentDeviceCommands[1]);
        requireDeviceAccess(deviceId);
        const { type, payload } = sanitizeDeviceCommand(value);
        const idempotencyKey = value.idempotency_key ? String(value.idempotency_key).slice(0, 128) : crypto.randomUUID();
        // A lock must survive a long offline period; the child persists it locally once delivered.
        const command = store.queueCommand(deviceId, type, { ...payload, issuedAt: new Date().toISOString() }, {
          idempotencyKey, expiryMs: type === "device.lock" ? 24 * 60 * 60 * 1000 : 60 * 60 * 1000
        });
        store.audit("parent", parentSession ? parentSession.parent_id : "operator", "device_command_queued", req.headers["x-request-id"] || null, { deviceId, type, commandId: command.id });
        sendJson(res, 201, { ok: true, command });
        return;
      }
      if (parentDeviceCommands && req.method === "GET") {
        const deviceId = normalizeDeviceId(parentDeviceCommands[1]);
        requireDeviceAccess(deviceId);
        sendJson(res, 200, { commands: store.state.commands.filter((command) => command.deviceId === deviceId).slice(-20).reverse() });
        return;
      }
      if (req.method === "POST" && pathname === "/api/parent/blocked-apps") {
        const rule = sanitizeRules([{ ...value, id: value.id || crypto.randomUUID() }])[0];
        store.setBlockedApp({ ...rule, deviceId: String(value.deviceId || "") });
        const targetDevices = value.deviceId ? [normalizeDeviceId(value.deviceId)] : Object.keys(store.state.devices);
        for (const deviceId of targetDevices) {
          store.queueCommand(deviceId, "policy.refresh", {}, { idempotencyKey: `policy-${store.state.policy.version}-${deviceId}` });
        }
        sendJson(res, 200, { ok: true, rule });
        return;
      }

      sendJson(res, 404, { ok: false, error: "not_found" });
    } catch (error) {
      const known = error instanceof AuthError || error instanceof StoreError
        || error instanceof ArtifactError || error instanceof ScreenTimeError || error instanceof LocationError;
      const status = known ? error.status : 500;
      const code = known ? error.code : "internal_error";
      if (status >= 500) log.error("request.failed", { code });
      sendJson(res, status, { ok: false, error: code });
    }
  });

  server.listen(options.port, options.host, () => {
    log.info("server.started", {
      host: options.host,
      port: options.port,
      dataDir: path.resolve(options.dataDir),
      storage: store.storageMode(),
      fcmEnabled: fcm.enabled(),
      authMode: auth.mode
    });
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});