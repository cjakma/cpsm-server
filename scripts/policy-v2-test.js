// Strict-auth integration test for family isolation, screen-time policy v2 and parent device commands.
const http = require("http");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { canonicalJson } = require("../src/store");

const projectRoot = path.resolve(__dirname, "..");
const dataDir = path.join(projectRoot, "smoke-data-v2");
process.on("exit", () => fs.rmSync(dataDir, { recursive: true, force: true }));
const port = 18743;
const adminToken = crypto.randomBytes(24).toString("hex");

fs.rmSync(dataDir, { recursive: true, force: true });

function assert(condition, message) {
  if (!condition) throw new Error(`assertion failed: ${message}`);
}

function raw(method, pathname, body, headers = {}) {
  const payload = body === undefined ? "" : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({
      method, hostname: "127.0.0.1", port, path: pathname,
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload), ...headers }
    }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body: data ? JSON.parse(data) : {} }));
    });
    req.on("error", reject);
    req.end(payload);
  });
}

async function ok(method, pathname, body, headers) {
  const response = await raw(method, pathname, body, headers);
  if (response.status >= 400) throw new Error(`${method} ${pathname} -> ${response.status} ${JSON.stringify(response.body)}`);
  return response.body;
}

function keyDevice(deviceId, platform) {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const signed = (method, pathname, body) => {
    const payload = body === undefined ? "" : JSON.stringify(body);
    const timestamp = String(Date.now());
    const nonce = crypto.randomUUID();
    const canonical = [method, pathname, timestamp, nonce, Buffer.from(payload, "utf8").toString("base64")].join("\n");
    const signature = crypto.sign("sha256", Buffer.from(canonical, "utf8"), pair.privateKey).toString("base64");
    return raw(method, pathname, body, {
      "x-cpsm-device-id": deviceId,
      "x-cpsm-device-public-key": publicKey,
      "x-cpsm-timestamp": timestamp,
      "x-cpsm-nonce": nonce,
      "x-cpsm-device-signature": signature
    });
  };
  return { deviceId, platform, publicKey, signed };
}

async function enrollParent(name) {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const fingerprint = crypto.createHash("sha256").update(Buffer.from(publicKey, "base64")).digest("hex");
  const enrollment = await ok("POST", "/api/parent/auth/auto-enroll", {
    device_pubkey: publicKey, device_fingerprint: fingerprint, platform: "android", display_name: name,
    metadata: { android_api_level: 35 }
  });
  return { authorization: `Bearer ${enrollment.session.session_token}` };
}

async function pair(parentHeaders, device) {
  const register = await ok("POST", "/api/devices/register", {
    device_id: device.deviceId, public_key: device.publicKey, platform: device.platform,
    auth_mode: device.platform === "windows" ? "windows_ec_signature" : "android_keystore_ec_signature",
    device_name: `${device.platform}-child`, child_name: "child",
    metadata: device.platform === "windows" ? { windows_release: "11", hostname: "y720" } : { android_api_level: 28 }
  });
  assert(register.registration_status === "registered_unpaired", "registered unpaired");
  const issued = (await device.signed("POST", `/api/devices/${device.deviceId}/pairing-sessions`, {})).body;
  await ok("POST", `/api/parent/pairing-sessions/${issued.pairing_session_id}/claim`, { pairing_code: issued.pairing_code }, parentHeaders);
  const confirmed = await ok("POST", `/api/parent/pairing-sessions/${issued.pairing_session_id}/confirm`, { consent: true }, parentHeaders);
  assert(confirmed.status === "confirmed", `pairing confirmed for ${device.platform}`);
}

async function wait() {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try { return await ok("GET", "/api/status"); } catch (_) { await new Promise((resolve) => setTimeout(resolve, 250)); }
  }
  throw new Error("server timeout");
}

async function main() {
  const server = spawn(process.execPath, ["src/index.js", "--port", String(port), "--data-dir", dataDir], {
    cwd: projectRoot,
    env: { ...process.env, CPSM_DISABLE_FCM: "1", CPSM_AUTH_MODE: "strict", CPSM_ADMIN_TOKEN: adminToken, CPSM_ARTIFACTS_DIR: path.join(dataDir, "artifacts"), NODE_ENV: "production" },
    stdio: "ignore"
  });
  const results = {};
  try {
    await wait();
    const parentA = await enrollParent("parent-a");
    const parentB = await enrollParent("parent-b");
    const phone = keyDevice(`android-${crypto.randomUUID()}`, "android");
    const pc = keyDevice(`windows-${crypto.randomUUID()}`, "windows");
    await pair(parentA, phone);
    await pair(parentA, pc);

    // 1. A parent session is not an admin credential.
    const adminWithSession = await raw("GET", "/api/admin/errors", undefined, parentB);
    assert(adminWithSession.status === 401, "parent session rejected on admin route");
    const adminWithToken = await raw("GET", "/api/admin/errors", undefined, { authorization: `Bearer ${adminToken}` });
    assert(adminWithToken.status === 200, "admin token accepted");
    results.adminScope = "parent_session_rejected";

    // 2. Family isolation.
    assert((await raw("GET", `/api/parent/devices/${phone.deviceId}/health`, undefined, parentB)).status === 404, "other family health hidden");
    assert((await raw("GET", `/api/parent/devices/${phone.deviceId}/timeline`, undefined, parentB)).status === 404, "other family timeline hidden");
    assert((await raw("POST", `/api/parent/devices/${phone.deviceId}/commands`, { type: "device.lock" }, parentB)).status === 404, "other family command rejected");
    const dashboardB = await ok("GET", "/api/parent/dashboard", undefined, parentB);
    assert(dashboardB.devices.length === 0 && dashboardB.recentEvents.length === 0, "other family dashboard empty");
    const devicesB = await ok("GET", "/api/parent/devices", undefined, parentB);
    assert(devicesB.devices.length === 0, "other family device list empty");
    results.familyIsolation = "enforced";

    // 3. Unauthenticated re-registration cannot replace an enrolled key.
    const hijack = keyDevice(phone.deviceId, "android");
    const hijackResult = await raw("POST", "/api/devices/register", { device_id: phone.deviceId, public_key: hijack.publicKey, auth_mode: "android_keystore_ec_signature" });
    assert(hijackResult.status === 409 && hijackResult.body.error === "device_key_conflict", "device key takeover rejected");
    results.deviceTakeover = "rejected";

    // 3b. A paired child cannot be re-paired into another family.
    const rePair = (await phone.signed("POST", `/api/devices/${phone.deviceId}/pairing-sessions`, {})).body;
    const foreignClaim = await raw("POST", `/api/parent/pairing-sessions/${rePair.pairing_session_id}/claim`, { pairing_code: rePair.pairing_code }, parentB);
    assert(foreignClaim.status === 409 && foreignClaim.body.error === "child_already_paired", "cross-family re-pairing rejected");
    results.rePairing = "rejected";

    // 4. Screen-time policy v2.
    const invalid = await raw("PUT", "/api/parent/policies/current", { rules: [], screenTime: { downtime: [{ start: "25:00", end: "07:00" }] } }, parentA);
    assert(invalid.status === 400 && invalid.body.error === "invalid_downtime_time", "invalid downtime rejected");
    await ok("PUT", "/api/parent/policies/current", {
      rules: [
        { id: "yt", name: "YouTube", platform: "android", action: "monitor", dailyLimitMinutes: 45, match: { type: "package", packageName: "com.google.android.youtube" } },
        { id: "steam", name: "steam.exe", platform: "windows", action: "block" }
      ],
      screenTime: { dailyLimitMinutes: 120, downtime: [{ days: [1, 2, 3, 4, 5], start: "22:00", end: "07:00" }], alwaysAllowed: { windows: ["cpsm-c.exe"] } }
    }, parentA);
    // A rule-only update (older Parent builds) must keep the screen-time section.
    const current = await ok("GET", "/api/parent/policies/current", undefined, parentA);
    await ok("PUT", "/api/parent/policies/current", { rules: current.rules }, parentA);
    const policyAfterRuleOnly = await ok("GET", "/api/parent/policies/current", undefined, parentA);
    assert(policyAfterRuleOnly.screenTime && policyAfterRuleOnly.screenTime.dailyLimitMinutes === 120, "screen time kept by rule-only update");

    const phoneSync = (await phone.signed("POST", `/api/devices/${phone.deviceId}/sync`, {
      platform: "android", local_policy_version: 0,
      status: { status: "running", health: { screen_time: { used_today_minutes: 12, state: "allowed" }, protection: { level: "protected", accessibility: true, boot_guard_gap_ms: 0 } } }
    })).body;
    assert(phoneSync.policy.available && phoneSync.policy.changed, "phone policy available");
    const phonePolicy = (await phone.signed("GET", phoneSync.policy.download_url)).body;
    assert(phonePolicy.schemaVersion === 2 && phonePolicy.screenTime.dailyLimitMinutes === 120, "phone screen time delivered");
    assert(phonePolicy.screenTime.alwaysAllowed.includes("com.android.dialer"), "android default allowlist");
    assert(phonePolicy.appRules.length === 1 && phonePolicy.appRules[0].dailyLimitMinutes === 45, "android per-app limit");
    const unsigned = { ...phonePolicy };
    for (const key of ["canonicalHash", "canonical_hash", "signatureAlgorithm", "signature_algorithm", "signatureMetadata", "signature_metadata", "signature", "keyId", "key_id"]) delete unsigned[key];
    const signatureValid = crypto.verify(null, Buffer.from(canonicalJson(unsigned)), crypto.createPublicKey(current.publicKey),
      Buffer.from(phonePolicy.signature.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
    assert(signatureValid, "Ed25519 signature covers screenTime");
    assert(crypto.createHash("sha256").update(canonicalJson(unsigned)).digest("hex") === phonePolicy.canonicalHash, "canonical hash covers screenTime");

    const pcSync = (await pc.signed("POST", `/api/devices/${pc.deviceId}/sync`, { platform: "windows", local_policy_version: 0, status: { status: "running" } })).body;
    const pcPolicy = (await pc.signed("GET", pcSync.policy.download_url)).body;
    assert(pcPolicy.screenTime.alwaysAllowed.join() === "cpsm-c.exe" && pcPolicy.appRules[0].name === "steam.exe", "windows view");
    results.policyV2 = { version: phonePolicy.version, hash: phonePolicy.canonicalHash.slice(0, 12) };

    // 5. Parent device commands with acknowledgement.
    const badCommand = await raw("POST", `/api/parent/devices/${phone.deviceId}/commands`, { type: "shell.exec" }, parentA);
    assert(badCommand.status === 400, "unknown command rejected");
    const lock = await ok("POST", `/api/parent/devices/${phone.deviceId}/commands`, { type: "device.lock", minutes: 30, idempotency_key: "lock-1" }, parentA);
    const lockAgain = await ok("POST", `/api/parent/devices/${phone.deviceId}/commands`, { type: "device.lock", minutes: 30, idempotency_key: "lock-1" }, parentA);
    assert(lock.command.id === lockAgain.command.id, "idempotent command");
    const delivered = (await phone.signed("POST", `/api/devices/${phone.deviceId}/sync`, { platform: "android", local_policy_version: phonePolicy.version, status: {} })).body;
    const lockCommand = delivered.commands.find((command) => command.type === "device.lock");
    assert(lockCommand && lockCommand.payload.minutes === 30, "lock delivered through sync");
    await phone.signed("POST", `/api/devices/${phone.deviceId}/commands/${lockCommand.id}/result`, { ok: true, state: "locked" });
    const commandList = await ok("GET", `/api/parent/devices/${phone.deviceId}/commands`, undefined, parentA);
    assert(commandList.commands.find((command) => command.id === lock.command.id).state === "succeeded", "lock acknowledged");
    results.commands = "lock_delivered_and_acknowledged";

    // 6. Android events queued locally are ingested through sync and acknowledged.
    const eventSync = (await phone.signed("POST", `/api/devices/${phone.deviceId}/sync`, {
      platform: "android", local_policy_version: phonePolicy.version, status: {},
      events: [
        { seq: 7, type: "health_check", timestamp_ms: Date.now(), details: { state: "running" } },
        { seq: 8, type: "foreground_app", timestamp_ms: Date.now(), package_name: "com.google.android.youtube" },
        { seq: 9, type: "enforcement_ready", timestamp_ms: Date.now(), details: { uptime_ms: 41000 } }
      ]
    })).body;
    assert(eventSync.accepted_event_seq === 9, "event sequence acknowledged");
    const timeline = await ok("GET", `/api/parent/devices/${phone.deviceId}/timeline`, undefined, parentA);
    const types = timeline.events.map((event) => event.type);
    assert(types.includes("app.foreground") && types.includes("enforcement_ready") && !types.includes("health_check"), "timeline events");
    results.events = types;
    await phone.signed("POST", `/api/devices/${phone.deviceId}/sync`, {
      platform: "android", local_policy_version: phonePolicy.version, status: {},
      events: [{ seq: 10, type: "time_request", timestamp_ms: Date.now(), details: { minutes: 20 } }]
    });
    const approvals = await ok("GET", "/api/parent/approval-requests", undefined, parentA);
    const timeRequest = approvals.requests.find((request) => request.kind === "screen_time");
    assert(timeRequest && timeRequest.requestedMinutes === 20, "time request surfaced to parent");
    assert((await ok("GET", "/api/parent/approval-requests", undefined, parentB)).requests.length === 0, "time request hidden from other family");
    const decided = await ok("POST", `/api/parent/approval-requests/${timeRequest.id}/decision`, { decision: "allow" }, parentA);
    assert(decided.command.type === "screen_time.bonus" && decided.command.payload.minutes === 20, "approval grants bonus");
    results.timeRequest = "bonus_20_minutes";

    // 7. Parent device list.
    const devicesA = await ok("GET", "/api/parent/devices", undefined, parentA);
    const phoneSummary = devicesA.devices.find((device) => device.device_id === phone.deviceId);
    assert(devicesA.devices.length === 2 && phoneSummary.presence === "online", "family devices listed");
    results.deviceList = devicesA.devices.map((device) => `${device.platform}:${device.presence}`);
    console.log(JSON.stringify({ ok: true, ...results }, null, 2));
  } finally {
    server.kill();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
