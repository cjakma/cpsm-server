// Isolated strict-auth integration coverage for child app-install requests.
const http = require("node:http");
const net = require("node:net");
const { spawn } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");
const { Store } = require("../src/store");

const projectRoot = path.resolve(__dirname, "..");
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "cpsm-app-install-"));
const expectedRequestKeys = [
  "request_id", "device_id", "child_name", "package_name", "display_name", "request_note",
  "status", "created_at", "expires_at", "decided_at", "decision_note"
].sort();
let port;
let server;
let assertionCount = 0;

process.on("exit", () => fs.rmSync(dataDir, { recursive: true, force: true }));

function assert(condition, message) {
  assertionCount += 1;
  if (!condition) throw new Error(`assertion failed: ${message}`);
}

async function reservePort() {
  const listener = net.createServer();
  await new Promise((resolve, reject) => listener.listen(0, "127.0.0.1", resolve).once("error", reject));
  const address = listener.address();
  const value = address.port;
  await new Promise((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
  return value;
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
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`${method} ${pathname} -> ${response.status} ${JSON.stringify(response.body)}`);
  }
  return response.body;
}

function parentKey() {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  return {
    publicKey,
    fingerprint: crypto.createHash("sha256").update(Buffer.from(publicKey, "base64")).digest("hex")
  };
}

function childKey(deviceId, platform = "android") {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  return {
    deviceId,
    platform,
    publicKey,
    signed(method, pathname, body) {
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
    }
  };
}

async function enrollParent(name) {
  const key = parentKey();
  const enrolled = await ok("POST", "/api/parent/auth/auto-enroll", {
    device_pubkey: key.publicKey,
    device_fingerprint: key.fingerprint,
    platform: "android",
    display_name: name,
    metadata: { android_api_level: 35 }
  });
  return { authorization: `Bearer ${enrolled.session.session_token}` };
}

async function registerAndPair(parentHeaders, child) {
  const registered = await ok("POST", "/api/devices/register", {
    device_id: child.deviceId,
    public_key: child.publicKey,
    platform: child.platform,
    auth_mode: "android_keystore_ec_signature",
    child_name: `child-${child.deviceId.slice(-6)}`,
    device_name: `device-${child.deviceId.slice(-6)}`,
    metadata: child.platform === "android" ? { android_api_level: 35 } : { windows_release: "11" }
  });
  assert(registered.registration_status === "registered_unpaired", `${child.platform} device initially unpaired`);
  const issued = await child.signed("POST", `/api/devices/${child.deviceId}/pairing-sessions`, {});
  assert(issued.status === 201, "child pairing session created");
  const claimed = await ok("POST", `/api/parent/pairing-sessions/${issued.body.pairing_session_id}/claim`, {
    pairing_code: issued.body.pairing_code
  }, parentHeaders);
  assert(claimed.mapping.status === "pending_consent", "pairing claim remains pending until explicit confirmation");
  const confirmed = await ok("POST", `/api/parent/pairing-sessions/${issued.body.pairing_session_id}/confirm`, { consent: true }, parentHeaders);
  assert(confirmed.status === "confirmed", "parent confirms child relationship");
}

async function waitForServer() {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (server && server.exitCode !== null) throw new Error(`server exited with code ${server.exitCode}`);
    try {
      const response = await raw("GET", "/api/status");
      if (response.status === 200) return response.body;
    } catch (_) { /* server has not bound yet */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("server startup timed out");
}

function startServer() {
  server = spawn(process.execPath, ["src/index.js", "--host", "127.0.0.1", "--port", String(port), "--data-dir", dataDir], {
    cwd: projectRoot,
    env: {
      ...process.env,
      CPSM_DISABLE_FCM: "1",
      CPSM_AUTH_MODE: "strict",
      CPSM_ADMIN_TOKEN: crypto.randomBytes(24).toString("hex"),
      CPSM_PARENT_TOKEN: crypto.randomBytes(24).toString("hex"),
      CPSM_DEVICE_SECRET: "",
      CPSM_DEVICE_SECRETS: "{}",
      CPSM_DEVICE_PUBLIC_KEYS: "{}",
      CPSM_ARTIFACTS_DIR: path.join(dataDir, "artifacts"),
      NODE_ENV: "production"
    },
    stdio: "ignore",
    windowsHide: true
  });
  return server;
}

async function stopServer() {
  if (!server || server.exitCode !== null) return;
  const child = server;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("server did not stop after SIGTERM"));
    }, 5000);
    child.once("exit", () => { clearTimeout(timer); resolve(); });
    child.kill("SIGTERM");
  });
}

function requestPath(child, suffix = "") {
  return `/api/devices/${child.deviceId}/app-install-requests${suffix}`;
}

function checkRequestShape(request, expectedStatus) {
  assert(request && typeof request === "object", "request object returned");
  assert(JSON.stringify(Object.keys(request).sort()) === JSON.stringify(expectedRequestKeys), "only documented server request fields returned");
  assert(request.status === expectedStatus, `request status ${expectedStatus}`);
  assert(!Object.hasOwn(request, "family_id") && !Object.hasOwn(request, "command"), "request omits internal family/command data");
}

async function verifyJsonFallbackPersistence() {
  const fallbackDir = path.join(dataDir, "json-fallback");
  fs.mkdirSync(path.join(fallbackDir, "cpsm.sqlite"), { recursive: true });
  const store = new Store(fallbackDir);
  assert(store.storageMode() === "json-fallback", "SQLite open failure uses JSON compatibility fallback");
  store.ensureFamily("fallback-family");
  store.ensureParentProfile({
    familyId: "fallback-family", deviceFingerprint: "fallback-fingerprint-0001", publicKey: "fallback-public-key",
    displayName: "fallback parent"
  });
  store.upsertDevice("fallback-child", { platform: "android", childName: "Fallback child" });
  const mapping = store.createParentChildMapping({
    familyId: "fallback-family", parentId: Object.keys(store.state.parentProfiles)[0], childDeviceId: "fallback-child"
  });
  store.setRelationshipConsent({ mappingId: mapping.mappingId, recipientType: "parent", recipientId: mapping.parentId, consent: true });
  store.setRelationshipConsent({ mappingId: mapping.mappingId, recipientType: "child", recipientId: mapping.childId, consent: true });
  const request = store.createAppInstallRequest({
    deviceId: "fallback-child", packageName: "com.example.fallback", displayName: "Fallback app", requestNote: "JSON persistence check"
  });
  store.decideAppInstallRequest({
    requestId: request.requestId, familyId: "fallback-family", parentId: mapping.parentId,
    decision: "approve", decisionNote: "Fallback approval audit"
  });
  const reloaded = new Store(fallbackDir);
  assert(reloaded.storageMode() === "json-fallback", "fallback remains selected after reload");
  const persisted = reloaded.state.appInstallRequests.find((item) => item.requestId === request.requestId);
  assert(persisted && persisted.status === "approved", "JSON fallback reloads approved app-install request state");
  assert(reloaded.state.auditLog.some((item) => item.action === "app_install_request_created" && item.requestId === request.requestId), "JSON fallback persists create audit entry");
  assert(reloaded.state.auditLog.some((item) => item.action === "app_install_request_decided" && item.requestId === request.requestId), "JSON fallback persists decision audit entry");
  persisted.familyId = "previous-family";
  reloaded.save();
  const afterFamilyChange = new Store(fallbackDir);
  assert(afterFamilyChange.listAppInstallRequests({ deviceId: "fallback-child", status: "all" }).length === 0,
    "child cannot read an old family's request after the active relationship family changes");
  store.db?.close();
  reloaded.db?.close();
  afterFamilyChange.db?.close();
}

async function main() {
  port = await reservePort();
  startServer();
  try {
    const status = await waitForServer();
    assert(status.storage === "sqlite", "integration fixture uses isolated SQLite persistence");

    const parentA = await enrollParent("Parent A");
    const parentB = await enrollParent("Parent B");
    const childA = childKey(`android-${crypto.randomUUID()}`);
    const childA2 = childKey(`android-${crypto.randomUUID()}`);
    const childB = childKey(`android-${crypto.randomUUID()}`);
    const windows = childKey(`windows-${crypto.randomUUID()}`, "windows");
    const unauthenticated = await raw("GET", requestPath(childA));
    assert(unauthenticated.status === 401, "unauthenticated child list denied");
    const unauthenticatedCreate = await raw("POST", requestPath(childA), {
      package_name: "com.example.app", display_name: "Example", request_note: "Need this app"
    });
    assert(unauthenticatedCreate.status === 401, "unauthenticated child create denied");
    const unauthenticatedCancel = await raw("POST", requestPath(childA, "/not-owned/cancel"), {});
    assert(unauthenticatedCancel.status === 401, "unauthenticated child cancellation denied");
    const unauthParent = await raw("GET", "/api/parent/app-install-requests?status=all");
    assert(unauthParent.status === 401, "unauthenticated parent list denied");
    const unauthParentDecision = await raw("POST", "/api/parent/app-install-requests/not-owned/decision", { decision: "approve" });
    assert(unauthParentDecision.status === 401, "unauthenticated parent decision denied");

    await ok("POST", "/api/devices/register", {
      device_id: childA.deviceId, public_key: childA.publicKey, platform: "android", child_name: "Unpaired child"
    });
    const unpairedCreate = await childA.signed("POST", requestPath(childA), {
      package_name: "com.example.app", display_name: "Example", request_note: "Need this app"
    });
    assert(unpairedCreate.status === 409 && unpairedCreate.body.error === "parent_mapping_required", "unconfirmed child cannot create requests");
    const unpairedList = await childA.signed("GET", requestPath(childA));
    assert(unpairedList.status === 409, "unconfirmed child cannot read request history");

    await registerAndPair(parentA, childA);
    await registerAndPair(parentA, childA2);
    await registerAndPair(parentB, childB);
    await registerAndPair(parentA, windows);

    const windowsAttempt = await windows.signed("POST", requestPath(windows), {
      package_name: "com.example.desktop", display_name: "Desktop app", request_note: "Should be Android only"
    });
    assert(windowsAttempt.status === 409 && windowsAttempt.body.error === "android_device_required", "Windows device cannot create Android install requests");

    const validInput = { package_name: "com.example.reader", display_name: "Reader", request_note: "Needed for school" };
    const invalidInputs = [
      { ...validInput, package_name: "" },
      { ...validInput, package_name: "Example.Reader" },
      { ...validInput, package_name: "com..reader" },
      { ...validInput, package_name: "com" },
      { ...validInput, display_name: "   " },
      { ...validInput, display_name: "x".repeat(121) },
      { ...validInput, request_note: "\n  " },
      { ...validInput, request_note: "x".repeat(501) },
      { ...validInput, request_note: 42 }
    ];
    for (const invalid of invalidInputs) {
      const response = await childA.signed("POST", requestPath(childA), invalid);
      assert(response.status === 400, `invalid child request rejected (${response.body.error || "400"})`);
    }

    const foreignDecision = await raw("POST", "/api/parent/app-install-requests/unknown/decision", { decision: "approve" }, parentA);
    assert(foreignDecision.status === 404, "unknown parent request hidden");
    const invalidFilter = await raw("GET", "/api/parent/app-install-requests?status=decided", undefined, parentA);
    assert(invalidFilter.status === 400, "invalid parent status filter rejected");

    const create = await childA.signed("POST", requestPath(childA), {
      ...validInput,
      status: "approved", decision_note: "client-controlled", family_id: "foreign", command: { type: "install" }
    });
    assert(create.status === 201, "valid app-install request created");
    assert(create.body.ok === true && create.body.requires_user_installer_confirmation === true, "create response requires user-controlled installer confirmation");
    checkRequestShape(create.body.request, "pending");
    assert(create.body.request.package_name === validInput.package_name && create.body.request.display_name === validInput.display_name, "server returns validated fields");
    assert(Date.parse(create.body.request.expires_at) - Date.parse(create.body.request.created_at) === 24 * 60 * 60 * 1000, "request expiry is exactly 24 hours");
    const requestId = create.body.request.request_id;

    const duplicate = await childA.signed("POST", requestPath(childA), { ...validInput, display_name: "Different display" });
    assert(duplicate.status === 409 && duplicate.body.error === "app_install_request_already_pending", "pending package duplicate rejected");
    const childList = await childA.signed("GET", requestPath(childA));
    assert(childList.status === 200 && childList.body.requests.length === 1, "child sees own pending request only");
    checkRequestShape(childList.body.requests[0], "pending");
    assert(childList.body.requests[0].request_id === requestId, "child list returns created request");

    const familyBList = await raw("GET", "/api/parent/app-install-requests?status=all", undefined, parentB);
    assert(familyBList.status === 200 && familyBList.body.requests.length === 0, "unrelated family cannot list request");
    const crossFamilyDecision = await raw("POST", `/api/parent/app-install-requests/${requestId}/decision`, { decision: "approve" }, parentB);
    assert(crossFamilyDecision.status === 404, "unrelated family cannot decide request");
    const familyAPending = await raw("GET", "/api/parent/app-install-requests?status=pending", undefined, parentA);
    assert(familyAPending.status === 200 && familyAPending.body.requests.length === 1, "confirmed family sees pending request");
    checkRequestShape(familyAPending.body.requests[0], "pending");

    const decision = await raw("POST", `/api/parent/app-install-requests/${requestId}/decision`, {
      decision: "approve", decision_note: "Approved for school"
    }, parentA);
    assert(decision.status === 200, "parent approves request");
    assert(decision.body.ok === true && decision.body.requires_user_installer_confirmation === true, "approval remains informational and requires installer confirmation");
    checkRequestShape(decision.body.request, "approved");
    assert(decision.body.request.decision_note === "Approved for school" && decision.body.request.decided_at, "decision note and timestamp persisted");
    const duplicateDecision = await raw("POST", `/api/parent/app-install-requests/${requestId}/decision`, { decision: "deny" }, parentA);
    assert(duplicateDecision.status === 409 && duplicateDecision.body.error === "app_install_request_not_pending", "approved request cannot transition again");
    const invalidDecision = await raw("POST", "/api/parent/app-install-requests/not-a-request/decision", { decision: "install" }, parentA);
    assert(invalidDecision.status === 400 && invalidDecision.body.error === "invalid_decision", "only approve or deny decisions accepted");

    const secondInput = { package_name: "com.example.notes", display_name: "Notes", request_note: "Take notes" };
    const secondCreate = await childA.signed("POST", requestPath(childA), secondInput);
    assert(secondCreate.status === 201, "different package request can be created after approval");
    const deny = await raw("POST", `/api/parent/app-install-requests/${secondCreate.body.request.request_id}/decision`, {
      decision: "deny", decision_note: "Not needed"
    }, parentA);
    assert(deny.status === 200, "parent denies request");
    checkRequestShape(deny.body.request, "denied");

    const cancelInput = { package_name: "com.example.calendar", display_name: "Calendar", request_note: "Family calendar" };
    const cancelCreate = await childA2.signed("POST", requestPath(childA2), cancelInput);
    assert(cancelCreate.status === 201, "second confirmed child can create independent request");
    const cancelPath = requestPath(childA2, `/${cancelCreate.body.request.request_id}/cancel`);
    const canceled = await childA2.signed("POST", cancelPath, {});
    assert(canceled.status === 200 && canceled.body.ok === true, "child cancels pending request");
    checkRequestShape(canceled.body.request, "cancelled");
    const cancelAgain = await childA2.signed("POST", cancelPath, {});
    assert(cancelAgain.status === 409 && cancelAgain.body.error === "app_install_request_not_pending", "canceled request cannot transition again");

    const expiredCreate = await childA2.signed("POST", requestPath(childA2), {
      package_name: "com.example.expired", display_name: "Expired app", request_note: "Expiry test"
    });
    assert(expiredCreate.status === 201, "expiry fixture request created");
    const database = new DatabaseSync(path.join(dataDir, "cpsm.sqlite"));
    database.prepare("UPDATE app_install_requests SET expires_at = ? WHERE request_id = ?")
      .run(new Date(Date.now() - 1000).toISOString(), expiredCreate.body.request.request_id);
    database.close();
    await stopServer();
    startServer();
    await waitForServer();
    const expireDecision = await raw("POST", `/api/parent/app-install-requests/${expiredCreate.body.request.request_id}/decision`, { decision: "approve" }, parentA);
    assert(expireDecision.status === 409 && expireDecision.body.error === "app_install_request_not_pending", "expired request cannot be approved");
    const allRequests = await raw("GET", "/api/parent/app-install-requests?status=all", undefined, parentA);
    assert(allRequests.status === 200, "family all-status request list returned");
    const expired = allRequests.body.requests.find((item) => item.request_id === expiredCreate.body.request.request_id);
    assert(expired && expired.status === "expired", "expired pending request transitions to expired");
    checkRequestShape(expired, "expired");

    const commands = await raw("GET", `/api/parent/devices/${childA.deviceId}/commands`, undefined, parentA);
    assert(commands.status === 200 && commands.body.commands.length === 0, "app-install approval does not enqueue any command");

    await stopServer();
    startServer();
    const restarted = await waitForServer();
    assert(restarted.storage === "sqlite", "server reload uses SQLite persistence");
    const reloaded = await raw("GET", "/api/parent/app-install-requests?status=all", undefined, parentA);
    assert(reloaded.status === 200, "parent session and request list survive SQLite reload");
    const byId = new Map(reloaded.body.requests.map((item) => [item.request_id, item]));
    assert(byId.get(requestId)?.status === "approved", "approved request survives SQLite reload");
    assert(byId.get(requestId)?.decision_note === "Approved for school", "approval note survives SQLite reload");
    assert(byId.get(secondCreate.body.request.request_id)?.status === "denied", "denied request survives SQLite reload");
    assert(byId.get(cancelCreate.body.request.request_id)?.status === "cancelled", "canceled request survives SQLite reload");
    assert(byId.get(expiredCreate.body.request.request_id)?.status === "expired", "expired request survives SQLite reload");

    await stopServer();
    const auditDb = new DatabaseSync(path.join(dataDir, "cpsm.sqlite"));
    const auditActions = auditDb.prepare("SELECT action, COUNT(*) AS count FROM audit_log WHERE action LIKE 'app_install_request_%' GROUP BY action").all();
    auditDb.close();
    const auditCounts = Object.fromEntries(auditActions.map((row) => [row.action, Number(row.count)]));
    assert(auditCounts.app_install_request_created >= 4, "request creation actions audited");
    assert(auditCounts.app_install_request_decided >= 2, "approve and deny decisions audited");
    assert(auditCounts.app_install_request_cancelled === 1, "child cancellation audited");
    assert(auditCounts.app_install_request_expired === 1, "expiry transition audited");

    await verifyJsonFallbackPersistence();
    console.log(JSON.stringify({
      ok: true,
      assertions: assertionCount,
      sqlite_reload: "passed",
      json_fallback_reload: "passed",
      coverage: ["auth", "confirmed_android_relationship", "validation", "dedupe", "family_isolation", "approve_deny_cancel", "expiry_pending_transitions", "no_command_queue", "audit"]
    }));
  } finally {
    await stopServer().catch(() => {});
    if (server && server.exitCode === null) server.kill("SIGKILL");
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exitCode = 1;
});
