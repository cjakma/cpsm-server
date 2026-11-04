// Child QR long-poll: /pairing-sessions/{id}/wait answers on claim/confirm at once, else holds ≤ CPSM_PAIRING_WAIT_MAX_MS.
const http = require("node:http");
const net = require("node:net");
const { spawn } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");
const { Store } = require("../src/store");
const root = path.resolve(__dirname, "..");
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpsm-pairing-wait-"));
let port; let server; let assertions = 0;
process.on("exit", () => fs.rmSync(dir, { recursive: true, force: true }));
function assert(ok, message) { assertions += 1; if (!ok) throw new Error(`assertion failed: ${message}`); }
async function reservePort() {
  const listener = net.createServer();
  await new Promise((resolve, reject) => listener.listen(0, "127.0.0.1", resolve).once("error", reject));
  const value = listener.address().port;
  await new Promise((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
  return value;
}
function request(method, pathname, body, headers = {}) {
  const payload = body === undefined ? "" : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({ method, hostname: "127.0.0.1", port, path: pathname,
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload), ...headers } }, (res) => {
      let data = ""; res.setEncoding("utf8"); res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body: data ? JSON.parse(data) : {} }));
    });
    req.on("error", reject); req.end(payload);
  });
}
async function ok(method, pathname, body, headers) {
  const response = await request(method, pathname, body, headers);
  if (response.status < 200 || response.status >= 300) throw new Error(`${method} ${pathname}: ${response.status} ${JSON.stringify(response.body)}`);
  return response.body;
}
function parentKey() {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const pub = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  return { pub, fingerprint: crypto.createHash("sha256").update(Buffer.from(pub, "base64")).digest("hex") };
}
function childKey(deviceId, platform = "android") {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  return { deviceId, platform, publicKey, signed(method, pathname, body) {
    const payload = body === undefined ? "" : JSON.stringify(body); const timestamp = String(Date.now()); const nonce = crypto.randomUUID();
    const canonical = [method, pathname, timestamp, nonce, Buffer.from(payload).toString("base64")].join("\n");
    const signature = crypto.sign("sha256", Buffer.from(canonical), pair.privateKey).toString("base64");
    return request(method, pathname, body, { "x-cpsm-device-id": deviceId, "x-cpsm-device-public-key": publicKey,
      "x-cpsm-timestamp": timestamp, "x-cpsm-nonce": nonce, "x-cpsm-device-signature": signature });
  } };
}
async function parent(name) {
  const key = parentKey();
  const response = await ok("POST", "/api/parent/auth/auto-enroll", { device_pubkey: key.pub,
    device_fingerprint: key.fingerprint, platform: "android", display_name: name, metadata: { android_api_level: 35 } });
  return { key, authorization: `Bearer ${response.session.session_token}`, parentId: response.session.parent_id, familyId: response.session.family_id };
}
async function pair(parentHeaders, child) {
  await ok("POST", "/api/devices/register", { device_id: child.deviceId, public_key: child.publicKey,
    platform: child.platform, auth_mode: "android_keystore_ec_signature", child_name: child.deviceId, device_name: child.deviceId });
  const issued = await child.signed("POST", `/api/devices/${child.deviceId}/pairing-sessions`, {});
  assert(issued.status === 201, "child pairing issued");
  await ok("POST", `/api/parent/pairing-sessions/${issued.body.pairing_session_id}/claim`, { pairing_code: issued.body.pairing_code }, parentHeaders);
  const confirmed = await ok("POST", `/api/parent/pairing-sessions/${issued.body.pairing_session_id}/confirm`, { consent: true }, parentHeaders);
  assert(confirmed.status === "confirmed", "explicit relationship confirmation");
}
function start() {
  server = spawn(process.execPath, ["src/index.js", "--host", "127.0.0.1", "--port", String(port), "--data-dir", dir], {
    cwd: root, stdio: "ignore", env: { ...process.env, CPSM_DISABLE_FCM: "1", CPSM_PAIRING_WAIT_MAX_MS: "1500", CPSM_AUTH_MODE: "strict",
      CPSM_ADMIN_TOKEN: crypto.randomBytes(24).toString("hex"), CPSM_PARENT_TOKEN: crypto.randomBytes(24).toString("hex"),
      CPSM_DEVICE_SECRET: "", CPSM_DEVICE_SECRETS: "{}", CPSM_DEVICE_PUBLIC_KEYS: "{}",
      CPSM_ARTIFACTS_DIR: path.join(dir, "artifacts"), NODE_ENV: "production" }
  });
}
async function wait() {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (server && server.exitCode !== null) throw new Error(`server exited: ${server.exitCode}`);
    try { const r = await request("GET", "/api/status"); if (r.status === 200) return r.body; } catch (_) { }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("server startup timeout");
}

async function main() {
  port = await reservePort(); start(); await wait();
  const a = await parent("엄마");
  const child = childKey("wait-child-1"); const other = childKey("wait-child-2");
  for (const c of [child, other]) await ok("POST", "/api/devices/register", { device_id: c.deviceId, public_key: c.publicKey,
    platform: c.platform, auth_mode: "android_keystore_ec_signature", child_name: c.deviceId, device_name: c.deviceId });
  const issued = (await child.signed("POST", `/api/devices/${child.deviceId}/pairing-sessions`, {})).body;
  const waitPath = (since) => `/api/devices/${child.deviceId}/pairing-sessions/${issued.pairing_session_id}/wait?since=${since}`;

  // Nothing happens → held ~1.5 s, then the unchanged state.
  let t = Date.now(); let r = await child.signed("GET", waitPath("pending"));
  assert(r.status === 200 && r.body.status === "pending" && Date.now() - t >= 1300, "idle wait holds then returns pending");
  // State already differs from ?since= → immediate answer.
  t = Date.now(); r = await child.signed("GET", waitPath("unknown"));
  assert(r.body.status === "pending" && Date.now() - t < 1000, "immediate when since differs");
  // Another device cannot watch this QR.
  r = await other.signed("GET", `/api/devices/${other.deviceId}/pairing-sessions/${issued.pairing_session_id}/wait?since=pending`);
  assert(r.status === 404, "foreign device rejected");

  // Parent scans while the child waits → wakes at once with claimed.
  t = Date.now(); const pending = child.signed("GET", waitPath("pending"));
  await new Promise((resolve) => setTimeout(resolve, 300));
  await ok("POST", `/api/parent/pairing-sessions/${issued.pairing_session_id}/claim`, { pairing_code: issued.pairing_code }, { authorization: a.authorization });
  r = await pending; assert(r.body.status === "claimed" && Date.now() - t < 1300, "claim wakes the wait");
  // Parent confirms → wakes with confirmed.
  t = Date.now(); const claimed = child.signed("GET", waitPath("claimed"));
  await new Promise((resolve) => setTimeout(resolve, 300));
  await ok("POST", `/api/parent/pairing-sessions/${issued.pairing_session_id}/confirm`, { consent: true }, { authorization: a.authorization });
  r = await claimed; assert(r.body.status === "confirmed" && r.body.relationship_status === "confirmed" && Date.now() - t < 1300, "confirm wakes the wait");
  r = await child.signed("GET", waitPath("confirmed"));
  assert(r.body.status === "confirmed", "terminal state answers at once");

  console.log(JSON.stringify({ ok: true, assertions, coverage: ["hold_timeout", "immediate", "foreign_device", "claim_wake", "confirm_wake", "terminal"] }));
}
main().then(() => { server.kill(); process.exit(0); }).catch((error) => { console.error(error); if (server) server.kill(); process.exit(1); });
