// Co-guardian family invites and policy-change notification to the other parents.
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
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpsm-family-invite-"));
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
    cwd: root, stdio: "ignore", env: { ...process.env, CPSM_DISABLE_FCM: "1", CPSM_AUTH_MODE: "strict",
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
  const a = await parent("엄마"); const b = await parent("아빠"); const c = await parent("이웃");
  const child = childKey("invite-child-1"); await pair({ authorization: a.authorization }, child);

  // B (no children) joins A's family with A's one-time invite.
  const invite = await ok("POST", "/api/parent/family-invites", {}, { authorization: a.authorization });
  assert(invite.invite_id && invite.invite_code && invite.expires_at, "invite issued");
  const wrong = await request("POST", `/api/parent/family-invites/${invite.invite_id}/accept`, { invite_code: "x" }, { authorization: b.authorization });
  assert(wrong.status === 403, "wrong invite code rejected");
  const own = await request("POST", `/api/parent/family-invites/${invite.invite_id}/accept`, { invite_code: invite.invite_code }, { authorization: a.authorization });
  assert(own.status === 409, "issuer cannot accept own invite");
  const joined = await ok("POST", `/api/parent/family-invites/${invite.invite_id}/accept`, { invite_code: invite.invite_code }, { authorization: b.authorization });
  assert(joined.family_id === a.familyId && joined.reenroll_required === true, "B joined A family");
  const stale = await request("GET", "/api/parent/devices", undefined, { authorization: b.authorization });
  assert(stale.status === 401 || stale.status === 403, "B old session revoked");
  const reused = await request("POST", `/api/parent/family-invites/${invite.invite_id}/accept`, { invite_code: invite.invite_code }, { authorization: c.authorization });
  assert(reused.status === 410, "invite is one-time");

  // B re-enrolls with the same device key and now sees A's child.
  const b2 = await ok("POST", "/api/parent/auth/auto-enroll", { device_pubkey: b.key.pub, device_fingerprint: b.key.fingerprint,
    platform: "android", display_name: "아빠", metadata: { android_api_level: 35 } });
  assert(b2.session.family_id === a.familyId, "re-enrolled into joined family");
  const db = new DatabaseSync(path.join(dir, "cpsm.sqlite"), { readOnly: true });
  const roleB = db.prepare("SELECT role FROM family_members WHERE member_type='parent' AND member_id=?").get(b.parentId);
  db.close();
  assert(roleB && roleB.role === "guardian", "co-guardian role kept after re-enroll");
  const bAuth = { authorization: `Bearer ${b2.session.session_token}` };
  const devices = await ok("GET", "/api/parent/devices", undefined, bAuth);
  assert(devices.devices.some((d) => d.device_id === child.deviceId), "co-guardian sees child");

  // A rule change notifies the other parent (FCM disabled here → counted as skipped, not sent).
  await ok("POST", "/api/parent/devices/fcm-token", { fcm_token: "token-b-" + crypto.randomUUID() }, bAuth);
  const saved = await ok("PUT", "/api/parent/policies/current", { rules: [{ id: "r1", name: "com.android.chrome", platform: "android",
    action: "block", match: { type: "package", packageName: "com.android.chrome" } }] }, { authorization: a.authorization });
  assert(saved.parents_notified && saved.parents_notified.parents === 1 && saved.parents_notified.skipped === 1, "other parent targeted");
  const current = await ok("GET", "/api/parent/policies/current", undefined, bAuth);
  assert(Array.isArray(current.rules) && current.rules.some((r) => r.id === "r1"), "co-guardian reads the new rule");
  const log = fs.readFileSync(path.join(dir, "notifications.ndjson"), "utf8");
  assert(log.includes("cpsm_policy_changed"), "policy change notification recorded");

  // A parent who already guards a child cannot be moved (would strand that child).
  const d = await parent("다른집"); await pair({ authorization: d.authorization }, childKey("invite-child-2"));
  const invite2 = await ok("POST", "/api/parent/family-invites", {}, { authorization: a.authorization });
  const blocked = await request("POST", `/api/parent/family-invites/${invite2.invite_id}/accept`, { invite_code: invite2.invite_code }, { authorization: d.authorization });
  assert(blocked.status === 409 && blocked.body.error === "parent_family_has_children", "parent with children refused");

  console.log(JSON.stringify({ ok: true, assertions, coverage: ["invite", "one_time", "revoke_session", "reenroll", "policy_notify", "strand_guard"] }));
}
main().then(() => { server.kill(); process.exit(0); }).catch((error) => { console.error(error); if (server) server.kill(); process.exit(1); });
