// Isolated integration and persistence coverage for family-scoped text missions.
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
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpsm-missions-"));
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
  return { authorization: `Bearer ${response.session.session_token}`, parentId: response.session.parent_id, familyId: response.session.family_id };
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
async function stop() {
  if (!server || server.exitCode !== null) return;
  const child = server;
  await new Promise((resolve, reject) => { const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("server stop timeout")); }, 5000);
    child.once("exit", () => { clearTimeout(timer); resolve(); }); child.kill("SIGTERM"); });
}
const pp = "/api/parent/missions";
const mp = (id) => `${pp}/${encodeURIComponent(id)}`;
const cp = (child, id) => `/api/devices/${child.deviceId}/missions/${encodeURIComponent(id)}`;
async function create(parentHeaders, deviceId, bonus = 0, fields = {}) {
  return request("POST", pp, { request_id: crypto.randomUUID(), device_id: deviceId,
    title: "Complete this task", instructions: "Finish the task and write a message.", bonus_minutes: bonus, ...fields }, parentHeaders);
}
async function fallbackTest() {
  const fallbackDir = path.join(dir, "json-fallback"); fs.mkdirSync(path.join(fallbackDir, "cpsm.sqlite"), { recursive: true });
  const s = new Store(fallbackDir); assert(s.storageMode() === "json-fallback", "fallback mode selected");
  s.ensureFamily("fallback-family");
  const p = s.ensureParentProfile({ familyId: "fallback-family", deviceFingerprint: "fallback-mission-parent-001", publicKey: "public", displayName: "P" });
  s.upsertDevice("fallback-child", { platform: "android", childName: "C" });
  const c = s.ensureChildProfile({ deviceId: "fallback-child" }); s.state.devices[c.deviceId].registrationStatus = "registered_paired";
  const mappingId = "fallback-confirmed-mapping";
  s.state.parentChildMappings[mappingId] = { mappingId, familyId: p.familyId, parentId: p.parentId, childId: c.childId,
    status: "confirmed", parentConsent: true, childConsent: true, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
  s.state.familyMembers.push({ familyId: p.familyId, memberType: "child", memberId: c.childId, role: "child", status: "active", createdAt: new Date().toISOString() });
  s.save();
  const requestId = crypto.randomUUID();
  const createInput = { familyId: p.familyId, parentId: p.parentId, deviceId: c.deviceId,
    title: "JSON mission", instructions: "Persist all states", bonusMinutes: 7, requestId };
  const created = s.createMission(createInput);
  const m = created.mission;
  assert(created.created, "JSON fallback creates mission on first request");
  const sub = s.submitMission({ missionId: m.missionId, deviceId: c.deviceId, message: "Complete" });
  const reviewed = s.reviewMission({ missionId: m.missionId, submissionId: sub.submission.submissionId, familyId: p.familyId, parentId: p.parentId, decision: "approve" });
  assert(reviewed.command?.type === "screen_time.bonus", "fallback approval creates bonus command");
  const loaded = new Store(fallbackDir);
  assert(loaded.state.missions.find((x) => x.missionId === m.missionId)?.status === "completed", "JSON reload preserves mission");
  assert(loaded.state.missionSubmissions.find((x) => x.submissionId === sub.submission.submissionId)?.status === "approved", "JSON reload preserves submission");
  assert(loaded.state.missionRewards.some((x) => x.submissionId === sub.submission.submissionId && x.bonusMinutes === 7), "JSON reload preserves reward ledger");
  assert(loaded.state.commands.some((x) => x.idempotencyKey === `mission-reward:${sub.submission.submissionId}`), "JSON reload preserves reward command");
  const retried = loaded.createMission(createInput);
  assert(!retried.created && retried.mission.missionId === m.missionId, "JSON retry after reload returns same mission");
  assert(loaded.state.missions.filter((x) => x.missionId === m.missionId).length === 1, "JSON retry creates no second mission row");
  const requestMapping = loaded.state.missionCreateRequests.find((x) => x.requestId === requestId);
  assert(requestMapping && /^[a-f0-9]{64}$/.test(requestMapping.payloadFingerprint), "JSON fallback persists only the payload fingerprint mapping");
  let conflict = false;
  try { loaded.createMission({ ...createInput, instructions: "Changed payload" }); }
  catch (error) { conflict = error.code === "mission_request_id_conflict" && error.status === 409; }
  assert(conflict, "JSON retry key with changed payload conflicts");
  const cancelFixture = loaded.createMission({ ...createInput, requestId: crypto.randomUUID(),
    title: "JSON cancel", instructions: "Persist all states", bonusMinutes: 0 }).mission;
  loaded.cancelMission({ missionId: cancelFixture.missionId, familyId: p.familyId, parentId: p.parentId });
  const rejectFixture = loaded.createMission({ ...createInput, requestId: crypto.randomUUID(),
    title: "JSON reject", instructions: "Persist all states", bonusMinutes: 0 }).mission;
  const rejectSubmission = loaded.submitMission({ missionId: rejectFixture.missionId,
    deviceId: c.deviceId, message: "Complete" });
  loaded.reviewMission({ missionId: rejectFixture.missionId, submissionId: rejectSubmission.submission.submissionId,
    familyId: p.familyId, parentId: p.parentId, decision: "reject", note: "Try again" });
  const missionAudits = loaded.state.auditLog.filter((entry) => entry.action.startsWith("mission_"));
  assert(missionAudits.filter((entry) => entry.action === "mission_created" && entry.requestId === requestId).length === 1,
    "JSON idempotent retry does not duplicate create audit");
  assert(missionAudits.some((entry) => entry.action === "mission_text_submitted")
    && missionAudits.some((entry) => entry.action === "mission_approved")
    && missionAudits.some((entry) => entry.action === "mission_cancelled")
    && missionAudits.some((entry) => entry.action === "mission_rejected"),
  "JSON fallback persists create/cancel/submit/approve/reject lifecycle audit entries");
  assert(missionAudits.every((entry) => !JSON.stringify(entry.metadata).includes("Persist all states")
    && !JSON.stringify(entry.metadata).includes("Complete")
    && !JSON.stringify(entry.metadata).includes("Try again")), "JSON audit metadata excludes mission, submission, and review text");
  const reviewRetry = loaded.reviewMission({ missionId: m.missionId, submissionId: sub.submission.submissionId,
    familyId: p.familyId, parentId: p.parentId, decision: "approve" });
  assert(reviewRetry.review.reviewId === reviewed.review.reviewId
    && loaded.state.auditLog.filter((entry) => entry.action === "mission_approved"
      && entry.metadata.submissionId === sub.submission.submissionId).length === 1,
  "JSON approval retry does not duplicate lifecycle audit");
  s.db?.close(); loaded.db?.close();

  const migrationDir = path.join(dir, "sqlite-migration");
  const initial = new Store(migrationDir);
  assert(initial.storageMode() === "sqlite", "migration fixture starts with SQLite");
  initial.db.close();
  const migrationDb = new DatabaseSync(path.join(migrationDir, "cpsm.sqlite"));
  migrationDb.exec("DROP TABLE mission_create_requests");
  migrationDb.close();
  const migrated = new Store(migrationDir);
  assert(migrated.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='mission_create_requests'").get(),
    "opening an older SQLite database adds the mission request mapping table");
  migrated.db.close();
}
async function main() {
  port = await reservePort(); start();
  try {
    assert((await wait()).storage === "sqlite", "integration fixture uses isolated SQLite");
    const pa = await parent("Parent A"); const pb = await parent("Parent B");
    const ca = childKey(`mission-a-${crypto.randomUUID()}`); const cb = childKey(`mission-b-${crypto.randomUUID()}`);
    const win = childKey(`mission-win-${crypto.randomUUID()}`, "windows"); const unpaired = childKey(`mission-unpaired-${crypto.randomUUID()}`);
    assert((await request("GET", "/api/parent/missions")).status === 401, "parent routes require auth");
    assert((await request("GET", `/api/devices/${ca.deviceId}/missions`)).status === 401, "child routes require device auth");
    assert((await request("GET", `/api/devices/${ca.deviceId}/mission-rewards`)).status === 401, "reward ledger requires device auth");
    assert((await request("POST", `/api/devices/${ca.deviceId}/missions/not-real/submissions`, { message: "No auth" })).status === 401,
      "unauthenticated child submission rejected");
    await ok("POST", "/api/devices/register", { device_id: unpaired.deviceId, public_key: unpaired.publicKey, platform: "android" });
    assert((await unpaired.signed("GET", `/api/devices/${unpaired.deviceId}/missions`)).status === 409, "unconfirmed child cannot read missions");
    assert((await unpaired.signed("GET", `/api/devices/${unpaired.deviceId}/mission-rewards`)).status === 409, "unconfirmed child cannot read rewards");
    assert((await create(pa, unpaired.deviceId, 0)).status === 409, "unconfirmed child cannot be assigned");
    await pair(pa, ca); await pair(pb, cb); await pair(pa, win);
    assert((await create(pa, win.deviceId, 4)).status === 409, "missions require Android device");
    assert((await create(pb, ca.deviceId, 4)).status === 404, "other family cannot assign child");

    const bad = [
      { title: " ", instructions: "valid", bonus_minutes: 0 }, { title: "x".repeat(81), instructions: "valid", bonus_minutes: 0 },
      { title: "valid", instructions: "x".repeat(1001), bonus_minutes: 0 }, { title: "valid", instructions: "valid" },
      { title: "valid", instructions: "valid", bonus_minutes: -1 }, { title: "valid", instructions: "valid", bonus_minutes: 241 },
      { title: "valid", instructions: "valid", bonus_minutes: 1.5 }, { title: "valid", instructions: "valid", bonus_minutes: "0" }
    ];
    for (const input of bad) assert((await request("POST", pp,
      { request_id: crypto.randomUUID(), device_id: ca.deviceId, ...input }, pa)).status === 400, "invalid mission inputs rejected");
    assert((await request("POST", pp, { request_id: crypto.randomUUID(), device_id: 42, title: "Bad device id", instructions: "Valid text", bonus_minutes: 0 }, pa)).status === 400,
      "mission device id must be a string");
    for (const media of [{ photo: "data" }, { metadata: { audio_url: "https://example.invalid/a" } }]) {
      const rejected = await create(pa, ca.deviceId, 0, media); assert(rejected.status === 400 && rejected.body.error === "mission_media_not_supported", "media fields rejected");
    }
    assert((await request("POST", pp, { request_id: crypto.randomUUID(), device_id: ca.deviceId, title: "No default", instructions: "Select minutes" }, pa)).status === 400, "bonus has no default");
    assert((await request("GET", `${pp}?status=invalid`, undefined, pa)).status === 400, "invalid parent filter rejected");
    assert((await ca.signed("GET", `/api/devices/${ca.deviceId}/missions?status=pending_review`)).status === 400, "invalid child filter rejected");
    const bList = await request("GET", `${pp}?status=all`, undefined, pb);
    assert(bList.status === 200 && bList.body.missions.length === 0, "family B cannot list family A missions");
    await stop();
    let membershipDb = new DatabaseSync(path.join(dir, "cpsm.sqlite"));
    membershipDb.prepare("UPDATE family_members SET status='revoked' WHERE family_id=? AND member_type='parent' AND member_id=?").run(pb.familyId, pb.parentId);
    membershipDb.close();
    start(); await wait();
    assert((await request("GET", `${pp}?status=all`, undefined, pb)).status === 403, "parent session without active family membership cannot use mission API");
    await stop();
    membershipDb = new DatabaseSync(path.join(dir, "cpsm.sqlite"));
    membershipDb.prepare("UPDATE family_members SET status='active' WHERE family_id=? AND member_type='parent' AND member_id=?").run(pb.familyId, pb.parentId);
    membershipDb.close();
    start(); await wait();

    const createRequestId = crypto.randomUUID();
    const created = await create(pa, ca.deviceId, 25, { request_id: createRequestId });
    assert(created.status === 201 && created.body.mission.status === "active" && created.body.mission.bonus_minutes === 25, "mission created with selected bonus");
    const mission = created.body.mission; const subPath = `${cp(ca, mission.mission_id)}/submissions`;
    const createRetry = await create(pa, ca.deviceId, 25, { request_id: createRequestId,
      title: " Complete this task ", instructions: " Finish the task and write a message. " });
    assert(createRetry.status === 200 && createRetry.body.mission.mission_id === mission.mission_id,
      "same create request ID and normalized payload returns the same mission");
    const scopedCreate = await create(pb, cb.deviceId, 25, { request_id: createRequestId });
    assert(scopedCreate.status === 201 && scopedCreate.body.mission.mission_id !== mission.mission_id,
      "the same request UUID is isolated by family and parent scope");
    const createConflict = await create(pa, ca.deviceId, 25,
      { request_id: createRequestId, instructions: "Different normalized payload" });
    assert(createConflict.status === 409 && createConflict.body.error === "mission_request_id_conflict",
      "same create request ID with changed payload conflicts");
    assert((await request("POST", pp, { device_id: ca.deviceId, title: "Missing ID", instructions: "Required UUID", bonus_minutes: 0 }, pa)).status === 400,
      "mission creation requires request_id");
    const childList = await ca.signed("GET", `/api/devices/${ca.deviceId}/missions?status=active`);
    assert(childList.status === 200 && childList.body.missions.some((x) => x.mission_id === mission.mission_id), "child sees own active mission");
    const mediaSubmit = await ca.signed("POST", subPath, { message: "Done", audio: "blob" });
    assert(mediaSubmit.status === 400 && mediaSubmit.body.error === "mission_media_not_supported", "audio is rejected");
    assert((await ca.signed("POST", subPath, { message: "x".repeat(2001) })).status === 400, "message length validated");
    assert((await cb.signed("POST", `${cp(cb, mission.mission_id)}/submissions`, { message: "foreign" })).status === 404, "other family cannot submit");
    const submitted = await ca.signed("POST", subPath, { message: "I completed it." });
    assert(submitted.status === 201 && submitted.body.submission.status === "pending_review" && submitted.body.mission.status === "pending_review", "text submission becomes pending review");
    const reviewQueue = await request("GET", `${pp}?status=pending_review`, undefined, pa);
    const pendingMission = reviewQueue.body.missions.find((item) => item.mission_id === mission.mission_id);
    assert(reviewQueue.status === 200 && pendingMission, "parent pending-review filter returns submitted mission");
    assert(pendingMission.latest_submission.reviewed_at === null && pendingMission.latest_submission.decision === null
      && pendingMission.latest_submission.note === null, "pending submission review metadata is explicitly null");
    assert((await request("POST", `${mp(mission.mission_id)}/cancel`, {}, pa)).status === 409,
      "pending-review mission cannot be canceled");
    assert((await ca.signed("POST", subPath, { message: "Duplicate" })).status === 409, "duplicate pending submission rejected");
    assert((await request("POST", `${mp(mission.mission_id)}/review`, { submission_id: submitted.body.submission.submission_id, decision: "maybe" }, pa)).status === 400,
      "review decision must be approve or reject");
    assert((await request("POST", `${mp(mission.mission_id)}/review`, { submission_id: submitted.body.submission.submission_id, decision: "reject", note: "x".repeat(501) }, pa)).status === 400,
      "review note maximum length validated");
    const rejected = await request("POST", `${mp(mission.mission_id)}/review`, { submission_id: submitted.body.submission.submission_id, decision: "reject", note: "Try again" }, pa);
    assert(rejected.status === 200 && rejected.body.mission.status === "active" && rejected.body.submission.status === "rejected", "reject retains submission and reactivates mission");
    assert(rejected.body.reward === null && rejected.body.command === null, "reject creates no reward or command");
    const rejectRetry = await request("POST", `${mp(mission.mission_id)}/review`, { submission_id: submitted.body.submission.submission_id, decision: "reject" }, pa);
    assert(rejectRetry.status === 200 && rejectRetry.body.review.review_id === rejected.body.review.review_id, "same rejection retry idempotent");
    const resub = await ca.signed("POST", subPath, { message: "Finished after retry." });
    assert(resub.status === 201 && resub.body.submission.submission_id !== submitted.body.submission.submission_id, "rejected task allows new text submission");
    assert((await request("POST", `${mp(mission.mission_id)}/review`, { submission_id: submitted.body.submission.submission_id, decision: "approve" }, pa)).status === 409, "reviewed submission cannot change decision");
    const approved = await request("POST", `${mp(mission.mission_id)}/review`, { submission_id: resub.body.submission.submission_id, decision: "approve", note: "Good" }, pa);
    assert(approved.status === 200 && approved.body.mission.status === "completed" && approved.body.submission.status === "approved", "approve completes mission");
    assert(approved.body.reward.bonus_minutes === 25 && approved.body.command.type === "screen_time.bonus" && approved.body.command.payload.minutes === 25, "approve creates ledger and capped bonus command");
    assert(approved.body.command.idempotency_key === `mission-reward:${resub.body.submission.submission_id}`, "stable reward command idempotency key");
    const approveRetry = await request("POST", `${mp(mission.mission_id)}/review`, { submission_id: resub.body.submission.submission_id, decision: "approve" }, pa);
    assert(approveRetry.status === 200 && approveRetry.body.review.review_id === approved.body.review.review_id
      && approveRetry.body.reward.reward_id === approved.body.reward.reward_id && approveRetry.body.command.id === approved.body.command.id,
    "approval retry has no duplicate review, ledger, or command");
    const childRewardLedger = await ca.signed("GET", `/api/devices/${ca.deviceId}/mission-rewards?limit=100`);
    assert(childRewardLedger.status === 200 && childRewardLedger.body.rewards.length === 1
      && childRewardLedger.body.rewards[0].mission_title === mission.title
      && childRewardLedger.body.rewards[0].bonus_minutes === 25
      && childRewardLedger.body.rewards[0].command_state === "queued",
    "child reads own reward ledger without submission text");
    const foreignRewardLedger = await cb.signed("GET", `/api/devices/${cb.deviceId}/mission-rewards`);
    assert(foreignRewardLedger.status === 200 && foreignRewardLedger.body.rewards.length === 0,
      "other family reward ledger is empty");
    assert((await ca.signed("GET", `/api/devices/${ca.deviceId}/mission-rewards?limit=101`)).status === 400,
      "reward ledger limit is bounded");

    await stop();
    const expiryDb = new DatabaseSync(path.join(dir, "cpsm.sqlite"));
    expiryDb.prepare("UPDATE commands SET expires_at=? WHERE id=? AND state='queued' AND delivered_at IS NULL")
      .run(new Date(Date.now() - 61 * 60 * 1000).toISOString(), approved.body.command.id);
    expiryDb.close();
    start(); await wait();
    const rewardPoll = await ca.signed("GET", `/api/devices/${ca.deviceId}/commands/poll`);
    const renewedRewards = rewardPoll.body.commands.filter((item) => item.idempotencyKey === approved.body.command.idempotency_key);
    assert(rewardPoll.status === 200 && renewedRewards.length === 1, "expired undelivered reward is delivered once on device poll");
    assert(renewedRewards[0].id === approved.body.command.id && Date.parse(renewedRewards[0].expiresAt) > Date.now(),
      "renewal preserves command ID and moves expiry into the future");
    const deliveredRewardLedger = await ca.signed("GET", `/api/devices/${ca.deviceId}/mission-rewards`);
    assert(deliveredRewardLedger.status === 200 && deliveredRewardLedger.body.rewards[0].command_state === "delivered",
      "reward ledger reflects queue delivery without claiming local time application");

    const praise = await create(pa, ca.deviceId, 0); assert(praise.status === 201 && praise.body.mission.bonus_minutes === 0, "zero-minute mission is explicit praise-only");
    const praiseSub = await ca.signed("POST", `${cp(ca, praise.body.mission.mission_id)}/submissions`, { message: "Done" });
    const praiseApproval = await request("POST", `${mp(praise.body.mission.mission_id)}/review`, { submission_id: praiseSub.body.submission.submission_id, decision: "approve" }, pa);
    assert(praiseApproval.status === 200 && praiseApproval.body.reward.bonus_minutes === 0 && praiseApproval.body.command === null, "praise-only stores ledger but no command");
    const fullRewardLedger = await ca.signed("GET", `/api/devices/${ca.deviceId}/mission-rewards`);
    assert(fullRewardLedger.status === 200 && fullRewardLedger.body.rewards.length === 2
      && fullRewardLedger.body.rewards.some((item) => item.bonus_minutes === 0 && item.command_state === "praise_only")
      && fullRewardLedger.body.rewards.some((item) => item.bonus_minutes === 25),
    "ledger distinguishes praise-only and time rewards");
    assert((await request("POST", `${mp(mission.mission_id)}/review`, { submission_id: "foreign", decision: "approve" }, pb)).status === 404, "other parent cannot review submission");
    const capMission = await create(pa, ca.deviceId, 240);
    assert(capMission.status === 201 && capMission.body.mission.bonus_minutes === 240, "maximum 240-minute bonus accepted");
    assert((await request("POST", `${mp(capMission.body.mission.mission_id)}/cancel`, {}, pa)).status === 200, "cap validation fixture canceled cleanly");
    const cancelMe = await create(pa, ca.deviceId, 3);
    const canceled = await request("POST", `${mp(cancelMe.body.mission.mission_id)}/cancel`, {}, pa);
    assert(canceled.status === 200 && canceled.body.mission.status === "cancelled", "parent cancels mission");
    assert((await ca.signed("POST", `${cp(ca, cancelMe.body.mission.mission_id)}/submissions`, { message: "too late" })).status === 409, "cancelled mission cannot be submitted");

    const parentList = await request("GET", `${pp}?status=all`, undefined, pa);
    assert(parentList.body.missions.some((x) => x.mission_id === mission.mission_id && x.latest_submission.status === "approved"), "parent sees latest submission history");
    await stop();
    let db = new DatabaseSync(path.join(dir, "cpsm.sqlite"));
    const count = db.prepare("SELECT COUNT(*) AS n FROM mission_rewards WHERE submission_id=?").get(resub.body.submission.submission_id).n;
    const cmdCount = db.prepare("SELECT COUNT(*) AS n FROM commands WHERE device_id=? AND idempotency_key=? AND type='screen_time.bonus'").get(ca.deviceId, `mission-reward:${resub.body.submission.submission_id}`).n;
    const praiseLedger = db.prepare("SELECT COUNT(*) AS n FROM mission_rewards WHERE submission_id=? AND bonus_minutes=0").get(praiseSub.body.submission.submission_id).n;
    const praiseCmd = db.prepare("SELECT COUNT(*) AS n FROM commands WHERE idempotency_key=?").get(`mission-reward:${praiseSub.body.submission.submission_id}`).n;
    const requestMapCount = db.prepare("SELECT COUNT(*) AS n FROM mission_create_requests WHERE family_id=? AND parent_id=? AND request_id=?")
      .get(pa.familyId, pa.parentId, createRequestId).n;
    const missionRowCount = db.prepare("SELECT COUNT(*) AS n FROM missions WHERE mission_id=?").get(mission.mission_id).n;
    const createAuditRows = db.prepare("SELECT metadata_json FROM audit_log WHERE action='mission_created' AND request_id=?")
      .all(createRequestId);
    const createAuditCount = createAuditRows.filter((entry) => JSON.parse(entry.metadata_json).missionId === mission.mission_id).length;
    const missionAuditRows = db.prepare("SELECT action, metadata_json FROM audit_log WHERE action LIKE 'mission_%'").all();
    assert(Number(count) === 1 && Number(cmdCount) === 1, "exactly one SQLite reward row and bonus command");
    assert(Number(praiseLedger) === 1 && Number(praiseCmd) === 0, "praise row has no command"); db.close();
    assert(Number(requestMapCount) === 1 && Number(missionRowCount) === 1, "SQLite stores one create mapping and one mission row for retries");
    assert(Number(createAuditCount) === 1, "SQLite idempotent create retry does not duplicate mission_created audit");
    assert(missionAuditRows.some((entry) => entry.action === "mission_cancelled")
      && missionAuditRows.some((entry) => entry.action === "mission_text_submitted")
      && missionAuditRows.some((entry) => entry.action === "mission_rejected")
      && missionAuditRows.some((entry) => entry.action === "mission_approved"), "SQLite stores mission lifecycle audit events");
    assert(missionAuditRows.every((entry) => !entry.metadata_json.includes("Finish the task and write a message.")
      && !entry.metadata_json.includes("I completed it.") && !entry.metadata_json.includes("Try again")
      && !entry.metadata_json.includes("Good")), "SQLite audit metadata excludes mission, submission, and review text");
    assert(missionAuditRows.filter((entry) => entry.action === "mission_approved"
      && JSON.parse(entry.metadata_json).submissionId === resub.body.submission.submission_id).length === 1
      && missionAuditRows.filter((entry) => entry.action === "mission_rejected"
        && JSON.parse(entry.metadata_json).submissionId === submitted.body.submission.submission_id).length === 1,
    "SQLite review retries do not duplicate approve or reject audit events");
    start(); assert((await wait()).storage === "sqlite", "SQLite reload works");
    const reload = await request("GET", `${pp}?status=all`, undefined, pa);
    const reloadedMission = reload.body.missions.find((item) => item.mission_id === mission.mission_id);
    assert(reloadedMission && reloadedMission.status === "completed"
      && reloadedMission.latest_submission.submission_id === resub.body.submission.submission_id,
    "SQLite reload preserves all mission history");
    assert(reloadedMission.latest_submission.reviewed_at === approved.body.review.reviewed_at
      && reloadedMission.latest_submission.decision === "approve"
      && reloadedMission.latest_submission.note === "Good",
    "review metadata remains available in mission list after SQLite reload");
    const retryReload = await request("POST", `${mp(mission.mission_id)}/review`, { submission_id: resub.body.submission.submission_id, decision: "approve" }, pa);
    assert(retryReload.status === 200 && retryReload.body.command.id === approved.body.command.id, "SQLite reload preserves approval idempotency");
    const createRetryReload = await create(pa, ca.deviceId, 25, { request_id: createRequestId });
    assert(createRetryReload.status === 200 && createRetryReload.body.mission.mission_id === mission.mission_id,
      "SQLite reload preserves mission-create idempotency mapping");
    await stop();
    db = new DatabaseSync(path.join(dir, "cpsm.sqlite"));
    db.prepare("UPDATE parent_child_mappings SET status='revoked' WHERE child_id=?").run(`child-${ca.deviceId}`); db.close();
    start(); await wait();
    const staleParent = await request("GET", `${pp}?status=all`, undefined, pa);
    assert(staleParent.status === 200 && !staleParent.body.missions.some((x) => x.mission_id === mission.mission_id), "parent history hidden after relationship revoked");
    assert((await ca.signed("GET", `/api/devices/${ca.deviceId}/missions?status=all`)).status === 409, "child history hidden after relationship revoked");
    assert((await ca.signed("GET", `/api/devices/${ca.deviceId}/mission-rewards`)).status === 409, "child reward history hidden after relationship revoked");
    assert((await request("POST", `${mp(mission.mission_id)}/review`, { submission_id: resub.body.submission.submission_id, decision: "approve" }, pa)).status === 404, "stale relationship cannot review old history");
    await stop(); await fallbackTest();
    console.log(JSON.stringify({ ok: true, assertions, sqlite_reload: "passed", json_fallback_reload: "passed",
      coverage: ["auth", "validation", "text_only", "confirmed_android", "family_and_stale_history_isolation", "reject_resubmit", "retry_idempotency", "one_ledger_and_command", "praise_only", "sqlite_json_reload"] }));
  } finally { await stop().catch(() => {}); if (server && server.exitCode === null) server.kill("SIGKILL"); fs.rmSync(dir, { recursive: true, force: true }); }
}
main().catch((error) => { console.error(error && error.stack ? error.stack : String(error)); process.exitCode = 1; });
