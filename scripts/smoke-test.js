const http = require("http");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const projectRoot = path.resolve(__dirname, "..");
const dataDir = path.join(projectRoot, "smoke-data");
const port = 18742;

fs.rmSync(dataDir, { recursive: true, force: true });
const artifactsDir = path.join(dataDir, "artifacts");
const cArtifact = Buffer.from("cpsm-c-test-update");
const pArtifact = Buffer.from("cpsm-p-test-update");
const mArtifact = Buffer.from("cpsm-m-test-update");
function publishSmokeArtifact(platform, product, artifact, packageName) {
  const directory = path.join(artifactsDir, platform, product);
  fs.mkdirSync(directory, { recursive: true });
  const name = `${product}-0.1.1.${platform === "android" ? "apk" : "zip"}`;
  fs.writeFileSync(path.join(directory, name), artifact);
  fs.writeFileSync(path.join(directory, "latest.json"), JSON.stringify({
    platform, product, versionCode: 2, versionName: "0.1.1", packageName,
    artifact: name, sha256: crypto.createHash("sha256").update(artifact).digest("hex"),
    size: artifact.length, minVersionCode: 1, channel: "test", releaseNotes: "smoke"
  }));
}
publishSmokeArtifact("windows", "cpsm-c", cArtifact);
publishSmokeArtifact("android", "cpsm-p", pArtifact, "com.cpsm.parents");
publishSmokeArtifact("android", "cpsm-m", mArtifact, "com.cpsm.child");

function request(method, pathname, body, extraHeaders = {}) {
  const payload = body ? JSON.stringify(body) : "";
  return new Promise((resolve, reject) => {
    const req = http.request({
      method,
      hostname: "127.0.0.1",
      port,
      path: pathname,
      headers: {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload),
        ...extraHeaders
      }
    }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        if (res.statusCode >= 400) {
          reject(new Error(data));
          return;
        }
        resolve(data ? JSON.parse(data) : {});
      });
    });
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

function requestRaw(method, pathname) {
  return new Promise((resolve, reject) => {
    const req = http.request({ method, hostname: "127.0.0.1", port, path: pathname }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const body = Buffer.concat(chunks);
        if (res.statusCode >= 400) return reject(new Error(body.toString("utf8")));
        resolve({ statusCode: res.statusCode, body, headers: res.headers });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

async function wait() {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      return await request("GET", "/api/status");
    } catch (_) {
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
  }
  throw new Error("server timeout");
}

async function main() {
  const child = spawn(process.execPath, ["src/index.js", "--port", String(port), "--data-dir", dataDir], {
    cwd: projectRoot,
    env: {
      ...process.env,
      CPSM_DISABLE_FCM: "1",
      CPSM_AUTH_MODE: "disabled",
      CPSM_LOCAL_DEV: "1",
      CPSM_ARTIFACTS_DIR: artifactsDir,
      CPSM_BOOTSTRAP_CODE: "smoke-bootstrap"    },
    stdio: "ignore",
    windowsHide: true
  });

  try {
    await wait();
    const publicCManifest = await request("GET", "/api/updates/manifest?platform=windows&product=cpsm-c");
    const publicCDownload = await requestRaw("GET", "/api/updates/download?platform=windows&product=cpsm-c");
    const publicMManifest = await request("GET", "/api/updates/manifest?platform=android&product=cpsm-m");
    const publicMDownload = await requestRaw("GET", "/api/updates/download?platform=android&product=cpsm-m");
    const publicPManifest = await request("GET", "/api/updates/manifest?platform=android&product=cpsm-p");
    const publicPDownload = await requestRaw("GET", "/api/updates/download?platform=android&product=cpsm-p");
    const stableMManifest = await request("GET", "/api/updates/android/cpsm-m/manifest.json");
    const stableMDownload = await requestRaw("GET", "/api/updates/android/cpsm-m/latest.apk");
    const stablePManifest = await request("GET", "/api/updates/android/cpsm-p/manifest.json");
    const stablePDownload = await requestRaw("GET", "/api/updates/android/cpsm-p/latest.apk");
    if (publicCManifest.versionCode !== 2 || !publicCManifest.downloadUrl || !publicCDownload.body.equals(cArtifact)
        || publicMManifest.versionCode !== 2 || !publicMManifest.downloadUrl || !publicMDownload.body.equals(mArtifact)
        || publicPManifest.versionCode !== 2 || !publicPManifest.downloadUrl || !publicPDownload.body.equals(pArtifact)
        || stableMManifest.product !== "cpsm-m" || !stableMManifest.downloadUrl || !stableMDownload.body.equals(mArtifact)
        || stablePManifest.product !== "cpsm-p" || !stablePManifest.downloadUrl || !stablePDownload.body.equals(pArtifact)) {
      throw new Error("public bootstrap artifact update flow failed");
    }
    const childKeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const childPublicKey = childKeyPair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const registration = await request("POST", "/api/devices/register", {
      device_id: "android-bootstrap-device",
      public_key: childPublicKey,
      auth_mode: "android_keystore_ec_signature",
      device_name: "smoke-note8",
      child_name: "smoke-child",
      metadata: { android_api_level: 28, os_release: "9", security_patch: "2026-01-01", manufacturer: "Samsung", model: "SM-N950N", device: "greatlte", product: "greatltexx", app_version_code: 6, app_version_name: "0.1.5-ota-bootstrap", wifi_ip: "192.0.2.10" }
    });
    const registrationStatus = await request("GET", "/api/devices/android-bootstrap-device/registration-status");
    const gatedSync = await request("POST", "/api/devices/android-bootstrap-device/sync", {
      platform: "android",
      local_policy_version: 0,
      status: { status: "running", policy: { state: "missing", version: 0, signature_status: "unknown" } }
    });
    if (registration.registration_status !== "registered_unpaired"
        || registrationStatus.relationship_status !== "unpaired"
        || registrationStatus.policy_ready !== false
        || !registrationStatus.device_compatibility
        || registrationStatus.device_compatibility.apiLevel !== 28
        || registrationStatus.device_compatibility.updateVerifier !== "signing_info"
        || gatedSync.policy.available !== false
        || gatedSync.policy.reason !== "parent_mapping_required") {
      throw new Error("automatic registration or policy gating flow failed");
    }
    const parentKeyPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const parentPublicKey = parentKeyPair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const parentFingerprint = crypto.createHash("sha256").update(Buffer.from(parentPublicKey, "base64")).digest("hex");
    let fingerprintMismatchRejected = false;
    try {
      await request("POST", "/api/parent/auth/auto-enroll", {
        device_pubkey: parentPublicKey,
        device_fingerprint: "0".repeat(64),
        platform: "android",
        metadata: { android_api_level: 35 }
      });
    } catch (error) {
      fingerprintMismatchRejected = String(error.message || error).includes("parent_device_fingerprint_mismatch");
    }
    if (!fingerprintMismatchRejected) throw new Error("automatic parent enrollment accepted a mismatched fingerprint");
    const enrollment = await request("POST", "/api/parent/auth/auto-enroll", {
      device_pubkey: parentPublicKey,
      device_fingerprint: parentFingerprint,
      platform: "android",
      display_name: "smoke-parent",
      metadata: { android_api_level: 35, os_release: "15", security_patch: "2026-01-01", manufacturer: "Samsung", model: "SM-G991N", device: "o1s", product: "o1sksx" }
    });
    if (enrollment.enrollment !== "automatic"
        || !enrollment.session.device_compatibility
        || enrollment.session.device_compatibility.apiLevel !== 35) {
      throw new Error("automatic parent enrollment or Android compatibility metadata flow failed");
    }
    const parentHeaders = { authorization: `Bearer ${enrollment.session.session_token}` };
    const qrRegistration = await request("POST", "/api/devices/register", {
      device_id: "android-qr-device",
      public_key: childPublicKey,
      auth_mode: "android_keystore_ec_signature",
      device_name: "smoke-qr-child",
      child_name: "smoke-qr-child",
      metadata: { android_api_level: 28, app_version_code: 10, app_version_name: "0.1.9-qr-pairing" }
    });
    const availableBeforeQr = await request("GET", "/api/parent/children/available", undefined, parentHeaders);
    const issuedPairing = await request("POST", "/api/devices/android-qr-device/pairing-sessions", {});
    const claimedPairing = await request(
      "POST",
      `/api/parent/pairing-sessions/${issuedPairing.pairing_session_id}/claim`,
      { pairing_code: issuedPairing.pairing_code },
      parentHeaders
    );
    let pairingReuseRejected = false;
    try {
      await request(
        "POST",
        `/api/parent/pairing-sessions/${issuedPairing.pairing_session_id}/claim`,
        { pairing_code: issuedPairing.pairing_code },
        parentHeaders
      );
    } catch (_) {
      pairingReuseRejected = true;
    }
    const confirmedPairing = await request(
      "POST",
      `/api/parent/pairing-sessions/${issuedPairing.pairing_session_id}/confirm`,
      { consent: true },
      parentHeaders
    );
    if (qrRegistration.registration_status !== "registered_unpaired"
        || !Array.isArray(availableBeforeQr.children)
        || availableBeforeQr.children.length !== 0
        || issuedPairing.pairing_session_id.length < 16
        || !issuedPairing.pairing_code
        || claimedPairing.mapping.status !== "pending_consent"
        || !claimedPairing.preview.parent.display_name
        || !claimedPairing.preview.child.display_name
        || confirmedPairing.mapping.status !== "confirmed"
        || confirmedPairing.policy_ready !== true
        || !pairingReuseRejected) {
      throw new Error("QR pairing preview, confirmation, or one-time-use flow failed");
    }
    const reverseRegistration = await request("POST", "/api/devices/register", {
      device_id: "android-qr-reverse-device",
      public_key: childPublicKey,
      auth_mode: "android_keystore_ec_signature",
      device_name: "smoke-reverse-child",
      child_name: "smoke-reverse-child",
      metadata: { android_api_level: 28, app_version_code: 10, app_version_name: "0.1.9-qr-pairing" }
    });
    const parentIssuedPairing = await request("POST", "/api/parent/pairing-sessions", {}, parentHeaders);
    const parentPairingStatusBeforeClaim = await request(
      "GET",
      `/api/parent/pairing-sessions/${parentIssuedPairing.pairing_session_id}`,
      null,
      parentHeaders
    );
    const childClaimedPairing = await request(
      "POST",
      `/api/devices/android-qr-reverse-device/pairing-sessions/${parentIssuedPairing.pairing_session_id}/claim`,
      { pairing_code: parentIssuedPairing.pairing_code }
    );
    let reverseReuseRejected = false;
    try {
      await request(
        "POST",
        `/api/devices/android-qr-reverse-device/pairing-sessions/${parentIssuedPairing.pairing_session_id}/claim`,
        { pairing_code: parentIssuedPairing.pairing_code }
      );
    } catch (_) {
      reverseReuseRejected = true;
    }
    const reverseConfirmedPairing = await request(
      "POST",
      `/api/devices/android-qr-reverse-device/pairing-sessions/${parentIssuedPairing.pairing_session_id}/confirm`,
      { consent: true }
    );
    const parentPairingStatusAfterConfirm = await request(
      "GET",
      `/api/parent/pairing-sessions/${parentIssuedPairing.pairing_session_id}`,
      null,
      parentHeaders
    );
    if (reverseRegistration.registration_status !== "registered_unpaired"
        || parentIssuedPairing.role !== "parent"
        || parentPairingStatusBeforeClaim.status !== "pending"
        || childClaimedPairing.mapping.status !== "pending_consent"
        || !childClaimedPairing.preview.parent.display_name
        || !childClaimedPairing.preview.child.display_name
        || reverseConfirmedPairing.mapping.status !== "confirmed"
        || parentPairingStatusAfterConfirm.status !== "confirmed"
        || reverseConfirmedPairing.policy_ready !== true
        || !reverseReuseRejected) {
      throw new Error("reverse Parent QR preview and confirmation flow failed");
    }
    const mapping = await request("POST", "/api/parent/mappings", { child_device_id: "android-bootstrap-device" }, parentHeaders);
    const pendingStatus = await request("GET", "/api/devices/android-bootstrap-device/registration-status");
    const parentConsent = await request("POST", `/api/parent/mappings/${mapping.mapping.mappingId}/consent`, { consent: true }, parentHeaders);
    const childConsent = await request("POST", `/api/devices/android-bootstrap-device/consent-requests/${pendingStatus.consent_requests[0].request_id}/decision`, { decision: "approve" });
    const confirmedStatus = await request("GET", "/api/devices/android-bootstrap-device/registration-status");
    const confirmedSync = await request("POST", "/api/devices/android-bootstrap-device/sync", {
      platform: "android",
      local_policy_version: 0,
      status: { status: "running", policy: { state: "missing", version: 0, signature_status: "unknown" } }
    });
    if (mapping.mapping.status !== "pending_consent"
        || parentConsent.mapping.status !== "pending_consent"
        || childConsent.status !== "confirmed"
        || confirmedStatus.relationship_status !== "confirmed"
        || confirmedStatus.policy_ready !== true
        || confirmedSync.policy.available !== true
        || confirmedSync.policy.changed !== true) {
      throw new Error("parent-child mapping, mutual consent, or policy release flow failed");
    }
    await request("POST", "/api/admin/portal-device/token", { fcm_token: "test-token" });
    await request("POST", "/api/devices/local-device/heartbeat", { hostname: "child-pc", childName: "민준" });
    const cManifest = await request("GET", "/api/devices/local-device/updates/manifest?product=cpsm-c");
    const cDownload = await requestRaw("GET", "/api/devices/local-device/updates/download?product=cpsm-c");
    if (cManifest.versionCode !== 2 || !cManifest.sha256 || !cDownload.body.equals(cArtifact)) {
      throw new Error("Windows artifact update flow failed");
    }
    await request("POST", "/api/devices/android-device/heartbeat", {
      hostname: "note8", platform: "android", childName: "민준"
    });
    const mManifest = await request("GET", "/api/devices/android-device/updates/manifest?product=cpsm-m");
    const mDownload = await requestRaw("GET", "/api/devices/android-device/updates/download?product=cpsm-m");
    if (mManifest.versionCode !== 2 || !mDownload.body.equals(mArtifact)) {
      throw new Error("Android child artifact update flow failed");
    }
    const pManifest = await request("GET", "/api/parent/updates/manifest?product=cpsm-p");
    const pDownload = await requestRaw("GET", "/api/parent/updates/download?product=cpsm-p");
    if (pManifest.versionCode !== 2 || !pDownload.body.equals(pArtifact)) {
      throw new Error("Android parent artifact update flow failed");
    }
    await request("POST", "/api/parent/blocked-apps", {
      platform: "windows",
      processName: "steam.exe",
      name: "steam.exe",
      action: "require_approval"
    });
    const sync = await request("POST", "/api/devices/local-device/sync", {
      platform: "windows",
      local_policy_version: 0,
      status: { status: "running" }
    });
    if (!sync.policy.changed) {
      throw new Error("sync did not report policy change");
    }
    await request("POST", "/api/devices/local-device/events", {
      events: [{
        eventId: "event-1",
        sequence: 1,
        type: "app.started",
        eventTime: new Date().toISOString(),
        payload: {
          appName: "steam.exe",
          executablePath: "C:\\Program Files (x86)\\Steam\\steam.exe",
          action: "require_approval",
          matchedRuleId: "steam-rule",
          pid: 1234
        }
      }]
    });
    const requests = await request("GET", "/api/parent/approval-requests");
    if (requests.requests.length !== 1) {
      throw new Error("approval request was not created");
    }
    const errorPayload = {
      client_request_id: "smoke-error-request",
      platform: "windows",
      product: "cpsm-c",
      app_version: { version_code: 3, version_name: "0.1.2-bootstrap-update" },
      runtime: { os_release: "Windows test", token: "must-not-persist" },
      errors: [{
        error_id: "smoke-client-error-1",
        occurred_at: new Date().toISOString(),
        error_code: "process_path_mismatch",
        category: "runtime",
        severity: "error",
        operation: "command.app_terminate",
        component: "processMonitor",
        message: "token=should-be-redacted process path mismatch",
        stack_trace: "Error: token=hidden\\n at processMonitor.js:1",
        context: { pid: 1234, authorization: "Bearer hidden" }
      }]
    };
    const uploadedError = await request("POST", "/api/devices/local-device/errors", errorPayload);
    const duplicatedError = await request("POST", "/api/devices/local-device/errors", errorPayload);
    if (uploadedError.accepted !== 1 || duplicatedError.deduplicated !== 1) {
      throw new Error("error upload deduplication flow failed");
    }
    const errorList = await request("GET", "/api/admin/errors?product=cpsm-c");
    if (errorList.errors.length !== 1 || errorList.errors[0].occurrenceCount !== 1 || errorList.errors[0].isFixed !== false) {
      throw new Error("admin error review list failed");
    }
    if (String(errorList.errors[0].messageRedacted).includes("should-be-redacted") || String(errorList.errors[0].messageRedacted).includes("hidden")) {
      throw new Error("error redaction failed");
    }
    const issueId = errorList.errors[0].errorId;
    const registeredVersion = await request("POST", "/api/admin/app-versions", {
      platform: "windows", product: "cpsm-c", version_code: 4, version_name: "0.1.3-error-fix",
      artifact: "cpsm-c-0.1.3.zip", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", size: 123,
      package_name: "", channel: "test", release_notes: "process path mismatch fix"
    });
    const change = await request("POST", "/api/admin/app-versions/windows/cpsm-c/4/changes", {
      change_type: "fixed", component: "processMonitor", change_key: "safe-process-path-check",
      change_summary: "Reject stale process path before terminate", issue_id: issueId, source_ref: "test-change"
    });
    const verifiedChange = await request("PATCH", `/api/admin/app-versions/windows/cpsm-c/4/changes/${change.change.changeId}`, {
      is_verified: true, verification_note: "Validated with a fresh process path fixture."
    });
    const resolvedError = await request("PATCH", `/api/admin/errors/${issueId}`, {
      status: "resolved", is_fixed: true, fixed_in_version_code: 4,
      resolution_note: "Verified in the Windows process-path fixture."
    });
    if (registeredVersion.version.versionCode !== 4 || !verifiedChange.change.isVerified
        || !resolvedError.error.isFixed || resolvedError.error.status !== "resolved") {
      throw new Error("error fix verification workflow failed");
    }
    const decision = await request("POST", `/api/parent/approval-requests/${requests.requests[0].id}/terminate`);
    const commands = await request("GET", "/api/devices/local-device/commands/poll");
    console.log(JSON.stringify({
      ok: true,
      requestId: requests.requests[0].id,
      decision: decision.request.decision,
      commandType: commands.commands[0].type,
      errorId: issueId,
      errorStatus: resolvedError.error.status
    }, null, 2));
  } finally {
    child.kill();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
