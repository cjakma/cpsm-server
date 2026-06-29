const http = require("http");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const projectRoot = path.resolve(__dirname, "..");
const dataDir = path.join(projectRoot, "smoke-data");
const port = 18742;

fs.rmSync(dataDir, { recursive: true, force: true });

function request(method, pathname, body) {
  const payload = body ? JSON.stringify(body) : "";
  return new Promise((resolve, reject) => {
    const req = http.request({
      method,
      hostname: "127.0.0.1",
      port,
      path: pathname,
      headers: {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload)
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
      CPSM_DISABLE_FCM: "1"
    },
    stdio: "ignore",
    windowsHide: true
  });

  try {
    await wait();
    await request("POST", "/api/admin/portal-device/token", { fcm_token: "test-token" });
    await request("POST", "/api/devices/local-device/heartbeat", { hostname: "child-pc", childName: "민준" });
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
    const decision = await request("POST", `/api/parent/approval-requests/${requests.requests[0].id}/terminate`);
    const commands = await request("GET", "/api/devices/local-device/commands/poll");
    console.log(JSON.stringify({
      ok: true,
      requestId: requests.requests[0].id,
      decision: decision.request.decision,
      commandType: commands.commands[0].type
    }, null, 2));
  } finally {
    child.kill();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
