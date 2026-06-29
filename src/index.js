const http = require("http");
const path = require("path");
const crypto = require("crypto");
const { Store } = require("./store");
const { FcmSender } = require("./fcm");

function parseArgs(args) {
  const parsed = {
    port: Number(process.env.PORT || 18732),
    dataDir: process.env.CPSM_SERVER_DATA_DIR || path.join(process.cwd(), "data"),
    dev: false
  };
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === "--port") {
      parsed.port = Number(args[index + 1]);
      index += 1;
    } else if (args[index] === "--data-dir") {
      parsed.dataDir = args[index + 1];
      index += 1;
    } else if (args[index] === "--dev") {
      parsed.dev = true;
    }
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
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(body, null, 2));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => { data += chunk; });
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (error) {
        reject(error);
      }
    });
  });
}

function makePolicyFromBlockedApps(store, deviceId) {
  const platform = store.state.devices[deviceId] && store.state.devices[deviceId].platform
    ? store.state.devices[deviceId].platform
    : "windows";
  const rules = store.state.policy.rules
    .filter((rule) => !rule.platform || rule.platform === platform)
    .filter((rule) => !rule.excludedUntil || Date.parse(rule.excludedUntil) < Date.now());

  return {
    policyId: store.state.policy.policyId,
    version: store.state.policy.version,
    hash: store.state.policy.hash,
    timezone: "Asia/Seoul",
    enforcementMode: "enforce",
    appRules: rules.map((rule) => ({
      id: rule.id,
      platform: rule.platform,
      name: rule.name,
      match: rule.match,
      action: rule.action || "block",
      reason: rule.reason || "parent_rule"
    }))
  };
}

function jitteredSyncMs() {
  return 30000 + Math.floor(Math.random() * 15000);
}

async function notifyParentForEvent(fcm, event, request) {
  const payload = event.payload || {};
  const childName = request ? request.childName : event.childName;
  const appName = request ? request.appName : (payload.appName || "앱");
  const type = request ? "cpsm_app_launch_request" : "cpsm_app_event";
  await fcm.sendToParents({
    type,
    request_id: request ? request.id : "",
    event_id: event.id,
    device_id: event.deviceId,
    child_name: childName || "자녀",
    device_name: request ? request.deviceName : "",
    app_name: appName,
    action: payload.action || "",
    matched_rule_id: payload.matchedRuleId || payload.ruleId || "",
    executable_path: payload.executablePath || "",
    pid: String(payload.pid || "")
  }, {
    title: `${childName || "자녀"} 앱 이벤트`,
    body: `${childName || "자녀"}가 ${appName}을 실행했습니다.`
  });
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const log = logger();
  const store = new Store(path.resolve(options.dataDir));
  const fcm = new FcmSender(store, log);

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://localhost");

      if (req.method === "GET" && url.pathname === "/api/status") {
        sendJson(res, 200, {
          ok: true,
          service: "cpsm-server",
          parentTokens: store.state.parentTokens.length,
          devices: Object.keys(store.state.devices).length,
          pendingCommands: store.state.commands.filter((command) => command.status === "queued").length,
          policyVersion: store.state.policy.version,
          fcmEnabled: fcm.enabled()
        });
        return;
      }

      if (req.method === "POST" && url.pathname === "/api/admin/portal-device/token") {
        const body = await readBody(req);
        store.registerParentToken(body.fcm_token || body.token);
        sendJson(res, 200, { ok: true, registered: true });
        return;
      }

      const deviceEvents = url.pathname.match(/^\/api\/devices\/([^/]+)\/events$/);
      if (req.method === "POST" && deviceEvents) {
        const deviceId = decodeURIComponent(deviceEvents[1]);
        const body = await readBody(req);
        const stored = store.addEvents(deviceId, body.events || []);
        for (const event of stored) {
          const action = event.payload && event.payload.action;
          if (action === "require_approval" && !store.pendingRequestForPid(deviceId, event.payload.pid)) {
            const request = store.createApprovalRequest(deviceId, event);
            await notifyParentForEvent(fcm, event, request);
          } else if (action === "monitor" || action === "block") {
            await notifyParentForEvent(fcm, event, null);
          }
        }
        sendJson(res, 200, { ok: true, received: stored.length });
        return;
      }

      const heartbeat = url.pathname.match(/^\/api\/devices\/([^/]+)\/heartbeat$/);
      if (req.method === "POST" && heartbeat) {
        const deviceId = decodeURIComponent(heartbeat[1]);
        const body = await readBody(req);
        store.upsertDevice(deviceId, {
          deviceName: body.hostname || body.deviceName || deviceId,
          childName: body.childName || "자녀",
          platform: body.platform || body.policy && body.policy.platform || "windows",
          status: body.status || "running"
        });
        sendJson(res, 200, { ok: true });
        return;
      }

      const sync = url.pathname.match(/^\/api\/devices\/([^/]+)\/sync$/);
      if (req.method === "POST" && sync) {
        const deviceId = decodeURIComponent(sync[1]);
        const body = await readBody(req);
        const device = store.upsertDevice(deviceId, {
          deviceName: body.deviceName || body.hostname || deviceId,
          childName: body.childName || "자녀",
          platform: body.platform || "windows",
          status: body.status && body.status.status ? body.status.status : "running",
          currentApp: body.status && body.status.current_app ? body.status.current_app : "",
          localPolicyVersion: Number(body.local_policy_version || 0),
          lastEventSeq: Number(body.last_event_seq || 0)
        });
        const commands = store.pollCommands(deviceId);
        sendJson(res, 200, {
          ok: true,
          server_time: new Date().toISOString(),
          device,
          policy: {
            changed: Number(body.local_policy_version || 0) < Number(store.state.policy.version || 0),
            version: store.state.policy.version,
            hash: store.state.policy.hash,
            download_url: `/api/devices/${encodeURIComponent(deviceId)}/policy?version=${store.state.policy.version}`
          },
          commands,
          next_sync_after_ms: jitteredSyncMs()
        });
        return;
      }

      const policy = url.pathname.match(/^\/api\/devices\/([^/]+)\/policy$/);
      if (req.method === "GET" && policy) {
        const deviceId = decodeURIComponent(policy[1]);
        sendJson(res, 200, makePolicyFromBlockedApps(store, deviceId));
        return;
      }

      const pollCommands = url.pathname.match(/^\/api\/devices\/([^/]+)\/commands\/poll$/);
      if (req.method === "GET" && pollCommands) {
        const deviceId = decodeURIComponent(pollCommands[1]);
        sendJson(res, 200, { commands: store.pollCommands(deviceId) });
        return;
      }

      const commandResult = url.pathname.match(/^\/api\/devices\/([^/]+)\/commands\/([^/]+)\/result$/);
      if (req.method === "POST" && commandResult) {
        const deviceId = decodeURIComponent(commandResult[1]);
        const commandId = decodeURIComponent(commandResult[2]);
        const body = await readBody(req);
        sendJson(res, 200, { ok: true, command: store.completeCommand(deviceId, commandId, body) });
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/parent/approval-requests") {
        sendJson(res, 200, { requests: store.state.approvalRequests.slice().reverse() });
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/parent/dashboard") {
        sendJson(res, 200, store.dashboard());
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/parent/policies/current") {
        sendJson(res, 200, store.state.policy);
        return;
      }

      if (req.method === "POST" && url.pathname === "/api/parent/policies") {
        const body = await readBody(req);
        const rules = Array.isArray(body.rules) ? body.rules : [];
        store.replacePolicyRules(rules.map((rule) => ({
          id: rule.id || crypto.randomUUID(),
          name: rule.name || rule.id || "rule",
          platform: rule.platform || "windows",
          match: rule.match || { type: "processName", processName: rule.processName || rule.packageName || "" },
          action: rule.action || "monitor",
          excludedUntil: rule.excludedUntil || "",
          reason: rule.reason || "parent_policy"
        })));
        for (const deviceId of Object.keys(store.state.devices)) {
          store.queueCommand(deviceId, "policy.refresh", {});
        }
        sendJson(res, 200, { ok: true, policy: store.state.policy });
        return;
      }

      const approvalAction = url.pathname.match(/^\/api\/parent\/approval-requests\/([^/]+)\/(allow|terminate)$/);
      if (req.method === "POST" && approvalAction) {
        const requestId = decodeURIComponent(approvalAction[1]);
        const action = approvalAction[2];
        const request = store.decideApprovalRequest(requestId, action);
        if (!request) {
          sendJson(res, 404, { ok: false, error: "request_not_found" });
          return;
        }

        const command = action === "allow"
          ? store.queueCommand(request.deviceId, "app.allow.temporary", {
            processName: request.appName,
            minutes: 120,
            requestId
          })
          : store.queueCommand(request.deviceId, "app.terminate", {
            pid: request.pid,
            processName: request.appName,
            requestId
          });

        sendJson(res, 200, { ok: true, request, command });
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/parent/blocked-apps") {
        sendJson(res, 200, { blockedApps: store.state.policy.rules });
        return;
      }

      if (req.method === "POST" && url.pathname === "/api/parent/blocked-apps") {
        const body = await readBody(req);
        const rule = {
          id: body.id || crypto.randomUUID(),
          deviceId: body.deviceId || "",
          name: body.name || body.processName,
          platform: body.platform || "windows",
          match: body.match || { type: "processName", processName: body.processName },
          action: body.action || "block",
          excludedUntil: body.excludedUntil || "",
          createdAt: new Date().toISOString()
        };
        store.setBlockedApp(rule);
        const targetDevices = rule.deviceId
          ? [rule.deviceId]
          : Object.keys(store.state.devices);
        for (const deviceId of targetDevices) {
          store.queueCommand(deviceId, "policy.refresh", {});
        }
        sendJson(res, 200, { ok: true, rule });
        return;
      }

      sendJson(res, 404, { ok: false, error: "not_found" });
    } catch (error) {
      log.error("request.failed", { message: error.message });
      sendJson(res, 500, { ok: false, error: error.message });
    }
  });

  server.listen(options.port, "127.0.0.1", () => {
    log.info("server.started", { port: options.port, dataDir: path.resolve(options.dataDir), fcmEnabled: fcm.enabled() });
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
