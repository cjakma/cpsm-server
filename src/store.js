const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function readJson(file, fallback) {
  if (!fs.existsSync(file)) {
    return fallback;
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2), "utf8");
}

class Store {
  constructor(dataDir) {
    this.dataDir = dataDir;
    ensureDir(dataDir);
    this.stateFile = path.join(dataDir, "state.json");
    this.notificationLog = path.join(dataDir, "notifications.ndjson");
    this.state = readJson(this.stateFile, {
      parentTokens: [],
      devices: {},
      events: [],
      commands: [],
      approvalRequests: [],
      blockedApps: [],
      policy: {
        policyId: "family-policy",
        version: 1,
        updatedAt: new Date().toISOString(),
        hash: "",
        rules: []
      }
    });
    this.ensurePolicy();
  }

  save() {
    this.ensurePolicy();
    writeJson(this.stateFile, this.state);
  }

  ensurePolicy() {
    if (!Array.isArray(this.state.blockedApps)) {
      this.state.blockedApps = [];
    }
    if (!this.state.policy) {
      this.state.policy = {
        policyId: "family-policy",
        version: 1,
        updatedAt: new Date().toISOString(),
        hash: "",
        rules: []
      };
    }
    if (!Array.isArray(this.state.policy.rules)) {
      this.state.policy.rules = [];
    }
    if (this.state.policy.rules.length === 0 && this.state.blockedApps.length > 0) {
      this.state.policy.rules = this.state.blockedApps.map((rule) => ({
        id: rule.id,
        name: rule.name || rule.processName || rule.packageName || "rule",
        platform: rule.platform || "windows",
        match: rule.match || {
          type: rule.platform === "android" ? "package" : "processName",
          processName: rule.processName || rule.name || "",
          packageName: rule.packageName || rule.name || ""
        },
        action: rule.action || "block",
        excludedUntil: rule.excludedUntil || "",
        reason: rule.reason || "legacy_blocked_app"
      }));
    }
    this.state.policy.hash = this.hashPolicy(this.state.policy);
  }

  hashPolicy(policy) {
    const stable = {
      policyId: policy.policyId,
      version: policy.version,
      rules: policy.rules
    };
    return crypto.createHash("sha256").update(JSON.stringify(stable)).digest("hex");
  }

  appendNotification(payload) {
    fs.appendFileSync(this.notificationLog, `${JSON.stringify({
      time: new Date().toISOString(),
      payload
    })}\n`, "utf8");
  }

  registerParentToken(token) {
    if (!this.state.parentTokens.includes(token)) {
      this.state.parentTokens.push(token);
      this.save();
    }
  }

  upsertDevice(deviceId, patch) {
    const existing = this.state.devices[deviceId] || {};
    this.state.devices[deviceId] = {
      deviceId,
      childName: existing.childName || "자녀",
      deviceName: existing.deviceName || deviceId,
      ...existing,
      ...patch,
      lastSeenAt: new Date().toISOString()
    };
    this.save();
    return this.state.devices[deviceId];
  }

  addEvents(deviceId, events) {
    const device = this.upsertDevice(deviceId, {});
    const stored = events.map((event) => ({
      id: crypto.randomUUID(),
      deviceId,
      childName: device.childName,
      receivedAt: new Date().toISOString(),
      ...event
    }));
    this.state.events.push(...stored);
    this.state.events = this.state.events.slice(-2000);
    this.save();
    return stored;
  }

  dashboard() {
    const pendingRequests = this.state.approvalRequests
      .filter((request) => request.status === "pending")
      .slice(-50)
      .reverse();
    const recentEvents = this.state.events.slice(-100).reverse();
    return {
      policy: this.state.policy,
      devices: Object.values(this.state.devices),
      pendingRequests,
      recentEvents,
      blockedApps: this.state.policy.rules
    };
  }

  createApprovalRequest(deviceId, event) {
    const device = this.upsertDevice(deviceId, {});
    const request = {
      id: crypto.randomUUID(),
      status: "pending",
      deviceId,
      childName: device.childName,
      deviceName: device.deviceName,
      appName: event.payload && event.payload.appName ? event.payload.appName : "unknown",
      executablePath: event.payload && event.payload.executablePath ? event.payload.executablePath : "",
      pid: event.payload && event.payload.pid ? event.payload.pid : null,
      eventId: event.id,
      createdAt: new Date().toISOString(),
      decidedAt: null,
      decision: null
    };
    this.state.approvalRequests.push(request);
    this.save();
    return request;
  }

  pendingRequestForPid(deviceId, pid) {
    return this.state.approvalRequests.find((request) =>
      request.deviceId === deviceId
      && request.pid === pid
      && request.status === "pending"
    );
  }

  decideApprovalRequest(requestId, decision) {
    const request = this.state.approvalRequests.find((item) => item.id === requestId);
    if (!request) {
      return null;
    }
    request.status = "decided";
    request.decision = decision;
    request.decidedAt = new Date().toISOString();
    this.save();
    return request;
  }

  queueCommand(deviceId, type, payload) {
    const command = {
      id: crypto.randomUUID(),
      deviceId,
      type,
      payload,
      status: "queued",
      createdAt: new Date().toISOString(),
      result: null
    };
    this.state.commands.push(command);
    this.save();
    return command;
  }

  pollCommands(deviceId, limit = 20) {
    const commands = this.state.commands
      .filter((command) => command.deviceId === deviceId && command.status === "queued")
      .slice(0, limit);
    for (const command of commands) {
      command.status = "sent";
      command.sentAt = new Date().toISOString();
    }
    this.save();
    return commands;
  }

  completeCommand(deviceId, commandId, result) {
    const command = this.state.commands.find((item) => item.deviceId === deviceId && item.id === commandId);
    if (!command) {
      return null;
    }
    command.status = result && result.ok ? "succeeded" : "failed";
    command.result = result;
    command.completedAt = new Date().toISOString();
    this.save();
    return command;
  }

  setBlockedApp(rule) {
    const existing = this.state.blockedApps.find((item) => item.id === rule.id);
    if (existing) {
      Object.assign(existing, rule);
    } else {
      this.state.blockedApps.push(rule);
    }
    this.upsertPolicyRule({
      id: rule.id,
      name: rule.name,
      platform: rule.platform || "windows",
      match: rule.match,
      action: rule.action || "block",
      excludedUntil: rule.excludedUntil || "",
      reason: rule.reason || "parent_rule"
    });
  }

  upsertPolicyRule(rule) {
    const existing = this.state.policy.rules.find((item) => item.id === rule.id);
    if (existing) {
      Object.assign(existing, rule);
    } else {
      this.state.policy.rules.push(rule);
    }
    this.bumpPolicyVersion();
  }

  replacePolicyRules(rules) {
    this.state.policy.rules = rules;
    this.state.blockedApps = rules;
    this.bumpPolicyVersion();
  }

  bumpPolicyVersion() {
    this.state.policy.version = Number(this.state.policy.version || 0) + 1;
    this.state.policy.updatedAt = new Date().toISOString();
    this.state.policy.hash = this.hashPolicy(this.state.policy);
    this.save();
  }
}

module.exports = {
  Store,
  ensureDir
};
