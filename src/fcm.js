const fs = require("fs");
const https = require("https");
const crypto = require("crypto");
const path = require("path");

function base64url(input) {
  return Buffer.from(input).toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

class FcmError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "FcmError";
    this.code = code;
    Object.assign(this, details);
  }
}

function requestJson(method, urlString, body, headers = {}, timeoutMs = 5000) {
  const url = new URL(urlString);
  const payload = body ? JSON.stringify(body) : "";
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      callback(value);
    };
    const req = https.request({
      method,
      hostname: url.hostname,
      port: url.port || 443,
      path: `${url.pathname}${url.search}`,
      timeout: timeoutMs,
      headers: {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload),
        ...headers
      }
    }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        data += chunk;
        if (data.length > 1024 * 1024) {
          req.destroy(new FcmError("response_too_large", "FCM response too large"));
        }
      });
      res.on("end", () => {
        let parsed = {};
        if (data) {
          try {
            parsed = JSON.parse(data);
          } catch (_) {
            finish(reject, new FcmError("malformed_response", "FCM returned malformed JSON", { statusCode: res.statusCode }));
            return;
          }
        }
        if (res.statusCode >= 400) {
          finish(reject, new FcmError(`http_${res.statusCode}`, `FCM HTTP ${res.statusCode}`, {
            statusCode: res.statusCode,
            response: parsed
          }));
          return;
        }
        finish(resolve, parsed);
      });
    });
    req.on("timeout", () => req.destroy(new FcmError("timeout", "FCM request timed out")));
    req.on("error", (error) => finish(reject, error));
    if (payload) req.write(payload);
    req.end();
  });
}

async function getAccessToken(serviceAccount, timeoutMs = 5000) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: serviceAccount.client_email,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  };
  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claim))}`;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  const signature = signer.sign(serviceAccount.private_key, "base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  const token = await requestJson("POST", "https://oauth2.googleapis.com/token", {
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: `${unsigned}.${signature}`
  }, {}, timeoutMs);
  if (!token || typeof token.access_token !== "string" || !token.access_token) {
    throw new FcmError("malformed_response", "FCM token response was missing access_token");
  }
  return token.access_token;
}

function looksLikeInvalidToken(error) {
  const text = JSON.stringify(error && (error.response || error.message || error));
  return Boolean(error && (error.statusCode === 404 || (error.statusCode === 400 && /UNREGISTERED|registration-token-not-registered|INVALID_ARGUMENT/i.test(text))));
}

class FcmSender {
  constructor(store, logger, options = {}) {
    this.store = store;
    this.logger = logger;
    this.timeoutMs = Number(options.timeoutMs || process.env.CPSM_FCM_TIMEOUT_MS || 5000);
    this.serviceAccount = null;
    this.projectId = process.env.FIREBASE_PROJECT_ID || "";
    this.configured = process.env.CPSM_FCM_ENABLED === "1";

    if (!this.configured) {
      return;
    }
    const defaultCredentials = path.join(process.cwd(), "secrets", "firebase-adminsdk.json");
    const credentials = process.env.GOOGLE_APPLICATION_CREDENTIALS || defaultCredentials;
    if (credentials && fs.existsSync(credentials)) {
      try {
        this.serviceAccount = JSON.parse(fs.readFileSync(credentials, "utf8"));
        this.projectId = this.projectId || this.serviceAccount.project_id || "";
      } catch (error) {
        this.logger.warn("fcm.credentials_invalid", { message: error.message });
      }
    }
  }

  enabled() {
    return Boolean(this.configured && this.serviceAccount && this.projectId);
  }

  async sendToDeviceIds(deviceIds, data, notification) {
    const wanted = new Set((deviceIds || []).filter(Boolean).map(String));
    const keys = Object.values(this.store.state.notificationKeys || {}).filter((item) => wanted.has(String(item.deviceId)) && item.status === "active");
    if (!keys.length) {
      this.store.appendNotification({ skipped: "no_device_notification_keys", deviceCount: wanted.size, data, notification });
      return { sent: 0, skipped: 0 };
    }
    if (!this.enabled()) {
      this.store.appendNotification({ fallback: "fcm_disabled_or_not_configured", tokenCount: keys.length, data, notification });
      this.logger.warn("fcm.relationship_fallback_logged", { tokens: keys.length, type: data.type });
      return { sent: 0, skipped: keys.length };
    }
    let accessToken;
    try {
      accessToken = await getAccessToken(this.serviceAccount, this.timeoutMs);
    } catch (error) {
      this.store.appendNotification({ fallback: "fcm_auth_failed", tokenCount: keys.length, type: data.type });
      return { sent: 0, failed: keys.length };
    }
    let sent = 0;
    for (const key of keys) {
      try {
        await requestJson(
          "POST",
          `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(this.projectId)}/messages:send`,
          { message: { token: key.token, notification, data } },
          { authorization: `Bearer ${accessToken}` },
          this.timeoutMs
        );
        sent += 1;
      } catch (error) {
        this.logger.warn("fcm.relationship_send_failed", { code: error.code || "request_failed" });
      }
    }
    return { sent, failed: keys.length - sent };
  }

  async sendToParents(data, notification) {
    const tokens = this.store.state.parentTokens.slice();
    if (!tokens.length) {
      this.store.appendNotification({ skipped: "no_parent_tokens", data, notification });
      return { sent: 0, skipped: 0 };
    }

    if (!this.enabled()) {
      this.store.appendNotification({ fallback: "fcm_disabled_or_not_configured", tokenCount: tokens.length, data, notification });
      this.logger.warn("fcm.fallback_logged", { tokens: tokens.length, type: data.type });
      return { sent: 0, skipped: tokens.length };
    }

    let accessToken;
    try {
      accessToken = await getAccessToken(this.serviceAccount, this.timeoutMs);
    } catch (error) {
      this.store.appendNotification({ fallback: "fcm_auth_failed", tokenCount: tokens.length, type: data.type });
      this.logger.warn("fcm.auth_failed", { code: error.code || "request_failed" });
      return { sent: 0, failed: tokens.length };
    }

    let sent = 0;
    let failed = 0;
    for (const token of tokens) {
      try {
        await requestJson(
          "POST",
          `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(this.projectId)}/messages:send`,
          { message: { token, notification, data } },
          { authorization: `Bearer ${accessToken}` },
          this.timeoutMs
        );
        sent += 1;
      } catch (error) {
        failed += 1;
        const invalidToken = looksLikeInvalidToken(error);
        if (invalidToken) {
          this.store.unregisterParentToken(token);
        }
        this.logger.warn("fcm.send_failed", { code: error.code || "request_failed", invalidToken });
      }
    }
    return { sent, failed };
  }
}

module.exports = {
  FcmSender,
  FcmError,
  requestJson,
  getAccessToken
};
