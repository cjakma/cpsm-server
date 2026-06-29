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

function requestJson(method, urlString, body, headers = {}) {
  const url = new URL(urlString);
  const payload = body ? JSON.stringify(body) : "";

  return new Promise((resolve, reject) => {
    const req = https.request({
      method,
      hostname: url.hostname,
      path: `${url.pathname}${url.search}`,
      headers: {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload),
        ...headers
      }
    }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        const parsed = data ? JSON.parse(data) : {};
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          return;
        }
        resolve(parsed);
      });
    });
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

async function getAccessToken(serviceAccount) {
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
  const assertion = `${unsigned}.${signature}`;

  const token = await requestJson("POST", "https://oauth2.googleapis.com/token", {
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion
  });
  return token.access_token;
}

class FcmSender {
  constructor(store, logger) {
    this.store = store;
    this.logger = logger;
    this.serviceAccount = null;
    this.projectId = process.env.FIREBASE_PROJECT_ID || "";

    const defaultCredentials = path.join(process.cwd(), "secrets", "firebase-adminsdk.json");
    const credentials = process.env.CPSM_DISABLE_FCM === "1"
      ? ""
      : (process.env.GOOGLE_APPLICATION_CREDENTIALS || defaultCredentials);
    if (credentials && fs.existsSync(credentials)) {
      this.serviceAccount = JSON.parse(fs.readFileSync(credentials, "utf8"));
      this.projectId = this.projectId || this.serviceAccount.project_id;
    }
  }

  enabled() {
    return Boolean(this.serviceAccount && this.projectId);
  }

  async sendToParents(data, notification) {
    const tokens = this.store.state.parentTokens;
    if (!tokens.length) {
      this.store.appendNotification({ skipped: "no_parent_tokens", data, notification });
      return;
    }

    if (!this.enabled()) {
      this.store.appendNotification({ fallback: "fcm_not_configured", tokens, data, notification });
      this.logger.warn("fcm.fallback_logged", { tokens: tokens.length, type: data.type });
      return;
    }

    const accessToken = await getAccessToken(this.serviceAccount);
    for (const token of tokens) {
      const message = {
        message: {
          token,
          notification,
          data
        }
      };
      await requestJson(
        "POST",
        `https://fcm.googleapis.com/v1/projects/${this.projectId}/messages:send`,
        message,
        { authorization: `Bearer ${accessToken}` }
      );
    }
  }
}

module.exports = {
  FcmSender
};
