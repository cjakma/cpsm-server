const crypto = require("crypto");

class AuthError extends Error {
  constructor(code, status = 401) {
    super(code);
    this.name = "AuthError";
    this.code = code;
    this.status = status;
    this.expose = true;
  }
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left), "utf8");
  const b = Buffer.from(String(right), "utf8");
  const same = a.length === b.length && crypto.timingSafeEqual(a, b);
  return same;
}

function canonicalDeviceRequest(method, requestPath, timestamp, nonce, rawBody) {
  const bodyHash = crypto.createHash("sha256").update(rawBody || "", "utf8").digest("hex");
  return [method.toUpperCase(), requestPath, String(timestamp), nonce, bodyHash].join("\n");
}

function signDeviceRequest(secret, method, requestPath, timestamp, nonce, rawBody) {
  return crypto.createHmac("sha256", secret)
    .update(canonicalDeviceRequest(method, requestPath, timestamp, nonce, rawBody))
    .digest("hex");
}

function decodeSignature(value) {
  let signature = String(value || "").trim();
  if (signature.startsWith("sha256=")) {
    signature = signature.slice("sha256=".length);
  }
  if (signature.startsWith("hex:")) {
    signature = signature.slice("hex:".length);
  }
  if (/^[0-9a-f]{64}$/i.test(signature)) {
    return Buffer.from(signature, "hex");
  }
  try {
    const decoded = Buffer.from(signature.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    return decoded.length === 32 ? decoded : null;
  } catch (_) {
    return null;
  }
}

function header(req, name) {
  const value = req.headers[String(name).toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function localModeAllowed(options = {}) {
  return Boolean(
    options.localDev
    || options.dev
    || process.env.NODE_ENV === "development"
    || process.env.NODE_ENV === "test"
    || process.env.CPSM_LOCAL_DEV === "1"
  );
}

function decodeBase64(value) {
  return Buffer.from(String(value || "").replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function createPublicKey(value) {
  const text = String(value || "").trim();
  if (text.includes("BEGIN PUBLIC KEY")) return crypto.createPublicKey(text);
  const der = decodeBase64(text);
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

function devicePublicKeyRequest(method, requestPath, timestamp, nonce, rawBody) {
  return [
    String(method).toUpperCase(),
    requestPath,
    String(timestamp),
    String(nonce),
    Buffer.from(rawBody || "", "utf8").toString("base64")
  ].join("\n");
}

class Authenticator {
  constructor(options = {}) {
    this.store = options.store;
    this.mode = String(options.mode || process.env.CPSM_AUTH_MODE || "strict").toLowerCase();
    this.localDev = localModeAllowed(options);
    if (!new Set(["strict", "disabled"]).has(this.mode)) {
      throw new AuthError("invalid_auth_mode", 500);
    }
    if (this.mode === "disabled" && !this.localDev) {
      throw new AuthError("disabled_auth_requires_local_mode", 500);
    }
    this.adminToken = process.env.CPSM_ADMIN_TOKEN || "";
    this.parentToken = process.env.CPSM_PARENT_TOKEN || this.adminToken;
    this.maxAgeMs = Number(process.env.CPSM_DEVICE_AUTH_MAX_AGE_MS || 300000);
    this.nonceTtlMs = Number(process.env.CPSM_DEVICE_NONCE_TTL_MS || Math.max(this.maxAgeMs, 300000));
    this.deviceSecrets = this.readDeviceSecrets();
    this.devicePublicKeys = this.readDevicePublicKeys();
  }

  readDeviceSecrets() {
    const raw = process.env.CPSM_DEVICE_SECRETS || "";
    if (!raw) {
      return {};
    }
    try {
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("not an object");
      }
      return parsed;
    } catch (_) {
      throw new AuthError("invalid_device_secret_configuration", 500);
    }
  }

  readDevicePublicKeys() {
    const raw = process.env.CPSM_DEVICE_PUBLIC_KEYS || "";
    if (!raw) return {};
    try {
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
      return parsed;
    } catch (_) {
      throw new AuthError("invalid_device_public_key_configuration", 500);
    }
  }

  isDisabled() {
    return this.mode === "disabled";
  }

  bearerToken(req) {
    const value = header(req, "authorization");
    if (!value || typeof value !== "string") {
      return "";
    }
    const match = value.match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : "";
  }

  requireBearer(req, kind) {
    if (this.isDisabled()) {
      return { actor: "local-dev" };
    }
    const candidates = kind === "admin"
      ? [this.adminToken]
      : [this.parentToken, this.adminToken];
    const token = this.bearerToken(req);
    const sessionValid = this.store && typeof this.store.validateParentSession === "function"
      ? this.store.validateParentSession(token)
      : false;
    if (sessionValid) return { actor: "parent-session" };
    if (!candidates.some((candidate) => candidate && safeEqual(token, candidate))) {
      if (!candidates.some(Boolean)) {
        throw new AuthError("auth_not_configured", 503);
      }
      throw new AuthError("invalid_bearer_token", 401);
    }
    return { actor: kind };
  }

  requireParent(req) {
    return this.requireBearer(req, "parent");
  }

  requireAdmin(req) {
    return this.requireBearer(req, "admin");
  }

  deviceSecret(deviceId) {
    if (this.deviceSecrets[deviceId]) {
      return String(this.deviceSecrets[deviceId]);
    }
    if (process.env.CPSM_DEVICE_SECRET) {
      return process.env.CPSM_DEVICE_SECRET;
    }
    if (this.store && typeof this.store.getDeviceSecret === "function") {
      return this.store.getDeviceSecret(deviceId) || "";
    }
    return "";
  }

  requireDevice(req, deviceId, requestPath, rawBody) {
    if (this.isDisabled()) {
      return { actor: "local-device", deviceId };
    }
    const headerDeviceId = header(req, "x-cpsm-device-id");
    if (!headerDeviceId || headerDeviceId !== deviceId) {
      throw new AuthError("device_id_mismatch", 401);
    }

    const publicKeyHeader = header(req, "x-cpsm-device-public-key");
    const publicSignature = header(req, "x-cpsm-device-signature");
    if (publicKeyHeader || publicSignature) {
      const configuredKey = this.devicePublicKeys[deviceId]
        || (this.store && typeof this.store.getDevicePublicKey === "function" ? this.store.getDevicePublicKey(deviceId) : "");
      if (!configuredKey) throw new AuthError("device_key_not_enrolled", 403);
      if (!publicKeyHeader || !safeEqual(publicKeyHeader, configuredKey)) {
        throw new AuthError("device_public_key_mismatch", 401);
      }
      const timestamp = header(req, "x-cpsm-timestamp");
      const nonce = header(req, "x-cpsm-nonce");
      if (!timestamp || !nonce || !/^[A-Za-z0-9._:-]{8,128}$/.test(nonce)) {
        throw new AuthError("invalid_device_auth", 401);
      }
      const timestampMs = Number(timestamp);
      if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > this.maxAgeMs) {
        throw new AuthError("stale_device_request", 401);
      }
      let valid = false;
      try {
        valid = crypto.verify(
          "sha256",
          Buffer.from(devicePublicKeyRequest(req.method, requestPath, timestamp, nonce, rawBody || ""), "utf8"),
          createPublicKey(configuredKey),
          decodeBase64(publicSignature)
        );
      } catch (_) {
        valid = false;
      }
      if (!valid) throw new AuthError("invalid_device_signature", 401);
      if (this.store && typeof this.store.consumeDeviceNonce === "function"
          && !this.store.consumeDeviceNonce(deviceId, nonce, Date.now() + this.nonceTtlMs)) {
        throw new AuthError("replayed_device_request", 409);
      }
      return { actor: "device-public-key", deviceId };
    }

    const timestamp = header(req, "x-cpsm-timestamp");
    const nonce = header(req, "x-cpsm-nonce");
    const supplied = decodeSignature(header(req, "x-cpsm-signature"));
    if (!timestamp || !nonce || !supplied || !/^[A-Za-z0-9._:-]{8,128}$/.test(nonce)) {
      throw new AuthError("invalid_device_auth", 401);
    }
    const numericTimestamp = Number(timestamp);
    if (!Number.isFinite(numericTimestamp)) {
      throw new AuthError("invalid_device_timestamp", 401);
    }
    const timestampMs = numericTimestamp < 100000000000 ? numericTimestamp * 1000 : numericTimestamp;
    if (Math.abs(Date.now() - timestampMs) > this.maxAgeMs) {
      throw new AuthError("stale_device_request", 401);
    }
    const secret = this.deviceSecret(deviceId);
    if (!secret) {
      throw new AuthError("device_auth_not_configured", 503);
    }
    const expected = crypto.createHmac("sha256", secret)
      .update(canonicalDeviceRequest(req.method, requestPath, timestamp, nonce, rawBody || ""))
      .digest();
    if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) {
      throw new AuthError("invalid_device_signature", 401);
    }
    if (this.store && typeof this.store.consumeDeviceNonce === "function") {
      const accepted = this.store.consumeDeviceNonce(deviceId, nonce, Date.now() + this.nonceTtlMs);
      if (!accepted) throw new AuthError("replayed_device_request", 409);
    }
    return { actor: "device", deviceId };
  }
}

module.exports = {
  AuthError,
  Authenticator,
  canonicalDeviceRequest,
  signDeviceRequest,
  safeEqual
};
