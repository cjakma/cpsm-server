const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { screenTimeForPlatform } = require("./screenTime");
const { classifyGeofence } = require("./location");

let DatabaseSync;
try {
  ({ DatabaseSync } = require("node:sqlite"));
} catch (_) {
  DatabaseSync = null;
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function parseJson(value, fallback) {
  try {
    return value == null || value === "" ? fallback : JSON.parse(value);
  } catch (_) {
    return fallback;
  }
}

function stableValue(value) {
  if (Array.isArray(value)) {
    return value.map(stableValue);
  }
  if (value && typeof value === "object") {
    return Object.keys(value).sort().reduce((result, key) => {
      result[key] = stableValue(value[key]);
      return result;
    }, {});
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(stableValue(value));
}

function base64url(value) {
  return Buffer.from(value).toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function nowIso() {
  return new Date().toISOString();
}

const ERROR_CATEGORIES = new Set(["policy", "network", "auth", "permission", "ota", "command", "runtime", "storage", "telemetry"]);
const ERROR_SEVERITIES = new Set(["info", "warning", "error", "critical"]);
const ERROR_STATUSES = new Set(["new", "triaged", "in_progress", "resolved", "wont_fix", "regressed"]);
const CHANGE_TYPES = new Set(["added", "modified", "fixed", "removed", "security", "compatibility"]);
const ERROR_LINK_RELATIONS = new Set(["introduced", "observed", "fixed", "regressed", "not_reproduced"]);

function redactText(value) {
  return String(value == null ? "" : value)
    .replace(/(authorization|bearer|token|password|passwd|secret|private[_ -]?key|bootstrap[_ -]?code|fcm[_ -]?token)\s*[:=]\s*[^\s,;]+/gi, "$1=[REDACTED]")
    .replace(/(-----BEGIN [^-]+-----)[\s\S]*?(-----END [^-]+-----)/gi, "$1[REDACTED]$2")
    .slice(0, 16384);
}

function redactValue(value, depth = 0) {
  if (depth > 5) return "[TRUNCATED]";
  if (typeof value === "string") return redactText(value);
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => redactValue(item, depth + 1));
  if (value && typeof value === "object") {
    return Object.entries(value).slice(0, 100).reduce((result, [key, item]) => {
      if (/(authorization|bearer|token|password|passwd|secret|private[_ -]?key|bootstrap[_ -]?code|fcm[_ -]?token)/i.test(key)) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = redactValue(item, depth + 1);
      }
      return result;
    }, {});
  }
  return value;
}

function errorFingerprint({ product, errorCode, category, component, operation, message }) {
  const normalizedMessage = String(message || "")
    .toLowerCase()
    .replace(/[0-9a-f]{8,}/g, "#")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 512);
  return crypto.createHash("sha256").update(canonicalJson({
    product, errorCode, category, component, operation, message: normalizedMessage
  })).digest("hex");
}

function severityRank(value) {
  return { info: 0, warning: 1, error: 2, critical: 3 }[value] ?? 2;
}

function defaultState() {
  return {
    parentTokens: [],
    parentSessions: [],
    pairingSessions: {},
    devices: {},
    events: [],
    commands: [],
    approvalRequests: [],
    blockedApps: [],
    families: {},
    parentProfiles: {},
    childProfiles: {},
    familyMembers: [],
    geofences: {},
    locationConsents: {},
    locationRequests: {},
    locationSamples: {},
    geofenceStates: {},
    locationTransitions: {},
    parentChildMappings: {},
    consentRequests: {},
    notificationKeys: {},
    appVersions: {},
    appVersionChanges: {},
    deviceErrors: {},
    errorOccurrences: {},
    errorVersionLinks: {},
    familyPolicies: {},
    devicePolicyAssignments: {},
    policySyncReceipts: {},
    policy: {
      policyId: "family-policy",
      version: 1,
      updatedAt: nowIso(),
      expiresAt: "",
      hash: "",
      canonicalHash: "",
      signature: "",
      keyId: "",
      rules: []
    }
  };
}

function normalizeState(input) {
  const state = input && typeof input === "object" ? input : defaultState();
  const result = {
    ...defaultState(),
    ...state,
    devices: state.devices && typeof state.devices === "object" && !Array.isArray(state.devices) ? state.devices : {},
    events: Array.isArray(state.events) ? state.events : [],
    commands: Array.isArray(state.commands) ? state.commands : [],
    approvalRequests: Array.isArray(state.approvalRequests) ? state.approvalRequests : [],
    parentTokens: Array.isArray(state.parentTokens) ? state.parentTokens.filter(Boolean) : [],
    parentSessions: Array.isArray(state.parentSessions) ? state.parentSessions : [],
    pairingSessions: state.pairingSessions && typeof state.pairingSessions === "object" && !Array.isArray(state.pairingSessions) ? state.pairingSessions : {},
    families: state.families && typeof state.families === "object" && !Array.isArray(state.families) ? state.families : {},
    parentProfiles: state.parentProfiles && typeof state.parentProfiles === "object" && !Array.isArray(state.parentProfiles) ? state.parentProfiles : {},
    childProfiles: state.childProfiles && typeof state.childProfiles === "object" && !Array.isArray(state.childProfiles) ? state.childProfiles : {},
    familyMembers: Array.isArray(state.familyMembers) ? state.familyMembers : [],
    geofences: state.geofences && typeof state.geofences === "object" && !Array.isArray(state.geofences) ? state.geofences : {},
    locationConsents: state.locationConsents && typeof state.locationConsents === "object" && !Array.isArray(state.locationConsents) ? state.locationConsents : {},
    locationRequests: state.locationRequests && typeof state.locationRequests === "object" && !Array.isArray(state.locationRequests) ? state.locationRequests : {},
    locationSamples: state.locationSamples && typeof state.locationSamples === "object" && !Array.isArray(state.locationSamples) ? state.locationSamples : {},
    geofenceStates: state.geofenceStates && typeof state.geofenceStates === "object" && !Array.isArray(state.geofenceStates) ? state.geofenceStates : {},
    locationTransitions: state.locationTransitions && typeof state.locationTransitions === "object" && !Array.isArray(state.locationTransitions) ? state.locationTransitions : {},
    parentChildMappings: state.parentChildMappings && typeof state.parentChildMappings === "object" && !Array.isArray(state.parentChildMappings) ? state.parentChildMappings : {},
    consentRequests: state.consentRequests && typeof state.consentRequests === "object" && !Array.isArray(state.consentRequests) ? state.consentRequests : {},
    notificationKeys: state.notificationKeys && typeof state.notificationKeys === "object" && !Array.isArray(state.notificationKeys) ? state.notificationKeys : {},
    appVersions: state.appVersions && typeof state.appVersions === "object" && !Array.isArray(state.appVersions) ? state.appVersions : {},
    appVersionChanges: state.appVersionChanges && typeof state.appVersionChanges === "object" && !Array.isArray(state.appVersionChanges) ? state.appVersionChanges : {},
    deviceErrors: state.deviceErrors && typeof state.deviceErrors === "object" && !Array.isArray(state.deviceErrors) ? state.deviceErrors : {},
    errorOccurrences: state.errorOccurrences && typeof state.errorOccurrences === "object" && !Array.isArray(state.errorOccurrences) ? state.errorOccurrences : {},
    errorVersionLinks: state.errorVersionLinks && typeof state.errorVersionLinks === "object" && !Array.isArray(state.errorVersionLinks) ? state.errorVersionLinks : {},
    familyPolicies: state.familyPolicies && typeof state.familyPolicies === "object" && !Array.isArray(state.familyPolicies) ? state.familyPolicies : {},
    devicePolicyAssignments: state.devicePolicyAssignments && typeof state.devicePolicyAssignments === "object" && !Array.isArray(state.devicePolicyAssignments) ? state.devicePolicyAssignments : {},
    policySyncReceipts: state.policySyncReceipts && typeof state.policySyncReceipts === "object" && !Array.isArray(state.policySyncReceipts) ? state.policySyncReceipts : {},
    blockedApps: Array.isArray(state.blockedApps) ? state.blockedApps : [],
    policy: {
      ...defaultState().policy,
      ...(state.policy && typeof state.policy === "object" ? state.policy : {})
    }
  };
  for (const command of result.commands) {
    if (!command.state) {
      command.state = command.status === "sent" ? "delivered" : (command.status || "queued");
    }
    command.status = command.state;
    command.retryCount = Number(command.retryCount || command.retry_count || 0);
    command.maxRetries = Number(command.maxRetries || 3);
    command.expiresAt = command.expiresAt || "";
    command.leaseExpiresAt = command.leaseExpiresAt || null;
    command.ack = command.ack || null;
    command.idempotencyKey = command.idempotencyKey || null;
  }
  return result;
}

function atomicWriteJson(file, value) {
  const directory = path.dirname(file);
  ensureDir(directory);
  const temp = path.join(directory, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`);
  const data = `${JSON.stringify(value, null, 2)}\n`;
  const fd = fs.openSync(temp, "wx", 0o600);
  try {
    fs.writeFileSync(fd, data, "utf8");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temp, file);
  try {
    const dirFd = fs.openSync(directory, "r");
    try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
  } catch (_) {
    // Directory fsync is not available on every supported filesystem.
  }
}

class StoreError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.name = "StoreError";
    this.code = code;
    this.status = status;
    this.expose = true;
  }
}

class Store {
  constructor(dataDir, options = {}) {
    this.dataDir = path.resolve(dataDir);
    ensureDir(this.dataDir);
    this.stateFile = path.join(this.dataDir, "state.json");
    this.databaseFile = path.join(this.dataDir, "cpsm.sqlite");
    this.notificationLog = path.join(this.dataDir, "notifications.ndjson");
    this._deviceSecrets = new Map();
    this._jsonNonces = [];
    this.policyTtlMs = Number(options.policyTtlMs || process.env.CPSM_POLICY_TTL_MS || 86400000);
    this.maxCommandRetries = Number(options.maxCommandRetries || process.env.CPSM_COMMAND_MAX_RETRIES || 3);
    const retentionDays = Number(options.locationRetentionDays ?? process.env.CPSM_LOCATION_RETENTION_DAYS ?? 30);
    this.locationRetentionDays = Number.isInteger(retentionDays) && retentionDays >= 1 && retentionDays <= 90 ? retentionDays : 30;
    const minBatteryPercent = Number(options.locationMinBatteryPercent ?? process.env.CPSM_LOCATION_MIN_BATTERY_PERCENT ?? 30);
    this.locationMinBatteryPercent = Number.isInteger(minBatteryPercent) && minBatteryPercent >= 0 && minBatteryPercent <= 100 ? minBatteryPercent : 30;
    this.sqlite = Boolean(DatabaseSync);
    this.db = null;

    if (this.sqlite) {
      try {
        this.db = new DatabaseSync(this.databaseFile);
        this.configureDatabase();
        this.initializeSqlite();
      } catch (error) {
        if (this.db) {
          try { this.db.close(); } catch (_) { /* best effort */ }
        }
        this.db = null;
        this.sqlite = false;
        this.initializeJson(error);
      }
    } else {
      this.initializeJson(null);
    }
    this.ensurePolicy();
    this.purgeLocationData();
    this.save();
  }

  configureDatabase() {
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS storage_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        child_name TEXT NOT NULL,
        device_name TEXT NOT NULL,
        platform TEXT NOT NULL,
        status TEXT NOT NULL,
        current_app TEXT NOT NULL,
        local_policy_version INTEGER NOT NULL,
        last_event_seq INTEGER NOT NULL,
        last_seen_at TEXT NOT NULL,
        hmac_secret TEXT,
        public_key TEXT,
        registration_status TEXT NOT NULL DEFAULT 'unregistered',
        registered_at TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        sequence INTEGER,
        type TEXT NOT NULL,
        event_time TEXT,
        payload_json TEXT NOT NULL,
        child_name TEXT NOT NULL,
        received_at TEXT NOT NULL,
        UNIQUE(device_id, event_id)
      );
      CREATE TABLE IF NOT EXISTS commands (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        state TEXT NOT NULL,
        ack_json TEXT,
        result_json TEXT,
        retry_count INTEGER NOT NULL,
        max_retries INTEGER NOT NULL,
        idempotency_key TEXT,
        lease_expires_at TEXT,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        delivered_at TEXT,
        completed_at TEXT,
        UNIQUE(device_id, idempotency_key)
      );
      CREATE TABLE IF NOT EXISTS approval_requests (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        child_name TEXT NOT NULL,
        device_name TEXT NOT NULL,
        app_name TEXT NOT NULL,
        executable_path TEXT NOT NULL,
        pid INTEGER,
        event_id TEXT NOT NULL,
        status TEXT NOT NULL,
        decision TEXT,
        created_at TEXT NOT NULL,
        decided_at TEXT
      );
      CREATE TABLE IF NOT EXISTS policies (
        policy_id TEXT PRIMARY KEY,
        version INTEGER NOT NULL,
        updated_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        hash TEXT NOT NULL,
        canonical_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        key_id TEXT NOT NULL,
        rules_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS parent_tokens (
        token TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        last_used_at TEXT
      );
      CREATE TABLE IF NOT EXISTS parent_sessions (
        token_hash TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        parent_id TEXT,
        expires_at INTEGER NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS pairing_sessions (
        session_id TEXT PRIMARY KEY,
        issuer_type TEXT NOT NULL DEFAULT 'child',
        issuer_id TEXT NOT NULL DEFAULT '',
        child_device_id TEXT NOT NULL DEFAULT '',
        code_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        parent_id TEXT,
        family_id TEXT,
        created_at TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        claimed_at TEXT
        ,mapping_id TEXT
        ,confirmed_at TEXT
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        actor_type TEXT NOT NULL,
        actor_id TEXT,
        action TEXT NOT NULL,
        request_id TEXT,
        metadata_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS families (
        family_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS parent_profiles (
        parent_id TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        device_fingerprint TEXT NOT NULL UNIQUE,
        public_key TEXT,
        display_name TEXT NOT NULL,
        status TEXT NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS child_profiles (
        child_id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS family_members (
        family_id TEXT NOT NULL,
        member_type TEXT NOT NULL,
        member_id TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (family_id, member_type, member_id)
      );
      CREATE TABLE IF NOT EXISTS geofences (
        geofence_id TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        name TEXT NOT NULL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        radius_m INTEGER NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_by_parent_id TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS geofences_family_updated ON geofences(family_id, updated_at);
      CREATE TABLE IF NOT EXISTS location_consents (
        device_id TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        parent_consented INTEGER NOT NULL DEFAULT 0,
        child_consented INTEGER NOT NULL DEFAULT 0,
        permission_granted INTEGER NOT NULL DEFAULT 0,
        parent_consented_at TEXT,
        child_consented_at TEXT,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS location_requests (
        request_id TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        parent_id TEXT NOT NULL,
        command_id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL,
        result_code TEXT,
        sample_id TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS location_requests_device_status ON location_requests(device_id, status, created_at);
      CREATE TABLE IF NOT EXISTS location_samples (
        device_id TEXT NOT NULL,
        sample_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        family_id TEXT NOT NULL,
        captured_at TEXT NOT NULL,
        received_at TEXT NOT NULL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        accuracy_m REAL NOT NULL,
        provider TEXT NOT NULL,
        battery_pct INTEGER NOT NULL,
        charging INTEGER NOT NULL,
        PRIMARY KEY (device_id, sample_id)
      );
      CREATE INDEX IF NOT EXISTS location_samples_family_captured ON location_samples(family_id, captured_at);
      CREATE TABLE IF NOT EXISTS geofence_states (
        device_id TEXT NOT NULL,
        geofence_id TEXT NOT NULL,
        state TEXT NOT NULL,
        sample_id TEXT NOT NULL,
        last_sample_at TEXT NOT NULL,
        distance_m REAL NOT NULL,
        accuracy_m REAL NOT NULL,
        PRIMARY KEY (device_id, geofence_id)
      );
      CREATE TABLE IF NOT EXISTS location_transitions (
        transition_id TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        geofence_id TEXT NOT NULL,
        geofence_name TEXT NOT NULL,
        transition_type TEXT NOT NULL,
        event_time TEXT NOT NULL,
        sample_id TEXT NOT NULL,
        distance_m REAL NOT NULL,
        accuracy_m REAL NOT NULL,
        received_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS location_transitions_family_time ON location_transitions(family_id, event_time);
      CREATE TABLE IF NOT EXISTS parent_child_mappings (
        mapping_id TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        parent_id TEXT NOT NULL,
        child_id TEXT NOT NULL,
        status TEXT NOT NULL,
        parent_consent INTEGER NOT NULL DEFAULT 0,
        child_consent INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        confirmed_at TEXT,
        UNIQUE (family_id, parent_id, child_id)
      );
      CREATE TABLE IF NOT EXISTS consent_requests (
        request_id TEXT PRIMARY KEY,
        mapping_id TEXT NOT NULL,
        recipient_type TEXT NOT NULL,
        recipient_id TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        responded_at TEXT,
        response TEXT
      );
      CREATE TABLE IF NOT EXISTS device_notification_keys (
        notification_key_id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        token TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (device_id, provider, token)
      );
      CREATE TABLE IF NOT EXISTS app_versions (
        platform TEXT NOT NULL,
        product TEXT NOT NULL,
        version_code INTEGER NOT NULL,
        version_name TEXT NOT NULL,
        artifact TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size INTEGER NOT NULL,
        package_name TEXT,
        signing_certificate_sha256 TEXT,
        channel TEXT NOT NULL,
        release_notes TEXT NOT NULL,
        published_at TEXT NOT NULL,
        PRIMARY KEY (platform, product, version_code)
      );
      CREATE TABLE IF NOT EXISTS app_version_changes (
        change_id TEXT PRIMARY KEY,
        platform TEXT NOT NULL,
        product TEXT NOT NULL,
        version_code INTEGER NOT NULL,
        previous_version_code INTEGER,
        change_type TEXT NOT NULL,
        component TEXT NOT NULL,
        change_key TEXT NOT NULL,
        change_summary TEXT NOT NULL,
        issue_id TEXT,
        source_ref TEXT,
        is_verified INTEGER NOT NULL DEFAULT 0,
        verification_note TEXT NOT NULL DEFAULT '',
        verified_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (platform, product, version_code)
          REFERENCES app_versions(platform, product, version_code)
      );
      CREATE TABLE IF NOT EXISTS device_errors (
        error_id TEXT PRIMARY KEY,
        fingerprint TEXT NOT NULL UNIQUE,
        device_id TEXT,
        platform TEXT NOT NULL,
        product TEXT NOT NULL,
        version_code INTEGER NOT NULL,
        version_name TEXT NOT NULL,
        error_code TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        component TEXT NOT NULL,
        operation TEXT NOT NULL,
        message_redacted TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'new',
        is_fixed INTEGER NOT NULL DEFAULT 0,
        fixed_in_version_code INTEGER,
        fixed_at TEXT,
        resolution_note TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS device_error_occurrences (
        occurrence_id TEXT PRIMARY KEY,
        error_id TEXT NOT NULL,
        client_error_id TEXT NOT NULL,
        device_id TEXT,
        request_id TEXT,
        correlation_id TEXT,
        occurred_at TEXT NOT NULL,
        runtime_json TEXT NOT NULL,
        context_json TEXT NOT NULL,
        message_redacted TEXT NOT NULL,
        stack_trace_redacted TEXT,
        upload_status TEXT NOT NULL DEFAULT 'accepted',
        created_at TEXT NOT NULL,
        UNIQUE (device_id, client_error_id),
        FOREIGN KEY (error_id) REFERENCES device_errors(error_id)
      );
      CREATE TABLE IF NOT EXISTS error_app_version_links (
        error_id TEXT NOT NULL,
        platform TEXT NOT NULL,
        product TEXT NOT NULL,
        version_code INTEGER NOT NULL,
        relation TEXT NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0,
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        PRIMARY KEY (error_id, platform, product, version_code, relation),
        FOREIGN KEY (error_id) REFERENCES device_errors(error_id),
        FOREIGN KEY (platform, product, version_code)
          REFERENCES app_versions(platform, product, version_code)
      );
      CREATE TABLE IF NOT EXISTS family_policies (
        family_id TEXT PRIMARY KEY,
        version INTEGER NOT NULL,
        policy_json TEXT NOT NULL,
        source TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS device_policy_assignments (
        assignment_id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        family_id TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        status TEXT NOT NULL,
        assigned_at TEXT NOT NULL,
        applied_at TEXT,
        rejection_reason TEXT,
        UNIQUE(device_id, family_id)
      );
      CREATE TABLE IF NOT EXISTS policy_sync_receipts (
        receipt_id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        policy_id TEXT,
        version INTEGER NOT NULL,
        canonical_hash TEXT,
        signature_status TEXT,
        local_state TEXT,
        accepted INTEGER NOT NULL DEFAULT 0,
        reported_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS request_nonces (
        device_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY(device_id, nonce)
      );
    `);
    for (const statement of [
      "ALTER TABLE devices ADD COLUMN public_key TEXT",
      "ALTER TABLE devices ADD COLUMN registration_status TEXT NOT NULL DEFAULT 'unregistered'",
      "ALTER TABLE devices ADD COLUMN registered_at TEXT",
      "ALTER TABLE devices ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'",
      "ALTER TABLE parent_profiles ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'",
      "ALTER TABLE parent_sessions ADD COLUMN parent_id TEXT",
      "ALTER TABLE pairing_sessions ADD COLUMN issuer_type TEXT NOT NULL DEFAULT 'child'",
      "ALTER TABLE pairing_sessions ADD COLUMN issuer_id TEXT NOT NULL DEFAULT ''",
      "ALTER TABLE pairing_sessions ADD COLUMN mapping_id TEXT",
      "ALTER TABLE pairing_sessions ADD COLUMN confirmed_at TEXT",
      "ALTER TABLE approval_requests ADD COLUMN kind TEXT NOT NULL DEFAULT 'app_launch'",
      "ALTER TABLE approval_requests ADD COLUMN requested_minutes INTEGER"
    ]) {
      try {
        this.db.exec(statement);
      } catch (_) {
        // Existing databases already have the column.
      }
    }
    this.db.prepare("INSERT OR REPLACE INTO storage_meta (key, value) VALUES (?, ?)").run("error_telemetry_schema", "1");
  }

  initializeSqlite() {
    const marker = this.db.prepare("SELECT value FROM storage_meta WHERE key = ?").get("initialized");
    if (marker) {
      this.loadSqliteState();
      return;
    }
    if (fs.existsSync(this.stateFile)) {
      const legacy = JSON.parse(fs.readFileSync(this.stateFile, "utf8"));
      this.state = normalizeState(legacy);
      const backup = path.join(this.dataDir, `state.json.migrated-${Date.now()}.bak`);
      fs.copyFileSync(this.stateFile, backup, fs.constants.COPYFILE_EXCL);
      try { fs.chmodSync(backup, 0o600); } catch (_) { /* best effort */ }
    } else {
      this.state = defaultState();
    }
    this.save();
  }

  initializeJson(sqliteError) {
    this.storageWarning = sqliteError ? "sqlite_unavailable" : "sqlite_not_available";
    if (fs.existsSync(this.stateFile)) {
      this.state = normalizeState(JSON.parse(fs.readFileSync(this.stateFile, "utf8")));
    } else {
      this.state = defaultState();
    }
    for (const [deviceId, device] of Object.entries(this.state.devices)) {
      if (device.hmacSecret) {
        this._deviceSecrets.set(deviceId, String(device.hmacSecret));
        delete device.hmacSecret;
      }
    }
    if (Array.isArray(this.state.requestNonces)) {
      this._jsonNonces = this.state.requestNonces;
      delete this.state.requestNonces;
    }
  }

  loadSqliteState() {
    this.state = defaultState();
    const devices = this.db.prepare("SELECT * FROM devices ORDER BY device_id").all();
    for (const device of devices) {
      this.state.devices[device.device_id] = {
        deviceId: device.device_id,
        childName: device.child_name,
        deviceName: device.device_name,
        platform: device.platform,
        status: device.status,
        currentApp: device.current_app,
        localPolicyVersion: device.local_policy_version,
        lastEventSeq: device.last_event_seq,
        lastSeenAt: device.last_seen_at,
        publicKey: device.public_key || "",
        registrationStatus: device.registration_status || "unregistered",
        registeredAt: device.registered_at || null,
        metadata: parseJson(device.metadata_json, {}),
      };
      if (device.hmac_secret) {
        this._deviceSecrets.set(device.device_id, device.hmac_secret);
      }
    }
    const events = this.db.prepare("SELECT * FROM events ORDER BY rowid").all();
    this.state.events = events.map((event) => ({
      id: event.id,
      deviceId: event.device_id,
      eventId: event.event_id,
      sequence: event.sequence,
      type: event.type,
      eventTime: event.event_time,
      payload: JSON.parse(event.payload_json),
      childName: event.child_name,
      receivedAt: event.received_at
    }));
    const commands = this.db.prepare("SELECT * FROM commands ORDER BY rowid").all();
    this.state.commands = commands.map((command) => this.dbCommandToState(command));
    const approvals = this.db.prepare("SELECT * FROM approval_requests ORDER BY rowid").all();
    this.state.approvalRequests = approvals.map((request) => ({
      id: request.id,
      deviceId: request.device_id,
      childName: request.child_name,
      deviceName: request.device_name,
      appName: request.app_name,
      executablePath: request.executable_path,
      pid: request.pid,
      eventId: request.event_id,
      status: request.status,
      decision: request.decision,
      createdAt: request.created_at,
      decidedAt: request.decided_at,
      kind: request.kind || "app_launch",
      requestedMinutes: request.requested_minutes == null ? null : Number(request.requested_minutes)
    }));
    const policy = this.db.prepare("SELECT * FROM policies LIMIT 1").get();
    if (policy) {
      this.state.policy = {
        policyId: policy.policy_id,
        version: policy.version,
        updatedAt: policy.updated_at,
        expiresAt: policy.expires_at,
        hash: policy.hash,
        canonicalHash: policy.canonical_hash,
        signature: policy.signature,
        keyId: policy.key_id,
        rules: JSON.parse(policy.rules_json)
      };
      this.state.blockedApps = clone(this.state.policy.rules);
    }
    this.state.parentTokens = this.db.prepare("SELECT token FROM parent_tokens ORDER BY created_at").all().map((item) => item.token);
    this.state.parentSessions = this.db.prepare("SELECT token_hash, family_id, parent_id, expires_at, created_at FROM parent_sessions ORDER BY created_at").all();
    this.loadNormalizedState();
  }

  loadNormalizedState() {
    this.state.pairingSessions = Object.fromEntries(this.db.prepare("SELECT * FROM pairing_sessions ORDER BY created_at").all().map((row) => [row.session_id, {
      sessionId: row.session_id, issuerType: row.issuer_type || "child", issuerId: row.issuer_id || "",
      childDeviceId: row.child_device_id || "", codeHash: row.code_hash,
      status: row.status, parentId: row.parent_id || null, familyId: row.family_id || null,
      createdAt: row.created_at, expiresAt: Number(row.expires_at), claimedAt: row.claimed_at || null,
      mappingId: row.mapping_id || null, confirmedAt: row.confirmed_at || null
    }]));
    this.state.families = Object.fromEntries(this.db.prepare("SELECT * FROM families ORDER BY family_id").all().map((row) => [row.family_id, {
      familyId: row.family_id, name: row.name, status: row.status, createdAt: row.created_at, updatedAt: row.updated_at
    }]));
    this.state.parentProfiles = Object.fromEntries(this.db.prepare("SELECT * FROM parent_profiles ORDER BY parent_id").all().map((row) => [row.parent_id, {
      parentId: row.parent_id, familyId: row.family_id, deviceFingerprint: row.device_fingerprint,
      publicKey: row.public_key || "", displayName: row.display_name, status: row.status,
      metadata: parseJson(row.metadata_json, {}),
      createdAt: row.created_at, updatedAt: row.updated_at
    }]));
    this.state.childProfiles = Object.fromEntries(this.db.prepare("SELECT * FROM child_profiles ORDER BY child_id").all().map((row) => [row.child_id, {
      childId: row.child_id, deviceId: row.device_id, displayName: row.display_name,
      status: row.status, createdAt: row.created_at, updatedAt: row.updated_at
    }]));
    this.state.familyMembers = this.db.prepare("SELECT * FROM family_members ORDER BY created_at").all().map((row) => ({
      familyId: row.family_id, memberType: row.member_type, memberId: row.member_id,
      role: row.role, status: row.status, createdAt: row.created_at
    }));
    this.state.geofences = Object.fromEntries(this.db.prepare("SELECT * FROM geofences ORDER BY created_at, geofence_id").all().map((row) => [row.geofence_id, {
      geofenceId: row.geofence_id, familyId: row.family_id, name: row.name,
      latitude: Number(row.latitude), longitude: Number(row.longitude), radiusMeters: Number(row.radius_m),
      enabled: Boolean(row.enabled), createdByParentId: row.created_by_parent_id || null,
      createdAt: row.created_at, updatedAt: row.updated_at
    }]));
    this.state.locationConsents = Object.fromEntries(this.db.prepare("SELECT * FROM location_consents ORDER BY device_id").all().map((row) => [row.device_id, {
      deviceId: row.device_id, familyId: row.family_id, parentConsented: Boolean(row.parent_consented),
      childConsented: Boolean(row.child_consented), permissionGranted: Boolean(row.permission_granted),
      parentConsentedAt: row.parent_consented_at || null, childConsentedAt: row.child_consented_at || null,
      updatedAt: row.updated_at
    }]));
    this.state.locationRequests = Object.fromEntries(this.db.prepare("SELECT * FROM location_requests ORDER BY created_at").all().map((row) => [row.request_id, {
      requestId: row.request_id, familyId: row.family_id, deviceId: row.device_id, parentId: row.parent_id,
      commandId: row.command_id, status: row.status, resultCode: row.result_code || "", sampleId: row.sample_id || "",
      createdAt: row.created_at, expiresAt: row.expires_at, updatedAt: row.updated_at
    }]));
    this.state.locationSamples = Object.fromEntries(this.db.prepare("SELECT * FROM location_samples ORDER BY captured_at").all().map((row) => [`${row.device_id}:${row.sample_id}`, {
      deviceId: row.device_id, sampleId: row.sample_id, requestId: row.request_id, familyId: row.family_id,
      capturedAt: row.captured_at, receivedAt: row.received_at, latitude: Number(row.latitude), longitude: Number(row.longitude),
      accuracyMeters: Number(row.accuracy_m), provider: row.provider, batteryPercent: Number(row.battery_pct), charging: Boolean(row.charging)
    }]));
    this.state.geofenceStates = Object.fromEntries(this.db.prepare("SELECT * FROM geofence_states ORDER BY device_id, geofence_id").all().map((row) => [`${row.device_id}:${row.geofence_id}`, {
      deviceId: row.device_id, geofenceId: row.geofence_id, state: row.state, sampleId: row.sample_id,
      lastSampleAt: row.last_sample_at, distanceMeters: Number(row.distance_m), accuracyMeters: Number(row.accuracy_m)
    }]));
    this.state.locationTransitions = Object.fromEntries(this.db.prepare("SELECT * FROM location_transitions ORDER BY event_time").all().map((row) => [row.transition_id, {
      transitionId: row.transition_id, familyId: row.family_id, deviceId: row.device_id,
      geofenceId: row.geofence_id, geofenceName: row.geofence_name, type: row.transition_type,
      eventTime: row.event_time, sampleId: row.sample_id, distanceMeters: Number(row.distance_m),
      accuracyMeters: Number(row.accuracy_m), receivedAt: row.received_at
    }]));
    this.state.parentChildMappings = Object.fromEntries(this.db.prepare("SELECT * FROM parent_child_mappings ORDER BY created_at").all().map((row) => [row.mapping_id, {
      mappingId: row.mapping_id, familyId: row.family_id, parentId: row.parent_id,
      childId: row.child_id, status: row.status, parentConsent: Boolean(row.parent_consent),
      childConsent: Boolean(row.child_consent), createdAt: row.created_at,
      updatedAt: row.updated_at, confirmedAt: row.confirmed_at || null
    }]));
    this.state.consentRequests = Object.fromEntries(this.db.prepare("SELECT * FROM consent_requests ORDER BY created_at").all().map((row) => [row.request_id, {
      requestId: row.request_id, mappingId: row.mapping_id, recipientType: row.recipient_type,
      recipientId: row.recipient_id, status: row.status, createdAt: row.created_at,
      expiresAt: row.expires_at, respondedAt: row.responded_at || null, response: row.response || null
    }]));
    this.state.notificationKeys = Object.fromEntries(this.db.prepare("SELECT * FROM device_notification_keys ORDER BY created_at").all().map((row) => [row.notification_key_id, {
      notificationKeyId: row.notification_key_id, deviceId: row.device_id, provider: row.provider,
      token: row.token, status: row.status, createdAt: row.created_at, updatedAt: row.updated_at
    }]));
    this.state.appVersions = Object.fromEntries(this.db.prepare("SELECT * FROM app_versions ORDER BY platform, product, version_code").all().map((row) => {
      const key = `${row.platform}:${row.product}:${row.version_code}`;
      return [key, {
        platform: row.platform, product: row.product, versionCode: row.version_code,
        versionName: row.version_name, artifact: row.artifact, sha256: row.sha256,
        size: row.size, packageName: row.package_name || "",
        signingCertificateSha256: row.signing_certificate_sha256 || "", channel: row.channel,
        releaseNotes: row.release_notes, publishedAt: row.published_at
      }];
    }));
    this.state.appVersionChanges = Object.fromEntries(this.db.prepare("SELECT * FROM app_version_changes ORDER BY created_at").all().map((row) => [row.change_id, {
      changeId: row.change_id, platform: row.platform, product: row.product, versionCode: row.version_code,
      previousVersionCode: row.previous_version_code, changeType: row.change_type, component: row.component,
      changeKey: row.change_key, changeSummary: row.change_summary, issueId: row.issue_id || "",
      sourceRef: row.source_ref || "", isVerified: Boolean(row.is_verified),
      verificationNote: row.verification_note || "", verifiedAt: row.verified_at || null, createdAt: row.created_at
    }]));
    this.state.deviceErrors = Object.fromEntries(this.db.prepare("SELECT * FROM device_errors ORDER BY updated_at").all().map((row) => [row.error_id, {
      errorId: row.error_id, fingerprint: row.fingerprint, deviceId: row.device_id || null,
      platform: row.platform, product: row.product, versionCode: row.version_code, versionName: row.version_name,
      errorCode: row.error_code, category: row.category, severity: row.severity, component: row.component,
      operation: row.operation, messageRedacted: row.message_redacted, firstSeenAt: row.first_seen_at,
      lastSeenAt: row.last_seen_at, occurrenceCount: row.occurrence_count, status: row.status,
      isFixed: Boolean(row.is_fixed), fixedInVersionCode: row.fixed_in_version_code,
      fixedAt: row.fixed_at || null, resolutionNote: row.resolution_note || "",
      createdAt: row.created_at, updatedAt: row.updated_at
    }]));
    this.state.errorOccurrences = Object.fromEntries(this.db.prepare("SELECT * FROM device_error_occurrences ORDER BY created_at").all().map((row) => [row.occurrence_id, {
      occurrenceId: row.occurrence_id, errorId: row.error_id, clientErrorId: row.client_error_id,
      deviceId: row.device_id || null, requestId: row.request_id || "", correlationId: row.correlation_id || "",
      occurredAt: row.occurred_at, runtime: parseJson(row.runtime_json, {}), context: parseJson(row.context_json, {}),
      messageRedacted: row.message_redacted, stackTraceRedacted: row.stack_trace_redacted || "",
      uploadStatus: row.upload_status, createdAt: row.created_at
    }]));
    this.state.errorVersionLinks = Object.fromEntries(this.db.prepare("SELECT * FROM error_app_version_links ORDER BY created_at").all().map((row) => {
      const key = `${row.error_id}:${row.platform}:${row.product}:${row.version_code}:${row.relation}`;
      return [key, {
        linkKey: key, errorId: row.error_id, platform: row.platform, product: row.product,
        versionCode: row.version_code, relation: row.relation, verified: Boolean(row.verified),
        note: row.note || "", createdAt: row.created_at
      }];
    }));
    this.state.familyPolicies = Object.fromEntries(this.db.prepare("SELECT * FROM family_policies ORDER BY family_id").all().map((row) => [row.family_id, {
      familyId: row.family_id, version: row.version, policy: parseJson(row.policy_json, {}),
      source: row.source, updatedAt: row.updated_at
    }]));
    this.state.devicePolicyAssignments = Object.fromEntries(this.db.prepare("SELECT * FROM device_policy_assignments ORDER BY assigned_at").all().map((row) => [row.assignment_id, {
      assignmentId: row.assignment_id, deviceId: row.device_id, familyId: row.family_id, policyId: row.policy_id,
      version: row.version, status: row.status, assignedAt: row.assigned_at, appliedAt: row.applied_at || null,
      rejectionReason: row.rejection_reason || ""
    }]));
    this.state.policySyncReceipts = Object.fromEntries(this.db.prepare("SELECT * FROM policy_sync_receipts ORDER BY reported_at").all().map((row) => [row.receipt_id, {
      receiptId: row.receipt_id, deviceId: row.device_id, policyId: row.policy_id || "", version: row.version,
      canonicalHash: row.canonical_hash || "", signatureStatus: row.signature_status || "unknown",
      localState: row.local_state || "unknown", accepted: Boolean(row.accepted), reportedAt: row.reported_at
    }]));
  }

  dbCommandToState(command) {
    const state = command.state;
    return {
      id: command.id,
      deviceId: command.device_id,
      type: command.type,
      payload: JSON.parse(command.payload_json),
      state,
      status: state,
      ack: command.ack_json ? JSON.parse(command.ack_json) : null,
      result: command.result_json ? JSON.parse(command.result_json) : null,
      retryCount: command.retry_count,
      maxRetries: command.max_retries,
      idempotencyKey: command.idempotency_key,
      leaseExpiresAt: command.lease_expires_at,
      expiresAt: command.expires_at,
      createdAt: command.created_at,
      deliveredAt: command.delivered_at,
      completedAt: command.completed_at
    };
  }

  keyPaths() {
    return {
      privateKey: path.join(this.dataDir, "policy-signing-private.pem"),
      publicKey: path.join(this.dataDir, "policy-signing-public.pem")
    };
  }

  ensureSigningKey() {
    const paths = this.keyPaths();
    if (!fs.existsSync(paths.privateKey)) {
      const pair = crypto.generateKeyPairSync("ed25519");
      fs.writeFileSync(paths.privateKey, pair.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600, flag: "wx" });
      fs.chmodSync(paths.privateKey, 0o600);
      fs.writeFileSync(paths.publicKey, pair.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644, flag: "wx" });
      try { fs.chmodSync(paths.publicKey, 0o644); } catch (_) { /* best effort */ }
    } else if (!fs.existsSync(paths.publicKey)) {
      const privateKey = crypto.createPrivateKey(fs.readFileSync(paths.privateKey, "utf8"));
      const publicKey = crypto.createPublicKey(privateKey);
      fs.writeFileSync(paths.publicKey, publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644, flag: "wx" });
    }
    fs.chmodSync(paths.privateKey, 0o600);
    this.privateKey = crypto.createPrivateKey(fs.readFileSync(paths.privateKey, "utf8"));
    this.publicKey = crypto.createPublicKey(fs.readFileSync(paths.publicKey, "utf8"));
    this.keyId = crypto.createHash("sha256").update(this.publicKey.export({ type: "spki", format: "der" })).digest("hex").slice(0, 16);
  }

  ensurePolicy() {
    if (!this.state) {
      this.state = defaultState();
    }
    if (!Array.isArray(this.state.blockedApps)) {
      this.state.blockedApps = [];
    }
    if (!this.state.policy || typeof this.state.policy !== "object") {
      this.state.policy = defaultState().policy;
    }
    if (!Array.isArray(this.state.policy.rules)) {
      this.state.policy.rules = [];
    }
    if (this.state.policy.rules.length === 0 && this.state.blockedApps.length > 0) {
      this.state.policy.rules = this.state.blockedApps.map((rule) => ({
        id: rule.id || crypto.randomUUID(),
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
    this.ensureSigningKey();
    const canonicalHash = this.hashPolicy(this.state.policy);
    this.state.policy.hash = canonicalHash;
    this.state.policy.canonicalHash = canonicalHash;
    this.state.policy.keyId = this.keyId;
    if (!this.state.policy.expiresAt || Date.parse(this.state.policy.expiresAt) <= Date.now()) {
      this.state.policy.expiresAt = new Date(Date.now() + this.policyTtlMs).toISOString();
    }
    const document = this.policyDocument(this.state.policy.rules, this.state.policy);
    this.state.policy.signature = this.signDocument(document);
  }

  hashPolicy(policy) {
    return crypto.createHash("sha256").update(canonicalJson({
      policyId: policy.policyId,
      version: Number(policy.version),
      rules: policy.rules
    })).digest("hex");
  }

  policyDocument(rules, policy = this.state.policy) {
    return {
      policyId: policy.policyId,
      version: Number(policy.version),
      expiresAt: policy.expiresAt,
      rules: rules || []
    };
  }

  signDocument(document) {
    return base64url(crypto.sign(null, Buffer.from(canonicalJson(document)), this.privateKey));
  }

  appendNotification(payload) {
    ensureDir(this.dataDir);
    const safe = { ...payload };
    if (Array.isArray(safe.tokens)) {
      safe.tokenCount = safe.tokens.length;
      delete safe.tokens;
    }
    fs.appendFileSync(this.notificationLog, `${JSON.stringify({ time: nowIso(), payload: safe })}\n`, { encoding: "utf8", mode: 0o600 });
  }

  save() {
    this.ensurePolicy();
    if (this.sqlite && this.db) {
      this.saveSqlite();
    } else {
      this.state.requestNonces = this._jsonNonces;
      atomicWriteJson(this.stateFile, this.state);
      delete this.state.requestNonces;
    }
  }

  saveSqlite() {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.exec("DELETE FROM error_app_version_links; DELETE FROM device_error_occurrences; DELETE FROM device_errors; DELETE FROM app_version_changes; DELETE FROM devices; DELETE FROM events; DELETE FROM commands; DELETE FROM approval_requests; DELETE FROM policies; DELETE FROM parent_tokens; DELETE FROM parent_sessions; DELETE FROM pairing_sessions; DELETE FROM location_transitions; DELETE FROM geofence_states; DELETE FROM location_samples; DELETE FROM location_requests; DELETE FROM location_consents; DELETE FROM geofences; DELETE FROM families; DELETE FROM parent_profiles; DELETE FROM child_profiles; DELETE FROM family_members; DELETE FROM parent_child_mappings; DELETE FROM consent_requests; DELETE FROM device_notification_keys; DELETE FROM app_versions; DELETE FROM family_policies; DELETE FROM device_policy_assignments; DELETE FROM policy_sync_receipts;");
      const deviceInsert = this.db.prepare("INSERT INTO devices (device_id, child_name, device_name, platform, status, current_app, local_policy_version, last_event_seq, last_seen_at, hmac_secret, public_key, registration_status, registered_at, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const [deviceId, device] of Object.entries(this.state.devices)) {
        deviceInsert.run(deviceId, device.childName || "자녀", device.deviceName || deviceId, device.platform || "windows", device.status || "running", device.currentApp || "", Number(device.localPolicyVersion || 0), Number(device.lastEventSeq || 0), device.lastSeenAt || nowIso(), this._deviceSecrets.get(deviceId) || null, device.publicKey || null, device.registrationStatus || "unregistered", device.registeredAt || null, JSON.stringify(device.metadata || {}), device.createdAt || device.lastSeenAt || nowIso());
      }
      const eventInsert = this.db.prepare("INSERT INTO events (id, device_id, event_id, sequence, type, event_time, payload_json, child_name, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const event of this.state.events) {
        eventInsert.run(event.id, event.deviceId, event.eventId, event.sequence == null ? null : Number(event.sequence), event.type || "unknown", event.eventTime || null, JSON.stringify(event.payload || {}), event.childName || "자녀", event.receivedAt || nowIso());
      }
      const commandInsert = this.db.prepare("INSERT INTO commands (id, device_id, type, payload_json, state, ack_json, result_json, retry_count, max_retries, idempotency_key, lease_expires_at, expires_at, created_at, delivered_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const command of this.state.commands) {
        commandInsert.run(command.id, command.deviceId, command.type, JSON.stringify(command.payload || {}), command.state || command.status || "queued", command.ack ? JSON.stringify(command.ack) : null, command.result ? JSON.stringify(command.result) : null, Number(command.retryCount || 0), Number(command.maxRetries || this.maxCommandRetries), command.idempotencyKey || null, command.leaseExpiresAt || null, command.expiresAt || new Date(Date.now() + 600000).toISOString(), command.createdAt || nowIso(), command.deliveredAt || null, command.completedAt || null);
      }
      const approvalInsert = this.db.prepare("INSERT INTO approval_requests (id, device_id, child_name, device_name, app_name, executable_path, pid, event_id, status, decision, created_at, decided_at, kind, requested_minutes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const request of this.state.approvalRequests) {
        approvalInsert.run(request.id, request.deviceId, request.childName || "자녀", request.deviceName || request.deviceId, request.appName || "unknown", request.executablePath || "", request.pid == null ? null : Number(request.pid), request.eventId || "", request.status || "pending", request.decision || null, request.createdAt || nowIso(), request.decidedAt || null, request.kind || "app_launch", request.requestedMinutes == null ? null : Number(request.requestedMinutes));
      }
      const policy = this.state.policy;
      this.db.prepare("INSERT INTO policies (policy_id, version, updated_at, expires_at, hash, canonical_hash, signature, key_id, rules_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(policy.policyId, Number(policy.version), policy.updatedAt, policy.expiresAt, policy.hash, policy.canonicalHash, policy.signature, policy.keyId, JSON.stringify(policy.rules));
      const tokenInsert = this.db.prepare("INSERT INTO parent_tokens (token, created_at) VALUES (?, ?)");
      for (const token of this.state.parentTokens) {
        tokenInsert.run(token, nowIso());
      }
      const sessionInsert = this.db.prepare("INSERT INTO parent_sessions (token_hash, family_id, parent_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)");
      for (const session of this.state.parentSessions || []) {
        sessionInsert.run(session.token_hash, session.family_id || "", session.parent_id || null, Number(session.expires_at), session.created_at || nowIso());
      }
      const pairingInsert = this.db.prepare("INSERT INTO pairing_sessions (session_id, issuer_type, issuer_id, child_device_id, code_hash, status, parent_id, family_id, created_at, expires_at, claimed_at, mapping_id, confirmed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const session of Object.values(this.state.pairingSessions || {})) pairingInsert.run(session.sessionId, session.issuerType || "child", session.issuerId || "", session.childDeviceId || "", session.codeHash, session.status || "pending", session.parentId || null, session.familyId || null, session.createdAt || nowIso(), Number(session.expiresAt), session.claimedAt || null, session.mappingId || null, session.confirmedAt || null);
      const familyInsert = this.db.prepare("INSERT INTO families (family_id, name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)");
      for (const family of Object.values(this.state.families || {})) familyInsert.run(family.familyId, family.name || family.familyId, family.status || "active", family.createdAt || nowIso(), family.updatedAt || nowIso());
      const geofenceInsert = this.db.prepare("INSERT INTO geofences (geofence_id, family_id, name, latitude, longitude, radius_m, enabled, created_by_parent_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const geofence of Object.values(this.state.geofences || {})) geofenceInsert.run(
        geofence.geofenceId, geofence.familyId, geofence.name, Number(geofence.latitude), Number(geofence.longitude),
        Number(geofence.radiusMeters), geofence.enabled === false ? 0 : 1, geofence.createdByParentId || null,
        geofence.createdAt || nowIso(), geofence.updatedAt || nowIso()
      );
      const locationConsentInsert = this.db.prepare("INSERT INTO location_consents (device_id, family_id, parent_consented, child_consented, permission_granted, parent_consented_at, child_consented_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
      for (const item of Object.values(this.state.locationConsents || {})) locationConsentInsert.run(
        item.deviceId, item.familyId, item.parentConsented ? 1 : 0, item.childConsented ? 1 : 0,
        item.permissionGranted ? 1 : 0, item.parentConsentedAt || null, item.childConsentedAt || null, item.updatedAt || nowIso()
      );
      const locationRequestInsert = this.db.prepare("INSERT INTO location_requests (request_id, family_id, device_id, parent_id, command_id, status, result_code, sample_id, created_at, expires_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const item of Object.values(this.state.locationRequests || {})) locationRequestInsert.run(
        item.requestId, item.familyId, item.deviceId, item.parentId, item.commandId, item.status,
        item.resultCode || null, item.sampleId || null, item.createdAt, item.expiresAt, item.updatedAt || nowIso()
      );
      const locationSampleInsert = this.db.prepare("INSERT INTO location_samples (device_id, sample_id, request_id, family_id, captured_at, received_at, latitude, longitude, accuracy_m, provider, battery_pct, charging) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const item of Object.values(this.state.locationSamples || {})) locationSampleInsert.run(
        item.deviceId, item.sampleId, item.requestId, item.familyId, item.capturedAt, item.receivedAt,
        Number(item.latitude), Number(item.longitude), Number(item.accuracyMeters), item.provider,
        Number(item.batteryPercent), item.charging ? 1 : 0
      );
      const geofenceStateInsert = this.db.prepare("INSERT INTO geofence_states (device_id, geofence_id, state, sample_id, last_sample_at, distance_m, accuracy_m) VALUES (?, ?, ?, ?, ?, ?, ?)");
      for (const item of Object.values(this.state.geofenceStates || {})) geofenceStateInsert.run(
        item.deviceId, item.geofenceId, item.state, item.sampleId, item.lastSampleAt,
        Number(item.distanceMeters), Number(item.accuracyMeters)
      );
      const locationTransitionInsert = this.db.prepare("INSERT INTO location_transitions (transition_id, family_id, device_id, geofence_id, geofence_name, transition_type, event_time, sample_id, distance_m, accuracy_m, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const item of Object.values(this.state.locationTransitions || {})) locationTransitionInsert.run(
        item.transitionId, item.familyId, item.deviceId, item.geofenceId, item.geofenceName,
        item.type, item.eventTime, item.sampleId, Number(item.distanceMeters), Number(item.accuracyMeters), item.receivedAt
      );
      const parentInsert = this.db.prepare("INSERT INTO parent_profiles (parent_id, family_id, device_fingerprint, public_key, display_name, status, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const parent of Object.values(this.state.parentProfiles || {})) parentInsert.run(parent.parentId, parent.familyId, parent.deviceFingerprint, parent.publicKey || null, parent.displayName || "부모", parent.status || "active", JSON.stringify(parent.metadata || {}), parent.createdAt || nowIso(), parent.updatedAt || nowIso());
      const childInsert = this.db.prepare("INSERT INTO child_profiles (child_id, device_id, display_name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)");
      for (const child of Object.values(this.state.childProfiles || {})) childInsert.run(child.childId, child.deviceId, child.displayName || "자녀", child.status || "active", child.createdAt || nowIso(), child.updatedAt || nowIso());
      const memberInsert = this.db.prepare("INSERT INTO family_members (family_id, member_type, member_id, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?)");
      for (const member of this.state.familyMembers || []) memberInsert.run(member.familyId, member.memberType, member.memberId, member.role || "member", member.status || "active", member.createdAt || nowIso());
      const mappingInsert = this.db.prepare("INSERT INTO parent_child_mappings (mapping_id, family_id, parent_id, child_id, status, parent_consent, child_consent, created_at, updated_at, confirmed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const mapping of Object.values(this.state.parentChildMappings || {})) mappingInsert.run(mapping.mappingId, mapping.familyId, mapping.parentId, mapping.childId, mapping.status || "pending_consent", mapping.parentConsent ? 1 : 0, mapping.childConsent ? 1 : 0, mapping.createdAt || nowIso(), mapping.updatedAt || nowIso(), mapping.confirmedAt || null);
      const consentInsert = this.db.prepare("INSERT INTO consent_requests (request_id, mapping_id, recipient_type, recipient_id, status, created_at, expires_at, responded_at, response) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const request of Object.values(this.state.consentRequests || {})) consentInsert.run(request.requestId, request.mappingId, request.recipientType, request.recipientId, request.status || "pending", request.createdAt || nowIso(), request.expiresAt || new Date(Date.now() + 86400000).toISOString(), request.respondedAt || null, request.response || null);
      const notificationInsert = this.db.prepare("INSERT INTO device_notification_keys (notification_key_id, device_id, provider, token, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
      for (const key of Object.values(this.state.notificationKeys || {})) notificationInsert.run(key.notificationKeyId, key.deviceId, key.provider, key.token, key.status || "active", key.createdAt || nowIso(), key.updatedAt || nowIso());
      const versionInsert = this.db.prepare("INSERT INTO app_versions (platform, product, version_code, version_name, artifact, sha256, size, package_name, signing_certificate_sha256, channel, release_notes, published_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const version of Object.values(this.state.appVersions || {})) versionInsert.run(version.platform, version.product, Number(version.versionCode), version.versionName || "", version.artifact, version.sha256, Number(version.size), version.packageName || null, version.signingCertificateSha256 || null, version.channel || "test", version.releaseNotes || "", version.publishedAt || nowIso());
      const changeInsert = this.db.prepare("INSERT INTO app_version_changes (change_id, platform, product, version_code, previous_version_code, change_type, component, change_key, change_summary, issue_id, source_ref, is_verified, verification_note, verified_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const change of Object.values(this.state.appVersionChanges || {})) changeInsert.run(change.changeId, change.platform, change.product, Number(change.versionCode), change.previousVersionCode == null ? null : Number(change.previousVersionCode), change.changeType, change.component, change.changeKey, change.changeSummary, change.issueId || null, change.sourceRef || null, change.isVerified ? 1 : 0, change.verificationNote || "", change.verifiedAt || null, change.createdAt || nowIso());
      const errorInsert = this.db.prepare("INSERT INTO device_errors (error_id, fingerprint, device_id, platform, product, version_code, version_name, error_code, category, severity, component, operation, message_redacted, first_seen_at, last_seen_at, occurrence_count, status, is_fixed, fixed_in_version_code, fixed_at, resolution_note, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const issue of Object.values(this.state.deviceErrors || {})) errorInsert.run(issue.errorId, issue.fingerprint, issue.deviceId || null, issue.platform, issue.product, Number(issue.versionCode || 0), issue.versionName || "", issue.errorCode, issue.category, issue.severity, issue.component, issue.operation, issue.messageRedacted, issue.firstSeenAt, issue.lastSeenAt, Number(issue.occurrenceCount || 0), issue.status, issue.isFixed ? 1 : 0, issue.fixedInVersionCode == null ? null : Number(issue.fixedInVersionCode), issue.fixedAt || null, issue.resolutionNote || null, issue.createdAt, issue.updatedAt);
      const occurrenceInsert = this.db.prepare("INSERT INTO device_error_occurrences (occurrence_id, error_id, client_error_id, device_id, request_id, correlation_id, occurred_at, runtime_json, context_json, message_redacted, stack_trace_redacted, upload_status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const occurrence of Object.values(this.state.errorOccurrences || {})) occurrenceInsert.run(occurrence.occurrenceId, occurrence.errorId, occurrence.clientErrorId, occurrence.deviceId || null, occurrence.requestId || null, occurrence.correlationId || null, occurrence.occurredAt, JSON.stringify(occurrence.runtime || {}), JSON.stringify(occurrence.context || {}), occurrence.messageRedacted || "", occurrence.stackTraceRedacted || null, occurrence.uploadStatus || "accepted", occurrence.createdAt || nowIso());
      const linkInsert = this.db.prepare("INSERT INTO error_app_version_links (error_id, platform, product, version_code, relation, verified, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
      for (const link of Object.values(this.state.errorVersionLinks || {})) linkInsert.run(link.errorId, link.platform, link.product, Number(link.versionCode), link.relation, link.verified ? 1 : 0, link.note || "", link.createdAt || nowIso());
      const familyPolicyInsert = this.db.prepare("INSERT INTO family_policies (family_id, version, policy_json, source, updated_at) VALUES (?, ?, ?, ?, ?)");
      for (const policy of Object.values(this.state.familyPolicies || {})) familyPolicyInsert.run(policy.familyId, Number(policy.version || 0), JSON.stringify(policy.policy || {}), policy.source || "default", policy.updatedAt || nowIso());
      const assignmentInsert = this.db.prepare("INSERT INTO device_policy_assignments (assignment_id, device_id, family_id, policy_id, version, status, assigned_at, applied_at, rejection_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const assignment of Object.values(this.state.devicePolicyAssignments || {})) assignmentInsert.run(assignment.assignmentId, assignment.deviceId, assignment.familyId, assignment.policyId, Number(assignment.version || 0), assignment.status || "pending", assignment.assignedAt || nowIso(), assignment.appliedAt || null, assignment.rejectionReason || null);
      const receiptInsert = this.db.prepare("INSERT INTO policy_sync_receipts (receipt_id, device_id, policy_id, version, canonical_hash, signature_status, local_state, accepted, reported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
      for (const receipt of Object.values(this.state.policySyncReceipts || {})) receiptInsert.run(receipt.receiptId, receipt.deviceId, receipt.policyId || null, Number(receipt.version || 0), receipt.canonicalHash || null, receipt.signatureStatus || "unknown", receipt.localState || "unknown", receipt.accepted ? 1 : 0, receipt.reportedAt || nowIso());
      this.db.prepare("INSERT OR REPLACE INTO storage_meta (key, value) VALUES (?, ?)").run("initialized", "1");
      this.db.exec("COMMIT");
    } catch (error) {
      try { this.db.exec("ROLLBACK"); } catch (_) { /* best effort */ }
      throw error;
    }
  }

  storageMode() {
    return this.sqlite && this.db ? "sqlite" : "json-fallback";
  }

  getDeviceSecret(deviceId) {
    return this._deviceSecrets.get(deviceId) || "";
  }

  setDeviceSecret(deviceId, secret) {
    if (!secret || typeof secret !== "string" || secret.length > 4096) {
      throw new StoreError("invalid_device_secret", 400);
    }
    this._deviceSecrets.set(deviceId, secret);
    this.save();
  }

  getDevicePublicKey(deviceId) {
    return this.state && this.state.devices[deviceId] ? String(this.state.devices[deviceId].publicKey || "") : "";
  }

  setDevicePublicKey(deviceId, publicKey) {
    if (typeof publicKey !== "string" || publicKey.length < 32 || publicKey.length > 8192) {
      throw new StoreError("invalid_device_public_key", 400);
    }
    this.upsertDevice(deviceId, { publicKey });
  }

  consumeDeviceNonce(deviceId, nonce, expiresAt) {
    const now = Date.now();
    if (this.sqlite && this.db) {
      this.db.prepare("DELETE FROM request_nonces WHERE expires_at <= ?").run(now);
      try {
        this.db.prepare("INSERT INTO request_nonces (device_id, nonce, expires_at) VALUES (?, ?, ?)").run(deviceId, nonce, Number(expiresAt));
        this.audit("device", deviceId, "device_request_accepted", null, { nonce });
        return true;
      } catch (error) {
        if (String(error.message).includes("UNIQUE")) {
          return false;
        }
        throw error;
      }
    }
    this._jsonNonces = this._jsonNonces.filter((entry) => entry.expiresAt > now);
    if (this._jsonNonces.some((entry) => entry.deviceId === deviceId && entry.nonce === nonce)) {
      return false;
    }
    this._jsonNonces.push({ deviceId, nonce, expiresAt: Number(expiresAt) });
    this.save();
    return true;
  }

  audit(actorType, actorId, action, requestId, metadata = {}) {
    const entry = {
      id: crypto.randomUUID(), actorType, actorId: actorId || null, action, requestId: requestId || null, metadata, createdAt: nowIso()
    };
    if (this.sqlite && this.db) {
      this.db.prepare("INSERT INTO audit_log (id, actor_type, actor_id, action, request_id, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(entry.id, entry.actorType, entry.actorId, entry.action, entry.requestId, JSON.stringify(entry.metadata), entry.createdAt);
    }
    return entry;
  }

  issueParentSession(familyId = "default", ttlMs = 3600000, parentId = null) {
    const token = base64url(crypto.randomBytes(32));
    const tokenHash = crypto.createHash("sha256").update(token, "utf8").digest("hex");
    const session = {
      token_hash: tokenHash,
      family_id: String(familyId || "default").slice(0, 128),
      parent_id: parentId ? String(parentId).slice(0, 128) : null,
      expires_at: Date.now() + Math.max(60000, Number(ttlMs || 3600000)),
      created_at: nowIso()
    };
    this.state.parentSessions = (this.state.parentSessions || []).filter((item) => Number(item.expires_at) > Date.now());
    this.state.parentSessions.push(session);
    this.save();
    return { token, familyId: session.family_id, parentId: session.parent_id, expiresAt: new Date(session.expires_at).toISOString() };
  }

  validateParentSession(token) {
    if (typeof token !== "string" || token.length < 16) return false;
    const tokenHash = crypto.createHash("sha256").update(token, "utf8").digest("hex");
    const now = Date.now();
    const active = (this.state.parentSessions || []).filter((item) => Number(item.expires_at) > now);
    const changed = active.length !== (this.state.parentSessions || []).length;
    this.state.parentSessions = active;
    if (changed) this.save();
    return active.some((item) => item.token_hash === tokenHash);
  }

  registerParentToken(token) {
    if (typeof token !== "string" || token.length < 8 || token.length > 4096) {
      throw new StoreError("invalid_fcm_token", 400);
    }
    if (!this.state.parentTokens.includes(token)) {
      this.state.parentTokens.push(token);
      this.save();
    }
  }

  unregisterParentToken(token) {
    const before = this.state.parentTokens.length;
    this.state.parentTokens = this.state.parentTokens.filter((item) => item !== token);
    if (before !== this.state.parentTokens.length) {
      this.save();
    }
  }

  ensureFamily(familyId, name = "CPSM Family") {
    const id = String(familyId || crypto.randomUUID()).slice(0, 128);
    const existing = this.state.families[id];
    const now = nowIso();
    this.state.families[id] = existing || { familyId: id, name: String(name || id).slice(0, 256), status: "active", createdAt: now, updatedAt: now };
    this.state.families[id].updatedAt = now;
    if (!this.state.familyPolicies[id]) {
      this.state.familyPolicies[id] = { familyId: id, version: Number(this.state.policy.version || 1), policy: clone(this.state.policy), source: "default", updatedAt: now };
    }
    this.save();
    return clone(this.state.families[id]);
  }

  ensureParentProfile({ familyId, deviceFingerprint, publicKey, displayName, metadata = {} }) {
    if (!deviceFingerprint || String(deviceFingerprint).length < 16) throw new StoreError("invalid_parent_device_fingerprint", 400);
    const family = this.ensureFamily(familyId, "CPSM Family");
    const existing = Object.values(this.state.parentProfiles).find((item) => item.deviceFingerprint === String(deviceFingerprint));
    const parentId = existing ? existing.parentId : `parent-${crypto.createHash("sha256").update(String(deviceFingerprint)).digest("hex").slice(0, 24)}`;
    const now = nowIso();
    this.state.parentProfiles[parentId] = {
      parentId, familyId: family.familyId, deviceFingerprint: String(deviceFingerprint),
      publicKey: String(publicKey || ""), displayName: String(displayName || "부모").slice(0, 256),
      metadata: metadata && typeof metadata === "object" ? clone(metadata) : {},
      status: "active", createdAt: existing ? existing.createdAt : now, updatedAt: now
    };
    this.state.familyMembers = this.state.familyMembers.filter((item) => !(item.familyId === family.familyId && item.memberType === "parent" && item.memberId === parentId));
    this.state.familyMembers.push({ familyId: family.familyId, memberType: "parent", memberId: parentId, role: "owner", status: "active", createdAt: existing ? existing.createdAt : now });
    this.save();
    return clone(this.state.parentProfiles[parentId]);
  }

  ensureChildProfile({ deviceId, displayName = "자녀" }) {
    const existing = Object.values(this.state.childProfiles).find((item) => item.deviceId === String(deviceId));
    const childId = existing ? existing.childId : `child-${String(deviceId)}`;
    const now = nowIso();
    this.state.childProfiles[childId] = {
      childId, deviceId: String(deviceId), displayName: String(displayName || "자녀").slice(0, 256),
      status: "active", createdAt: existing ? existing.createdAt : now, updatedAt: now
    };
    this.save();
    return clone(this.state.childProfiles[childId]);
  }

  registerChildDevice({ deviceId, publicKey, authMode, deviceName, childName, platform = "android", metadata = {} }) {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(String(deviceId || ""))) throw new StoreError("invalid_device_id", 400);
    if (typeof publicKey !== "string" || publicKey.length < 32 || publicKey.length > 8192) throw new StoreError("invalid_device_public_key", 400);
    try { crypto.createPublicKey({ key: Buffer.from(publicKey, "base64"), format: "der", type: "spki" }); } catch (_) { throw new StoreError("invalid_device_public_key", 400); }
    const current = this.state.devices[deviceId] || {};
    // An unauthenticated register call must not replace an enrolled key (device takeover).
    if (current.publicKey && current.publicKey !== publicKey) throw new StoreError("device_key_conflict", 409);
    const samePublicKey = current.publicKey && current.publicKey === publicKey;
    const registrationStatus = current.registrationStatus === "registered_paired" && samePublicKey
      ? "registered_paired" : "registered_unpaired";
    const device = this.upsertDevice(deviceId, {
      platform: platform === "windows" ? "windows" : "android", deviceName: String(deviceName || deviceId).slice(0, 256),
      childName: String(childName || "자녀").slice(0, 256), publicKey, authMode: String(authMode || "android_keystore_ec_signature"),
      registrationStatus, registeredAt: current.registeredAt || nowIso(), metadata: metadata && typeof metadata === "object" ? clone(metadata) : {}
    });
    const child = this.ensureChildProfile({ deviceId, displayName: device.childName });
    return { device, child, registrationStatus, parentMappings: this.getChildMappings(child.childId) };
  }

  createPairingSession({ issuerType, issuerId, childDeviceId = "", familyId = null, ttlMs = 120000 }) {
    const type = String(issuerType || "");
    const issuer = String(issuerId || "");
    const childDevice = String(childDeviceId || "");
    if (!["parent", "child"].includes(type) || !issuer) throw new StoreError("invalid_pairing_issuer", 400);
    if (type === "child") {
      const device = this.state.devices[childDevice];
      const child = Object.values(this.state.childProfiles).find((item) => item.deviceId === childDevice);
      if (!device || !child || device.registrationStatus === "unregistered") throw new StoreError("child_device_not_registered", 404);
    } else {
      const parent = this.state.parentProfiles[issuer];
      if (!parent || (familyId && parent.familyId !== familyId)) throw new StoreError("parent_profile_not_found", 404);
    }
    const ttl = Math.min(Math.max(Number(ttlMs) || 120000, 30000), 300000);
    const now = Date.now();
    for (const session of Object.values(this.state.pairingSessions || {})) {
      if (session.status === "pending" && Number(session.expiresAt) <= now) session.status = "expired";
    }
    const sessionId = crypto.randomUUID();
    const pairingCode = crypto.randomBytes(24).toString("base64url");
    const session = {
      sessionId,
      issuerType: type,
      issuerId: issuer,
      childDeviceId: childDevice,
      codeHash: crypto.createHash("sha256").update(pairingCode, "utf8").digest("hex"),
      status: "pending",
      parentId: type === "parent" ? issuer : null,
      familyId: familyId || null,
      createdAt: nowIso(),
      expiresAt: now + ttl,
      claimedAt: null,
      mappingId: null
    };
    this.state.pairingSessions[sessionId] = session;
    this.save();
    return { sessionId, role: type, pairingCode, expiresAt: new Date(session.expiresAt).toISOString() };
  }

  claimPairingSession({ sessionId, pairingCode, claimantType, familyId, parentId, childDeviceId }) {
    const session = this.state.pairingSessions[String(sessionId || "")];
    if (!session || session.status !== "pending") throw new StoreError("pairing_session_not_found", 404);
    if (Number(session.expiresAt) <= Date.now()) {
      session.status = "expired";
      this.save();
      throw new StoreError("pairing_session_expired", 410);
    }
    const expected = Buffer.from(String(session.codeHash), "hex");
    const actual = crypto.createHash("sha256").update(String(pairingCode || ""), "utf8").digest();
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
      throw new StoreError("invalid_pairing_code", 401);
    }
    const claimant = String(claimantType || "");
    let targetParentId = String(parentId || "");
    let targetFamilyId = String(familyId || "");
    let targetChildDeviceId = String(childDeviceId || "");
    if (session.issuerType === "child") {
      if (claimant !== "parent" || !targetParentId || !targetFamilyId) throw new StoreError("pairing_role_mismatch", 403);
      if (session.familyId && session.familyId !== targetFamilyId) throw new StoreError("pairing_family_mismatch", 403);
      targetChildDeviceId = session.childDeviceId;
    } else if (session.issuerType === "parent") {
      if (claimant !== "child" || !targetChildDeviceId) throw new StoreError("pairing_role_mismatch", 403);
      targetParentId = session.parentId || session.issuerId;
      targetFamilyId = session.familyId || targetFamilyId;
    } else {
      throw new StoreError("invalid_pairing_issuer", 400);
    }
    // A confirmed child cannot be moved into another family by scanning a new QR (e.g. a
    // self-enrolled "parent" app); a second parent of the same family is still allowed.
    const existingFamily = this.familyIdForDevice(targetChildDeviceId);
    if (existingFamily && existingFamily !== targetFamilyId) throw new StoreError("child_already_paired", 409);
    const mapping = this.createParentChildMapping({ familyId: targetFamilyId, parentId: targetParentId, childDeviceId: targetChildDeviceId });
    session.status = "claimed";
    session.parentId = targetParentId;
    session.familyId = targetFamilyId;
    session.childDeviceId = targetChildDeviceId;
    session.claimedAt = nowIso();
    session.mappingId = mapping.mappingId;
    this.save();
    return { mapping: clone(mapping), sessionId: session.sessionId, status: session.status };
  }

  pairingPreview(mappingId) {
    const mapping = this.state.parentChildMappings[String(mappingId || "")];
    if (!mapping) throw new StoreError("mapping_not_found", 404);
    const parent = this.state.parentProfiles[mapping.parentId] || null;
    const child = this.state.childProfiles[mapping.childId] || null;
    return {
      mapping_id: mapping.mappingId,
      parent: {
        parent_id: mapping.parentId,
        display_name: parent ? parent.displayName : "부모"
      },
      child: {
        child_id: mapping.childId,
        device_id: child ? child.deviceId : "",
        display_name: child ? child.displayName : "자녀"
      }
    };
  }

  confirmPairingSession({ sessionId, claimantType, familyId, parentId, childDeviceId, consent }) {
    const session = this.state.pairingSessions[String(sessionId || "")];
    if (!session || session.status !== "claimed" || !session.mappingId) {
      throw new StoreError("pairing_confirmation_not_found", 404);
    }
    if (Number(session.expiresAt) <= Date.now()) {
      session.status = "expired";
      this.save();
      throw new StoreError("pairing_session_expired", 410);
    }
    const mapping = this.state.parentChildMappings[session.mappingId];
    if (!mapping) throw new StoreError("mapping_not_found", 404);
    if (String(claimantType || "") === "parent") {
      if (mapping.parentId !== String(parentId || "") || mapping.familyId !== String(familyId || "")) {
        throw new StoreError("pairing_confirmation_actor_mismatch", 403);
      }
    } else if (String(claimantType || "") === "child") {
      const child = this.state.childProfiles[mapping.childId];
      if (!child || child.deviceId !== String(childDeviceId || "")) {
        throw new StoreError("pairing_confirmation_actor_mismatch", 403);
      }
    } else {
      throw new StoreError("invalid_pairing_claimant", 400);
    }

    if (consent !== true) {
      const now = nowIso();
      mapping.status = "declined";
      mapping.parentConsent = false;
      mapping.childConsent = false;
      mapping.updatedAt = now;
      for (const request of Object.values(this.state.consentRequests)) {
        if (request.mappingId === mapping.mappingId && request.status === "pending") {
          Object.assign(request, { status: "declined", respondedAt: now, response: "declined" });
        }
      }
      session.status = "declined";
      session.confirmedAt = null;
      this.save();
      return { mapping: clone(mapping), sessionId: session.sessionId, status: session.status };
    }

    const now = nowIso();
    mapping.parentConsent = true;
    mapping.childConsent = true;
    mapping.status = "confirmed";
    mapping.confirmedAt = now;
    mapping.updatedAt = now;
    for (const request of Object.values(this.state.consentRequests)) {
      if (request.mappingId === mapping.mappingId && request.status === "pending") {
        Object.assign(request, { status: "accepted", respondedAt: now, response: "accepted" });
      }
    }
    const member = this.state.familyMembers.find((item) => item.familyId === mapping.familyId
      && item.memberType === "child" && item.memberId === mapping.childId);
    if (member) member.status = "active";
    const child = this.state.childProfiles[mapping.childId];
    if (child && this.state.devices[child.deviceId]) {
      this.state.devices[child.deviceId].registrationStatus = "registered_paired";
      this.ensurePolicyAssignmentForChild(child.childId, mapping.familyId);
    }
    session.status = "confirmed";
    session.confirmedAt = now;
    this.save();
    return { mapping: clone(mapping), sessionId: session.sessionId, status: session.status };
  }

  getParentSession(token) {
    if (typeof token !== "string" || token.length < 16) return null;
    const tokenHash = crypto.createHash("sha256").update(token, "utf8").digest("hex");
    const session = (this.state.parentSessions || []).find((item) => item.token_hash === tokenHash && Number(item.expires_at) > Date.now());
    return session ? clone(session) : null;
  }

  getChildMappings(childId) {
    return Object.values(this.state.parentChildMappings || {}).filter((mapping) => mapping.childId === childId);
  }

  getRegistrationStatus(deviceId) {
    const device = this.state.devices[deviceId] || null;
    const child = Object.values(this.state.childProfiles).find((item) => item.deviceId === deviceId) || null;
    const mappings = child ? this.getChildMappings(child.childId) : [];
    const confirmed = mappings.filter((mapping) => mapping.status === "confirmed");
    const pending = mappings.filter((mapping) => mapping.status === "pending_consent");
    const requests = child ? Object.values(this.state.consentRequests).filter((request) => request.recipientType === "child" && request.recipientId === child.childId && request.status === "pending") : [];
    const assignment = device ? Object.values(this.state.devicePolicyAssignments || {}).find((item) => item.deviceId === deviceId) || null : null;
    const receipt = device ? this.state.policySyncReceipts[`latest-${deviceId}`] || null : null;
    return {
      device: device ? clone(device) : null, child: child ? clone(child) : null,
      registrationStatus: device ? (device.registrationStatus || "unregistered") : "unregistered",
      mappings: clone(mappings), relationshipStatus: confirmed.length ? "confirmed" : (pending.length ? "pending_consent" : "unpaired"),
      policyReady: confirmed.length > 0, policyAssignment: assignment ? clone(assignment) : null, policyReceipt: receipt ? clone(receipt) : null, consentRequests: clone(requests)
    };
  }

  listAvailableChildren(familyId) {
    const targetFamilyId = String(familyId || "");
    if (!targetFamilyId) return [];
    return Object.values(this.state.childProfiles).map((child) => {
      const device = this.state.devices[child.deviceId] || {};
      const mappings = this.getChildMappings(child.childId).filter((item) => item.familyId === targetFamilyId && item.status !== "revoked");
      return { child: clone(child), device: clone(device), relationshipStatus: mappings.some((item) => item.status === "confirmed") ? "confirmed" : (mappings.length ? "pending_consent" : "unpaired"), familyVisible: mappings.length > 0 };
    }).filter((item) => item.familyVisible && (item.device.registrationStatus === "registered_unpaired" || item.relationshipStatus !== "confirmed"));
  }

  createParentChildMapping({ familyId, parentId, childDeviceId }) {
    const family = this.ensureFamily(familyId, "CPSM Family");
    const parent = this.state.parentProfiles[parentId];
    if (!parent || parent.familyId !== family.familyId) throw new StoreError("parent_profile_not_found", 404);
    const child = this.ensureChildProfile({ deviceId: childDeviceId });
    const existing = Object.values(this.state.parentChildMappings).find((item) => item.familyId === family.familyId && item.parentId === parentId && item.childId === child.childId && item.status !== "revoked");
    if (existing) return clone(existing);
    const now = nowIso();
    const mapping = { mappingId: crypto.randomUUID(), familyId: family.familyId, parentId, childId: child.childId, status: "pending_consent", parentConsent: false, childConsent: false, createdAt: now, updatedAt: now, confirmedAt: null };
    this.state.parentChildMappings[mapping.mappingId] = mapping;
    this.state.familyMembers = this.state.familyMembers.filter((item) => !(item.familyId === family.familyId && item.memberType === "child" && item.memberId === child.childId));
    this.state.familyMembers.push({ familyId: family.familyId, memberType: "child", memberId: child.childId, role: "child", status: "pending", createdAt: now });
    for (const recipient of [["parent", parentId], ["child", child.childId]]) {
      const request = { requestId: crypto.randomUUID(), mappingId: mapping.mappingId, recipientType: recipient[0], recipientId: recipient[1], status: "pending", createdAt: now, expiresAt: new Date(Date.now() + 86400000).toISOString(), respondedAt: null, response: null };
      this.state.consentRequests[request.requestId] = request;
    }
    this.appendNotification({ type: "relationship_consent", mappingId: mapping.mappingId, recipientCount: 2 });
    this.save();
    return clone(mapping);
  }

  setRelationshipConsent({ mappingId, recipientType, recipientId, consent }) {
    const mapping = this.state.parentChildMappings[mappingId];
    if (!mapping) throw new StoreError("mapping_not_found", 404);
    if (!["parent", "child"].includes(recipientType)) throw new StoreError("invalid_consent_recipient", 400);
    if ((recipientType === "parent" && mapping.parentId !== recipientId) || (recipientType === "child" && mapping.childId !== recipientId)) throw new StoreError("consent_recipient_mismatch", 403);
    const request = Object.values(this.state.consentRequests).find((item) => item.mappingId === mappingId && item.recipientType === recipientType && item.recipientId === recipientId && item.status === "pending");
    if (request) Object.assign(request, { status: consent ? "accepted" : "declined", respondedAt: nowIso(), response: consent ? "accepted" : "declined" });
    if (recipientType === "parent") mapping.parentConsent = Boolean(consent); else mapping.childConsent = Boolean(consent);
    mapping.updatedAt = nowIso();
    if (mapping.parentConsent && mapping.childConsent) {
      mapping.status = "confirmed";
      mapping.confirmedAt = nowIso();
      const member = this.state.familyMembers.find((item) => item.familyId === mapping.familyId && item.memberType === "child" && item.memberId === mapping.childId);
      if (member) member.status = "active";
      const child = Object.values(this.state.childProfiles).find((item) => item.childId === mapping.childId);
      if (child && this.state.devices[child.deviceId]) {
        this.state.devices[child.deviceId].registrationStatus = "registered_paired";
        this.ensurePolicyAssignmentForChild(child.childId, mapping.familyId);
      }
    } else if (!consent) {
      mapping.status = "declined";
    }
    this.save();
    return clone(mapping);
  }

  ensurePolicyAssignmentForChild(childId, familyId) {
    const child = this.state.childProfiles[childId];
    const familyPolicy = this.state.familyPolicies[familyId];
    if (!child || !familyPolicy || !familyPolicy.policy) return null;
    const existing = Object.values(this.state.devicePolicyAssignments).find((item) => item.deviceId === child.deviceId && item.familyId === familyId);
    const now = nowIso();
    const assignment = existing || { assignmentId: crypto.randomUUID(), deviceId: child.deviceId, familyId };
    assignment.policyId = familyPolicy.policy.policyId || `family-policy-${familyId}`;
    assignment.version = Number(familyPolicy.version || familyPolicy.policy.version || 0);
    assignment.status = existing && existing.version === assignment.version && existing.status === "applied" ? "applied" : "pending";
    assignment.assignedAt = existing ? existing.assignedAt : now;
    assignment.appliedAt = assignment.status === "applied" ? assignment.appliedAt : null;
    assignment.rejectionReason = "";
    this.state.devicePolicyAssignments[assignment.assignmentId] = assignment;
    return assignment;
  }

  recordPolicySyncReceipt(deviceId, policyHealth = {}) {
    const registration = this.getRegistrationStatus(deviceId);
    const confirmed = registration.mappings.find((mapping) => mapping.status === "confirmed");
    const assignment = confirmed ? Object.values(this.state.devicePolicyAssignments).find((item) => item.deviceId === deviceId && item.familyId === confirmed.familyId) : null;
    const localState = String(policyHealth.state || "unknown");
    const version = Number(policyHealth.version || 0);
    const accepted = Boolean(assignment && localState === "fresh" && version >= Number(assignment.version || 0)
      && ["verified", "unsigned_dev_mode"].includes(String(policyHealth.signature_status || "")));
    if (assignment) {
      assignment.status = accepted ? "applied" : (localState === "expired_or_invalid" ? "rejected" : "pending");
      assignment.appliedAt = accepted ? nowIso() : null;
      assignment.rejectionReason = accepted ? "" : String(policyHealth.last_rejection || "").slice(0, 256);
    }
    const receiptId = `latest-${deviceId}`;
    this.state.policySyncReceipts[receiptId] = {
      receiptId, deviceId, policyId: String(policyHealth.policy_id || policyHealth.policyId || (assignment ? assignment.policyId : "")),
      version, canonicalHash: String(policyHealth.canonical_hash || "").slice(0, 128),
      signatureStatus: String(policyHealth.signature_status || "unknown").slice(0, 64),
      localState, accepted, reportedAt: nowIso()
    };
    this.save();
    return clone(this.state.policySyncReceipts[receiptId]);
  }

  getFamilyPolicyForChild(deviceId) {
    const status = this.getRegistrationStatus(deviceId);
    const confirmed = status.mappings.find((mapping) => mapping.status === "confirmed");
    if (confirmed && this.state.familyPolicies[confirmed.familyId]) return clone(this.state.familyPolicies[confirmed.familyId].policy);
    return clone(this.state.policy);
  }

  addNotificationKey({ deviceId, provider, token }) {
    if (!deviceId || !provider || !token || String(token).length > 4096) throw new StoreError("invalid_notification_key", 400);
    const existing = Object.values(this.state.notificationKeys).find((item) => item.deviceId === deviceId && item.provider === provider && item.token === token);
    const now = nowIso();
    const key = existing || { notificationKeyId: crypto.randomUUID(), deviceId, provider, token, createdAt: now };
    key.status = "active"; key.updatedAt = now; this.state.notificationKeys[key.notificationKeyId] = key; this.save();
    return { notificationKeyId: key.notificationKeyId, deviceId, provider, status: key.status };
  }

  upsertDevice(deviceId, patch = {}) {
    const existing = this.state.devices[deviceId] || {};
    if (patch.hmacSecret) {
      this._deviceSecrets.set(deviceId, String(patch.hmacSecret));
    }
    const cleanPatch = { ...patch };
    delete cleanPatch.hmacSecret;
    this.state.devices[deviceId] = {
      deviceId,
      childName: existing.childName || "자녀",
      deviceName: existing.deviceName || deviceId,
      platform: existing.platform || "windows",
      status: existing.status || "running",
      currentApp: existing.currentApp || "",
      localPolicyVersion: Number(existing.localPolicyVersion || 0),
      lastEventSeq: Number(existing.lastEventSeq || 0),
      registrationStatus: existing.registrationStatus || "unregistered",
      registeredAt: existing.registeredAt || null,
      metadata: existing.metadata && typeof existing.metadata === "object" ? existing.metadata : {},
      createdAt: existing.createdAt || nowIso(),
      ...existing,
      ...cleanPatch,
      lastSeenAt: nowIso()
    };
    this.save();
    return clone(this.state.devices[deviceId]);
  }

  appVersionKey(platform, product, versionCode) {
    return `${platform}:${product}:${Number(versionCode)}`;
  }

  registerAppVersion(input = {}) {
    const platform = String(input.platform || "");
    const product = String(input.product || "");
    const versionCode = Number(input.version_code ?? input.versionCode);
    if (!["android", "windows"].includes(platform) || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(product)) {
      throw new StoreError("invalid_app_version_selector", 400);
    }
    if (!Number.isInteger(versionCode) || versionCode < 1) throw new StoreError("invalid_version_code", 400);
    const version = {
      platform,
      product,
      versionCode,
      versionName: String(input.version_name ?? input.versionName ?? "").slice(0, 128),
      artifact: String(input.artifact || "").slice(0, 512),
      sha256: String(input.sha256 || "").toLowerCase().slice(0, 128),
      size: Number(input.size || 0),
      packageName: String(input.package_name ?? input.packageName ?? "").slice(0, 256),
      signingCertificateSha256: String(input.signing_certificate_sha256 ?? input.signingCertificateSha256 ?? "").toLowerCase().slice(0, 128),
      channel: String(input.channel || "production").slice(0, 64),
      releaseNotes: redactText(input.release_notes ?? input.releaseNotes ?? "").slice(0, 8192),
      publishedAt: String(input.published_at ?? input.publishedAt ?? nowIso()).slice(0, 64)
    };
    if (!version.versionName || !version.artifact || !/^[a-f0-9]{64}$/.test(version.sha256) || !Number.isSafeInteger(version.size) || version.size < 0) {
      throw new StoreError("invalid_app_version_metadata", 400);
    }
    const key = this.appVersionKey(platform, product, versionCode);
    const existing = this.state.appVersions[key];
    if (existing) {
      if (canonicalJson(existing) !== canonicalJson(version)) throw new StoreError("app_version_immutable_conflict", 409);
      return clone(existing);
    }
    this.state.appVersions[key] = version;
    this.save();
    return clone(version);
  }

  listAppVersions({ platform = "", product = "", limit = 100 } = {}) {
    const boundedLimit = Math.max(1, Math.min(200, Number(limit) || 100));
    return Object.values(this.state.appVersions || {})
      .filter((item) => !platform || item.platform === platform)
      .filter((item) => !product || item.product === product)
      .sort((a, b) => b.versionCode - a.versionCode)
      .slice(0, boundedLimit)
      .map(clone);
  }

  upsertErrorVersionLink({ errorId, platform, product, versionCode, relation, verified = false, note = "" }) {
    if (!ERROR_LINK_RELATIONS.has(relation)) throw new StoreError("invalid_error_version_relation", 400);
    const version = this.state.appVersions[this.appVersionKey(platform, product, versionCode)];
    if (!version) return null;
    const linkKey = `${errorId}:${platform}:${product}:${Number(versionCode)}:${relation}`;
    const existing = this.state.errorVersionLinks[linkKey];
    const link = existing || {
      linkKey, errorId, platform, product, versionCode: Number(versionCode), relation, createdAt: nowIso()
    };
    link.verified = Boolean(verified);
    link.note = redactText(note).slice(0, 2048);
    this.state.errorVersionLinks[linkKey] = link;
    return link;
  }

  createAppVersionChange(input = {}) {
    const platform = String(input.platform || "");
    const product = String(input.product || "");
    const versionCode = Number(input.version_code ?? input.versionCode);
    const version = this.state.appVersions[this.appVersionKey(platform, product, versionCode)];
    if (!version) throw new StoreError("app_version_not_found", 404);
    const changeType = String(input.change_type ?? input.changeType ?? "");
    if (!CHANGE_TYPES.has(changeType)) throw new StoreError("invalid_change_type", 400);
    const component = redactText(input.component || "").slice(0, 256);
    const changeKey = redactText(input.change_key ?? input.changeKey ?? "").slice(0, 512);
    const changeSummary = redactText(input.change_summary ?? input.changeSummary ?? "").slice(0, 4096);
    if (!component || !changeKey || !changeSummary) throw new StoreError("invalid_change_metadata", 400);
    const issueId = String(input.issue_id ?? input.issueId ?? "").slice(0, 128);
    const issue = issueId ? this.state.deviceErrors[issueId] : null;
    if (issueId && !issue) throw new StoreError("error_not_found", 404);
    if (issue && (issue.platform !== platform || issue.product !== product)) throw new StoreError("error_version_product_mismatch", 409);
    const now = nowIso();
    const change = {
      changeId: crypto.randomUUID(), platform, product, versionCode,
      previousVersionCode: input.previous_version_code == null && input.previousVersionCode == null
        ? null : Number(input.previous_version_code ?? input.previousVersionCode),
      changeType, component, changeKey, changeSummary, issueId,
      sourceRef: redactText(input.source_ref ?? input.sourceRef ?? "").slice(0, 512),
      isVerified: false, verificationNote: "", verifiedAt: null, createdAt: now
    };
    this.state.appVersionChanges[change.changeId] = change;
    if (issue) {
      this.upsertErrorVersionLink({
        errorId: issue.errorId, platform, product, versionCode,
        relation: changeType === "fixed" ? "fixed" : "observed",
        verified: false,
        note: `change_id=${change.changeId}`
      });
    }
    this.audit("admin", "admin", "app_version_change_created", change.changeId, { platform, product, versionCode, issueId: issueId || null });
    this.save();
    return clone(change);
  }

  verifyAppVersionChange(changeId, { verified, verificationNote } = {}) {
    const change = this.state.appVersionChanges[String(changeId || "")];
    if (!change) throw new StoreError("app_version_change_not_found", 404);
    const nextVerified = Boolean(verified);
    const note = redactText(verificationNote || "").slice(0, 4096);
    if (nextVerified && note.length < 8) throw new StoreError("verification_note_required", 400);
    change.isVerified = nextVerified;
    change.verificationNote = note;
    change.verifiedAt = nextVerified ? nowIso() : null;
    if (change.issueId && change.changeType === "fixed") {
      const linkKey = `${change.issueId}:${change.platform}:${change.product}:${change.versionCode}:fixed`;
      const link = this.state.errorVersionLinks[linkKey];
      if (link) {
        link.verified = nextVerified;
        link.note = `${note}${note ? " " : ""}change_id=${change.changeId}`.slice(0, 2048);
      }
    }
    this.audit("admin", "admin", "app_version_change_verified", change.changeId, { verified: nextVerified });
    this.save();
    return clone(change);
  }

  listAppVersionChanges({ platform, product, versionCode }) {
    return Object.values(this.state.appVersionChanges || {})
      .filter((item) => item.platform === platform && item.product === product && Number(item.versionCode) === Number(versionCode))
      .sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)))
      .map(clone);
  }

  recordDeviceErrors({ deviceId, payload = {}, requestId = null }) {
    const device = this.state.devices[deviceId];
    if (!device) throw new StoreError("device_not_found", 404);
    if (!Array.isArray(payload.errors) || payload.errors.length < 1 || payload.errors.length > 50) throw new StoreError("invalid_error_batch", 400);
    const platform = String(payload.platform || device.platform || "");
    const product = String(payload.product || (platform === "android" ? "cpsm-m" : "cpsm-c"));
    if (!["android", "windows"].includes(platform) || (platform === "android" && product !== "cpsm-m") || (platform === "windows" && product !== "cpsm-c")) throw new StoreError("invalid_error_product", 400);
    const appVersion = payload.app_version && typeof payload.app_version === "object" ? payload.app_version : {};
    const runtime = redactValue(payload.runtime && typeof payload.runtime === "object" ? payload.runtime : {});
    const versionCode = Number(appVersion.version_code ?? appVersion.versionCode ?? runtime.app_version_code ?? 0);
    const versionName = redactText(appVersion.version_name ?? appVersion.versionName ?? runtime.app_version_name ?? "").slice(0, 128);
    let accepted = 0;
    let deduplicated = 0;
    const acknowledgedErrorIds = [];
    const now = nowIso();
    for (const raw of payload.errors) {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new StoreError("invalid_error_record", 400);
      const clientErrorId = String(raw.error_id ?? raw.errorId ?? "").slice(0, 128);
      const errorCode = redactText(raw.error_code ?? raw.errorCode ?? "").slice(0, 128);
      const category = String(raw.category || "runtime");
      const severity = String(raw.severity || "error");
      const component = redactText(raw.component || "unknown").slice(0, 256);
      const operation = redactText(raw.operation || "unknown").slice(0, 256);
      const message = redactText(raw.message || errorCode).slice(0, 2048);
      if (!clientErrorId || !errorCode || !ERROR_CATEGORIES.has(category) || !ERROR_SEVERITIES.has(severity)) throw new StoreError("invalid_error_record", 400);
      const existingOccurrence = Object.values(this.state.errorOccurrences).find((item) => item.deviceId === deviceId && item.clientErrorId === clientErrorId);
      acknowledgedErrorIds.push(clientErrorId);
      if (existingOccurrence) {
        deduplicated += 1;
        continue;
      }
      const fingerprint = errorFingerprint({ product, errorCode, category, component, operation, message });
      let issue = Object.values(this.state.deviceErrors).find((item) => item.fingerprint === fingerprint);
      if (!issue) {
        issue = {
          errorId: crypto.randomUUID(), fingerprint, deviceId, platform, product,
          versionCode, versionName, errorCode, category, severity, component, operation,
          messageRedacted: message, firstSeenAt: now, lastSeenAt: now, occurrenceCount: 0,
          status: "new", isFixed: false, fixedInVersionCode: null, fixedAt: null,
          resolutionNote: "", createdAt: now, updatedAt: now
        };
        this.state.deviceErrors[issue.errorId] = issue;
      }
      issue.deviceId = issue.deviceId || deviceId;
      issue.lastSeenAt = now;
      issue.updatedAt = now;
      issue.occurrenceCount = Number(issue.occurrenceCount || 0) + 1;
      if (severityRank(severity) > severityRank(issue.severity)) issue.severity = severity;
      if (issue.isFixed) {
        issue.isFixed = false;
        issue.fixedAt = null;
        issue.status = "regressed";
        issue.resolutionNote = "A new occurrence was received after the issue was marked fixed.";
        this.upsertErrorVersionLink({ errorId: issue.errorId, platform, product, versionCode, relation: "regressed", verified: false, note: "new occurrence after resolved" });
      }
      const occurrence = {
        occurrenceId: crypto.randomUUID(), errorId: issue.errorId, clientErrorId, deviceId,
        requestId: String(raw.request_id ?? raw.requestId ?? requestId ?? "").slice(0, 256),
        correlationId: String(raw.correlation_id ?? raw.correlationId ?? "").slice(0, 256),
        occurredAt: String(raw.occurred_at ?? raw.occurredAt ?? now).slice(0, 64),
        runtime,
        context: redactValue(raw.context && typeof raw.context === "object" ? raw.context : {}),
        messageRedacted: message,
        stackTraceRedacted: redactText(raw.stack_trace ?? raw.stackTrace ?? "").slice(0, 16384),
        uploadStatus: "accepted", createdAt: now
      };
      this.state.errorOccurrences[occurrence.occurrenceId] = occurrence;
      const relation = issue.occurrenceCount === 1 ? "introduced" : "observed";
      this.upsertErrorVersionLink({ errorId: issue.errorId, platform, product, versionCode, relation, verified: false, note: `occurrence_id=${occurrence.occurrenceId}` });
      accepted += 1;
    }
    this.save();
    return { accepted, deduplicated, acknowledgedErrorIds };
  }

  listDeviceErrors({ status = "", product = "", limit = 100, cursor = "" } = {}) {
    const boundedLimit = Math.max(1, Math.min(100, Number(limit) || 100));
    const offset = Math.max(0, Number.isInteger(Number(cursor)) ? Number(cursor) : 0);
    const filtered = Object.values(this.state.deviceErrors || {})
      .filter((item) => !status || item.status === status)
      .filter((item) => !product || item.product === product)
      .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
    const page = filtered.slice(offset, offset + boundedLimit).map(clone);
    return { errors: page, nextCursor: offset + page.length < filtered.length ? String(offset + page.length) : null, total: filtered.length };
  }

  getDeviceError(errorId) {
    const issue = this.state.deviceErrors[String(errorId || "")];
    if (!issue) return null;
    return {
      ...clone(issue),
      occurrences: Object.values(this.state.errorOccurrences || {}).filter((item) => item.errorId === issue.errorId).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).slice(0, 100).map(clone),
      versionLinks: Object.values(this.state.errorVersionLinks || {}).filter((item) => item.errorId === issue.errorId).map(clone),
      changes: Object.values(this.state.appVersionChanges || {}).filter((item) => item.issueId === issue.errorId).map(clone)
    };
  }

  updateDeviceError(errorId, patch = {}) {
    const issue = this.state.deviceErrors[String(errorId || "")];
    if (!issue) throw new StoreError("error_not_found", 404);
    const nextStatus = patch.status == null ? issue.status : String(patch.status);
    if (!ERROR_STATUSES.has(nextStatus)) throw new StoreError("invalid_error_status", 400);
    const wantsFixed = patch.is_fixed == null ? issue.isFixed : Boolean(patch.is_fixed);
    const fixedVersionCode = patch.fixed_in_version_code == null && patch.fixedInVersionCode == null
      ? issue.fixedInVersionCode : Number(patch.fixed_in_version_code ?? patch.fixedInVersionCode);
    if (wantsFixed || nextStatus === "resolved") {
      const version = this.state.appVersions[this.appVersionKey(issue.platform, issue.product, fixedVersionCode)];
      const link = Object.values(this.state.errorVersionLinks || {}).find((item) => item.errorId === issue.errorId && item.platform === issue.platform && item.product === issue.product && Number(item.versionCode) === Number(fixedVersionCode) && item.relation === "fixed" && item.verified);
      if (!version || !link) throw new StoreError("error_fix_not_verified", 409);
    }
    issue.status = nextStatus;
    issue.isFixed = wantsFixed;
    issue.fixedInVersionCode = wantsFixed ? fixedVersionCode : null;
    issue.fixedAt = wantsFixed ? nowIso() : null;
    if (patch.resolution_note != null || patch.resolutionNote != null) issue.resolutionNote = redactText(patch.resolution_note ?? patch.resolutionNote).slice(0, 4096);
    issue.updatedAt = nowIso();
    this.audit("admin", "admin", "device_error_updated", issue.errorId, { status: issue.status, isFixed: issue.isFixed, fixedInVersionCode: issue.fixedInVersionCode });
    this.save();
    return this.getDeviceError(issue.errorId);
  }

  addEvents(deviceId, events) {
    if (!Array.isArray(events) || events.length > 100) {
      throw new StoreError("invalid_events", 400);
    }
    const device = this.state.devices[deviceId] || this.upsertDevice(deviceId, {});
    const known = new Set(this.state.events.filter((event) => event.deviceId === deviceId).map((event) => event.eventId));
    const stored = [];
    for (const event of events) {
      if (!event || typeof event !== "object" || Array.isArray(event)) {
        throw new StoreError("invalid_event", 400);
      }
      const eventId = String(event.eventId || event.id || "");
      if (!eventId || eventId.length > 256) {
        throw new StoreError("invalid_event_id", 400);
      }
      if (known.has(eventId)) {
        continue;
      }
      known.add(eventId);
      stored.push({
        id: crypto.randomUUID(),
        deviceId,
        eventId,
        sequence: event.sequence == null ? null : Number(event.sequence),
        type: String(event.type || "unknown").slice(0, 128),
        eventTime: event.eventTime || nowIso(),
        childName: device.childName,
        receivedAt: nowIso(),
        payload: event.payload && typeof event.payload === "object" ? event.payload : {}
      });
    }
    this.state.events.push(...stored);
    this.state.events = this.state.events.slice(-Number(process.env.CPSM_EVENT_RETENTION || 4000));
    this.save();
    return clone(stored);
  }

  familyIdForDevice(deviceId) {
    const registration = this.getRegistrationStatus(deviceId);
    const confirmed = registration.mappings.find((mapping) => mapping.status === "confirmed");
    return confirmed ? confirmed.familyId : null;
  }

  listGeofences(familyId) {
    const target = String(familyId || "");
    if (!target) return [];
    return Object.values(this.state.geofences || {})
      .filter((item) => item.familyId === target)
      .sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)) || a.geofenceId.localeCompare(b.geofenceId))
      .map(clone);
  }

  getGeofence(familyId, geofenceId) {
    const item = this.state.geofences[String(geofenceId || "")];
    return item && item.familyId === String(familyId || "") ? clone(item) : null;
  }

  upsertGeofence(input) {
    const familyId = String(input.familyId || "");
    if (!familyId || !this.state.families[familyId]) throw new StoreError("family_not_found", 404);
    const geofenceId = String(input.geofenceId || crypto.randomUUID()).slice(0, 128);
    const previous = this.state.geofences[geofenceId];
    if (previous && previous.familyId !== familyId) throw new StoreError("geofence_not_found", 404);
    const now = nowIso();
    const geofence = {
      geofenceId,
      familyId,
      name: String(input.name),
      latitude: Number(input.latitude),
      longitude: Number(input.longitude),
      radiusMeters: Number(input.radiusMeters),
      enabled: input.enabled !== false,
      createdByParentId: previous ? previous.createdByParentId : (input.parentId || null),
      createdAt: previous ? previous.createdAt : now,
      updatedAt: now
    };
    this.state.geofences[geofenceId] = geofence;
    if (previous && (previous.latitude !== geofence.latitude || previous.longitude !== geofence.longitude
        || previous.radiusMeters !== geofence.radiusMeters || previous.enabled !== geofence.enabled)) {
      for (const [key, state] of Object.entries(this.state.geofenceStates || {})) {
        if (state.geofenceId === geofenceId) delete this.state.geofenceStates[key];
      }
    }
    this.save();
    this.audit("parent", input.parentId || null, previous ? "geofence_updated" : "geofence_created", input.requestId || null, {
      familyId, geofenceId, radiusMeters: geofence.radiusMeters, enabled: geofence.enabled
    });
    return clone(geofence);
  }

  deleteGeofence(familyId, geofenceId, parentId = null, requestId = null) {
    const existing = this.state.geofences[String(geofenceId || "")];
    if (!existing || existing.familyId !== String(familyId || "")) return false;
    delete this.state.geofences[existing.geofenceId];
    for (const [key, state] of Object.entries(this.state.geofenceStates || {})) {
      if (state.geofenceId === existing.geofenceId) delete this.state.geofenceStates[key];
    }
    this.save();
    this.audit("parent", parentId, "geofence_deleted", requestId, { familyId: existing.familyId, geofenceId: existing.geofenceId });
    return true;
  }

  getLocationConsent(deviceId, familyId) {
    const existing = this.state.locationConsents[String(deviceId || "")];
    if (existing && existing.familyId === String(familyId || "")) return clone(existing);
    return {
      deviceId: String(deviceId || ""), familyId: String(familyId || ""),
      parentConsented: false, childConsented: false, permissionGranted: false,
      parentConsentedAt: null, childConsentedAt: null, updatedAt: null
    };
  }

  setLocationConsent({ deviceId, familyId, actorType, consent, permissionGranted = false, actorId = null, requestId = null }) {
    const targetDevice = String(deviceId || "");
    const targetFamily = String(familyId || "");
    if (!this.state.devices[targetDevice] || !targetFamily || this.familyIdForDevice(targetDevice) !== targetFamily) {
      throw new StoreError("device_not_found", 404);
    }
    if (!["parent", "child"].includes(actorType) || typeof consent !== "boolean") throw new StoreError("invalid_location_consent", 400);
    if (typeof permissionGranted !== "boolean") throw new StoreError("invalid_location_permission_state", 400);
    const current = this.getLocationConsent(targetDevice, targetFamily);
    const now = nowIso();
    if (actorType === "parent") {
      current.parentConsented = consent;
      current.parentConsentedAt = consent ? now : null;
    } else {
      current.childConsented = consent;
      current.permissionGranted = consent && permissionGranted;
      current.childConsentedAt = consent ? now : null;
    }
    current.updatedAt = now;
    this.state.locationConsents[targetDevice] = current;
    if (!current.parentConsented || !current.childConsented || !current.permissionGranted) {
      for (const request of Object.values(this.state.locationRequests || {})) {
        if (request.deviceId !== targetDevice || !["queued", "deferred"].includes(request.status)) continue;
        request.status = "cancelled";
        request.resultCode = "consent_or_permission_revoked";
        request.updatedAt = now;
        const command = this.state.commands.find((item) => item.id === request.commandId);
        if (command && !["succeeded", "failed", "expired"].includes(command.state)) {
          command.state = "expired";
          command.status = "expired";
          command.completedAt = now;
        }
      }
    }
    this.save();
    this.audit(actorType, actorId, "location_consent_updated", requestId, {
      deviceId: targetDevice, familyId: targetFamily, consent, permissionGranted: actorType === "child" && current.permissionGranted
    });
    return clone(current);
  }

  expireLocationRequests(now = Date.now()) {
    let changed = false;
    for (const request of Object.values(this.state.locationRequests || {})) {
      if (!["queued", "deferred"].includes(request.status) || Date.parse(request.expiresAt) > now) continue;
      request.status = "expired";
      request.resultCode = "request_expired";
      request.updatedAt = nowIso();
      const command = this.state.commands.find((item) => item.id === request.commandId);
      if (command && !["succeeded", "failed", "expired"].includes(command.state)) {
        command.state = "expired";
        command.status = "expired";
        command.completedAt = request.updatedAt;
      }
      changed = true;
    }
    return changed;
  }

  purgeLocationData(now = Date.now()) {
    const cutoff = now - this.locationRetentionDays * 24 * 60 * 60 * 1000;
    let changed = this.expireLocationRequests(now);
    for (const [key, sample] of Object.entries(this.state.locationSamples || {})) {
      if (Date.parse(sample.capturedAt) < cutoff) {
        delete this.state.locationSamples[key];
        changed = true;
      }
    }
    for (const [id, transition] of Object.entries(this.state.locationTransitions || {})) {
      if (Date.parse(transition.eventTime) < cutoff) {
        delete this.state.locationTransitions[id];
        changed = true;
      }
    }
    for (const [key, state] of Object.entries(this.state.geofenceStates || {})) {
      if (Date.parse(state.lastSampleAt) < cutoff) {
        delete this.state.geofenceStates[key];
        changed = true;
      }
    }
    for (const [id, request] of Object.entries(this.state.locationRequests || {})) {
      if (!["queued", "deferred"].includes(request.status) && Date.parse(request.createdAt) < cutoff) {
        delete this.state.locationRequests[id];
        changed = true;
      }
    }
    for (let index = (this.state.commands || []).length - 1; index >= 0; index -= 1) {
      const command = this.state.commands[index];
      if (command.type === "location.refresh" && Date.parse(command.createdAt) < cutoff) {
        this.state.commands.splice(index, 1);
        changed = true;
      }
    }
    if (this.sqlite && this.db) {
      const result = this.db.prepare("DELETE FROM audit_log WHERE action IN ('location_request_created', 'location_request_result', 'location_sample_received') AND created_at < ?")
        .run(new Date(cutoff).toISOString());
      if (Number(result.changes || 0) > 0) changed = true;
    }
    return changed;
  }

  createLocationRequest({ deviceId, familyId, parentId, expiryMs = 60 * 60 * 1000 }) {
    const targetDevice = String(deviceId || "");
    const targetFamily = String(familyId || "");
    const device = this.state.devices[targetDevice];
    if (!device || device.platform !== "android" || this.familyIdForDevice(targetDevice) !== targetFamily) {
      throw new StoreError("device_not_found", 404);
    }
    if (this.purgeLocationData()) this.save();
    const consent = this.getLocationConsent(targetDevice, targetFamily);
    if (!consent.parentConsented || !consent.childConsented) throw new StoreError("location_consent_required", 409);
    if (!consent.permissionGranted) throw new StoreError("location_permission_required", 409);
    const nowMs = Date.now();
    const active = Object.values(this.state.locationRequests || {}).find((item) => item.deviceId === targetDevice
      && ["queued", "deferred"].includes(item.status) && Date.parse(item.expiresAt) > nowMs);
    if (active) {
      const command = this.state.commands.find((item) => item.id === active.commandId);
      return { request: clone(active), command: clone(command || null), reused: true };
    }
    const createdAt = nowIso();
    const requestId = crypto.randomUUID();
    const commandId = crypto.randomUUID();
    const expiresAt = new Date(nowMs + Math.max(60_000, Math.min(60 * 60 * 1000, Number(expiryMs) || 15 * 60 * 1000))).toISOString();
    const request = {
      requestId, familyId: targetFamily, deviceId: targetDevice, parentId: String(parentId || ""),
      commandId, status: "queued", resultCode: "", sampleId: "", createdAt, expiresAt, updatedAt: createdAt
    };
    const command = {
      id: commandId, deviceId: targetDevice, type: "location.refresh",
      payload: { request_id: requestId, min_battery_percent: this.locationMinBatteryPercent, charging_override: true },
      state: "queued", status: "queued", ack: null, result: null, retryCount: 0,
      maxRetries: this.maxCommandRetries, idempotencyKey: `location-${requestId}`,
      leaseExpiresAt: null, expiresAt, createdAt, deliveredAt: null, completedAt: null
    };
    this.state.locationRequests[requestId] = request;
    this.state.commands.push(command);
    this.save();
    this.audit("parent", parentId, "location_request_created", requestId, {
      familyId: targetFamily, deviceId: targetDevice, commandId, minBatteryPercent: this.locationMinBatteryPercent
    });
    return { request: clone(request), command: clone(command), reused: false };
  }

  reportLocationRequestResult({ deviceId, requestId, status, code }) {
    const request = this.state.locationRequests[String(requestId || "")];
    if (!request || request.deviceId !== String(deviceId || "")) throw new StoreError("location_request_not_found", 404);
    if (!["deferred", "failed"].includes(status)) throw new StoreError("invalid_location_request_result", 400);
    if (!["low_battery", "permission_denied", "location_unavailable", "network_unavailable", "unsupported_location", "unknown"].includes(code)) {
      throw new StoreError("invalid_location_result_code", 400);
    }
    if (request.status === "deferred" && status === "deferred" && request.resultCode === code) return clone(request);
    if (!["queued", "deferred"].includes(request.status)) throw new StoreError("location_request_not_pending", 409);
    const now = Date.now();
    const command = this.state.commands.find((item) => item.id === request.commandId);
    request.resultCode = code;
    request.updatedAt = nowIso();
    if (status === "deferred" && Date.parse(request.expiresAt) > now && command) {
      // The command has been handled; the child schedules a battery/permission-constrained
      // local retry. Keep the request pending so an eventual one-shot sample can complete it.
      request.status = "deferred";
      command.state = "succeeded";
      command.status = "succeeded";
      command.ack = { ok: true, state: "location_capture_deferred", reason: code };
      command.result = { ok: true, state: "location_capture_deferred", reason: code };
      command.completedAt = request.updatedAt;
      command.leaseExpiresAt = null;
    } else {
      request.status = "failed";
      if (command) {
        command.state = "failed";
        command.status = "failed";
        command.result = { ok: false, error: code };
        command.completedAt = request.updatedAt;
      }
    }
    this.save();
    this.audit("device", deviceId, "location_request_result", requestId, { status: request.status, code });
    return clone(request);
  }

  recordLocationSample({ deviceId, sample }) {
    const targetDevice = String(deviceId || "");
    const request = this.state.locationRequests[String(sample.requestId || "")];
    if (!request || request.deviceId !== targetDevice) throw new StoreError("location_request_not_found", 404);
    const device = this.state.devices[targetDevice];
    if (!device || device.platform !== "android" || this.familyIdForDevice(targetDevice) !== request.familyId) {
      throw new StoreError("device_not_found", 404);
    }
    const consent = this.getLocationConsent(targetDevice, request.familyId);
    if (!consent.parentConsented || !consent.childConsented || !consent.permissionGranted) {
      throw new StoreError("location_consent_required", 403);
    }
    const key = `${targetDevice}:${sample.sampleId}`;
    const existing = this.state.locationSamples[key];
    if (existing) {
      if (existing.requestId !== request.requestId) throw new StoreError("location_sample_conflict", 409);
      return { sample: clone(existing), transitions: [], duplicate: true };
    }
    if (!["queued", "deferred"].includes(request.status)) throw new StoreError("location_request_not_pending", 409);
    const capturedMs = Date.parse(sample.capturedAt);
    const createdMs = Date.parse(request.createdAt);
    const expiresMs = Date.parse(request.expiresAt);
    const nowMs = Date.now();
    if (capturedMs < createdMs - 60_000 || capturedMs > expiresMs || capturedMs > nowMs + 60_000) {
      throw new StoreError("location_sample_outside_request_window", 400);
    }
    const receivedAt = nowIso();
    const stored = {
      ...clone(sample), deviceId: targetDevice, familyId: request.familyId, receivedAt
    };
    this.state.locationSamples[key] = stored;
    const transitions = [];
    for (const geofence of this.listGeofences(request.familyId).filter((item) => item.enabled)) {
      const classification = classifyGeofence(geofence, stored);
      if (classification.state === "uncertain") continue;
      const stateKey = `${targetDevice}:${geofence.geofenceId}`;
      const previous = this.state.geofenceStates[stateKey];
      if (previous && Date.parse(stored.capturedAt) <= Date.parse(previous.lastSampleAt)) continue;
      if (previous && previous.state !== classification.state) {
        const transition = {
          transitionId: crypto.randomUUID(), familyId: request.familyId, deviceId: targetDevice,
          geofenceId: geofence.geofenceId, geofenceName: geofence.name,
          type: classification.state === "inside" ? "enter" : "exit",
          eventTime: stored.capturedAt, sampleId: stored.sampleId,
          distanceMeters: classification.distanceMeters, accuracyMeters: stored.accuracyMeters, receivedAt
        };
        this.state.locationTransitions[transition.transitionId] = transition;
        transitions.push(clone(transition));
      }
      this.state.geofenceStates[stateKey] = {
        deviceId: targetDevice, geofenceId: geofence.geofenceId, state: classification.state,
        sampleId: stored.sampleId, lastSampleAt: stored.capturedAt,
        distanceMeters: classification.distanceMeters, accuracyMeters: stored.accuracyMeters
      };
    }
    request.status = "captured";
    request.resultCode = "captured";
    request.sampleId = stored.sampleId;
    request.updatedAt = receivedAt;
    const command = this.state.commands.find((item) => item.id === request.commandId);
    if (command) {
      command.state = "succeeded";
      command.status = "succeeded";
      command.ack = { ok: true, state: "location_uploaded" };
      command.result = { ok: true, state: "location_uploaded", sample_id: stored.sampleId };
      command.completedAt = receivedAt;
      command.leaseExpiresAt = null;
    }
    this.purgeLocationData(nowMs);
    this.save();
    this.audit("device", targetDevice, "location_sample_received", request.requestId, {
      sampleId: stored.sampleId, capturedAt: stored.capturedAt, accuracyMeters: stored.accuracyMeters,
      provider: stored.provider, batteryPercent: stored.batteryPercent, transitionCount: transitions.length
    });
    return { sample: clone(stored), transitions, duplicate: false };
  }

  listLocationTimeline(deviceId, familyId, limit = 100) {
    const targetDevice = String(deviceId || "");
    const targetFamily = String(familyId || "");
    if (!targetDevice || !targetFamily || this.familyIdForDevice(targetDevice) !== targetFamily) {
      throw new StoreError("device_not_found", 404);
    }
    if (this.purgeLocationData()) this.save();
    const samples = Object.values(this.state.locationSamples || {})
      .filter((item) => item.deviceId === targetDevice && item.familyId === targetFamily)
      .sort((a, b) => Date.parse(b.capturedAt) - Date.parse(a.capturedAt))
      .slice(0, Math.max(1, Math.min(500, Number(limit) || 100)));
    const transitions = Object.values(this.state.locationTransitions || {})
      .filter((item) => item.deviceId === targetDevice && item.familyId === targetFamily)
      .sort((a, b) => Date.parse(b.eventTime) - Date.parse(a.eventTime))
      .slice(0, Math.max(1, Math.min(500, Number(limit) || 100)));
    const requests = Object.values(this.state.locationRequests || {})
      .filter((item) => item.deviceId === targetDevice && item.familyId === targetFamily)
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
      .slice(0, 5);
    return { samples: clone(samples), transitions: clone(transitions), requests: clone(requests), retentionDays: this.locationRetentionDays };
  }

  familyDeviceIds(familyId) {
    const target = String(familyId || "");
    if (!target) return [];
    const ids = new Set();
    for (const mapping of Object.values(this.state.parentChildMappings || {})) {
      if (mapping.familyId !== target || mapping.status !== "confirmed") continue;
      const child = this.state.childProfiles[mapping.childId];
      if (child && child.deviceId && this.state.devices[child.deviceId]) ids.add(child.deviceId);
    }
    return [...ids];
  }

  dashboardForFamily(familyId) {
    const deviceIds = new Set(this.familyDeviceIds(familyId));
    const familyPolicy = this.getFamilyPolicy(familyId);
    const policy = familyPolicy && familyPolicy.policy ? familyPolicy.policy : { rules: [] };
    return {
      policy: clone(policy),
      devices: [...deviceIds].map((deviceId) => clone(this.state.devices[deviceId])),
      pendingRequests: clone(this.state.approvalRequests.filter((request) => request.status === "pending" && deviceIds.has(request.deviceId)).slice(-50).reverse()),
      recentEvents: clone(this.state.events.filter((event) => deviceIds.has(event.deviceId)).slice(-100).reverse()),
      blockedApps: clone(policy.rules || [])
    };
  }

  dashboard() {
    const pendingRequests = this.state.approvalRequests.filter((request) => request.status === "pending").slice(-50).reverse();
    return {
      policy: clone(this.state.policy),
      devices: Object.values(this.state.devices).map(clone),
      pendingRequests: clone(pendingRequests),
      recentEvents: clone(this.state.events.slice(-100).reverse()),
      blockedApps: clone(this.state.policy.rules)
    };
  }

  createApprovalRequest(deviceId, event) {
    const device = this.state.devices[deviceId] || this.upsertDevice(deviceId, {});
    const request = {
      id: crypto.randomUUID(),
      status: "pending",
      deviceId,
      childName: device.childName,
      deviceName: device.deviceName,
      appName: String(event.payload && event.payload.appName || "unknown").slice(0, 256),
      executablePath: String(event.payload && event.payload.executablePath || "").slice(0, 2048),
      pid: event.payload && event.payload.pid != null ? Number(event.payload.pid) : null,
      eventId: event.eventId || event.id,
      kind: event.type === "time_request" ? "screen_time" : "app_launch",
      requestedMinutes: event.type === "time_request"
        ? Math.min(240, Math.max(1, Number(event.payload && event.payload.minutes) || 30)) : null,
      createdAt: nowIso(),
      decidedAt: null,
      decision: null
    };
    this.state.approvalRequests.push(request);
    this.save();
    return clone(request);
  }

  pendingRequestForPid(deviceId, pid) {
    return this.state.approvalRequests.find((request) => request.deviceId === deviceId && request.pid === pid && request.status === "pending");
  }

  decideApprovalRequest(requestId, decision) {
    const request = this.state.approvalRequests.find((item) => item.id === requestId);
    if (!request) {
      return null;
    }
    if (request.status !== "pending") {
      throw new StoreError("approval_already_decided", 409);
    }
    request.status = "decided";
    request.decision = decision;
    request.decidedAt = nowIso();
    this.audit("parent", "parent", "approval_decided", requestId, { decision });
    this.save();
    return clone(request);
  }

  queueCommand(deviceId, type, payload = {}, options = {}) {
    const idempotencyKey = options.idempotencyKey || payload.requestId || null;
    if (idempotencyKey) {
      const existing = this.state.commands.find((command) => command.deviceId === deviceId && command.idempotencyKey === idempotencyKey);
      if (existing) {
        return clone(existing);
      }
    }
    const command = {
      id: crypto.randomUUID(),
      deviceId,
      type,
      payload: clone(payload),
      state: "queued",
      status: "queued",
      ack: null,
      result: null,
      retryCount: 0,
      maxRetries: Number(options.maxRetries || this.maxCommandRetries),
      idempotencyKey,
      leaseExpiresAt: null,
      expiresAt: new Date(Date.now() + Number(options.expiryMs || 600000)).toISOString(),
      createdAt: nowIso(),
      deliveredAt: null,
      completedAt: null
    };
    this.state.commands.push(command);
    this.save();
    return clone(command);
  }

  expireAndRequeueCommands(now = Date.now()) {
    let changed = false;
    for (const command of this.state.commands) {
      if (["succeeded", "failed", "expired"].includes(command.state)) {
        continue;
      }
      if (command.expiresAt && Date.parse(command.expiresAt) <= now) {
        command.state = "expired";
        command.status = "expired";
        changed = true;
        continue;
      }
      if (command.state === "delivered" && command.leaseExpiresAt && Date.parse(command.leaseExpiresAt) <= now) {
        if (command.retryCount >= command.maxRetries) {
          command.state = "failed";
          command.status = "failed";
          command.ack = { ok: false, error: "lease_expired" };
          command.completedAt = nowIso();
        } else {
          command.state = "queued";
          command.status = "queued";
          command.retryCount += 1;
          command.leaseExpiresAt = null;
        }
        changed = true;
      }
    }
    return changed;
  }

  pollCommands(deviceId, limit = 20, leaseMs = Number(process.env.CPSM_COMMAND_LEASE_MS || 30000)) {
    const changed = this.expireAndRequeueCommands(Date.now());
    const commands = this.state.commands.filter((command) => command.deviceId === deviceId && command.state === "queued").slice(0, Math.max(1, Math.min(100, limit)));
    const leaseExpiresAt = new Date(Date.now() + leaseMs).toISOString();
    for (const command of commands) {
      command.state = "delivered";
      command.status = "delivered";
      command.deliveredAt = nowIso();
      command.leaseExpiresAt = leaseExpiresAt;
    }
    if (changed || commands.length) {
      this.save();
    }
    return clone(commands);
  }

  completeCommand(deviceId, commandId, result) {
    const command = this.state.commands.find((item) => item.deviceId === deviceId && item.id === commandId);
    if (!command) {
      return null;
    }
    if (["succeeded", "failed", "expired"].includes(command.state)) {
      return clone(command);
    }
    const safeResult = result && typeof result === "object" ? clone(result) : { ok: false, error: "invalid_result" };
    command.ack = { ok: true, receivedAt: nowIso() };
    command.result = safeResult;
    command.state = safeResult.ack === true && safeResult.ok == null ? "acked" : (safeResult.ok ? "succeeded" : "failed");
    command.status = command.state;
    command.completedAt = nowIso();
    command.leaseExpiresAt = null;
    this.save();
    return clone(command);
  }

  setBlockedApp(rule) {
    const existing = this.state.blockedApps.find((item) => item.id === rule.id);
    if (existing) Object.assign(existing, rule); else this.state.blockedApps.push(rule);
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
    if (existing) Object.assign(existing, rule); else this.state.policy.rules.push(rule);
    this.bumpPolicyVersion();
  }

  replacePolicyRules(rules) {
    this.state.policy.rules = clone(rules);
    this.state.blockedApps = clone(rules);
    this.bumpPolicyVersion();
  }

  getFamilyPolicy(familyId) {
    const family = this.state.familyPolicies[String(familyId || "")];
    return family ? clone(family) : null;
  }

  // screenTime === undefined keeps the current value so rule-only clients cannot erase it.
  replaceFamilyPolicyRules(familyId, rules, screenTime = undefined) {
    const family = this.ensureFamily(familyId, "CPSM Family");
    const current = this.state.familyPolicies[family.familyId] || { version: 0, policy: {} };
    const nextVersion = Number(current.version || 0) + 1;
    const now = nowIso();
    const nextScreenTime = screenTime === undefined ? (current.policy && current.policy.screenTime) || null : screenTime;
    this.state.familyPolicies[family.familyId] = {
      familyId: family.familyId,
      version: nextVersion,
      policy: {
        policyId: `family-policy-${family.familyId}`,
        version: nextVersion,
        updatedAt: now,
        expiresAt: new Date(Date.now() + this.policyTtlMs).toISOString(),
        rules: clone(rules),
        ...(nextScreenTime ? { screenTime: clone(nextScreenTime) } : {})
      },
      source: "parent",
      updatedAt: now
    };
    for (const mapping of Object.values(this.state.parentChildMappings || {})) {
      if (mapping.familyId === family.familyId && mapping.status === "confirmed") this.ensurePolicyAssignmentForChild(mapping.childId, family.familyId);
    }
    this.save();
    return clone(this.state.familyPolicies[family.familyId]);
  }

  bumpPolicyVersion() {
    this.state.policy.version = Number(this.state.policy.version || 0) + 1;
    this.state.policy.updatedAt = nowIso();
    this.state.policy.expiresAt = new Date(Date.now() + this.policyTtlMs).toISOString();
    this.ensurePolicy();
    this.save();
  }

  getSignedPolicy(deviceId) {
    const device = this.state.devices[deviceId] || {};
    const platform = device.platform || "windows";
    const registration = this.getRegistrationStatus(deviceId);
    const confirmed = registration.mappings.find((mapping) => mapping.status === "confirmed");
    const selectedFamilyPolicy = confirmed ? this.state.familyPolicies[confirmed.familyId] : null;
    const source = selectedFamilyPolicy && selectedFamilyPolicy.policy ? selectedFamilyPolicy.policy : this.state.policy;
    const rules = (source.rules || [])
      .filter((rule) => !rule.platform || rule.platform === platform)
      .filter((rule) => !rule.excludedUntil || Date.parse(rule.excludedUntil) < Date.now())
      .map((rule) => ({
        id: rule.id,
        platform: rule.platform,
        name: rule.name,
        match: rule.match,
        action: rule.action || "block",
        reason: rule.reason || "parent_rule",
        ...(Number(rule.dailyLimitMinutes || 0) > 0 ? { dailyLimitMinutes: Number(rule.dailyLimitMinutes) } : {})
      }));
    const screenTime = selectedFamilyPolicy ? screenTimeForPlatform(source.screenTime, platform) : null;
    const payload = {
      policyId: source.policyId || this.state.policy.policyId,
      version: Number(source.version || selectedFamilyPolicy?.version || this.state.policy.version),
      timezone: "Asia/Seoul",
      enforcementMode: "enforce",
      appRules: rules,
      ...(screenTime ? { schemaVersion: 2, screenTime } : {}),
      expiresAt: source.expiresAt || this.state.policy.expiresAt
    };
    const canonicalHash = crypto.createHash("sha256").update(canonicalJson(payload)).digest("hex");
    return {
      ...payload,
      canonicalHash,
      canonical_hash: canonicalHash,
      signatureAlgorithm: "Ed25519",
      signature_algorithm: "Ed25519",
      signatureMetadata: { algorithm: "Ed25519", keyId: this.keyId },
      signature_metadata: { algorithm: "Ed25519", keyId: this.keyId },
      signature: this.signDocument(payload),
      keyId: this.keyId,
      key_id: this.keyId
    };
  }
}

module.exports = {
  Store,
  StoreError,
  atomicWriteJson,
  canonicalJson,
  ensureDir
};
