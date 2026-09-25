"use strict";

// Screen-time policy (policy schema v2). The server owns validation so that both
// agents receive the same bounded, signed document; agents re-validate locally.

class ScreenTimeError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
    this.status = 400;
  }
}

const TIME_PATTERN = /^([01]\d|2[0-3]):([0-5]\d)$/;
const ANDROID_PACKAGE = /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/;
const WINDOWS_PROCESS = /^[A-Za-z0-9 ._()+-]{1,128}$/;

// Emergency/communication apps stay usable during lock unless the parent removes them.
const DEFAULT_ALWAYS_ALLOWED = {
  android: [
    "com.android.dialer",
    "com.samsung.android.dialer",
    "com.google.android.dialer",
    "com.android.phone",
    "com.android.emergency",
    "com.samsung.android.emergency"
  ],
  windows: []
};

const COMMAND_TYPES = new Set(["device.lock", "device.unlock", "screen_time.bonus", "sync_now"]);

function intInRange(value, min, max, code) {
  if (value === undefined || value === null || value === "") return min;
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) throw new ScreenTimeError(code);
  return number;
}

function sanitizeDowntime(list) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list) || list.length > 14) throw new ScreenTimeError("invalid_downtime");
  return list.map((window) => {
    if (!window || typeof window !== "object") throw new ScreenTimeError("invalid_downtime");
    const start = String(window.start || "");
    const end = String(window.end || "");
    if (!TIME_PATTERN.test(start) || !TIME_PATTERN.test(end) || start === end) {
      throw new ScreenTimeError("invalid_downtime_time");
    }
    const days = Array.isArray(window.days) && window.days.length ? window.days : [1, 2, 3, 4, 5, 6, 7];
    const cleanDays = [...new Set(days.map(Number))].sort((a, b) => a - b);
    if (cleanDays.some((day) => !Number.isInteger(day) || day < 1 || day > 7)) {
      throw new ScreenTimeError("invalid_downtime_days");
    }
    return { days: cleanDays, start, end };
  });
}

function sanitizeAllowed(value, pattern, code) {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value) || value.length > 100) throw new ScreenTimeError(code);
  const clean = [...new Set(value.map((item) => String(item || "").trim()).filter(Boolean))];
  if (clean.some((item) => !pattern.test(item))) throw new ScreenTimeError(code);
  return clean.sort();
}

function sanitizeScreenTime(input) {
  if (input === undefined) return undefined;
  if (input === null) return null;
  if (typeof input !== "object" || Array.isArray(input)) throw new ScreenTimeError("invalid_screen_time");
  const allowed = input.alwaysAllowed && typeof input.alwaysAllowed === "object" ? input.alwaysAllowed : {};
  return {
    dailyLimitMinutes: intInRange(input.dailyLimitMinutes, 0, 1440, "invalid_daily_limit"),
    downtime: sanitizeDowntime(input.downtime),
    alwaysAllowed: {
      android: sanitizeAllowed(allowed.android, ANDROID_PACKAGE, "invalid_always_allowed_android")
        || DEFAULT_ALWAYS_ALLOWED.android.slice(),
      windows: sanitizeAllowed(allowed.windows, WINDOWS_PROCESS, "invalid_always_allowed_windows")
        || DEFAULT_ALWAYS_ALLOWED.windows.slice()
    },
    // Fail-closed boot: agents lock until the last-known-good policy is evaluated.
    bootGuard: input.bootGuard !== false,
    message: String(input.message || "").slice(0, 120)
  };
}

// The per-device signed view carries only the device platform's allowlist.
function screenTimeForPlatform(screenTime, platform) {
  if (!screenTime) return null;
  const allowed = (screenTime.alwaysAllowed && screenTime.alwaysAllowed[platform]) || [];
  return {
    dailyLimitMinutes: Number(screenTime.dailyLimitMinutes || 0),
    downtime: (screenTime.downtime || []).map((window) => ({ days: window.days.slice(), start: window.start, end: window.end })),
    alwaysAllowed: allowed.slice(),
    bootGuard: screenTime.bootGuard !== false,
    message: String(screenTime.message || "")
  };
}

function sanitizeDeviceCommand(input) {
  const type = String(input && input.type || "");
  if (!COMMAND_TYPES.has(type)) throw new ScreenTimeError("unsupported_command_type");
  const payload = {};
  if (type === "device.lock") {
    // 0 means "until the parent unlocks".
    payload.minutes = intInRange(input.minutes, 0, 1440, "invalid_lock_minutes");
  }
  if (type === "screen_time.bonus") {
    payload.minutes = intInRange(input.minutes, 1, 240, "invalid_bonus_minutes");
  }
  if (input && input.reason) payload.reason = String(input.reason).slice(0, 120);
  return { type, payload };
}

module.exports = {
  DEFAULT_ALWAYS_ALLOWED,
  ScreenTimeError,
  sanitizeDeviceCommand,
  sanitizeScreenTime,
  screenTimeForPlatform
};
