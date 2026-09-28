"use strict";

class LocationError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.name = "LocationError";
    this.code = code;
    this.status = status;
    this.expose = true;
  }
}

function finiteNumber(value, code, min, max) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max) {
    throw new LocationError(code, 400);
  }
  return value;
}

function sanitizeGeofence(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new LocationError("invalid_geofence", 400);
  }
  if (typeof input.name !== "string") throw new LocationError("invalid_geofence_name", 400);
  const name = input.name.trim();
  if (!name || name.length > 80) throw new LocationError("invalid_geofence_name", 400);
  const latitude = finiteNumber(input.latitude, "invalid_geofence_latitude", -90, 90);
  const longitude = finiteNumber(input.longitude, "invalid_geofence_longitude", -180, 180);
  const radiusMeters = input.radius_m;
  if (!Number.isInteger(radiusMeters) || radiusMeters < 1000 || radiusMeters > 20000) {
    throw new LocationError("invalid_geofence_radius", 400);
  }
  const enabled = input.enabled === undefined ? true : input.enabled;
  if (typeof enabled !== "boolean") throw new LocationError("invalid_geofence_enabled", 400);
  return { name, latitude, longitude, radiusMeters, enabled };
}

const LOCATION_PROVIDERS = new Set(["gps", "network", "fused", "passive", "unknown"]);

function sanitizeLocationConsent(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)
      || typeof input.consent !== "boolean") {
    throw new LocationError("invalid_location_consent", 400);
  }
  const permissionGranted = input.permission_granted === undefined ? false : input.permission_granted;
  if (typeof permissionGranted !== "boolean") throw new LocationError("invalid_location_permission_state", 400);
  return { consent: input.consent, permissionGranted };
}

function sanitizeLocationSample(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new LocationError("invalid_location_sample", 400);
  const sampleId = typeof input.sample_id === "string" ? input.sample_id.trim() : "";
  const requestId = typeof input.request_id === "string" ? input.request_id.trim() : "";
  if (!sampleId || sampleId.length > 128) throw new LocationError("invalid_location_sample_id", 400);
  if (!requestId || requestId.length > 128) throw new LocationError("invalid_location_request_id", 400);
  if (typeof input.captured_at !== "string" || !Number.isFinite(Date.parse(input.captured_at))) {
    throw new LocationError("invalid_location_timestamp", 400);
  }
  const latitude = finiteNumber(input.latitude, "invalid_location_latitude", -90, 90);
  const longitude = finiteNumber(input.longitude, "invalid_location_longitude", -180, 180);
  const accuracyMeters = finiteNumber(input.accuracy_m, "invalid_location_accuracy", 1, 10000);
  const batteryPercent = input.battery_pct;
  if (!Number.isInteger(batteryPercent) || batteryPercent < 0 || batteryPercent > 100) {
    throw new LocationError("invalid_location_battery", 400);
  }
  if (typeof input.charging !== "boolean") throw new LocationError("invalid_location_charging_state", 400);
  const provider = typeof input.provider === "string" ? input.provider : "unknown";
  if (!LOCATION_PROVIDERS.has(provider)) throw new LocationError("invalid_location_provider", 400);
  return {
    sampleId,
    requestId,
    capturedAt: new Date(Date.parse(input.captured_at)).toISOString(),
    latitude,
    longitude,
    accuracyMeters,
    provider,
    batteryPercent,
    charging: input.charging
  };
}

function distanceMeters(aLatitude, aLongitude, bLatitude, bLongitude) {
  const toRadians = (degrees) => degrees * Math.PI / 180;
  const earthRadiusMeters = 6371008.8;
  const lat1 = toRadians(aLatitude);
  const lat2 = toRadians(bLatitude);
  const deltaLat = toRadians(bLatitude - aLatitude);
  const deltaLon = toRadians(bLongitude - aLongitude);
  const haversine = Math.sin(deltaLat / 2) ** 2
    + Math.cos(lat1) * Math.cos(lat2) * Math.sin(deltaLon / 2) ** 2;
  return 2 * earthRadiusMeters * Math.asin(Math.sqrt(Math.min(1, haversine)));
}

function classifyGeofence(geofence, sample) {
  const distance = distanceMeters(geofence.latitude, geofence.longitude, sample.latitude, sample.longitude);
  if (distance + sample.accuracyMeters <= geofence.radiusMeters) return { state: "inside", distanceMeters: distance };
  if (distance - sample.accuracyMeters > geofence.radiusMeters) return { state: "outside", distanceMeters: distance };
  return { state: "uncertain", distanceMeters: distance };
}

module.exports = {
  LocationError,
  sanitizeGeofence,
  sanitizeLocationConsent,
  sanitizeLocationSample,
  distanceMeters,
  classifyGeofence
};
