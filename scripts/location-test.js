"use strict";

const assert = require("assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Store } = require("../src/store");
const { LocationError, sanitizeGeofence, sanitizeLocationConsent, sanitizeLocationSample, distanceMeters } = require("../src/location");

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "cpsm-location-"));
let store = null;

function expectCode(fn, code) {
  assert.throws(fn, (error) => error instanceof LocationError && error.code === code);
}

try {
  const minimum = sanitizeGeofence({ name: " 집 ", latitude: 37.5, longitude: 127, radius_m: 1000 });
  assert.deepEqual(minimum, { name: "집", latitude: 37.5, longitude: 127, radiusMeters: 1000, enabled: true });
  const maximum = sanitizeGeofence({ name: "학교", latitude: -90, longitude: 180, radius_m: 20000, enabled: false });
  assert.equal(maximum.radiusMeters, 20000);
  assert.equal(maximum.enabled, false);
  expectCode(() => sanitizeGeofence({ name: "집", latitude: 0, longitude: 0, radius_m: 999 }), "invalid_geofence_radius");
  expectCode(() => sanitizeGeofence({ name: "집", latitude: 0, longitude: 0, radius_m: 20001 }), "invalid_geofence_radius");
  expectCode(() => sanitizeGeofence({ name: "집", latitude: "37.5", longitude: 0, radius_m: 1000 }), "invalid_geofence_latitude");
  expectCode(() => sanitizeGeofence({ name: "집", latitude: 91, longitude: 0, radius_m: 1000 }), "invalid_geofence_latitude");
  expectCode(() => sanitizeGeofence({ name: "집", latitude: 0, longitude: 181, radius_m: 1000 }), "invalid_geofence_longitude");
  expectCode(() => sanitizeGeofence({ name: " ", latitude: 0, longitude: 0, radius_m: 1000 }), "invalid_geofence_name");
  assert.deepEqual(sanitizeLocationConsent({ consent: true, permission_granted: true }), { consent: true, permissionGranted: true });
  expectCode(() => sanitizeLocationConsent({ consent: "yes" }), "invalid_location_consent");
  const sample = sanitizeLocationSample({ sample_id: "sample-1", request_id: "request-1", captured_at: new Date().toISOString(), latitude: 37.5, longitude: 127, accuracy_m: 12, provider: "gps", battery_pct: 80, charging: false });
  assert.equal(sample.sampleId, "sample-1");
  assert(distanceMeters(37.5, 127, 37.52, 127) > 2000, "circle distance calculation");
  expectCode(() => sanitizeLocationSample({ sample_id: "sample-2", request_id: "request-2", captured_at: sample.capturedAt, latitude: sample.latitude, longitude: sample.longitude, accuracy_m: sample.accuracyMeters, provider: sample.provider, battery_pct: 101, charging: false }), "invalid_location_battery");

  store = new Store(dataDir);
  assert.equal(store.storageMode(), "sqlite", "test requires SQLite persistence");
  assert.equal(store.locationRetentionDays, 30, "default location retention is 30 days");
  assert.equal(store.locationMinBatteryPercent, 30, "default location battery threshold is 30 percent");
  const timestamp = new Date().toISOString();
  store.state.families["family-test"] = {
    familyId: "family-test", name: "test", status: "active", createdAt: timestamp, updatedAt: timestamp
  };
  store.save();
  const created = store.upsertGeofence({
    familyId: "family-test", parentId: "parent-test", ...minimum
  });
  assert.equal(store.listGeofences("family-test").length, 1);
  store.db.close();
  store = new Store(dataDir);
  const reloaded = store.getGeofence("family-test", created.geofenceId);
  assert.deepEqual(reloaded, created, "geofence survives SQLite reload");
  assert.equal(store.listGeofences("other-family").length, 0, "family filter is strict");
  assert.equal(store.deleteGeofence("other-family", created.geofenceId), false, "foreign family cannot delete row");
  assert.equal(store.deleteGeofence("family-test", created.geofenceId, "parent-test"), true);
  assert.equal(store.listGeofences("family-test").length, 0);

  const deviceId = "android-location-test";
  store.state.devices[deviceId] = { deviceId, platform: "android", childName: "자녀", deviceName: "test-phone", status: "running", currentApp: "", localPolicyVersion: 1, lastEventSeq: 0, lastSeenAt: timestamp, metadata: {} };
  store.state.childProfiles["child-location-test"] = { childId: "child-location-test", deviceId, displayName: "자녀", status: "active", createdAt: timestamp, updatedAt: timestamp };
  store.state.parentChildMappings["mapping-location-test"] = { mappingId: "mapping-location-test", familyId: "family-test", parentId: "parent-test", childId: "child-location-test", status: "confirmed", parentConsent: true, childConsent: true, createdAt: timestamp, updatedAt: timestamp, confirmedAt: timestamp };
  store.save();
  store.setLocationConsent({ deviceId, familyId: "family-test", actorType: "parent", consent: true, actorId: "parent-test" });
  store.setLocationConsent({ deviceId, familyId: "family-test", actorType: "child", consent: true, permissionGranted: true, actorId: deviceId });
  const zone = store.upsertGeofence({ familyId: "family-test", parentId: "parent-test", name: "집", latitude: 37.5, longitude: 127, radiusMeters: 1000, enabled: true });
  const addSample = (lat, capturedAt, suffix) => {
    const pending = store.createLocationRequest({ deviceId, familyId: "family-test", parentId: "parent-test" });
    assert.equal(pending.command.payload.min_battery_percent, 30, "location request carries 30% default battery threshold");
    assert.equal(pending.command.payload.charging_override, true, "charging bypasses the low-battery gate");
    const sampleValue = { sampleId: `sample-${suffix}`, requestId: pending.request.requestId, capturedAt: new Date(capturedAt).toISOString(), latitude: lat, longitude: 127, accuracyMeters: 10, provider: "gps", batteryPercent: 80, charging: false };
    return store.recordLocationSample({ deviceId, sample: sampleValue });
  };
  const sampleBase = Date.now();
  assert.equal(addSample(37.5, sampleBase, "inside-1").transitions.length, 0, "first sample establishes geofence baseline only");
  const exit = addSample(37.52, Date.now() + 1000, "outside");
  assert.equal(exit.transitions[0].type, "exit", "outside sample creates exit transition");
  const enter = addSample(37.5, Date.now() + 2000, "inside-2");
  assert.equal(enter.transitions[0].type, "enter", "inside sample creates enter transition");
  assert.equal(store.recordLocationSample({ deviceId, sample: { ...enter.sample, receivedAt: undefined } }).duplicate, true, "sample retry is idempotent");
  store.db.close();
  store = new Store(dataDir);
  const staleAt = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
  store.state.locationSamples[`${deviceId}:stale-sample`] = {
    sampleId: "stale-sample", requestId: "old-request", deviceId, familyId: "family-test",
    capturedAt: staleAt, receivedAt: staleAt, latitude: 37.5, longitude: 127,
    accuracyMeters: 10, provider: "gps", batteryPercent: 50, charging: false
  };
  store.state.locationTransitions["stale-transition"] = {
    transitionId: "stale-transition", deviceId, familyId: "family-test", geofenceId: zone.geofenceId,
    type: "exit", eventTime: staleAt, receivedAt: staleAt
  };
  store.state.commands.push({ id: "stale-location-command", deviceId, type: "location.refresh", createdAt: staleAt });
  store.db.prepare("INSERT INTO audit_log (id, actor_type, actor_id, action, request_id, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run("stale-location-audit", "device", deviceId, "location_sample_received", "old-request", "{}", staleAt);
  assert.equal(store.purgeLocationData(), true, "30-day retention removes expired location rows");
  assert.equal(store.state.locationSamples[`${deviceId}:stale-sample`], undefined);
  assert.equal(store.state.locationTransitions["stale-transition"], undefined);
  assert.equal(store.state.commands.some((item) => item.id === "stale-location-command"), false);
  assert.equal(store.db.prepare("SELECT COUNT(*) AS count FROM audit_log WHERE id = ?").get("stale-location-audit").count, 0);
  store.save();
  const timeline = store.listLocationTimeline(deviceId, "family-test", 10);
  assert.equal(timeline.samples.length, 3, "location sample history survives reload");
  assert.deepEqual(timeline.transitions.map((item) => item.type).sort(), ["enter", "exit"], "transition history survives reload");
  assert.equal(store.getLocationConsent(deviceId, "family-test").childConsented, true, "location consent survives reload");
  store.setLocationConsent({ deviceId, familyId: "family-test", actorType: "child", consent: false, actorId: deviceId });
  assert.throws(() => store.createLocationRequest({ deviceId, familyId: "family-test", parentId: "parent-test" }), (error) => error.code === "location_consent_required");
  assert.equal(store.getGeofence("family-test", zone.geofenceId).name, "집");
  store.db.close();
  store = null;
  console.log(JSON.stringify({ ok: true, storage: "sqlite", boundaryValidation: "passed", persistence: "roundtrip", familyScope: "isolated" }));
} finally {
  if (store && store.db) store.db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
}
