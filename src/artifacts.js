const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

class ArtifactError extends Error {
  constructor(code, status = 404) {
    super(code);
    this.name = "ArtifactError";
    this.code = code;
    this.status = status;
  }
}

const PLATFORM_PATTERN = /^(android|windows)$/;
const PRODUCT_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const FILE_PATTERN = /^[A-Za-z0-9._-]{1,160}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/i;

function productDirectory(root, platform, product) {
  if (!PLATFORM_PATTERN.test(platform) || !PRODUCT_PATTERN.test(product)) {
    throw new ArtifactError("invalid_artifact_selector", 400);
  }
  return path.join(root, platform, product);
}

function validateManifest(value, platform, product) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ArtifactError("invalid_artifact_manifest", 500);
  }
  if (value.platform !== platform || value.product !== product) {
    throw new ArtifactError("artifact_manifest_mismatch", 500);
  }
  if (!FILE_PATTERN.test(String(value.artifact || ""))) {
    throw new ArtifactError("invalid_artifact_filename", 500);
  }
  if (!SHA256_PATTERN.test(String(value.sha256 || ""))) {
    throw new ArtifactError("invalid_artifact_hash", 500);
  }
  if (!Number.isSafeInteger(Number(value.size)) || Number(value.size) < 1) {
    throw new ArtifactError("invalid_artifact_size", 500);
  }
  if (!Number.isSafeInteger(Number(value.versionCode)) || Number(value.versionCode) < 1) {
    throw new ArtifactError("invalid_artifact_version", 500);
  }
  return {
    platform,
    product,
    versionCode: Number(value.versionCode),
    versionName: String(value.versionName || value.version || "").slice(0, 128),
    packageName: value.packageName ? String(value.packageName).slice(0, 256) : undefined,
    signingCertificateSha256: value.signingCertificateSha256
      ? String(value.signingCertificateSha256).toLowerCase()
      : undefined,
    artifact: String(value.artifact),
    sha256: String(value.sha256).toLowerCase(),
    size: Number(value.size),
    downloadUrl: String(value.downloadUrl || ""),
    minVersionCode: Number.isSafeInteger(Number(value.minVersionCode))
      ? Number(value.minVersionCode)
      : 1,
    channel: String(value.channel || "test").slice(0, 32),
    releaseNotes: String(value.releaseNotes || "").slice(0, 2000),
    publishedAt: String(value.publishedAt || "")
  };
}

class ArtifactStore {
  constructor(rootDirectory) {
    this.rootDirectory = path.resolve(rootDirectory);
  }

  manifestPath(platform, product) {
    return path.join(productDirectory(this.rootDirectory, platform, product), "latest.json");
  }

  artifactPath(platform, product, manifest) {
    const directory = productDirectory(this.rootDirectory, platform, product);
    const artifact = String(manifest.artifact || "");
    if (!FILE_PATTERN.test(artifact)) throw new ArtifactError("invalid_artifact_filename", 500);
    const resolved = path.resolve(directory, artifact);
    if (path.dirname(resolved) !== path.resolve(directory)) {
      throw new ArtifactError("invalid_artifact_path", 500);
    }
    return resolved;
  }

  loadManifest(platform, product) {
    const filePath = this.manifestPath(platform, product);
    if (!fs.existsSync(filePath)) throw new ArtifactError("artifact_not_published", 404);
    let value;
    try {
      value = JSON.parse(fs.readFileSync(filePath, "utf8"));
    } catch (_) {
      throw new ArtifactError("invalid_artifact_manifest", 500);
    }
    const manifest = validateManifest(value, platform, product);
    const artifactPath = this.artifactPath(platform, product, manifest);
    if (!fs.existsSync(artifactPath) || !fs.statSync(artifactPath).isFile()) {
      throw new ArtifactError("artifact_file_missing", 503);
    }
    const actualSize = fs.statSync(artifactPath).size;
    if (actualSize !== manifest.size) throw new ArtifactError("artifact_size_mismatch", 503);
    return { ...manifest, artifactPath };
  }

  sendManifest(res, platform, product, downloadUrl = "") {
    const { artifactPath, ...manifest } = this.loadManifest(platform, product);
    if (downloadUrl) manifest.downloadUrl = downloadUrl;
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    });
    res.end(JSON.stringify(manifest));
  }

  sendArtifact(res, platform, product) {
    const manifest = this.loadManifest(platform, product);
    res.writeHead(200, {
      "content-type": platform === "android" ? "application/vnd.android.package-archive" : "application/zip",
      "content-length": String(manifest.size),
      "content-disposition": `attachment; filename="${manifest.artifact}"`,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    });
    fs.createReadStream(manifest.artifactPath).on("error", () => {
      if (!res.headersSent) res.writeHead(503);
      res.end();
    }).pipe(res);
  }
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

module.exports = {
  ArtifactError,
  ArtifactStore,
  sha256File,
  validateManifest
};
