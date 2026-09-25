#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const { sha256File } = require("../src/artifacts");

function usage() {
  console.error("usage: node scripts/publish-artifact.js --platform android|windows --product cpsm-m|cpsm-p|cpsm-c --input FILE --version-code N --version-name VERSION [--package-name NAME] [--signing-certificate-sha256 HEX] [--release-notes TEXT]");
  process.exit(2);
}

function argsToObject(args) {
  const result = {};
  for (let i = 0; i < args.length; i += 1) {
    const key = args[i];
    if (!key.startsWith("--")) usage();
    const name = key.slice(2);
    const value = args[i + 1];
    if (!value || value.startsWith("--")) usage();
    result[name] = value;
    i += 1;
  }
  return result;
}

const options = argsToObject(process.argv.slice(2));
const platform = options.platform;
const product = options.product;
const input = options.input && path.resolve(options.input);
const versionCode = Number(options["version-code"]);
const versionName = String(options["version-name"] || "");
if (!/^(android|windows)$/.test(platform) || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(product)
    || !input || !fs.existsSync(input) || !Number.isSafeInteger(versionCode) || versionCode < 1
    || !versionName) usage();

const root = path.resolve(process.env.CPSM_ARTIFACTS_DIR || path.join(process.cwd(), "artifacts"));
const destinationDir = path.join(root, platform, product);
fs.mkdirSync(destinationDir, { recursive: true });
const extension = platform === "android" ? ".apk" : ".zip";
const artifact = `${product}-${versionName}${extension}`.replace(/[^A-Za-z0-9._-]/g, "_");
const destination = path.join(destinationDir, artifact);
fs.copyFileSync(input, destination);
const stat = fs.statSync(destination);
const manifest = {
  platform,
  product,
  versionCode,
  versionName,
  packageName: options["package-name"] || undefined,
  signingCertificateSha256: options["signing-certificate-sha256"]
    ? options["signing-certificate-sha256"].toLowerCase()
    : undefined,
  artifact,
  sha256: sha256File(destination),
  size: stat.size,
  minVersionCode: 1,
  channel: options.channel || "test",
  releaseNotes: options["release-notes"] || "",
  publishedAt: new Date().toISOString()
};
for (const key of Object.keys(manifest)) {
  if (manifest[key] === undefined) delete manifest[key];
}
fs.writeFileSync(path.join(destinationDir, "latest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify(manifest, null, 2));
