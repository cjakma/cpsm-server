const fs = require("fs");
const https = require("https");
const path = require("path");
const crypto = require("crypto");

const projectRoot = path.resolve(__dirname, "..");
const defaultCredentials = path.join(projectRoot, "secrets", "firebase-adminsdk.json");
const defaultOut = path.resolve(projectRoot, "..", "cpsm-p", "app", "google-services.json");

function argValue(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

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
    scope: "https://www.googleapis.com/auth/firebase https://www.googleapis.com/auth/cloud-platform",
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

  const response = await requestJson("POST", "https://oauth2.googleapis.com/token", {
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: `${unsigned}.${signature}`
  });
  return response.access_token;
}

async function main() {
  const packageName = argValue("--package", "com.cpsm.parents");
  const displayName = argValue("--display-name", "CPSM Parents");
  const credentialsPath = path.resolve(argValue("--credentials", process.env.GOOGLE_APPLICATION_CREDENTIALS || defaultCredentials));
  const outPath = path.resolve(argValue("--out", defaultOut));

  const serviceAccount = JSON.parse(fs.readFileSync(credentialsPath, "utf8"));
  const projectId = argValue("--project", serviceAccount.project_id);
  const token = await getAccessToken(serviceAccount);
  const auth = { authorization: `Bearer ${token}` };
  const base = `https://firebase.googleapis.com/v1beta1/projects/${encodeURIComponent(projectId)}`;

  const list = await requestJson("GET", `${base}/androidApps`, null, auth);
  let app = (list.apps || []).find((candidate) => candidate.packageName === packageName);

  if (!app) {
    try {
      app = await requestJson("POST", `${base}/androidApps`, {
        packageName,
        displayName
      }, auth);
    } catch (error) {
      if (!String(error.message).includes("INVALID_ARGUMENT")) {
        throw error;
      }
      app = await requestJson("POST", `${base}/androidApps`, {
        packageName
      }, auth);
    }
  }

  const config = await requestJson("GET", `https://firebase.googleapis.com/v1beta1/${app.name}/config`, null, auth);
  const contents = Buffer.from(config.configFileContents, "base64").toString("utf8");
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, contents, "utf8");

  const parsed = JSON.parse(contents);
  console.log(JSON.stringify({
    ok: true,
    projectId: parsed.project_info.project_id,
    projectNumber: parsed.project_info.project_number,
    packageName: parsed.client[0].client_info.android_client_info.package_name,
    appId: app.appId,
    outPath
  }, null, 2));
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
