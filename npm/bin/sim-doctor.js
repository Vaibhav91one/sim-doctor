#!/usr/bin/env node
// `npx sim-doctor ...`: fetch the prebuilt release binary matching this package's version
// once into a cache directory, then run it. Node built-ins and the system tar only.
// The Linux binary links libpcsclite; install pcsc-lite (and run pcscd) to talk to a reader.
"use strict";

const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");

const { version } = require("../package.json");
const targets = {
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "linux-x64": "x86_64-unknown-linux-gnu",
};
const target = targets[`${process.platform}-${process.arch}`];
const REPO = "https://github.com/Vaibhav91one/sim-doctor";

// Release asset names, as published by .github/workflows/release.yml. Exported for the tests.
const assetName = (t) => `sim-doctor-${t}.tar.gz`;
const assetUrl = (t, v) => `${REPO}/releases/download/v${v}/${assetName(t)}`;
const sha256 = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
// A `.sha256` asset is `<hex>  <file name>` (shasum output); take the hex.
const parseChecksum = (text) => (/^([0-9a-f]{64})\b/i.exec(text.trim()) || [])[1]?.toLowerCase();
const cache =
  process.env.SIM_DOCTOR_CACHE ||
  path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"), "sim-doctor", version);
const bin = path.join(cache, "sim-doctor");

function fail(message) {
  console.error(`sim-doctor (npm): ${message}`);
  process.exit(2);
}

function download(url, to, redirects = 5) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
          res.resume();
          return resolve(download(res.headers.location, to, redirects - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`GET ${url}: HTTP ${res.statusCode}`));
        }
        const out = fs.createWriteStream(to);
        res.pipe(out);
        out.on("finish", () => out.close(resolve));
        out.on("error", reject);
      })
      .on("error", reject);
  });
}

async function install() {
  const name = assetName(target);
  const url = assetUrl(target, version);
  fs.mkdirSync(cache, { recursive: true });
  const tarball = path.join(cache, name);
  console.error(`sim-doctor (npm): downloading ${url}`);
  await download(url, tarball);
  await download(`${url}.sha256`, `${tarball}.sha256`);
  const want = parseChecksum(fs.readFileSync(`${tarball}.sha256`, "utf8"));
  fs.rmSync(`${tarball}.sha256`, { force: true });
  if (!want || sha256(tarball) !== want) {
    fs.rmSync(tarball, { force: true });
    throw new Error(`checksum mismatch for ${name}; refusing to run it`);
  }
  const untar = spawnSync("tar", ["xzf", tarball, "-C", cache], { stdio: "inherit" });
  fs.rmSync(tarball, { force: true });
  if (untar.status !== 0 || !fs.existsSync(bin)) fail(`cannot extract ${name}`);
  fs.chmodSync(bin, 0o755);
}

module.exports = { assetName, assetUrl, parseChecksum, sha256, targets };

if (require.main === module)
(async () => {
  if (!target) fail(`no prebuilt binary for ${process.platform}-${process.arch}; use cargo install`);
  if (!fs.existsSync(bin)) {
    try {
      await install();
    } catch (error) {
      fail(`${error.message}. Or: cargo install sim-doctor`);
    }
  }
  const result = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
  if (result.error) fail(result.error.message);
  process.exit(result.status === null ? 2 : result.status);
})();
