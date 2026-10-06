// No-network tests: asset names, checksum parsing and verification.
"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { version } = require("../package.json");
const { assetName, assetUrl, parseChecksum, sha256, targets } = require("../bin/sim-doctor.js");

test("asset names match what release.yml publishes", () => {
  const wf = fs.readFileSync(path.join(__dirname, "..", "..", ".github", "workflows", "release.yml"), "utf8");
  for (const t of Object.values(targets)) {
    assert.ok(wf.includes(`target: ${t}`), `release.yml builds ${t}`);
    assert.strictEqual(assetName(t), `sim-doctor-${t}.tar.gz`);
  }
  assert.ok(wf.includes("sim-doctor-${{ matrix.target }}.tar.gz"));
});

test("asset url is the tagged GitHub release download", () => {
  assert.strictEqual(
    assetUrl("x86_64-unknown-linux-gnu", version),
    `https://github.com/Vaibhav91one/sim-doctor/releases/download/v${version}/sim-doctor-x86_64-unknown-linux-gnu.tar.gz`,
  );
});

test("parseChecksum reads shasum output and rejects junk", () => {
  const hex = "a".repeat(64);
  assert.strictEqual(parseChecksum(`${hex.toUpperCase()}  sim-doctor-x.tar.gz\n`), hex);
  assert.strictEqual(parseChecksum("<html>not found</html>"), undefined);
  assert.strictEqual(parseChecksum(""), undefined);
});

test("sha256 matches a known digest", () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "sim-doctor-")), "f");
  fs.writeFileSync(f, "abc");
  assert.strictEqual(sha256(f), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});
