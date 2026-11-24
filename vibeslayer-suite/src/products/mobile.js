"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { vsError } = require("../core/authority.js");
const { buildNativeArtifacts } = require("../../scripts/build-native.js");

const RUNNER_BIN = path.resolve(__dirname, "../../dist_bin/vs_mobile_runner");

function ensureBuilt() {
  if (!fs.existsSync(RUNNER_BIN)) {
    buildNativeArtifacts();
  }
}

function packMobileAsset({ authority, packageName, apkCertSha256Hex, assetId, plainBytes }) {
  const plain = Buffer.isBuffer(plainBytes) ? plainBytes : Buffer.from(plainBytes);
  const leaseRootKey = authority.deriveAssetKey("mobile", assetId, packageName);
  const infoStr = `VS_MOBILE_V1|${packageName}|${apkCertSha256Hex}|${assetId}`;
  const derivedKey = Buffer.from(
    crypto.hkdfSync("sha256", leaseRootKey, Buffer.from(assetId, "utf8"), Buffer.from(infoStr, "utf8"), 32)
  );
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("chacha20-poly1305", derivedKey, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(infoStr, "utf8"), { plaintextLength: plain.length });
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  leaseRootKey.fill(0);
  derivedKey.fill(0);

  const metaJson = Buffer.from(JSON.stringify({ assetId, packageName }), "utf8");
  const hdr = Buffer.alloc(34);
  hdr.write("VSMB", 0, "ascii");
  hdr.writeUInt16LE(metaJson.length, 4);
  nonce.copy(hdr, 6);
  tag.copy(hdr, 18);

  return {
    assetId,
    vspkBytes: Buffer.concat([hdr, metaJson, ct]),
  };
}

function issueMobileLease({
  authority,
  action,
  params,
  subject,
  scopes,
  packageName,
  apkCertSha256Hex,
  assetId,
}) {
  authority.checkPolicyAction(action, params, scopes, "");
  const leaseRootKey = authority.deriveAssetKey("mobile", assetId, packageName);
  try {
    return {
      subject,
      assetId,
      expectedCertSha256Hex: apkCertSha256Hex,
      leaseKeyHex: leaseRootKey.toString("hex"),
    };
  } finally {
    leaseRootKey.fill(0);
  }
}

function unsealViaNativeSo({ vspkBytes, lease, packageName, runtimeApkCertSha256Hex }) {
  ensureBuilt();
  const buf = Buffer.isBuffer(vspkBytes) ? vspkBytes : Buffer.from(vspkBytes);
  if (buf.length < 34 || buf.subarray(0, 4).toString("ascii") !== "VSMB") {
    throw vsError("BAD_VSMB", "Invalid mobile VSMB pack");
  }
  const metaLen = buf.readUInt16LE(4);
  if (34 + metaLen > buf.length) {
    throw vsError("BAD_VSMB", "Truncated mobile VSMB metadata");
  }
  const nonceHex = buf.subarray(6, 18).toString("hex");
  const tagHex = buf.subarray(18, 34).toString("hex");
  const meta = JSON.parse(buf.subarray(34, 34 + metaLen).toString("utf8"));
  const cipherHex = buf.subarray(34 + metaLen).toString("hex");

  try {
    const stdinPayload = [
      lease.leaseKeyHex,
      packageName,
      runtimeApkCertSha256Hex,
      meta.assetId,
      nonceHex,
      tagHex,
      cipherHex,
      "",
    ].join("\n");
    const outHex = execFileSync(
      RUNNER_BIN,
      ["--stdin"],
      { input: stdinPayload, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }
    ).trim();
    return Buffer.from(outHex, "hex");
  } catch (err) {
    throw vsError("MOBILE_AUTH_TAG_FAILED", err.stderr ? err.stderr.toString("utf8").trim() : "Native JNI unseal failed");
  }
}

module.exports = {
  packMobileAsset,
  issueMobileLease,
  unsealViaNativeSo,
};
