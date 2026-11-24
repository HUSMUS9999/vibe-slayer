"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const { spawn } = require("node:child_process");
const { vsError } = require("../core/authority.js");
const { buildNativeArtifacts } = require("../../scripts/build-native.js");

const ENCLAVE_BIN = path.resolve(__dirname, "../../dist_bin/vs_desktop_enclave");

function ensureBuilt() {
  if (!fs.existsSync(ENCLAVE_BIN)) {
    buildNativeArtifacts();
  }
}

function packDesktopBundle({ authority, outPath, appId, files }) {
  const entries = {};
  for (const [relPath, rawBuf] of Object.entries(files)) {
    const plain = Buffer.isBuffer(rawBuf) ? rawBuf : Buffer.from(rawBuf);
    const key = authority.deriveAssetKey("desktop", `${appId}:${relPath}`, appId);
    const nonce = crypto.randomBytes(12);
    const aadStr = `VS_DESKTOP_V1|${appId}|${relPath}`;
    const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    cipher.setAAD(Buffer.from(aadStr, "utf8"), { plaintextLength: plain.length });
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag = cipher.getAuthTag();
    key.fill(0);

    entries[relPath] = {
      aad: aadStr,
      nonceHex: nonce.toString("hex"),
      tagHex: tag.toString("hex"),
      cipherHex: ct.toString("hex"),
    };
  }

  const manifestBody = Buffer.from(
    JSON.stringify({ format: "VSASAR_V1", appId, entries }),
    "utf8"
  ).toString("base64url");
  const sig = crypto
    .sign(null, Buffer.from(manifestBody, "utf8"), authority.policy.signingPrivateKeyPem)
    .toString("base64url");

  fs.writeFileSync(outPath, JSON.stringify({ manifestBody, sig }), "utf8");
  return { outPath, fileCount: Object.keys(entries).length };
}

async function spawnDesktopEnclave({ authority, bundlePath, appId }) {
  ensureBuilt();
  const rawArchive = JSON.parse(fs.readFileSync(bundlePath, "utf8"));
  const sigOk = crypto.verify(
    null,
    Buffer.from(rawArchive.manifestBody, "utf8"),
    authority.policy.signingPublicKeyPem,
    Buffer.from(rawArchive.sig, "base64url")
  );
  if (!sigOk) {
    throw vsError("BAD_BUNDLE_SIGNATURE", "Ed25519 desktop bundle signature invalid");
  }
  const manifest = JSON.parse(Buffer.from(rawArchive.manifestBody, "base64url").toString("utf8"));
  if (manifest.appId !== appId) {
    throw vsError("APP_ID_MISMATCH", "Desktop bundle appId mismatch");
  }

  const enclaveRel = "enclave/pricing-rules.json";
  const entry = manifest.entries[enclaveRel];
  if (!entry) {
    throw vsError("MISSING_ENCLAVE_RULES", "Bundle missing enclave/pricing-rules.json");
  }

  const proc = spawn(ENCLAVE_BIN, [], { stdio: ["pipe", "pipe", "pipe"] });
  const rl = readline.createInterface({ input: proc.stdout });
  const pending = [];
  let exited = false;
  let exitReason = null;

  const rejectPending = (err) => {
    while (pending.length > 0) {
      const waiter = pending.shift();
      waiter.reject(err);
    }
  };

  proc.stdin.on("error", (err) => {
    exited = true;
    exitReason = exitReason || `ENCLAVE_STDIN_ERROR:${err.code || err.message}`;
    rejectPending(new Error(exitReason));
  });

  proc.once("error", (err) => {
    exited = true;
    exitReason = `ENCLAVE_SPAWN_ERROR:${err.code || err.message}`;
    rejectPending(new Error(exitReason));
  });

  proc.once("exit", (code, signal) => {
    exited = true;
    exitReason = `ENCLAVE_EXITED:${code ?? signal ?? "unknown"}`;
  });

  proc.once("close", (code, signal) => {
    exited = true;
    exitReason = exitReason || `ENCLAVE_EXITED:${code ?? signal ?? "unknown"}`;
    rejectPending(new Error(exitReason));
  });

  rl.once("close", () => {
    exited = true;
    exitReason = exitReason || "ENCLAVE_STREAM_CLOSED";
    rejectPending(new Error(exitReason));
  });

  rl.on("line", (line) => {
    const waiter = pending.shift();
    if (!waiter) return;
    try {
      waiter.resolve(JSON.parse(line));
    } catch (err) {
      waiter.reject(new Error(`ENCLAVE_BAD_IPC:${err.message}`));
    }
  });

  const nextLine = () => {
    if (exited || proc.exitCode !== null || proc.signalCode !== null) {
      return Promise.reject(new Error(exitReason || `ENCLAVE_EXITED:${proc.exitCode ?? proc.signalCode ?? "closed"}`));
    }
    return new Promise((resolve, reject) => pending.push({ resolve, reject }));
  };

  const key = authority.deriveAssetKey("desktop", `${appId}:${enclaveRel}`, appId);
  const bootLine = `${key.toString("hex")} ${entry.nonceHex} ${entry.tagHex} ${entry.aad} ${entry.cipherHex}\n`;
  key.fill(0);
  proc.stdin.write(bootLine);

  const readyMsg = await nextLine();
  if (!readyMsg.ok) {
    proc.kill();
    throw vsError(readyMsg.code || "ENCLAVE_BOOT_FAILED", "Desktop enclave failed to boot");
  }

  return {
    enclaveDumpable: readyMsg.enclaveDumpable,
    async invokeIpc({ action, params, subject, scopes }) {
      authority.checkPolicyAction(action, params, scopes, "");
      if (exited || proc.exitCode !== null || proc.signalCode !== null) {
        throw new Error(exitReason || `ENCLAVE_EXITED:${proc.exitCode ?? proc.signalCode ?? "closed"}`);
      }
      const linePromise = nextLine();
      proc.stdin.write(`${params.op} ${params.seats}\n`);
      return linePromise;
    },
    async close() {
      if (!exited && proc.exitCode === null && proc.signalCode === null && !proc.killed) {
        const exitPromise = new Promise((resolve) => {
          proc.once("close", resolve);
          proc.once("exit", resolve);
          proc.once("error", resolve);
        });
        try {
          if (!proc.stdin.destroyed && proc.stdin.writable) {
            proc.stdin.write("SHUTDOWN\n");
            proc.stdin.end();
          }
        } catch {
          // Ignore write failures if process exits concurrently.
        }
        await exitPromise;
      }
      rl.close();
    },
  };
}

module.exports = {
  packDesktopBundle,
  spawnDesktopEnclave,
};
