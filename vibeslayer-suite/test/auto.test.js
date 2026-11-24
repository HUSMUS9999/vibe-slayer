"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const WORKSPACE_ROOT = path.resolve(__dirname, "../..");
const PROTECT_CLI = path.join(WORKSPACE_ROOT, "protect");

function runProtect(args, { env = process.env } = {}) {
  const out = execFileSync(PROTECT_CLI, args, {
    encoding: "utf8",
    env,
    maxBuffer: 32 * 1024 * 1024,
  });
  return JSON.parse(out.trim());
}

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function createSampleGlb() {
  const jsonBuf = Buffer.from(
    JSON.stringify({ asset: { version: "2.0" }, buffers: [{ byteLength: 64 }] }),
    "utf8"
  );
  const pad = (4 - (jsonBuf.length % 4)) % 4;
  const paddedJson = Buffer.concat([jsonBuf, Buffer.alloc(pad, 0x20)]);

  const binBuf = Buffer.alloc(64);
  for (let i = 0; i < 64; i += 4) binBuf.writeFloatLE((i - 32) * 0.25, i);

  const totalLen = 12 + 8 + paddedJson.length + 8 + binBuf.length;
  const out = Buffer.alloc(totalLen);
  out.write("glTF", 0, "ascii");
  out.writeUInt32LE(2, 4);
  out.writeUInt32LE(totalLen, 8);
  out.writeUInt32LE(paddedJson.length, 12);
  out.writeUInt32LE(0x4e4f534a, 16);
  paddedJson.copy(out, 20);
  const binOff = 20 + paddedJson.length;
  out.writeUInt32LE(binBuf.length, binOff);
  out.writeUInt32LE(0x004e4942, binOff + 4);
  binBuf.copy(out, binOff + 8);
  return out;
}

function createSampleWasm() {
  return Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
    0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
  ]);
}

function compileSampleElf(destBin) {
  const cPath = `${destBin}.c`;
  fs.writeFileSync(
    cPath,
    [
      "#include <stdio.h>",
      "#include <stdlib.h>",
      "int main(int argc, char **argv) {",
      '  const char *p = getenv("LD_PRELOAD");',
      '  printf("ARGS:%s PRELOAD:%s\\n", argc > 1 ? argv[1] : "NONE", p ? p : "NONE");',
      "  return 42;",
      "}",
      "",
    ].join("\n")
  );
  execFileSync("gcc", ["-O2", "-fPIE", "-pie", cPath, "-o", destBin]);
  fs.unlinkSync(cPath);
}

test("auto: single JS file protect, test, and lossless unseal", () => {
  const tmp = makeTempDir("vs-auto-js-");
  const reg = path.join(tmp, "reg.json");
  try {
    const jsPath = path.join(tmp, "app.js");
    const original = Buffer.from("export const secretFormula = (x) => (x ^ 0x5a) + 1337;\n", "utf8");
    fs.writeFileSync(jsPath, original);

    const prot = runProtect([jsPath, "--registry", reg, "--json"]);
    assert.equal(prot.ok, true);
    assert.equal(prot.mode, "file");
    assert.equal(prot.engine, "vspk3");
    assert.equal(prot.outputPath, path.join(tmp, "app.js.vspk3"));
    assert.equal(prot.keysFile, path.join(tmp, ".vibeslayer", "keys.json"));
    assert.equal(fs.statSync(prot.keysFile).mode & 0o777, 0o600);
    assert.equal(prot.selfCheck.ok, true);

    const testRes = runProtect(["test", prot.outputPath, "--registry", reg, "--json"]);
    assert.equal(testRes.ok, true);
    assert.equal(testRes.checks.tamperRejected, true);
    assert.equal(testRes.checks.roundTripUnsealOk, true);

    const restoredPath = path.join(tmp, "app.restored.js");
    const unsealRes = runProtect([
      "unseal",
      prot.outputPath,
      "-o",
      restoredPath,
      "--registry",
      reg,
      "--json",
    ]);
    assert.equal(unsealRes.ok, true);
    assert.deepEqual(fs.readFileSync(restoredPath), original);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("auto: compiled ELF64 wrap-elf lease-bound & standalone execution", () => {
  const tmp = makeTempDir("vs-auto-elf-");
  const reg = path.join(tmp, "reg.json");
  try {
    const binPath = path.join(tmp, "my_bin");
    compileSampleElf(binPath);

    const prot = runProtect([binPath, "--registry", reg, "--json"]);
    assert.equal(prot.ok, true);
    assert.equal(prot.engine, "wrap-elf");
    assert.equal(prot.outputPath, path.join(tmp, "my_bin.protected"));
    assert.equal(prot.selfCheck.ok, true);

    // Direct execution without lease key must fail closed with rc=2
    const directNoKey = spawnSync(prot.outputPath, ["hello_world"], { encoding: "utf8" });
    assert.equal(directNoKey.status, 2);

    // ./protect run injects FD 3 lease key, strips hostile LD_PRELOAD, forwards args & exit code
    const runRes = spawnSync(
      PROTECT_CLI,
      ["run", prot.outputPath, "--registry", reg, "--", "hello_world"],
      {
        encoding: "utf8",
        env: { ...process.env, LD_PRELOAD: "/tmp/evil_preload.so" },
      }
    );
    assert.equal(runRes.status, 42);
    assert.match(runRes.stdout, /ARGS:hello_world PRELOAD:NONE/);

    // --standalone runs directly without keys or env
    const saOut = path.join(tmp, "my_bin.standalone");
    const saProt = runProtect([
      binPath,
      "-o",
      saOut,
      "--standalone",
      "--registry",
      reg,
      "--json",
    ]);
    assert.equal(saProt.ok, true);
    assert.equal(saProt.standalone, true);
    assert.equal(saProt.selfCheck.ok, true);

    const saRun = spawnSync(saOut, ["alpha"], { encoding: "utf8", env: {} });
    assert.equal(saRun.status, 42);
    assert.match(saRun.stdout, /ARGS:alpha PRELOAD:NONE/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("auto: multi-asset repo scan, protect, gitignore, secret redaction, 3D trace under noise, and full unseal", () => {
  const tmp = makeTempDir("vs-auto-repo-");
  const reg = path.join(tmp, "reg.json");
  try {
    const repoDir = path.join(tmp, "sample-repo");
    fs.mkdirSync(path.join(repoDir, "src"), { recursive: true });
    fs.mkdirSync(path.join(repoDir, "compute"), { recursive: true });
    fs.mkdirSync(path.join(repoDir, "assets"), { recursive: true });
    fs.mkdirSync(path.join(repoDir, "models"), { recursive: true });
    fs.mkdirSync(path.join(repoDir, "bin"), { recursive: true });
    fs.mkdirSync(path.join(repoDir, "secrets"), { recursive: true });

    const readmeBytes = Buffer.from("# Sample Repo\nPublic documentation.\n");
    const logicBytes = Buffer.from("module.exports.mul = (a, b) => a * b;\n");
    const wasmBytes = createSampleWasm();
    const glbBytes = createSampleGlb();
    const weightsBytes = Buffer.alloc(1024);
    for (let i = 0; i < weightsBytes.length; i += 4) weightsBytes.writeFloatLE(i * 0.25, i);
    const vaultBytes = Buffer.from("TOP_SECRET_ROOT_SEED_VALUE_123456");
    const envBytes = Buffer.from("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345\n");

    fs.writeFileSync(path.join(repoDir, "README.md"), readmeBytes);
    fs.writeFileSync(path.join(repoDir, "src/logic.js"), logicBytes);
    fs.writeFileSync(path.join(repoDir, "compute/mod.wasm"), wasmBytes);
    fs.writeFileSync(path.join(repoDir, "assets/mesh.glb"), glbBytes);
    fs.writeFileSync(path.join(repoDir, "models/w.safetensors"), weightsBytes);
    compileSampleElf(path.join(repoDir, "bin/tool"));
    fs.writeFileSync(path.join(repoDir, "secrets/k.vault"), vaultBytes);
    fs.writeFileSync(path.join(repoDir, ".env"), envBytes);

    // 1) Scan detects redacted secret and expected engines
    const scanRes = runProtect(["scan", repoDir, "--json"]);
    assert.equal(scanRes.ok, true);
    assert.equal(scanRes.mode, "directory");
    assert.ok(scanRes.secretWarnings.length >= 1);
    assert.equal(JSON.stringify(scanRes).includes("abcdefghijklmnopqrstuvwxyz012345"), false);

    const byRel = Object.fromEntries(scanRes.items.map((it) => [it.relPath, it]));
    assert.equal(byRel["README.md"].engine, "copy-public");
    assert.equal(byRel["src/logic.js"].engine, "vspk3");
    assert.equal(byRel["compute/mod.wasm"].engine, "vspk3");
    assert.equal(byRel["assets/mesh.glb"].engine, "glb-dual");
    assert.equal(byRel["models/w.safetensors"].engine, "vspk3");
    assert.equal(byRel["bin/tool"].engine, "wrap-elf");
    assert.equal(byRel["secrets/k.vault"].engine, "freestanding-vault");
    assert.equal(byRel[".env"].engine, "vspk3");

    // 2) Full repo protect + .gitignore + key-free manifest
    const protRes = runProtect([repoDir, "--registry", reg, "--json"]);
    assert.equal(protRes.ok, true);
    assert.equal(protRes.mode, "directory");
    assert.equal(protRes.outputDir, `${repoDir}-protected`);
    assert.equal(protRes.selfCheck.ok, true);

    const gitignore = fs.readFileSync(path.join(repoDir, ".gitignore"), "utf8");
    assert.equal(gitignore.includes(".vibeslayer/"), true);
    assert.equal(gitignore.includes(".env"), true);

    const keys = JSON.parse(fs.readFileSync(protRes.keysFile, "utf8"));
    const manifestRaw = fs.readFileSync(protRes.manifestPath, "utf8");
    assert.equal(manifestRaw.includes(keys.masterKeyHex), false);
    assert.equal(manifestRaw.includes("leaseKeyHex"), false);

    // 3) 3D traitor watermark survives +-2 LSB quantization noise across all coords
    const vs3dPath = path.join(protRes.outputDir, "assets/mesh.glb.vs3d");
    const posPath = path.join(tmp, "bob.pos.bin");
    const noisyPosPath = path.join(tmp, "bob_noisy.pos.bin");
    const wmRes = runProtect([
      "watermark",
      vs3dPath,
      "--buyer",
      "bob@corp.test",
      "-o",
      posPath,
      "--registry",
      reg,
      "--json",
    ]);
    assert.equal(wmRes.ok, true);
    assert.equal(wmRes.buyer, "bob@corp.test");

    const rawPos = fs.readFileSync(posPath);
    const noisyPos = Buffer.alloc(rawPos.length);
    for (let i = 0; i + 1 < rawPos.length; i += 2) {
      const v = rawPos.readInt16LE(i);
      const delta = ((i / 2) % 2 === 0) ? 2 : -2;
      noisyPos.writeInt16LE(Math.max(-32767, Math.min(32767, v + delta)), i);
    }
    fs.writeFileSync(noisyPosPath, noisyPos);

    const traceRes = runProtect(["trace", noisyPosPath, "--registry", reg, "--json"]);
    assert.equal(traceRes.ok, true);
    assert.equal(traceRes.buyer, "bob@corp.test");
    assert.equal(traceRes.decodedWatermarkIdHex, wmRes.wmIdHex);

    // 4) Unseal repo restores non-executable assets byte-for-byte & lists executables in skippedExecutables
    const restoredDir = path.join(tmp, "sample-repo-restored");
    const unsealRes = runProtect([
      "unseal",
      protRes.outputDir,
      "-o",
      restoredDir,
      "--registry",
      reg,
      "--json",
    ]);
    assert.equal(unsealRes.ok, true);
    assert.deepEqual(fs.readFileSync(path.join(restoredDir, "README.md")), readmeBytes);
    assert.deepEqual(fs.readFileSync(path.join(restoredDir, "src/logic.js")), logicBytes);
    assert.deepEqual(fs.readFileSync(path.join(restoredDir, "compute/mod.wasm")), wasmBytes);
    assert.deepEqual(fs.readFileSync(path.join(restoredDir, "assets/mesh.glb")), glbBytes);
    assert.deepEqual(fs.readFileSync(path.join(restoredDir, "models/w.safetensors")), weightsBytes);
    assert.deepEqual(fs.readFileSync(path.join(restoredDir, ".env")), envBytes);

    const skippedRels = unsealRes.skippedExecutables.map((s) => s.relPath).sort();
    assert.deepEqual(skippedRels, ["bin/tool", "secrets/k.vault"]);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("auto: ./protect demo end-to-end sandbox workflow", () => {
  const tmp = makeTempDir("vs-auto-demo-");
  const reg = path.join(tmp, "reg.json");
  const demoDir = path.join(tmp, "demo-app");
  try {
    const demoRes = runProtect(["demo", "--dir", demoDir, "--registry", reg, "--json"]);
    assert.equal(demoRes.ok, true);
    assert.equal(demoRes.selfCheckOk, true);
    assert.equal(demoRes.watermarkBuyer, "alice@demo.local");
    assert.match(demoRes.execCheckOutput, /DEMO_ELF_OK seats=42/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
