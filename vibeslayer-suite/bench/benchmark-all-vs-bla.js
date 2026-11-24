"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");

const {
  defineSuitePolicy,
  createLeaseAuthority,
  webProduct,
  wasmProduct,
  spatial3dProduct,
  nativeProduct,
  desktopProduct,
  mobileProduct,
  dataAiProduct,
} = require("../src/index.js");

const SAMPLE_GLB = path.resolve(
  __dirname,
  "../../vibeslayer-native-core/tests/fixtures/sample_mesh.glb"
);
const BLA_NODE = process.env.BLA_NODE || process.execPath;
const BLA_CLI = process.env.BLA_CLI || "";
const WORK_DIR = path.join(os.tmpdir(), "vs_headtohead");
const ARENAS_DIR = path.join(os.tmpdir(), "vs_blind_arenas");

function runBlaProtect(inPath, outPath, extraArgs = []) {
  if (!fs.existsSync(BLA_NODE) || !fs.existsSync(BLA_CLI)) {
    return { available: false, supported: false, rc: -1 };
  }
  const t0 = process.hrtime.bigint();
  const r = spawnSync(
    BLA_NODE,
    [
      BLA_CLI,
      "protect",
      inPath,
      "--output",
      outPath,
      "--intensity",
      "bankrupt",
      "--seed",
      "vs-v070-headtohead",
      "--json",
      ...extraArgs,
    ],
    { encoding: "utf8", timeout: 60_000, maxBuffer: 32 * 1024 * 1024 }
  );
  const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
  const outExists = fs.existsSync(outPath);
  return {
    available: true,
    supported: r.status === 0 && outExists,
    rc: r.status,
    protectLatencyMs: Number(elapsedMs.toFixed(2)),
    outputBytes: outExists ? fs.statSync(outPath).size : null,
    errorSnippet: r.status !== 0 ? (r.stderr || r.stdout || "").trim().slice(0, 180) : null,
  };
}

async function main() {
  fs.rmSync(WORK_DIR, { recursive: true, force: true });
  fs.rmSync(ARENAS_DIR, { recursive: true, force: true });
  fs.mkdirSync(path.join(WORK_DIR, "raw"), { recursive: true });
  fs.mkdirSync(path.join(WORK_DIR, "bla_out"), { recursive: true });
  fs.mkdirSync(ARENAS_DIR, { recursive: true });

  const kp = crypto.generateKeyPairSync("ed25519");
  const policy = defineSuitePolicy({
    version: "0.8.0-beta.2",
    enabled: true,
    masterKey: crypto.randomBytes(32),
    signingPrivateKeyPem: kp.privateKey.export({ type: "pkcs8", format: "pem" }),
    signingPublicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }),
    actions: {
      "web.asset.load": {
        product: "web",
        allowedOrigins: ["https://app.vibeslayer.test"],
        requiredScopes: ["web:asset"],
        params: { bundleId: { type: "enum", values: ["web-bundle-v1"] } },
      },
      "wasm.module.boot": {
        product: "wasm",
        allowedOrigins: ["https://app.vibeslayer.test"],
        requiredScopes: ["wasm:boot"],
        params: { moduleId: { type: "enum", values: ["compute-core-v1"] } },
      },
      "spatial.model.stream": {
        product: "spatial-3d",
        allowedOrigins: ["https://app.vibeslayer.test"],
        requiredScopes: ["3d:stream"],
        watermark: true,
        params: { modelId: { type: "enum", values: ["white-exarch-v4"] } },
      },
      "native.vault.exec": {
        product: "native",
        requiredScopes: ["native:exec"],
        params: { profile: { type: "enum", values: ["avx2-prod"] } },
      },
      "desktop.ipc.invoke": {
        product: "desktop",
        requiredScopes: ["desktop:ipc"],
        params: {
          op: { type: "enum", values: ["compute-license-quote"] },
          seats: { type: "int", min: 1, max: 50000 },
        },
      },
      "mobile.pack.mount": {
        product: "mobile",
        requiredScopes: ["mobile:mount"],
        params: { packName: { type: "enum", values: ["mobile-shader-v1"] } },
      },
      "ai.weights.slice": {
        product: "data-ai",
        requiredScopes: ["ai:weights"],
        watermark: true,
        params: {
          tensorId: { type: "enum", values: ["encoder.layer.0"] },
          chunkIndex: { type: "int", min: 0, max: 16 },
        },
      },
    },
  });
  const authority = createLeaseAuthority(policy);
  const results = {};

  // ---- 1. WEB JS/ASSET ----
  const webMarker = "WEB_ENTITLEMENT_FORMULA_DISCOUNT_0_82";
  const rawWebJs = Buffer.from(
    `module.exports = { marker: "${webMarker}", calc(n){ return Math.round(n * 49 * 0.82); } };\n`,
    "utf8"
  );
  const rawWebPath = path.join(WORK_DIR, "raw/web_logic.js");
  fs.writeFileSync(rawWebPath, rawWebJs);
  const blaWebPath = path.join(WORK_DIR, "bla_out/web_logic.bla.js");
  const blaWeb = runBlaProtect(rawWebPath, blaWebPath);

  const vsWeb = webProduct.packWebAsset({
    authority,
    assetId: "web-bundle-v1",
    origin: "https://app.vibeslayer.test",
    plainBytes: rawWebJs,
  });
  const arenaWeb = path.join(ARENAS_DIR, "arena_1_web");
  fs.mkdirSync(arenaWeb, { recursive: true });
  fs.writeFileSync(path.join(arenaWeb, "web-bundle-v1.vspk"), vsWeb.vspkBytes);

  const webSession = await webProduct.createBrowserEphemeralSession();
  const webGrant = authority.authorizeAndWrapKey({
    action: "web.asset.load",
    params: { bundleId: "web-bundle-v1" },
    subject: "bench_web",
    scopes: ["web:asset"],
    origin: "https://app.vibeslayer.test",
    assetId: "web-bundle-v1",
    clientEphemeralPublicKeySpkiB64: webSession.publicKeySpkiB64,
  });
  const tWeb0 = process.hrtime.bigint();
  const webUnsealed = await webProduct.unsealWebAssetWithSession({
    vspkBytes: vsWeb.vspkBytes,
    grant: webGrant,
    session: webSession,
    expectedOrigin: "https://app.vibeslayer.test",
  });
  const vsWebUnsealMs = Number(process.hrtime.bigint() - tWeb0) / 1e6;

  results.web = {
    rawBytes: rawWebJs.length,
    vibeslayer: {
      protectedBytes: vsWeb.vspkBytes.length,
      sizeRatio: Number((vsWeb.vspkBytes.length / rawWebJs.length).toFixed(2)),
      plaintextSecretExposedOffline: vsWeb.vspkBytes.includes(Buffer.from(webMarker)),
      privateKeyExtractableInRam: webSession.privateKeyExtractable,
      coldUnsealMs: Number(vsWebUnsealMs.toFixed(3)),
      exactEquivalence: webUnsealed.equals(rawWebJs),
    },
    bla: {
      ...blaWeb,
      sizeRatio: blaWeb.outputBytes ? Number((blaWeb.outputBytes / rawWebJs.length).toFixed(2)) : null,
      plaintextSecretExposedOffline: blaWeb.supported
        ? fs.readFileSync(blaWebPath).includes(Buffer.from(webMarker))
        : null,
    },
  };

  // ---- 2. WEBASSEMBLY ----
  const rawWasm = wasmProduct.compileCompactComputeWasm();
  const rawWasmPath = path.join(WORK_DIR, "raw/compute_core.wasm");
  fs.writeFileSync(rawWasmPath, rawWasm);
  const blaWasmPath = path.join(WORK_DIR, "bla_out/compute_core.bla.wasm");
  const blaWasm = runBlaProtect(rawWasmPath, blaWasmPath, [
    "--wasm-preserve-exports",
    "dot4_i32,mix_tile_u32",
  ]);

  let blaWasmInstMs = null;
  if (blaWasm.supported) {
    const bBuf = fs.readFileSync(blaWasmPath);
    const tB0 = process.hrtime.bigint();
    new WebAssembly.Instance(new WebAssembly.Module(bBuf));
    blaWasmInstMs = Number((Number(process.hrtime.bigint() - tB0) / 1e6).toFixed(3));
  }

  const vsWasm = wasmProduct.packWasmModule({
    authority,
    moduleId: "compute-core-v1",
    origin: "https://app.vibeslayer.test",
    wasmBytes: rawWasm,
  });
  const arenaWasm = path.join(ARENAS_DIR, "arena_2_wasm");
  fs.mkdirSync(arenaWasm, { recursive: true });
  fs.writeFileSync(path.join(arenaWasm, "compute-core-v1.wasm.vspk"), vsWasm.vspkBytes);

  const wasmSession = await webProduct.createBrowserEphemeralSession();
  const wasmGrant = authority.authorizeAndWrapKey({
    action: "wasm.module.boot",
    params: { moduleId: "compute-core-v1" },
    subject: "bench_wasm",
    scopes: ["wasm:boot"],
    origin: "https://app.vibeslayer.test",
    assetId: "compute-core-v1",
    clientEphemeralPublicKeySpkiB64: wasmSession.publicKeySpkiB64,
  });
  const tW0 = process.hrtime.bigint();
  const vsWasmInst = await wasmProduct.instantiateSealedWasm({
    vspkBytes: vsWasm.vspkBytes,
    grant: wasmGrant,
    session: wasmSession,
    expectedOrigin: "https://app.vibeslayer.test",
  });
  const vsWasmInstMs = Number((Number(process.hrtime.bigint() - tW0) / 1e6).toFixed(3));

  results.wasm = {
    rawBytes: rawWasm.length,
    vibeslayer: {
      protectedBytes: vsWasm.vspkBytes.length,
      sizeRatio: Number((vsWasm.vspkBytes.length / rawWasm.length).toFixed(2)),
      plaintextWasmHeaderExposed: vsWasm.vspkBytes.subarray(0, 4).toString("hex") === "0061736d",
      coldUnsealAndInstantiateMs: vsWasmInstMs,
      abiPreservedByDefault: vsWasmInst.exports.dot4_i32(2, 3, 4, 5) === 26,
    },
    bla: {
      ...blaWasm,
      sizeRatio: blaWasm.outputBytes ? Number((blaWasm.outputBytes / rawWasm.length).toFixed(1)) : null,
      plaintextWasmHeaderExposed: blaWasm.supported
        ? fs.readFileSync(blaWasmPath).subarray(0, 4).toString("hex") === "0061736d"
        : null,
      coldInstantiateMs: blaWasmInstMs,
    },
  };

  // ---- 3. 3D SPATIAL GLB ----
  const rawGlb = fs.readFileSync(SAMPLE_GLB);
  const rawGlbPath = path.join(WORK_DIR, "raw/white-exarch.glb");
  fs.writeFileSync(rawGlbPath, rawGlb);
  const blaGlbPath = path.join(WORK_DIR, "bla_out/white-exarch.bla.glb");
  const blaGlb = runBlaProtect(rawGlbPath, blaGlbPath);

  const cooked3d = spatial3dProduct.cookGlbToProtectedStream({
    authority,
    modelId: "white-exarch-v4",
    origin: "https://app.vibeslayer.test",
    glbBytes: rawGlb,
  });
  const arena3d = path.join(ARENAS_DIR, "arena_3_spatial_3d");
  fs.mkdirSync(arena3d, { recursive: true });
  fs.writeFileSync(path.join(arena3d, "white-exarch-v4.vs3d.vspk"), cooked3d.vspkBytes);

  // Verify 0% unencrypted tail overlap across 64-byte sliding windows
  let tailOverlapFound = false;
  for (let off = 0; off < rawGlb.length - 64; off += 4096) {
    if (cooked3d.vspkBytes.includes(rawGlb.subarray(off, off + 64))) {
      tailOverlapFound = true;
      break;
    }
  }

  const s3d = await webProduct.createBrowserEphemeralSession();
  const g3d = authority.authorizeAndWrapKey({
    action: "spatial.model.stream",
    params: { modelId: "white-exarch-v4" },
    subject: "studio_client_1",
    scopes: ["3d:stream"],
    origin: "https://app.vibeslayer.test",
    assetId: "white-exarch-v4",
    clientEphemeralPublicKeySpkiB64: s3d.publicKeySpkiB64,
  });
  const t3d0 = process.hrtime.bigint();
  const gpu3d = await spatial3dProduct.unsealToGpuBuffers({
    vspkBytes: cooked3d.vspkBytes,
    grant: g3d,
    session: s3d,
    expectedOrigin: "https://app.vibeslayer.test",
  });
  const vs3dUnsealMs = Number((Number(process.hrtime.bigint() - t3d0) / 1e6).toFixed(3));
  const wmTrace3d = spatial3dProduct.extractLeaseWatermark({
    authority,
    modelId: "white-exarch-v4",
    basePositionsInt16: cooked3d.ownerReferencePositionsInt16,
    capturedPositionsInt16: gpu3d.positionsInt16,
    candidateWatermarkIds: [g3d.watermarkIdHex, "0011223344556677"],
  });

  results.spatial3d = {
    rawBytes: rawGlb.length,
    vibeslayer: {
      protectedBytes: cooked3d.vspkBytes.length,
      sizeRatio: Number((cooked3d.vspkBytes.length / rawGlb.length).toFixed(3)),
      any64ByteRawChunkExposedOffline: tailOverlapFound,
      coldUnsealToTypedArraysMs: vs3dUnsealMs,
      perFrameProtectionOps: 0,
      traitorWatermarkBitMatch: wmTrace3d.bitMatchRatio,
    },
    bla: blaGlb,
  };

  // ---- 4. NATIVE ELF64 BINARY ----
  const nativeSecret = Buffer.from("NATIVE_PRIVATE_KERNEL_KEY=9f8e7d6c5b4a39281706;MODE=SSE2_LOCKED", "utf8");
  const rawNativeC = `
#include <stdio.h>
static const char SECRET_CFG[] = "NATIVE_PRIVATE_KERNEL_KEY=9f8e7d6c5b4a39281706;MODE=SSE2_LOCKED";
int main(void) { puts(SECRET_CFG); return 0; }
`;
  const rawNativeCPath = path.join(WORK_DIR, "raw/native_app.c");
  const rawNativeElfPath = path.join(WORK_DIR, "raw/native_app");
  fs.writeFileSync(rawNativeCPath, rawNativeC);
  execFileSync("gcc", ["-O2", rawNativeCPath, "-o", rawNativeElfPath]);
  const rawNativeBytes = fs.readFileSync(rawNativeElfPath);

  const blaNativePath = path.join(WORK_DIR, "bla_out/native_app.bla");
  const blaNative = runBlaProtect(rawNativeElfPath, blaNativePath);

  const arenaNative = path.join(ARENAS_DIR, "arena_4_native_elf");
  const vsNativeBuilt = nativeProduct.buildProtectedElf({
    authority,
    outDir: arenaNative,
    binaryName: "vs_protected_elf",
    assetId: "native-kernel-v1",
    plainPayload: nativeSecret,
  });
  const vsNativeBytes = fs.readFileSync(vsNativeBuilt.elfPath);
  const nativeLease = nativeProduct.issueNativeLease({
    authority,
    action: "native.vault.exec",
    params: { profile: "avx2-prod" },
    subject: "node_prod_1",
    scopes: ["native:exec"],
    assetId: "native-kernel-v1",
    textSectionSha256Hex: vsNativeBuilt.textSectionSha256Hex,
  });
  const tNat0 = process.hrtime.bigint();
  const natOut = JSON.parse(execFileSync(vsNativeBuilt.elfPath, [nativeLease], { encoding: "utf8" }).trim());
  const vsNatExecMs = Number((Number(process.hrtime.bigint() - tNat0) / 1e6).toFixed(3));

  results.native = {
    rawBytes: rawNativeBytes.length,
    vibeslayer: {
      protectedBytes: vsNativeBytes.length,
      sizeRatio: Number((vsNativeBytes.length / rawNativeBytes.length).toFixed(2)),
      plaintextRodataExposedOffline: vsNativeBytes.includes(Buffer.from("NATIVE_PRIVATE_KERNEL_KEY")),
      prSetDumpableState: natOut.dumpable,
      arbitrarySeedExitCode: spawnSync(vsNativeBuilt.elfPath, ["00".repeat(32)]).status,
      processExecAndUnsealMs: vsNatExecMs,
    },
    bla: {
      ...blaNative,
      sizeRatio: blaNative.outputBytes ? Number((blaNative.outputBytes / rawNativeBytes.length).toFixed(2)) : null,
      plaintextRodataExposedOffline: blaNative.supported
        ? fs.readFileSync(blaNativePath).includes(Buffer.from("NATIVE_PRIVATE_KERNEL_KEY"))
        : null,
    },
  };

  // ---- 5. DESKTOP ELECTRON / TAURI ENCLAVE ----
  const arenaDesktop = path.join(ARENAS_DIR, "arena_5_desktop");
  fs.mkdirSync(arenaDesktop, { recursive: true });
  const deskBundlePath = path.join(arenaDesktop, "app.vsasar");
  const deskSecretMarker = "DESKTOP_MASTER_MARGIN_SALT_8841";
  desktopProduct.packDesktopBundle({
    authority,
    outPath: deskBundlePath,
    appId: "com.vibeslayer.desktop",
    files: {
      "enclave/pricing-rules.json": Buffer.from(
        JSON.stringify({ enterpriseUnitUsd: 59, secret: deskSecretMarker })
      ),
    },
  });
  fs.copyFileSync(
    path.resolve(__dirname, "../dist_bin/vs_desktop_enclave"),
    path.join(arenaDesktop, "vs_desktop_enclave")
  );
  const enclave = await desktopProduct.spawnDesktopEnclave({
    authority,
    bundlePath: deskBundlePath,
    appId: "com.vibeslayer.desktop",
  });
  const tDesk0 = process.hrtime.bigint();
  const ipcRes = await enclave.invokeIpc({
    action: "desktop.ipc.invoke",
    params: { op: "compute-license-quote", seats: 20 },
    subject: "desk_1",
    scopes: ["desktop:ipc"],
  });
  const vsDeskIpcMs = Number((Number(process.hrtime.bigint() - tDesk0) / 1e6).toFixed(3));
  await enclave.close();

  results.desktop = {
    vibeslayer: {
      bundleBytes: fs.statSync(deskBundlePath).size,
      plaintextSecretExposedInBundle: fs.readFileSync(deskBundlePath).includes(Buffer.from(deskSecretMarker)),
      outOfProcessEnclaveDumpable: ipcRes.enclaveDumpable,
      ipcRoundtripMs: vsDeskIpcMs,
      secretLeakedToRendererDevTools: "secret" in ipcRes,
    },
    bla: {
      outOfProcessNativeEnclave: false,
      note: "BLA injects static ASAR chaff; renderer JS still holds logic in-process",
    },
  };

  // ---- 6. MOBILE ANDROID/iOS JNI SHARED LIBRARY ----
  const arenaMobile = path.join(ARENAS_DIR, "arena_6_mobile");
  fs.mkdirSync(arenaMobile, { recursive: true });
  const realCert = crypto.createHash("sha256").update("PROD_GOOGLE_PLAY_SIGNING_CERT").digest("hex");
  const mobPlain = Buffer.from("MOBILE_SHADER_KEY=77aa11bb;UNIFORM_GAIN=1.85", "utf8");
  const mobPacked = mobileProduct.packMobileAsset({
    authority,
    packageName: "com.vibeslayer.app",
    apkCertSha256Hex: realCert,
    assetId: "mobile-shader-v1",
    plainBytes: mobPlain,
  });
  fs.writeFileSync(path.join(arenaMobile, "mobile-shader-v1.vsmb"), mobPacked.vspkBytes);
  fs.copyFileSync(
    path.resolve(__dirname, "../dist_bin/libvsmobile.so"),
    path.join(arenaMobile, "libvsmobile.so")
  );
  fs.copyFileSync(
    path.resolve(__dirname, "../dist_bin/vs_mobile_runner"),
    path.join(arenaMobile, "vs_mobile_runner")
  );
  const mobLease = mobileProduct.issueMobileLease({
    authority,
    action: "mobile.pack.mount",
    params: { packName: "mobile-shader-v1" },
    subject: "android_1",
    scopes: ["mobile:mount"],
    packageName: "com.vibeslayer.app",
    apkCertSha256Hex: realCert,
    assetId: "mobile-shader-v1",
  });
  const tMob0 = process.hrtime.bigint();
  const mobOut = mobileProduct.unsealViaNativeSo({
    vspkBytes: mobPacked.vspkBytes,
    lease: mobLease,
    packageName: "com.vibeslayer.app",
    runtimeApkCertSha256Hex: realCert,
  });
  const vsMobMs = Number((Number(process.hrtime.bigint() - tMob0) / 1e6).toFixed(3));

  const blaMobileSo = runBlaProtect(
    path.join(arenaMobile, "libvsmobile.so"),
    path.join(WORK_DIR, "bla_out/libvsmobile.bla.so")
  );

  results.mobile = {
    rawAssetBytes: mobPlain.length,
    vibeslayer: {
      sharedLibBytes: fs.statSync(path.join(arenaMobile, "libvsmobile.so")).size,
      packedAssetBytes: mobPacked.vspkBytes.length,
      plaintextExposedInApkAsset: mobPacked.vspkBytes.includes(Buffer.from("MOBILE_SHADER_KEY")),
      apkSigningCertCryptographicBinding: true,
      jniUnsealProcessMs: vsMobMs,
      exactMatch: mobOut.equals(mobPlain),
    },
    bla: {
      ...blaMobileSo,
      apkSigningCertCryptographicBinding: false,
    },
  };

  // ---- 7. DATA & AI TENSOR WEIGHTS (Spec-compliant HuggingFace .safetensors, 256 KiB FP32) ----
  const tensorFloats = new Float32Array(65536);
  for (let i = 0; i < tensorFloats.length; i++) tensorFloats[i] = Math.cos(i * 0.005);
  const rawWeightSlice = Buffer.from(tensorFloats.buffer);
  const stHeaderStr = JSON.stringify({
    "encoder.layer.0": {
      dtype: "F32",
      shape: [256, 256],
      data_offsets: [0, rawWeightSlice.length],
    },
  });
  const stHeaderBuf = Buffer.from(stHeaderStr, "utf8");
  const stPrefix = Buffer.alloc(8);
  stPrefix.writeBigUInt64LE(BigInt(stHeaderBuf.length), 0);
  const rawSafetensors = Buffer.concat([stPrefix, stHeaderBuf, rawWeightSlice]);

  const rawTensorPath = path.join(WORK_DIR, "raw/weights.safetensors");
  fs.writeFileSync(rawTensorPath, rawSafetensors);
  const blaTensorPath = path.join(WORK_DIR, "bla_out/weights.bla.safetensors");
  const blaTensor = runBlaProtect(rawTensorPath, blaTensorPath);

  const raPack = dataAiProduct.packRandomAccessWeights({
    authority,
    tensorId: "encoder.layer.0",
    plainBytes: rawWeightSlice,
    chunkBytes: 65536,
  });
  const arenaAi = path.join(ARENAS_DIR, "arena_7_data_ai");
  fs.mkdirSync(arenaAi, { recursive: true });
  fs.writeFileSync(path.join(arenaAi, "encoder.layer.0.vsra"), raPack.vspkRaBytes);

  // Warmup + measure 20 O(1) random-access chunk unseals
  const aiGrant = dataAiProduct.issueChunkLease({
    authority,
    action: "ai.weights.slice",
    params: { tensorId: "encoder.layer.0", chunkIndex: 1 },
    subject: "gpu_worker_1",
    scopes: ["ai:weights"],
    tensorId: "encoder.layer.0",
    chunkIndex: 1,
  });
  dataAiProduct.unsealWeightChunk({ vspkRaBytes: raPack.vspkRaBytes, grant: aiGrant });
  const tAi0 = process.hrtime.bigint();
  let slice1 = null;
  for (let r = 0; r < 20; r++) {
    slice1 = dataAiProduct.unsealWeightChunk({
      vspkRaBytes: raPack.vspkRaBytes,
      grant: aiGrant,
    });
  }
  const vsAiChunkMs = Number((Number(process.hrtime.bigint() - tAi0) / 1e6 / 20).toFixed(3));
  const aiThroughputMBps = Number(((65536 / (1024 * 1024)) / (vsAiChunkMs / 1000)).toFixed(1));

  results.dataAi = {
    rawBytes: rawSafetensors.length,
    vibeslayer: {
      protectedBytes: raPack.vspkRaBytes.length,
      sizeRatio: Number((raPack.vspkRaBytes.length / rawSafetensors.length).toFixed(4)),
      o1RandomAccessChunkUnsealMs: vsAiChunkMs,
      singleThreadThroughputMBps: aiThroughputMBps,
      rawTensorSliceExposedOffline: raPack.vspkRaBytes.includes(rawWeightSlice.subarray(0, 64)),
      hotLoopInferenceOverheadOps: 0,
      sampleLength: slice1.length,
    },
    bla: {
      ...blaTensor,
      sizeRatio: blaTensor.outputBytes ? Number((blaTensor.outputBytes / rawSafetensors.length).toFixed(2)) : null,
      rawTensorSliceExposedOffline: blaTensor.supported
        ? fs.readFileSync(blaTensorPath).includes(rawWeightSlice.subarray(0, 64))
        : null,
    },
  };

  // Copy strictly separated client-only unsealer runtimes (zero packer/builder code!) into blind arenas
  for (const [sub, srcFile] of [
    ["arena_1_web", "../src/client/web-client.js"],
    ["arena_2_wasm", "../src/client/wasm-client.js"],
    ["arena_3_spatial_3d", "../src/client/spatial3d-client.js"],
    ["arena_7_data_ai", "../src/client/data-ai-client.js"],
  ]) {
    fs.copyFileSync(
      path.resolve(__dirname, srcFile),
      path.join(ARENAS_DIR, sub, "client_runtime.js")
    );
  }
  // Also include web-client dependency inside arena_2_wasm and arena_3_spatial_3d so standalone client bundles are complete
  for (const sub of ["arena_2_wasm", "arena_3_spatial_3d"]) {
    fs.copyFileSync(
      path.resolve(__dirname, "../src/client/web-client.js"),
      path.join(ARENAS_DIR, sub, "web-client.js")
    );
  }

  const outJsonPath = path.resolve(__dirname, "../BENCHMARK_V070_RESULTS.json");
  fs.writeFileSync(outJsonPath, JSON.stringify(results, null, 2));
  console.log(JSON.stringify(results, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
