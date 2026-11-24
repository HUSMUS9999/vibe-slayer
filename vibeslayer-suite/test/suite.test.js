"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const {
  CONFIG,
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

function makeAuthority() {
  const kp = crypto.generateKeyPairSync("ed25519");
  const masterKey = crypto.randomBytes(32);
  const policy = defineSuitePolicy({
    version: "0.8.0-beta.2",
    enabled: true,
    masterKey,
    signingPrivateKeyPem: kp.privateKey.export({ type: "pkcs8", format: "pem" }),
    signingPublicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }),
    actions: {
      "web.asset.load": {
        product: "web",
        allowedOrigins: ["https://app.vibeslayer.test"],
        requiredScopes: ["web:asset"],
        ttlMs: 30_000,
        maxUses: 2,
        params: {
          bundleId: { type: "enum", values: ["ui-pack-v1"] },
          locale: { type: "string", minLength: 2, maxLength: 8, optional: true },
        },
      },
      "wasm.module.boot": {
        product: "wasm",
        allowedOrigins: ["https://app.vibeslayer.test"],
        requiredScopes: ["wasm:boot"],
        ttlMs: 30_000,
        maxUses: 2,
        params: {
          moduleId: { type: "enum", values: ["simd-filter-core"] },
        },
      },
      "spatial.model.stream": {
        product: "spatial-3d",
        allowedOrigins: ["https://app.vibeslayer.test"],
        requiredScopes: ["3d:stream"],
        ttlMs: 30_000,
        maxUses: 2,
        watermark: true,
        params: {
          modelId: { type: "enum", values: ["white-exarch-v4"] },
          quality: { type: "int", min: 0, max: 2 },
        },
      },
      "native.vault.exec": {
        product: "native",
        requiredScopes: ["native:exec"],
        ttlMs: 30_000,
        maxUses: 2,
        params: {
          profile: { type: "enum", values: ["prod-avx2"] },
        },
      },
      "desktop.ipc.invoke": {
        product: "desktop",
        requiredScopes: ["desktop:ipc"],
        ttlMs: 30_000,
        maxUses: 4,
        params: {
          op: { type: "enum", values: ["compute-license-quote", "export-preset"] },
          seats: { type: "int", min: 1, max: 10000 },
        },
      },
      "mobile.pack.mount": {
        product: "mobile",
        requiredScopes: ["mobile:mount"],
        ttlMs: 30_000,
        maxUses: 2,
        params: {
          packName: { type: "enum", values: ["android-shader-pack"] },
        },
      },
      "ai.weights.slice": {
        product: "data-ai",
        requiredScopes: ["ai:weights"],
        ttlMs: 30_000,
        maxUses: 4,
        watermark: true,
        params: {
          tensorId: { type: "enum", values: ["encoder.layer.0"] },
          chunkIndex: { type: "int", min: 0, max: 64 },
        },
      },
    },
  });
  return { policy, authority: createLeaseAuthority(policy) };
}

test("0. Suite policy defaults to disabled and validates every action & parameter rule", () => {
  assert.equal(CONFIG.DEFAULT_ENABLED, false);
  const kp = crypto.generateKeyPairSync("ed25519");
  const disabled = defineSuitePolicy({
    masterKey: crypto.randomBytes(32),
    signingPrivateKeyPem: kp.privateKey.export({ type: "pkcs8", format: "pem" }),
    signingPublicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }),
    actions: {
      "noop.act": { product: "web", params: {} },
    },
  });
  const auth = createLeaseAuthority(disabled);
  assert.throws(
    () => auth.authorizeAndWrapKey({ action: "noop.act", params: {}, subject: "u1" }),
    /POLICY_DISABLED/
  );
});

test("1. Product 1 (Web): non-extractable ECDH P-256 session wrap + VSPK AEAD blocks offline/wrong-origin theft", async () => {
  const { authority } = makeAuthority();
  const rawBundle = Buffer.from(
    JSON.stringify({ pricingTable: [19, 49, 129], featureGate: "PRO_ONLY_RENDER" }),
    "utf8"
  );
  const packed = webProduct.packWebAsset({
    authority,
    assetId: "ui-pack-v1",
    origin: "https://app.vibeslayer.test",
    plainBytes: rawBundle,
  });

  // Static bundle holds 0 plaintext substrings
  assert.equal(packed.vspkBytes.includes(Buffer.from("PRO_ONLY_RENDER")), false);

  // Client creates non-extractable WebCrypto ECDH P-256 keypair in RAM
  const session = await webProduct.createBrowserEphemeralSession();
  assert.equal(session.privateKeyExtractable, false);

  // Wrong origin rejected
  assert.throws(
    () =>
      authority.authorizeAndWrapKey({
        action: "web.asset.load",
        params: { bundleId: "ui-pack-v1", locale: "en-US" },
        subject: "user_web_1",
        scopes: ["web:asset"],
        origin: "https://pirate-clone.example",
        assetId: "ui-pack-v1",
        clientEphemeralPublicKeySpkiB64: session.publicKeySpkiB64,
      }),
    /ORIGIN_DENIED/
  );

  // Valid origin + valid params -> wrapped ephemeral key -> local WebCrypto unseal
  const grant = authority.authorizeAndWrapKey({
    action: "web.asset.load",
    params: { bundleId: "ui-pack-v1", locale: "en-US" },
    subject: "user_web_1",
    scopes: ["web:asset"],
    origin: "https://app.vibeslayer.test",
    assetId: "ui-pack-v1",
    clientEphemeralPublicKeySpkiB64: session.publicKeySpkiB64,
  });

  const unsealed = await webProduct.unsealWebAssetWithSession({
    vspkBytes: packed.vspkBytes,
    grant,
    session,
    expectedOrigin: "https://app.vibeslayer.test",
  });
  assert.deepEqual(unsealed, rawBundle);
});

test("2. Product 2 (WASM): ultra-compact encrypted WASM (<1 KB vs BLA 6.88 MB) preserves ABI and runs natively", async () => {
  const { authority } = makeAuthority();
  const rawWasm = wasmProduct.compileCompactComputeWasm();
  assert.equal(WebAssembly.validate(rawWasm), true);
  assert.ok(rawWasm.length < 1024, `Expected compact WASM <1024B, got ${rawWasm.length}`);

  const packed = wasmProduct.packWasmModule({
    authority,
    moduleId: "simd-filter-core",
    origin: "https://app.vibeslayer.test",
    wasmBytes: rawWasm,
  });
  // Sealed container never exposes \0asm header
  assert.notEqual(packed.vspkBytes.subarray(0, 4).toString("hex"), "0061736d");

  const session = await webProduct.createBrowserEphemeralSession();
  const grant = authority.authorizeAndWrapKey({
    action: "wasm.module.boot",
    params: { moduleId: "simd-filter-core" },
    subject: "user_wasm_1",
    scopes: ["wasm:boot"],
    origin: "https://app.vibeslayer.test",
    assetId: "simd-filter-core",
    clientEphemeralPublicKeySpkiB64: session.publicKeySpkiB64,
  });

  const instance = await wasmProduct.instantiateSealedWasm({
    vspkBytes: packed.vspkBytes,
    grant,
    session,
    expectedOrigin: "https://app.vibeslayer.test",
  });
  assert.equal(typeof instance.exports.mix_tile_u32, "function");
  assert.equal(typeof instance.exports.dot4_i32, "function");
  assert.equal(instance.exports.dot4_i32(2, 3, 4, 5), 2 * 3 + 4 * 5);
});

test("3. Product 3 (3D Spatial): cooks GLB to nameless permuted GPU stream + embeds/recovers 64-bit per-lease traitor watermark", async () => {
  const { authority } = makeAuthority();
  const rawGlb = fs.readFileSync(SAMPLE_GLB);
  const cooked = spatial3dProduct.cookGlbToProtectedStream({
    authority,
    modelId: "white-exarch-v4",
    origin: "https://app.vibeslayer.test",
    glbBytes: rawGlb,
  });

  // Cooked & encrypted file is smaller than raw 581 KB GLB and contains zero plaintext glTF JSON or node names
  assert.equal(cooked.vspkBytes.includes(Buffer.from("glTF-Transform")), false);
  assert.equal(cooked.vspkBytes.includes(Buffer.from("EXT_meshopt_compression")), false);

  const sessionA = await webProduct.createBrowserEphemeralSession();
  const sessionB = await webProduct.createBrowserEphemeralSession();

  const grantA = authority.authorizeAndWrapKey({
    action: "spatial.model.stream",
    params: { modelId: "white-exarch-v4", quality: 2 },
    subject: "leaker_account_A",
    scopes: ["3d:stream"],
    origin: "https://app.vibeslayer.test",
    assetId: "white-exarch-v4",
    clientEphemeralPublicKeySpkiB64: sessionA.publicKeySpkiB64,
  });
  const grantB = authority.authorizeAndWrapKey({
    action: "spatial.model.stream",
    params: { modelId: "white-exarch-v4", quality: 2 },
    subject: "honest_account_B",
    scopes: ["3d:stream"],
    origin: "https://app.vibeslayer.test",
    assetId: "white-exarch-v4",
    clientEphemeralPublicKeySpkiB64: sessionB.publicKeySpkiB64,
  });

  const gpuBuffersA = await spatial3dProduct.unsealToGpuBuffers({
    vspkBytes: cooked.vspkBytes,
    grant: grantA,
    session: sessionA,
    expectedOrigin: "https://app.vibeslayer.test",
  });
  const gpuBuffersB = await spatial3dProduct.unsealToGpuBuffers({
    vspkBytes: cooked.vspkBytes,
    grant: grantB,
    session: sessionB,
    expectedOrigin: "https://app.vibeslayer.test",
  });

  assert.ok(gpuBuffersA.vertexCount > 1000);
  assert.ok(gpuBuffersA.indexCount > 3000);
  // Different leases receive distinct watermarked vertex buffers, within <= 8 LSB SNORM delta (WM_AMPLITUDE=4)
  assert.notDeepEqual(
    Buffer.from(gpuBuffersA.positionsInt16.buffer),
    Buffer.from(gpuBuffersB.positionsInt16.buffer)
  );
  let maxDelta = 0;
  for (let i = 0; i < gpuBuffersA.positionsInt16.length; i++) {
    const d = Math.abs(gpuBuffersA.positionsInt16[i] - gpuBuffersB.positionsInt16[i]);
    if (d > maxDelta) maxDelta = d;
  }
  assert.ok(
    maxDelta <= 2 * spatial3dProduct.WM_AMPLITUDE,
    `Expected imperceptible <=${2 * spatial3dProduct.WM_AMPLITUDE} int16 LSB delta, got ${maxDelta}`
  );

  // Forensic watermark extraction identifies the exact leaked session!
  const tracedA = spatial3dProduct.extractLeaseWatermark({
    authority,
    modelId: "white-exarch-v4",
    basePositionsInt16: cooked.ownerReferencePositionsInt16,
    capturedPositionsInt16: gpuBuffersA.positionsInt16,
    candidateWatermarkIds: [grantA.watermarkIdHex, grantB.watermarkIdHex],
  });
  assert.equal(tracedA.matchedWatermarkIdHex, grantA.watermarkIdHex);
  assert.ok(tracedA.bitMatchRatio >= 0.99);

  // O(1) candidate-free 64-bit BPSK watermark survives +-2 LSB coordinate quantization noise!
  const wm64Emb = spatial3dProduct.embedLeaseWatermark64({
    authority,
    modelId: "white-exarch-v4",
    positionsInt16: cooked.ownerReferencePositionsInt16,
    watermarkIdHex: grantA.watermarkIdHex,
  });
  const noisy = new Int16Array(wm64Emb.positionsInt16);
  for (let i = 0; i < noisy.length; i++) {
    const noise = ((i * 37) % 5) - 2; // deterministic +-2 LSB noise across every coordinate
    noisy[i] = Math.max(-32767, Math.min(32767, noisy[i] + noise));
  }
  const wm64Dec = spatial3dProduct.decodeLeaseWatermark64O1({
    authority,
    modelId: "white-exarch-v4",
    basePositionsInt16: cooked.ownerReferencePositionsInt16,
    capturedPositionsInt16: noisy,
  });
  assert.equal(wm64Dec.decodedWatermarkIdHex, grantA.watermarkIdHex);
  assert.ok(wm64Dec.meanChipConfidence > 0.9);
  assert.equal(wm64Dec.leakerRecord.subject, "leaker_account_A");
});

test("4. Product 4 (Native ELF64): RFC 8439 ChaCha20-Poly1305 + .text SHA-256 self-binding + PR_SET_DUMPABLE=0", () => {
  const { authority } = makeAuthority();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vs-native-test-"));
  try {
    const secretAlgoConfig = Buffer.from(
      "NATIVE_KERNEL_WEIGHTS=17,43,89,131;SECRET_MODE=AVX2_LOCKED",
      "utf8"
    );
    const built = nativeProduct.buildProtectedElf({
      authority,
      outDir: tmpDir,
      binaryName: "vs_protected_elf",
      assetId: "native-kernel-v1",
      plainPayload: secretAlgoConfig,
    });

    const elfBytes = fs.readFileSync(built.elfPath);
    assert.equal(elfBytes.includes(Buffer.from("AVX2_LOCKED")), false);

    // Offline execution without lease fails cleanly with non-zero exit code (not fake rc=0!)
    assert.throws(
      () => execFileSync(built.elfPath, [], { stdio: "pipe" }),
      (err) => err.status === 2
    );

    // Issue lease bound to exact .text SHA-256 of the compiled ELF
    const leaseEnv = nativeProduct.issueNativeLease({
      authority,
      action: "native.vault.exec",
      params: { profile: "prod-avx2" },
      subject: "workstation_7",
      scopes: ["native:exec"],
      assetId: "native-kernel-v1",
      textSectionSha256Hex: built.textSectionSha256Hex,
    });

    const stdout = execFileSync(built.elfPath, [leaseEnv], { encoding: "utf8" }).trim();
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.dumpable, 0);
    assert.equal(parsed.payloadSha256, crypto.createHash("sha256").update(secretAlgoConfig).digest("hex"));

    // Tamper 1 byte in .text (simulating 0xCC breakpoint or binary patch): HKDF key shifts -> AEAD tag fails!
    const patchedElf = path.join(tmpDir, "vs_protected_elf_patched");
    const mod = Buffer.from(elfBytes);
    mod[built.patchableTextFileOffset] ^= 0x01;
    fs.writeFileSync(patchedElf, mod, { mode: 0o755 });
    assert.throws(
      () => execFileSync(patchedElf, [leaseEnv], { stdio: "pipe" }),
      (err) => err.status === 3
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("5. Product 5 (Desktop Electron/Tauri): Ed25519-signed bundle + out-of-process Native C Enclave Sidecar", async () => {
  const { authority } = makeAuthority();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vs-desktop-test-"));
  try {
    const bundlePath = path.join(tmpDir, "app.vsasar");
    desktopProduct.packDesktopBundle({
      authority,
      outPath: bundlePath,
      appId: "com.vibeslayer.studio",
      files: {
        "enclave/pricing-rules.json": Buffer.from(
          JSON.stringify({ enterpriseUnitUsd: 49, floorMargin: 0.72, masterSalt: "ENCLAVE_ONLY_SALT" })
        ),
        "renderer/ui-theme.json": Buffer.from(JSON.stringify({ accent: "#0ea5e9" })),
      },
    });

    const rawDisk = fs.readFileSync(bundlePath);
    assert.equal(rawDisk.includes(Buffer.from("ENCLAVE_ONLY_SALT")), false);

    const enclave = await desktopProduct.spawnDesktopEnclave({
      authority,
      bundlePath,
      appId: "com.vibeslayer.studio",
    });
    try {
      const quote = await enclave.invokeIpc({
        action: "desktop.ipc.invoke",
        params: { op: "compute-license-quote", seats: 10 },
        subject: "desktop_user_1",
        scopes: ["desktop:ipc"],
      });
      assert.equal(quote.ok, true);
      assert.equal(quote.totalUsd, 490);
      assert.equal("masterSalt" in quote, false);
      assert.equal(quote.enclaveDumpable, 0);
    } finally {
      await enclave.close();
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("6. Product 6 (Mobile Android/iOS): compiled libvsmobile.so JNI/C shared library rejects APK cert repackaging", () => {
  const { authority } = makeAuthority();
  const realApkCertSha256 = crypto.createHash("sha256").update("OFFICIAL_ANDROID_KEYSTORE_CERT").digest("hex");
  const pirateApkCertSha256 = crypto.createHash("sha256").update("REPACKAGED_APKTOOL_DEBUG_CERT").digest("hex");
  const shaderAsset = Buffer.from("precision highp float; void main(){ gl_FragColor=vec4(0.13,0.45,0.88,1.0); }");

  const mobilePack = mobileProduct.packMobileAsset({
    authority,
    packageName: "com.vibeslayer.mobile",
    apkCertSha256Hex: realApkCertSha256,
    assetId: "android-shader-pack",
    plainBytes: shaderAsset,
  });
  assert.equal(mobilePack.vspkBytes.includes(Buffer.from("gl_FragColor")), false);

  const lease = mobileProduct.issueMobileLease({
    authority,
    action: "mobile.pack.mount",
    params: { packName: "android-shader-pack" },
    subject: "device_pixel_9",
    scopes: ["mobile:mount"],
    packageName: "com.vibeslayer.mobile",
    apkCertSha256Hex: realApkCertSha256,
    assetId: "android-shader-pack",
  });

  // Legitimate APK cert -> C shared library (`libvsmobile.so`) unseals exact shader bytes
  const okBytes = mobileProduct.unsealViaNativeSo({
    vspkBytes: mobilePack.vspkBytes,
    lease,
    packageName: "com.vibeslayer.mobile",
    runtimeApkCertSha256Hex: realApkCertSha256,
  });
  assert.deepEqual(okBytes, shaderAsset);

  // Repackaged APK with pirate signing cert -> libvsmobile.so fails AEAD tag check!
  assert.throws(
    () =>
      mobileProduct.unsealViaNativeSo({
        vspkBytes: mobilePack.vspkBytes,
        lease,
        packageName: "com.vibeslayer.mobile",
        runtimeApkCertSha256Hex: pirateApkCertSha256,
      }),
    /MOBILE_AUTH_TAG_FAILED/
  );
});

test("7. Product 7 (Data & AI Weights): 64 KiB O(1) random-access AEAD + per-lease FP32 tensor watermark", () => {
  const { authority } = makeAuthority();
  const numFloats = 65536; // 256 KiB = 4 random-access chunks
  const weights = new Float32Array(numFloats);
  for (let i = 0; i < numFloats; i++) {
    weights[i] = Math.sin(i * 0.01) * 0.5;
  }
  const rawBytes = Buffer.from(weights.buffer);

  const container = dataAiProduct.packRandomAccessWeights({
    authority,
    tensorId: "encoder.layer.0",
    plainBytes: rawBytes,
    chunkBytes: 65536,
  });
  assert.equal(container.chunkCount, 4);

  // Unseal ONLY chunk #2 in O(1) without decrypting chunks 0, 1, 3
  const grantA = dataAiProduct.issueChunkLease({
    authority,
    action: "ai.weights.slice",
    params: { tensorId: "encoder.layer.0", chunkIndex: 2 },
    subject: "tenant_alpha",
    scopes: ["ai:weights"],
    tensorId: "encoder.layer.0",
    chunkIndex: 2,
  });
  const grantB = dataAiProduct.issueChunkLease({
    authority,
    action: "ai.weights.slice",
    params: { tensorId: "encoder.layer.0", chunkIndex: 2 },
    subject: "tenant_beta",
    scopes: ["ai:weights"],
    tensorId: "encoder.layer.0",
    chunkIndex: 2,
  });

  assert.equal(grantA.wmSeedHex, undefined);
  assert.equal("wmSeedHex" in grantA, false);
  assert.notEqual(grantA.chunkKeyHex, grantB.chunkKeyHex);

  const sliceA = dataAiProduct.unsealWeightChunk({
    vspkRaBytes: container.vspkRaBytes,
    grant: grantA,
  });
  const sliceB = dataAiProduct.unsealWeightChunk({
    vspkRaBytes: container.vspkRaBytes,
    grant: grantB,
  });

  // Explicit split flow: server seals watermarked chunk under grant key -> pure client unseals without wmSeedHex
  const { unsealWeightChunkClient } = require("../src/client/data-ai-client.js");
  const sealedChunkA = dataAiProduct.sealWatermarkedChunkForGrant({
    authority,
    vspkRaBytes: container.vspkRaBytes,
    grant: grantA,
  });
  const clientSliceA = unsealWeightChunkClient({
    vspkRaBytes: sealedChunkA,
    grant: grantA,
  });
  assert.deepEqual(clientSliceA, sliceA);

  // Compromised client cannot unseal raw unwatermarked container directly using lease key
  assert.throws(
    () => unsealWeightChunkClient({ vspkRaBytes: container.vspkRaBytes, grant: grantA }),
    /unable to authenticate data|Unsupported state/
  );
  // Strict VSRA header & bounds validation rejects malformed containers
  assert.throws(
    () => unsealWeightChunkClient({ vspkRaBytes: Buffer.from("VSRA\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"), grant: grantA }),
    /BAD_VSRA/
  );
  assert.throws(
    () => dataAiProduct.extractTensorWatermark({
      authority,
      tensorId: "encoder.layer.0",
      chunkIndex: 2,
      baseFloats: new Float32Array(128),
      leakedFloats: new Float32Array(128),
      candidateWatermarkIds: [grantA.watermarkIdHex],
    }),
    /VSRA_TOO_SMALL/
  );

  // Verify numerical fidelity (>0.999999 cosine similarity, <= 2e-6 max diff) + traitor attribution
  const origSlice = new Float32Array(rawBytes.buffer, 2 * 65536, 16384);
  let maxAbsErr = 0;
  for (let i = 0; i < origSlice.length; i++) {
    const err = Math.abs(sliceA[i] - origSlice[i]);
    if (err > maxAbsErr) maxAbsErr = err;
  }
  assert.ok(maxAbsErr < 1e-5, `Expected tiny watermark perturbation <1e-5, got ${maxAbsErr}`);

  const trace = dataAiProduct.extractTensorWatermark({
    authority,
    tensorId: "encoder.layer.0",
    chunkIndex: 2,
    baseFloats: origSlice,
    leakedFloats: sliceA,
    candidateWatermarkIds: [grantA.watermarkIdHex, grantB.watermarkIdHex],
  });
  assert.equal(trace.matchedWatermarkIdHex, grantA.watermarkIdHex);
  assert.ok(trace.bitMatchRatio >= 0.99);
});

test("8. Unified CLI (`cli/vs.js`) packs, verifies, and audits standalone artifacts end to end", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vs-cli-test-"));
  try {
    const cliPath = path.resolve(__dirname, "../cli/vs.js");
    const initJson = JSON.parse(
      execFileSync(process.execPath, [cliPath, "init-keys", "--out", tmpDir], { encoding: "utf8" })
    );
    assert.equal(fs.existsSync(initJson.keyFile), true);

    const inFile = path.join(tmpDir, "secret.json");
    const outFile = path.join(tmpDir, "secret.json.vspk");
    fs.writeFileSync(inFile, JSON.stringify({ secret: "CLI_E2E_PAYLOAD_OK" }));

    const packRes = JSON.parse(
      execFileSync(
        process.execPath,
        [cliPath, "pack", "--keyfile", initJson.keyFile, "--in", inFile, "--out", outFile, "--asset-id", "cli-doc", "--origin", "https://cli.example"],
        { encoding: "utf8" }
      )
    );
    assert.equal(packRes.ok, true);
    assert.equal(fs.readFileSync(outFile).includes(Buffer.from("CLI_E2E_PAYLOAD_OK")), false);

    const verifyRes = JSON.parse(
      execFileSync(
        process.execPath,
        [cliPath, "verify", "--keyfile", initJson.keyFile, "--in", outFile, "--asset-id", "cli-doc", "--origin", "https://cli.example"],
        { encoding: "utf8" }
      )
    );
    assert.equal(verifyRes.ok, true);
    assert.equal(verifyRes.aeadVerified, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("9. Validation edge cases, grant verification, ChaCha20 VSPK, and tamper paths", () => {
  const { authority } = makeAuthority();

  assert.throws(() => defineSuitePolicy(null), /INVALID_POLICY/);
  assert.throws(() => defineSuitePolicy({ masterKey: "abcd" }), /masterKey/);
  assert.throws(
    () => defineSuitePolicy({ masterKey: crypto.randomBytes(32) }),
    /signing keypair/
  );
  assert.throws(
    () =>
      defineSuitePolicy({
        masterKey: crypto.randomBytes(32),
        signingPrivateKeyPem: "a",
        signingPublicKeyPem: "b",
        actions: {},
      }),
    /At least one action/
  );
  assert.throws(
    () =>
      defineSuitePolicy({
        masterKey: crypto.randomBytes(32),
        signingPrivateKeyPem: "a",
        signingPublicKeyPem: "b",
        actions: { bad: { product: "unknown" } },
      }),
    /Unsupported product/
  );
  assert.throws(
    () =>
      defineSuitePolicy({
        masterKey: crypto.randomBytes(32),
        signingPrivateKeyPem: "a",
        signingPublicKeyPem: "b",
        actions: {
          badParam: {
            product: "web",
            params: { x: { type: "number", min: 5, max: 1 } },
          },
        },
      }),
    /min > max/
  );
  assert.throws(
    () =>
      defineSuitePolicy({
        masterKey: crypto.randomBytes(32),
        signingPrivateKeyPem: "a",
        signingPublicKeyPem: "b",
        actions: {
          badEnum: {
            product: "web",
            params: { e: { type: "enum", values: [] } },
          },
        },
      }),
    /Empty enum/
  );

  // Grant Ed25519 sign & verify + tamper rejection
  const grant = authority.authorizeAndWrapKey({
    action: "web.asset.load",
    params: { bundleId: "ui-pack-v1", locale: "fr" },
    subject: "edge_user",
    scopes: ["web:asset"],
    origin: "https://app.vibeslayer.test",
    assetId: "ui-pack-v1",
  });
  const verified = authority.verifyGrantToken(grant.token);
  assert.equal(verified.sub, "edge_user");
  assert.equal(authority.resolveLeaker(grant.watermarkIdHex).subject, "edge_user");
  assert.equal(authority.resolveLeaker("0000000000000000"), null);

  assert.throws(() => authority.verifyGrantToken("malformed"), /BAD_GRANT/);
  assert.throws(
    () => authority.verifyGrantToken(grant.token.slice(0, -4) + "AAAA"),
    /BAD_SIGNATURE/
  );

  // Action validation rejections
  assert.throws(
    () => authority.checkPolicyAction("missing.act", {}, [], ""),
    /UNKNOWN_ACTION/
  );
  assert.throws(
    () => authority.checkPolicyAction("web.asset.load", null, ["web:asset"], "https://app.vibeslayer.test"),
    /BAD_PARAMS/
  );
  assert.throws(
    () => authority.checkPolicyAction("web.asset.load", { extra: 1 }, ["web:asset"], "https://app.vibeslayer.test"),
    /UNKNOWN_PARAM/
  );
  assert.throws(
    () => authority.checkPolicyAction("web.asset.load", {}, ["web:asset"], "https://app.vibeslayer.test"),
    /MISSING_PARAM/
  );
  assert.throws(
    () => authority.checkPolicyAction("web.asset.load", { bundleId: "ui-pack-v1" }, [], "https://app.vibeslayer.test"),
    /SCOPE_DENIED/
  );
  assert.throws(
    () => authority.checkPolicyAction("spatial.model.stream", { modelId: "white-exarch-v4", quality: 99 }, ["3d:stream"], "https://app.vibeslayer.test"),
    /PARAM_OUT_OF_RANGE/
  );

  // ChaCha20-Poly1305 VSPK roundtrip in Node core
  const { packVspk, unpackVspk } = require("../src/core/authority.js");
  const k = crypto.randomBytes(32);
  const vspk = packVspk({
    key32: k,
    domain: "native",
    assetId: "t1",
    origin: "local",
    cipher: "chacha20-poly1305",
    plainBytes: Buffer.from("CHACHA_OK"),
  });
  assert.equal(
    unpackVspk({ vspkBytes: vspk, key32: k, expectedDomain: "native", expectedOrigin: "local" }).toString("utf8"),
    "CHACHA_OK"
  );
  assert.throws(
    () => unpackVspk({ vspkBytes: Buffer.from("NOPE"), key32: k }),
    /BAD_VSPK/
  );
});

test("10. Adversarial Web/WASM/Spatial3D Ed25519 pinning, verified-claims-only, and non-finite exp enforcement", async () => {
  const { authority } = makeAuthority();
  const attackerKp = crypto.generateKeyPairSync("ed25519");
  const attackerPriv = attackerKp.privateKey.export({ type: "pkcs8", format: "pem" });
  const attackerPubSpkiB64 = attackerKp.publicKey.export({ format: "der", type: "spki" }).toString("base64url");

  const session = await webProduct.createBrowserEphemeralSession();
  const packed = webProduct.packWebAsset({
    authority,
    assetId: "ui-pack-v1",
    origin: "https://app.vibeslayer.test",
    plainBytes: Buffer.from("PINNED_OK", "utf8"),
  });
  const grant = authority.authorizeAndWrapKey({
    action: "web.asset.load",
    params: { bundleId: "ui-pack-v1", locale: "en-US" },
    subject: "user_pin",
    scopes: ["web:asset"],
    origin: "https://app.vibeslayer.test",
    assetId: "ui-pack-v1",
    clientEphemeralPublicKeySpkiB64: session.publicKeySpkiB64,
  });

  // Stripping authorityPublicKeySpkiB64 from an external copy without server pinning must fail closed (never skip verify)
  const detachedGrant = JSON.parse(JSON.stringify(grant));
  delete detachedGrant.authorityPublicKeySpkiB64;
  await assert.rejects(
    () =>
      webProduct.unsealVspkWithWebCrypto({
        vspkBytes: packed.vspkBytes,
        grant: detachedGrant,
        session,
        expectedProduct: "web",
        expectedOrigin: "https://app.vibeslayer.test",
      }),
    /MISSING_GRANT_SIGNATURE_KEY/
  );

  // Explicit pinned authority key must NOT fall back to grant.authorityPublicKeySpkiB64
  const forgedBody = Buffer.from(JSON.stringify({ ...grant.claims, exp: Date.now() + 60_000 }), "utf8").toString("base64url");
  const forgedSig = crypto.sign(null, Buffer.from(forgedBody, "utf8"), attackerPriv).toString("base64url");
  const attackerGrant = {
    token: `${forgedBody}.${forgedSig}`,
    authorityPublicKeySpkiB64: attackerPubSpkiB64,
    claims: grant.claims,
  };
  await assert.rejects(
    () =>
      webProduct.unsealWebAssetWithSession({
        vspkBytes: packed.vspkBytes,
        grant: attackerGrant,
        session,
        expectedOrigin: "https://app.vibeslayer.test",
        authorityPublicKeySpkiB64: grant.authorityPublicKeySpkiB64,
      }),
    /BAD_GRANT_SIGNATURE/
  );
  await assert.rejects(
    () =>
      webProduct.unsealVspkWithWebCrypto({
        vspkBytes: packed.vspkBytes,
        grant: attackerGrant,
        session,
        expectedProduct: "web",
        expectedOrigin: "https://app.vibeslayer.test",
        authorityPublicKeySpkiB64: "",
      }),
    /MISSING_GRANT_SIGNATURE_KEY/
  );

  // Non-finite / missing exp must be rejected even if validly signed, and multi-dot tokens must be rejected
  const noExpToken = authority.signGrantPayload({ ...grant.claims, exp: undefined });
  assert.throws(() => authority.verifyGrantToken(noExpToken), /BAD_GRANT/);
  assert.throws(() => authority.verifyGrantToken(`${grant.token}.extra`), /BAD_GRANT/);

  const noExpGrant = { token: noExpToken, authorityPublicKeySpkiB64: grant.authorityPublicKeySpkiB64 };
  await assert.rejects(
    () =>
      webProduct.deriveNonExtractableContentKey({
        grant: noExpGrant,
        session,
        expectedProduct: "web",
        expectedOrigin: "https://app.vibeslayer.test",
        authorityPublicKeySpkiB64: grant.authorityPublicKeySpkiB64,
      }),
    /MALFORMED_GRANT_CLAIMS/
  );

  // Mutated unverified grant.claims are ignored; verified claims govern origin/product checks cleanly
  const mutatedClaimsGrant = {
    token: grant.token,
    authorityPublicKeySpkiB64: grant.authorityPublicKeySpkiB64,
    claims: { ...grant.claims, org: "https://evil.example", exp: Date.now() + 999_999 },
  };
  const okPlain = await webProduct.unsealWebAssetWithSession({
    vspkBytes: packed.vspkBytes,
    grant: mutatedClaimsGrant,
    session,
    expectedOrigin: "https://app.vibeslayer.test",
    authorityPublicKeySpkiB64: grant.authorityPublicKeySpkiB64,
  });
  assert.equal(okPlain.toString("utf8"), "PINNED_OK");
});

test("11. Round 2 HIGH-1: wire self-signed attacker grants with embedded authorityPublicKeySpkiB64 fail across all web/wasm/spatial3d entrypoints", async () => {
  const webClient = require("../src/client/web-client.js");
  const wasmClient = require("../src/client/wasm-client.js");
  const { packVspk } = require("../src/core/authority.js");

  const { authority: legitAuth } = makeAuthority();
  const attackerKp = crypto.generateKeyPairSync("ed25519");
  const attackerPolicy = defineSuitePolicy({
    enabled: true,
    masterKey: crypto.randomBytes(32),
    signingPrivateKeyPem: attackerKp.privateKey.export({ type: "pkcs8", format: "pem" }),
    signingPublicKeyPem: attackerKp.publicKey.export({ type: "spki", format: "pem" }),
    actions: {
      "web.asset.read": { product: "web", params: { assetId: { type: "enum", values: ["evil-app"] } } },
      "wasm.module.boot": { product: "wasm", params: { moduleId: { type: "enum", values: ["evil-wasm"] } } },
      "spatial.model.stream": { product: "spatial-3d", params: { modelId: { type: "enum", values: ["evil-3d"] } } },
    },
  });
  const attackerAuth = createLeaseAuthority(attackerPolicy);
  const expectedOrigin = "https://app.vibeslayer.test";

  // Attacker self-signs & seals forged Web, WASM, and 3D payloads and embeds attacker pubkey inside the wire grant
  const atkWeb = webProduct.packWebAsset({
    authority: attackerAuth,
    assetId: "evil-app",
    origin: expectedOrigin,
    plainBytes: Buffer.from("console.log('FORGED_WEB');", "utf8"),
  });
  const webSess = await webProduct.createBrowserEphemeralSession();
  const atkWebGrantWire = JSON.parse(
    JSON.stringify(
      attackerAuth.authorizeAndWrapKey({
        action: "web.asset.read",
        params: { assetId: "evil-app" },
        subject: "attacker",
        scopes: ["web:read"],
        origin: expectedOrigin,
        assetId: "evil-app",
        clientEphemeralPublicKeySpkiB64: webSess.publicKeySpkiB64,
      })
    )
  );
  assert.equal(typeof atkWebGrantWire.authorityPublicKeySpkiB64, "string");

  const atkWasm = wasmProduct.packWasmModule({
    authority: attackerAuth,
    moduleId: "evil-wasm",
    origin: expectedOrigin,
    wasmBytes: wasmProduct.compileCompactComputeWasm(),
  });
  const wasmSess = await webProduct.createBrowserEphemeralSession();
  const atkWasmGrantWire = JSON.parse(
    JSON.stringify(
      attackerAuth.authorizeAndWrapKey({
        action: "wasm.module.boot",
        params: { moduleId: "evil-wasm" },
        subject: "attacker",
        scopes: ["wasm:boot"],
        origin: expectedOrigin,
        assetId: "evil-wasm",
        clientEphemeralPublicKeySpkiB64: wasmSess.publicKeySpkiB64,
      })
    )
  );

  const s3dSess = await webProduct.createBrowserEphemeralSession();
  const atk3dGrant = attackerAuth.authorizeAndWrapKey({
    action: "spatial.model.stream",
    params: { modelId: "evil-3d" },
    subject: "attacker",
    scopes: ["3d:stream"],
    origin: expectedOrigin,
    assetId: "evil-3d",
    clientEphemeralPublicKeySpkiB64: s3dSess.publicKeySpkiB64,
  });
  const atk3dDek = attackerAuth.deriveAssetKey("spatial-3d", "evil-3d", expectedOrigin);
  const atk3dVspk = packVspk({
    key32: atk3dDek,
    domain: "spatial-3d",
    assetId: "evil-3d",
    origin: expectedOrigin,
    cipher: "aes-256-gcm",
    plainBytes: Buffer.from(JSON.stringify({ vertexCount: 0, positionsB64: "" }), "utf8"),
  });
  const atk3dGrantWire = JSON.parse(JSON.stringify(atk3dGrant));

  await assert.rejects(() => webClient.verifyGrantEd25519Client(atkWebGrantWire), /MISSING_GRANT_SIGNATURE_KEY/);
  await assert.rejects(
    () =>
      webClient.unsealVspkClient({
        vspkBytes: atkWeb.vspkBytes,
        grant: atkWebGrantWire,
        session: webSess,
        expectedProduct: "web",
        expectedOrigin,
      }),
    /MISSING_GRANT_SIGNATURE_KEY/
  );
  await assert.rejects(
    () =>
      wasmClient.instantiateSealedWasmClient({
        vspkBytes: atkWasm.vspkBytes,
        grant: atkWasmGrantWire,
        session: wasmSess,
        expectedOrigin,
      }),
    /MISSING_GRANT_SIGNATURE_KEY/
  );
  await assert.rejects(
    () =>
      webProduct.unsealVspkWithWebCrypto({
        vspkBytes: atkWeb.vspkBytes,
        grant: atkWebGrantWire,
        session: webSess,
        expectedProduct: "web",
        expectedOrigin,
      }),
    /MISSING_GRANT_SIGNATURE_KEY/
  );
  await assert.rejects(
    () =>
      spatial3dProduct.unsealToGpuBuffers({
        vspkBytes: atk3dVspk,
        grant: atk3dGrantWire,
        session: s3dSess,
        expectedOrigin,
      }),
    /MISSING_GRANT_SIGNATURE_KEY/
  );

  // Legitimate client calls with explicit pinned authorityPublicKeySpkiB64 still succeed end-to-end
  const legitWasm = wasmProduct.packWasmModule({
    authority: legitAuth,
    moduleId: "simd-filter-core",
    origin: expectedOrigin,
    wasmBytes: wasmProduct.compileCompactComputeWasm(),
  });
  const legitSess = await webProduct.createBrowserEphemeralSession();
  const legitWasmGrant = legitAuth.authorizeAndWrapKey({
    action: "wasm.module.boot",
    params: { moduleId: "simd-filter-core" },
    subject: "trusted_client",
    scopes: ["wasm:boot"],
    origin: expectedOrigin,
    assetId: "simd-filter-core",
    clientEphemeralPublicKeySpkiB64: legitSess.publicKeySpkiB64,
  });
  const inst = await wasmClient.instantiateSealedWasmClient({
    vspkBytes: legitWasm.vspkBytes,
    grant: JSON.parse(JSON.stringify(legitWasmGrant)),
    session: legitSess,
    expectedOrigin,
    authorityPublicKeySpkiB64: legitWasmGrant.authorityPublicKeySpkiB64,
  });
  assert.equal(inst.exports.dot4_i32(1, 2, 3, 4), 14);
});

test("12. Round 2 LOW-3: Desktop enclave malformed/exit rejection + idempotent close, and VSRA bogus chunkCount bounds check", async () => {
  const { parseVsraForGrant } = require("../src/client/data-ai-client.js");
  const { authority: aiAuth } = makeAuthority();
  const aiGrant = dataAiProduct.issueChunkLease({
    authority: aiAuth,
    action: "ai.weights.slice",
    params: { tensorId: "encoder.layer.0", chunkIndex: 0 },
    subject: "worker_1",
    scopes: ["ai:weights"],
    tensorId: "encoder.layer.0",
    chunkIndex: 0,
  });

  // Forged VSRA declaring chunkCount=0x7fffffff while only containing 1 record must reject cleanly without OOM
  const tid = Buffer.from("encoder.layer.0", "utf8");
  const forgedVsra = Buffer.alloc(16 + tid.length + 32 + 16);
  forgedVsra.write("VSRA", 0, "ascii");
  forgedVsra.writeUInt32LE(16, 4);
  forgedVsra.writeUInt32LE(0x7fffffff, 8);
  forgedVsra.writeUInt32LE(tid.length, 12);
  tid.copy(forgedVsra, 16);
  assert.throws(() => parseVsraForGrant(forgedVsra, aiGrant), /BAD_VSRA/);
  assert.throws(
    () =>
      dataAiProduct.sealWatermarkedChunkForGrant({
        masterKey: crypto.randomBytes(32),
        authority: aiAuth,
        vspkRaBytes: forgedVsra,
        grant: aiGrant,
      }),
    /BAD_VSRA/
  );

  // Desktop enclave: malformed IPC & unexpected child exit never hang nextLine() or close()
  const kp = crypto.generateKeyPairSync("ed25519");
  const deskPolicy = defineSuitePolicy({
    enabled: true,
    masterKey: crypto.randomBytes(32),
    signingPrivateKeyPem: kp.privateKey.export({ type: "pkcs8", format: "pem" }),
    signingPublicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }),
    actions: {
      "desktop.ipc.invoke": {
        product: "desktop",
        params: {
          op: { type: "enum", values: ["compute-license-quote", "SHUTDOWN"] },
          seats: { type: "enum", values: ["10", "undefined"] },
        },
      },
    },
  });
  const deskAuth = createLeaseAuthority(deskPolicy);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vs-desk-exit-"));
  try {
    const bundlePath = path.join(tmpDir, "app.vsasar");
    desktopProduct.packDesktopBundle({
      authority: deskAuth,
      outPath: bundlePath,
      appId: "com.vibeslayer.exit.test",
      files: {
        "enclave/pricing-rules.json": Buffer.from(JSON.stringify({ enterpriseUnitUsd: 49, masterSalt: "S" })),
      },
    });
    const enclave = await desktopProduct.spawnDesktopEnclave({
      authority: deskAuth,
      bundlePath,
      appId: "com.vibeslayer.exit.test",
    });
    try {
      const badFrame = await enclave.invokeIpc({
        action: "desktop.ipc.invoke",
        params: { op: "compute-license-quote", seats: "undefined" },
        subject: "u1",
        scopes: ["desktop:ipc"],
      });
      assert.equal(badFrame.ok, false);
      assert.equal(badFrame.code, "BAD_IPC_FRAME");

      // Force child exit mid-request and confirm invokeIpc rejects and close() does not hang
      await assert.rejects(
        () =>
          enclave.invokeIpc({
            action: "desktop.ipc.invoke",
            params: { op: "SHUTDOWN", seats: "10" },
            subject: "u1",
            scopes: ["desktop:ipc"],
          }),
        /ENCLAVE_EXITED|ENCLAVE_STREAM_CLOSED/
      );
      await assert.rejects(
        () =>
          enclave.invokeIpc({
            action: "desktop.ipc.invoke",
            params: { op: "compute-license-quote", seats: "10" },
            subject: "u1",
            scopes: ["desktop:ipc"],
          }),
        /ENCLAVE_EXITED|ENCLAVE_STREAM_CLOSED/
      );
      await enclave.close();
      await enclave.close();
    } finally {
      await enclave.close();
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("13. Tier-4 Web Component antiStealth denies CloakBrowser invariants & enforces server attestation", async () => {
  const { authority } = makeAuthority();
  const origin = "https://app.vibeslayer.test";
  const packed = webProduct.packWebAsset({
    authority,
    assetId: "ui-pack-v1",
    origin,
    plainBytes: Buffer.from("export class PricingCard extends HTMLElement {}", "utf8"),
  });

  // CloakBrowser live invariant profile (Canvas2D=5, WebGL=5, Audio=512, DOMRect drift, OS Font lie)
  const cloakTelemetry = {
    canvas2dUniqueColors: 5,
    webglClearUniqueColors: 5,
    silentAudioNonZeroSamples: 512,
    domRectSubpixelDrift: true,
    osFontLie: true,
    d3d11ExtMismatch: true,
    platform: "Win32",
  };
  await assert.rejects(
    () => webProduct.createBrowserEphemeralSession({ antiStealth: "balanced", telemetry: cloakTelemetry }),
    /STEALTH_BROWSER_DENIED/
  );
  await assert.rejects(
    () => webProduct.createBrowserEphemeralSession({ antiStealth: "strict", telemetry: cloakTelemetry }),
    /STEALTH_BROWSER_DENIED/
  );
  // Even without OS font lie (--fingerprint-platform=linux), CloakBrowser still triggers 8/11 -> denied!
  await assert.rejects(
    () =>
      webProduct.createBrowserEphemeralSession({
        antiStealth: "balanced",
        telemetry: { ...cloakTelemetry, osFontLie: false, d3d11ExtMismatch: false, platform: "Linux x86_64" },
      }),
    /STEALTH_BROWSER_DENIED/
  );

  // Clean Chrome profile passes both balanced and strict and unseals Web Component cleanly
  const cleanTelemetry = {
    canvas2dUniqueColors: 1,
    webglClearUniqueColors: 1,
    silentAudioNonZeroSamples: 0,
    domRectSubpixelDrift: false,
    osFontLie: false,
    d3d11ExtMismatch: false,
    platform: "Linux x86_64",
  };
  const session = await webProduct.createBrowserEphemeralSession({
    antiStealth: "strict",
    ticket: "tk-wc-1",
    telemetry: cleanTelemetry,
  });
  assert.equal(session.attest.s, 0);
  const verified = await webProduct.verifyStealthAttestation({
    mode: "strict",
    headers: {
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/158.0.0.0 Safari/537.36",
      "sec-ch-ua-platform": '"Linux"',
    },
    attest: session.attest,
    ticket: "tk-wc-1",
    publicKey: session.publicKeySpkiB64,
  });
  assert.equal(verified.ok, true);

  // Server-side verification rejects missing attest, HeadlessChrome UA, and OS header lies
  await assert.rejects(
    () => webProduct.verifyStealthAttestation({ mode: "strict", headers: {}, attest: null }),
    /STEALTH_ATTEST_REQUIRED/
  );
  await assert.rejects(
    () =>
      webProduct.verifyStealthAttestation({
        mode: "strict",
        headers: { "user-agent": "Mozilla/5.0 HeadlessChrome/158.0.0.0" },
        attest: session.attest,
        ticket: "tk-wc-1",
        publicKey: session.publicKeySpkiB64,
      }),
    /AUTOMATION_DENIED/
  );

  const grant = authority.authorizeAndWrapKey({
    action: "web.asset.load",
    params: { bundleId: "ui-pack-v1", locale: "en-US" },
    subject: "user-wc-1",
    scopes: ["web:asset"],
    assetId: "ui-pack-v1",
    origin,
    clientEphemeralPublicKeySpkiB64: session.publicKeySpkiB64,
  });
  const unsealed = await webProduct.unsealWebAssetWithSession({
    vspkBytes: packed.vspkBytes,
    grant,
    session,
    expectedOrigin: origin,
    antiStealth: "strict",
    telemetry: cleanTelemetry,
  });
  assert.equal(unsealed.toString("utf8"), "export class PricingCard extends HTMLElement {}");
});
