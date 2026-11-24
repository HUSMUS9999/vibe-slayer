"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const {
  definePolicy,
  createGateway,
  createClient,
  buildBoundingBoxPreviewGlb,
  sealAssetAes256Gcm,
  unsealAssetAes256Gcm,
} = require("../src/index.js");

const SAMPLE_GLB = path.resolve(
  __dirname,
  "../../vibeslayer-native-core/tests/fixtures/sample_mesh.glb"
);

function makeTestPolicy() {
  const masterSecret = crypto.randomBytes(32);
  const fullModelBytes = fs.readFileSync(SAMPLE_GLB);
  const previewGlb = buildBoundingBoxPreviewGlb(fullModelBytes, {
    generator: "vibeslayer-policy-kit/preview-0.6.0-beta.1",
    nodeName: "Releasable_Bounds_Preview",
  });

  return {
    masterSecret,
    fullModelBytes,
    previewGlb,
    policy: definePolicy({
      version: "0.6.0-beta.1",
      enabled: true,
      signingSecret: masterSecret,
      defaultLeaseTtlMs: 30_000,
      actions: {
        "model.preview": {
          mode: "public-preview",
          allowedOrigins: ["https://app.example.test"],
          params: {
            modelId: { type: "enum", values: ["white-exarch"] },
            lod: { type: "int", min: 0, max: 2 },
          },
          rateLimit: { max: 5, windowMs: 60_000 },
          handler: async () => ({
            contentType: "model/gltf-binary",
            body: previewGlb,
          }),
        },
        "quote.compute": {
          mode: "server-only",
          requiredScopes: ["quote:run"],
          allowedOrigins: ["https://app.example.test"],
          replayWindowMs: 15_000,
          maxUses: 1,
          rateLimit: { max: 2, windowMs: 60_000 },
          redactFields: ["internalMargin", "supplierKey"],
          params: {
            units: { type: "int", min: 1, max: 1000 },
            tier: { type: "enum", values: ["std", "pro"] },
            express: { type: "boolean", optional: true },
          },
          handler: async ({ params, subject }) => {
            const unitPrice = params.tier === "pro" ? 19 : 11;
            const rush = params.express ? 25 : 0;
            return {
              subject,
              totalUsd: params.units * unitPrice + rush,
              internalMargin: 0.67,
              supplierKey: "SERVER_PRIVATE_SUPPLIER_SECRET",
            };
          },
        },
        "model.sealed": {
          mode: "client-sealed",
          requiredScopes: ["asset:sealed"],
          allowedOrigins: ["https://app.example.test"],
          replayWindowMs: 15_000,
          maxUses: 1,
          rateLimit: { max: 3, windowMs: 60_000 },
          params: {
            assetId: { type: "enum", values: ["white-exarch-sealed"] },
          },
          handler: async () => ({
            assetBytes: Buffer.from("BOUNDED_CLIENT_ASSET_BYTES_FOR_AUTHORIZED_VIEWER"),
          }),
        },
      },
    }),
  };
}

test("disabled policy emits nothing until explicitly enabled", async () => {
  const { masterSecret } = makeTestPolicy();
  const policy = definePolicy({
    version: "0.6.0-beta.1",
    signingSecret: masterSecret,
    actions: {
      "ping.check": {
        mode: "server-only",
        params: {},
        handler: async () => ({ ok: true }),
      },
    },
  });
  const gateway = createGateway(policy);
  await gateway.listen(0);
  try {
    const res = await fetch(`${gateway.url}/v1/action/ping.check`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.code, "POLICY_DISABLED");
  } finally {
    await gateway.close();
  }
});

test("definePolicy rejects invalid action mode and malformed parameter schema", () => {
  assert.throws(
    () =>
      definePolicy({
        enabled: true,
        signingSecret: crypto.randomBytes(32),
        actions: {
          bad: { mode: "magic-unbreakable", params: {}, handler: async () => ({}) },
        },
      }),
    /Unsupported action mode/
  );
  assert.throws(
    () =>
      definePolicy({
        enabled: true,
        signingSecret: crypto.randomBytes(32),
        actions: {
          badParam: {
            mode: "server-only",
            params: { count: { type: "int", min: 10, max: 2 } },
            handler: async () => ({}),
          },
        },
      }),
    /Invalid min\/max/
  );
});

test("public-preview serves a valid coarse GLB that omits original meshopt geometry", async () => {
  const { policy, fullModelBytes, previewGlb } = makeTestPolicy();
  assert.equal(previewGlb.subarray(0, 4).toString("ascii"), "glTF");
  assert.equal(previewGlb.readUInt32LE(4), 2);
  assert.equal(previewGlb.readUInt32LE(8), previewGlb.length);
  assert.ok(previewGlb.length < 4096);
  assert.notEqual(
    crypto.createHash("sha256").update(previewGlb).digest("hex"),
    crypto.createHash("sha256").update(fullModelBytes).digest("hex")
  );
  assert.equal(previewGlb.includes(fullModelBytes.subarray(512, 1024)), false);

  const gateway = createGateway(policy);
  await gateway.listen(0);
  try {
    const client = createClient({
      baseUrl: gateway.url,
      origin: "https://app.example.test",
    });
    const out = await client.invokeBinary("model.preview", {
      modelId: "white-exarch",
      lod: 0,
    });
    assert.equal(Buffer.compare(out, previewGlb), 0);
  } finally {
    await gateway.close();
  }
});

test("server-only enforces per-action parameter rules, scope, origin, replay, rate limit, and field redaction", async () => {
  const { policy } = makeTestPolicy();
  const gateway = createGateway(policy);
  await gateway.listen(0);
  try {
    const lease = gateway.issueLease({
      subject: "acct_42",
      scopes: ["quote:run"],
      origin: "https://app.example.test",
      action: "quote.compute",
    });
    const client = createClient({
      baseUrl: gateway.url,
      origin: "https://app.example.test",
      leaseToken: lease,
    });

    await assert.rejects(
      () => client.invoke("quote.compute", { units: 0, tier: "pro" }),
      /PARAM_OUT_OF_RANGE/
    );
    await assert.rejects(
      () => client.invoke("quote.compute", { units: 2, tier: "pro", injected: 1 }),
      /UNKNOWN_PARAM/
    );

    const wrongOriginClient = createClient({
      baseUrl: gateway.url,
      origin: "https://evil.example.test",
      leaseToken: lease,
    });
    await assert.rejects(
      () => wrongOriginClient.invoke("quote.compute", { units: 2, tier: "pro" }),
      /ORIGIN_DENIED/
    );

    const ok = await client.invoke("quote.compute", {
      units: 3,
      tier: "pro",
      express: true,
    });
    assert.deepEqual(ok, { subject: "acct_42", totalUsd: 82 });
    assert.equal("internalMargin" in ok, false);
    assert.equal("supplierKey" in ok, false);

    await assert.rejects(
      () => client.invoke("quote.compute", { units: 3, tier: "pro" }),
      /LEASE_REPLAYED/
    );

    const lease2 = gateway.issueLease({
      subject: "acct_42",
      scopes: ["quote:run"],
      origin: "https://app.example.test",
      action: "quote.compute",
    });
    const ok2 = await createClient({
      baseUrl: gateway.url,
      origin: "https://app.example.test",
      leaseToken: lease2,
    }).invoke("quote.compute", { units: 1, tier: "std" });
    assert.deepEqual(ok2, { subject: "acct_42", totalUsd: 11 });

    const lease3 = gateway.issueLease({
      subject: "acct_42",
      scopes: ["quote:run"],
      origin: "https://app.example.test",
      action: "quote.compute",
    });
    await assert.rejects(
      () =>
        createClient({
          baseUrl: gateway.url,
          origin: "https://app.example.test",
          leaseToken: lease3,
        }).invoke("quote.compute", { units: 1, tier: "std" }),
      /RATE_LIMITED/
    );
  } finally {
    await gateway.close();
  }
});

test("forged, expired, and wrong-scope leases are rejected", async () => {
  const { policy } = makeTestPolicy();
  const gateway = createGateway(policy);
  await gateway.listen(0);
  try {
    const expired = gateway.issueLease({
      subject: "acct_42",
      scopes: ["quote:run"],
      origin: "https://app.example.test",
      action: "quote.compute",
      ttlMs: -50,
    });
    await assert.rejects(
      () =>
        createClient({
          baseUrl: gateway.url,
          origin: "https://app.example.test",
          leaseToken: expired,
        }).invoke("quote.compute", { units: 1, tier: "std" }),
      /LEASE_EXPIRED/
    );

    const wrongScope = gateway.issueLease({
      subject: "acct_42",
      scopes: ["other:scope"],
      origin: "https://app.example.test",
      action: "quote.compute",
    });
    await assert.rejects(
      () =>
        createClient({
          baseUrl: gateway.url,
          origin: "https://app.example.test",
          leaseToken: wrongScope,
        }).invoke("quote.compute", { units: 1, tier: "std" }),
      /SCOPE_DENIED/
    );

    const tampered = wrongScope.slice(0, -4) + "AAAA";
    await assert.rejects(
      () =>
        createClient({
          baseUrl: gateway.url,
          origin: "https://app.example.test",
          leaseToken: tampered,
        }).invoke("quote.compute", { units: 1, tier: "std" }),
      /BAD_SIGNATURE/
    );
  } finally {
    await gateway.close();
  }
});

test("client-sealed uses AES-256-GCM with AAD; offline ciphertext fails without key and unseals once authorized", async () => {
  const { policy } = makeTestPolicy();
  const plain = Buffer.from("TEST_PAYLOAD_ONLY_FOR_AUTHORIZED_SESSION");
  const key = crypto.randomBytes(32);
  const aad = "action=model.sealed;asset=white-exarch-sealed";
  const envelope = sealAssetAes256Gcm(plain, key, aad);

  assert.equal(envelope.ciphertext.includes(plain), false);
  assert.throws(
    () => unsealAssetAes256Gcm(envelope, crypto.randomBytes(32), aad),
    /Unsupported state or unable to authenticate data/
  );
  assert.throws(
    () => unsealAssetAes256Gcm(envelope, key, "wrong-aad"),
    /Unsupported state or unable to authenticate data/
  );
  assert.deepEqual(unsealAssetAes256Gcm(envelope, key, aad), plain);

  const gateway = createGateway(policy);
  await gateway.listen(0);
  try {
    const lease = gateway.issueLease({
      subject: "acct_99",
      scopes: ["asset:sealed"],
      origin: "https://app.example.test",
      action: "model.sealed",
    });
    const client = createClient({
      baseUrl: gateway.url,
      origin: "https://app.example.test",
      leaseToken: lease,
    });
    const unsealed = await client.invokeSealed("model.sealed", {
      assetId: "white-exarch-sealed",
    });
    assert.equal(
      unsealed.toString("utf8"),
      "BOUNDED_CLIENT_ASSET_BYTES_FOR_AUTHORIZED_VIEWER"
    );
  } finally {
    await gateway.close();
  }
});

test("parameter validation, HTTP error paths, GLB edge cases, and body limits behave deterministically", async () => {
  assert.throws(() => definePolicy(null), /INVALID_POLICY/);
  assert.throws(
    () => definePolicy({ signingSecret: "short", actions: { a: { mode: "server-only", handler: async () => ({}) } } }),
    /signingSecret/
  );
  assert.throws(
    () => definePolicy({ signingSecret: "x".repeat(32), actions: {} }),
    /At least one action/
  );
  assert.throws(
    () =>
      definePolicy({
        signingSecret: "x".repeat(32),
        actions: { a: { mode: "server-only", handler: null } },
      }),
    /requires handler/
  );
  assert.throws(
    () =>
      definePolicy({
        signingSecret: "x".repeat(32),
        actions: {
          a: {
            mode: "server-only",
            params: { s: { type: "string", minLength: 5, maxLength: 2 } },
            handler: async () => ({}),
          },
        },
      }),
    /Invalid minLength\/maxLength/
  );
  assert.throws(
    () =>
      definePolicy({
        signingSecret: "x".repeat(32),
        actions: {
          a: {
            mode: "server-only",
            params: { e: { type: "enum", values: [] } },
            handler: async () => ({}),
          },
        },
      }),
    /non-empty values/
  );
  assert.throws(
    () =>
      definePolicy({
        signingSecret: "x".repeat(32),
        actions: {
          a: {
            mode: "server-only",
            params: { u: { type: "bogus" } },
            handler: async () => ({}),
          },
        },
      }),
    /Unsupported param type/
  );
  assert.throws(() => buildBoundingBoxPreviewGlb(Buffer.from("not-a-glb")), /INVALID_GLB/);
  assert.throws(() => sealAssetAes256Gcm(Buffer.from("a"), Buffer.alloc(16)), /32-byte key/);

  const minimalJson = Buffer.from(JSON.stringify({ asset: { version: "2.0" } }), "utf8");
  const padJson = Buffer.concat([minimalJson, Buffer.alloc((4 - (minimalJson.length % 4)) % 4, 0x20)]);
  const minimalGlb = Buffer.alloc(20 + padJson.length);
  minimalGlb.write("glTF", 0, "ascii");
  minimalGlb.writeUInt32LE(2, 4);
  minimalGlb.writeUInt32LE(minimalGlb.length, 8);
  minimalGlb.writeUInt32LE(padJson.length, 12);
  minimalGlb.writeUInt32LE(0x4e4f534a, 16);
  padJson.copy(minimalGlb, 20);
  const fallbackPreview = buildBoundingBoxPreviewGlb(minimalGlb);
  assert.equal(fallbackPreview.subarray(0, 4).toString("ascii"), "glTF");

  const policy = definePolicy({
    enabled: true,
    signingSecret: "s".repeat(32),
    maxBodyBytes: 128,
    actions: {
      "check.types": {
        mode: "server-only",
        params: {
          ratio: { type: "number", min: 0.1, max: 1.5 },
          tag: { type: "string", minLength: 2, maxLength: 8, pattern: /^[a-z0-9_-]+$/ },
          flag: { type: "boolean" },
          count: { type: "int", min: 1, max: 5 },
        },
        handler: async ({ params }) => params,
      },
      "sealed.json": {
        mode: "client-sealed",
        redactFields: ["secretField"],
        params: {},
        handler: async () => ({ visible: 1, secretField: "HIDDEN" }),
      },
    },
  });

  const gateway = createGateway(policy);
  await gateway.listen(0);
  try {
    const r404 = await fetch(`${gateway.url}/unknown`, { method: "GET" });
    assert.equal(r404.status, 404);

    const rUnknownAct = await fetch(`${gateway.url}/v1/action/nope`, {
      method: "POST",
      body: "{}",
    });
    assert.equal(rUnknownAct.status, 404);

    const rBadJson = await fetch(`${gateway.url}/v1/action/check.types`, {
      method: "POST",
      body: "{bad",
    });
    assert.equal(rBadJson.status, 400);

    const rTooBig = await fetch(`${gateway.url}/v1/action/check.types`, {
      method: "POST",
      body: JSON.stringify({ pad: "x".repeat(300) }),
    });
    assert.equal(rTooBig.status, 413);

    const rNoLease = await fetch(`${gateway.url}/v1/action/check.types`, {
      method: "POST",
      body: JSON.stringify({ params: { ratio: 0.5, tag: "ab", flag: true, count: 1 } }),
    });
    assert.equal(rNoLease.status, 401);

    const wrongActionLease = gateway.issueLease({
      subject: "u1",
      action: "sealed.json",
    });
    const cWrongAct = createClient({ baseUrl: gateway.url, leaseToken: wrongActionLease });
    await assert.rejects(
      () => cWrongAct.invoke("check.types", { ratio: 0.5, tag: "ab", flag: true, count: 1 }),
      /ACTION_MISMATCH/
    );

    const cJsonSealed = createClient({ baseUrl: gateway.url, leaseToken: wrongActionLease });
    const unsealedJson = JSON.parse((await cJsonSealed.invokeSealed("sealed.json", {})).toString("utf8"));
    assert.deepEqual(unsealedJson, { visible: 1 });

    const makeClient = () =>
      createClient({
        baseUrl: gateway.url,
        leaseToken: gateway.issueLease({ subject: "u1", action: "check.types", maxUses: 10 }),
      });
    const client = makeClient();
    await assert.rejects(() => client.invoke("check.types", []), /BAD_PARAMS/);
    await assert.rejects(() => client.invoke("check.types", { ratio: 0.5, tag: "ab", flag: true }), /MISSING_PARAM/);
    await assert.rejects(
      () => client.invoke("check.types", { ratio: "bad", tag: "ab", flag: true, count: 1 }),
      /BAD_PARAM_TYPE/
    );
    await assert.rejects(
      () => client.invoke("check.types", { ratio: 9.9, tag: "ab", flag: true, count: 1 }),
      /PARAM_OUT_OF_RANGE/
    );
    await assert.rejects(
      () => client.invoke("check.types", { ratio: 0.5, tag: 123, flag: true, count: 1 }),
      /BAD_PARAM_TYPE/
    );
    await assert.rejects(
      () => client.invoke("check.types", { ratio: 0.5, tag: "a", flag: true, count: 1 }),
      /PARAM_OUT_OF_RANGE/
    );
    await assert.rejects(
      () => client.invoke("check.types", { ratio: 0.5, tag: "BAD!", flag: true, count: 1 }),
      /PARAM_PATTERN_MISMATCH/
    );
    await assert.rejects(
      () => client.invoke("check.types", { ratio: 0.5, tag: "ab", flag: "no", count: 1 }),
      /BAD_PARAM_TYPE/
    );
    await assert.rejects(
      () => client.invoke("check.types", { ratio: 0.5, tag: "ab", flag: true, count: 1.5 }),
      /BAD_PARAM_TYPE/
    );
  } finally {
    await gateway.close();
  }
});

test("antiStealth strict/balanced denies CloakBrowser invariants and headless headers on Web Component actions", async () => {
  const policy = definePolicy({
    enabled: true,
    antiStealth: "strict",
    signingSecret: crypto.randomBytes(32),
    actions: {
      "wc.render": {
        mode: "server-only",
        allowedOrigins: ["https://wc.example.test"],
        params: { widget: { type: "string", minLength: 1, maxLength: 64 } },
        handler: async ({ params }) => ({ html: `<vs-card>${params.widget}</vs-card>` }),
      },
    },
  });
  const gateway = createGateway(policy);
  await gateway.listen(0);
  try {
    const mkLease = () =>
      gateway.issueLease({
        subject: "wc_user",
        origin: "https://wc.example.test",
        action: "wc.render",
        maxUses: 5,
      });

    // 1. CloakBrowser telemetry rejected client-side before even touching server
    const cloakClient = createClient({
      baseUrl: gateway.url,
      origin: "https://wc.example.test",
      leaseToken: mkLease(),
      antiStealth: "strict",
      telemetry: {
        canvas2dUniqueColors: 5,
        webglClearUniqueColors: 5,
        silentAudioNonZeroSamples: 512,
        domRectSubpixelDrift: true,
        osFontLie: true,
        platform: "Win32",
      },
    });
    await assert.rejects(() => cloakClient.invoke("wc.render", { widget: "pro" }), /STEALTH_BROWSER_DENIED/);

    // 2. Client skipping attestation rejected server-side with 403 STEALTH_ATTEST_REQUIRED
    const noAttestClient = createClient({
      baseUrl: gateway.url,
      origin: "https://wc.example.test",
      leaseToken: mkLease(),
      antiStealth: "off",
    });
    await assert.rejects(() => noAttestClient.invoke("wc.render", { widget: "pro" }), /STEALTH_ATTEST_REQUIRED/);

    // 3. HeadlessChrome User-Agent rejected server-side with 403 AUTOMATION_DENIED
    const headlessClient = createClient({
      baseUrl: gateway.url,
      origin: "https://wc.example.test",
      leaseToken: mkLease(),
      antiStealth: "strict",
      telemetry: { platform: "Linux x86_64" },
      extraHeaders: { "user-agent": "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/158.0.0.0" },
    });
    await assert.rejects(() => headlessClient.invoke("wc.render", { widget: "pro" }), /AUTOMATION_DENIED/);

    // 4. Clean real Chrome telemetry + consistent UA succeeds cleanly
    const cleanClient = createClient({
      baseUrl: gateway.url,
      origin: "https://wc.example.test",
      leaseToken: mkLease(),
      antiStealth: "strict",
      telemetry: {
        canvas2dUniqueColors: 1,
        webglClearUniqueColors: 1,
        silentAudioNonZeroSamples: 0,
        domRectSubpixelDrift: false,
        osFontLie: false,
        platform: "Linux x86_64",
      },
      extraHeaders: {
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/158.0.0.0 Safari/537.36",
        "sec-ch-ua-platform": '"Linux"',
      },
    });
    const out = await cleanClient.invoke("wc.render", { widget: "pro" });
    assert.deepEqual(out, { html: "<vs-card>pro</vs-card>" });
  } finally {
    await gateway.close();
  }
});

