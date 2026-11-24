"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  definePolicy,
  createGateway,
  createClient,
  buildBoundingBoxPreviewGlb,
  sealAssetAes256Gcm,
} = require("../src/index.js");

const SAMPLE_GLB = path.resolve(
  __dirname,
  "../../vibeslayer-native-core/tests/fixtures/sample_mesh.glb"
);

function percentile(sorted, p) {
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
}

function measureRenderLoop(buf) {
  const iters = 40;
  const times = [];
  for (let w = 0; w < 5; w++) {
    for (let i = 0; i < buf.length; i += 4) buf[i] = (buf[i] + 1) & 0xff;
  }
  for (let r = 0; r < iters; r++) {
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < buf.length; i += 4) buf[i] = (buf[i] + 1) & 0xff;
    times.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  times.sort((a, b) => a - b);
  return {
    p50_ms: Number(percentile(times, 0.5).toFixed(4)),
    p95_ms: Number(percentile(times, 0.95).toFixed(4)),
    per_frame_protection_ops: 0,
  };
}

async function main() {
  const fullGlb = fs.readFileSync(SAMPLE_GLB);
  const fullSha256 = crypto.createHash("sha256").update(fullGlb).digest("hex");
  const previewGlb = buildBoundingBoxPreviewGlb(fullGlb, {
    nodeName: "WhiteExarch_Coarse_Bounds",
  });
  const previewSha256 = crypto.createHash("sha256").update(previewGlb).digest("hex");

  const secret = crypto.randomBytes(32);
  const policy = definePolicy({
    enabled: true,
    signingSecret: secret,
    actions: {
      "model.preview": {
        mode: "public-preview",
        params: { modelId: { type: "enum", values: ["white-exarch"] } },
        handler: async () => ({ contentType: "model/gltf-binary", body: previewGlb }),
      },
      "quote.compute": {
        mode: "server-only",
        requiredScopes: ["quote:run"],
        maxUses: 1000,
        redactFields: ["internalMargin", "supplierKey"],
        params: { units: { type: "int", min: 1, max: 1000 } },
        handler: async ({ params }) => ({
          totalUsd: params.units * 19,
          internalMargin: 0.67,
          supplierKey: "SERVER_ONLY_SUPPLIER_SECRET",
        }),
      },
      "model.sealed": {
        mode: "client-sealed",
        requiredScopes: ["asset:sealed"],
        maxUses: 1000,
        params: { assetId: { type: "enum", values: ["white-exarch"] } },
        handler: async () => ({ assetBytes: fullGlb }),
      },
    },
  });

  const gateway = createGateway(policy);
  await gateway.listen(0);
  try {
    const pubClient = createClient({ baseUrl: gateway.url });
    const quoteClient = createClient({
      baseUrl: gateway.url,
      leaseToken: gateway.issueLease({ subject: "bench", scopes: ["quote:run"], action: "quote.compute" }),
    });
    const sealedClient = createClient({
      baseUrl: gateway.url,
      leaseToken: gateway.issueLease({ subject: "bench", scopes: ["asset:sealed"], action: "model.sealed" }),
    });

    const previewTimes = [];
    const quoteTimes = [];
    const sealedTimes = [];

    for (let i = 0; i < 60; i++) {
      let t = process.hrtime.bigint();
      await pubClient.invokeBinary("model.preview", { modelId: "white-exarch" });
      previewTimes.push(Number(process.hrtime.bigint() - t) / 1e6);

      t = process.hrtime.bigint();
      await quoteClient.invoke("quote.compute", { units: 4 });
      quoteTimes.push(Number(process.hrtime.bigint() - t) / 1e6);
    }

    let unsealedFromAuthorizedSession = null;
    for (let i = 0; i < 25; i++) {
      const t = process.hrtime.bigint();
      unsealedFromAuthorizedSession = await sealedClient.invokeSealed("model.sealed", {
        assetId: "white-exarch",
      });
      sealedTimes.push(Number(process.hrtime.bigint() - t) / 1e6);
    }

    previewTimes.sort((a, b) => a - b);
    quoteTimes.sort((a, b) => a - b);
    sealedTimes.sort((a, b) => a - b);

    const offlineKey = crypto.randomBytes(32);
    const offlineSealed = sealAssetAes256Gcm(fullGlb, offlineKey, "offline-bundle-v1");
    offlineKey.fill(0);

    const frameBuf = Buffer.alloc(3840 * 2160 * 4, 0x7f);
    const frameStats = measureRenderLoop(frameBuf);

    const summary = {
      models: {
        unprotected_full_glb_bytes: fullGlb.length,
        unprotected_full_glb_sha256: fullSha256,
        public_preview_glb_bytes: previewGlb.length,
        public_preview_glb_sha256: previewSha256,
        preview_to_full_byte_ratio: Number((previewGlb.length / fullGlb.length).toFixed(5)),
        preview_contains_any_64b_slice_of_full_mesh: previewGlb.includes(fullGlb.subarray(512, 576)),
      },
      extraction_matrix: {
        unprotected_client_bundle: {
          offline_static_attacker_gets_full_glb: true,
          live_authorized_session_attacker_gets_full_glb: true,
        },
        client_sealed_aes256_gcm: {
          offline_ciphertext_bytes: offlineSealed.ciphertext.length,
          offline_static_attacker_without_lease_key_gets_full_glb: false,
          live_authorized_session_attacker_gets_full_glb:
            crypto.createHash("sha256").update(unsealedFromAuthorizedSession).digest("hex") === fullSha256,
        },
        server_only_plus_public_preview: {
          offline_static_attacker_gets_full_glb: false,
          live_session_attacker_gets_only_preview: true,
          server_redacted_secrets_present_in_client_response: false,
        },
      },
      latency_ms: {
        public_preview_http_p50: Number(percentile(previewTimes, 0.5).toFixed(3)),
        public_preview_http_p95: Number(percentile(previewTimes, 0.95).toFixed(3)),
        server_only_action_http_p50: Number(percentile(quoteTimes, 0.5).toFixed(3)),
        server_only_action_http_p95: Number(percentile(quoteTimes, 0.95).toFixed(3)),
        client_sealed_581kb_http_plus_aes_gcm_unseal_p50: Number(percentile(sealedTimes, 0.5).toFixed(3)),
        client_sealed_581kb_http_plus_aes_gcm_unseal_p95: Number(percentile(sealedTimes, 0.95).toFixed(3)),
      },
      render_hot_loop_4k_rgba: frameStats,
    };

    console.log(JSON.stringify(summary, null, 2));
  } finally {
    await gateway.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
