"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  definePolicy,
  createGateway,
  createClient,
  buildBoundingBoxPreviewGlb,
} = require("./src/index.js");

const SAMPLE_GLB = path.resolve(
  __dirname,
  "../vibeslayer-native-core/tests/fixtures/sample_mesh.glb"
);

// Developer-authored source configuration: every action declares its mode and parameter rules.
function createAppPolicy({ enabled = false, signingSecret }) {
  const previewGlb = buildBoundingBoxPreviewGlb(fs.readFileSync(SAMPLE_GLB), {
    nodeName: "WhiteExarch_Bounds_Preview",
  });

  return definePolicy({
    version: "0.6.0-beta.1",
    enabled,
    signingSecret,
    defaultLeaseTtlMs: 20_000,
    actions: {
      "scene.previewGlb": {
        mode: "public-preview",
        allowedOrigins: ["https://app.example.test"],
        rateLimit: { max: 30, windowMs: 60_000 },
        params: {
          modelId: { type: "enum", values: ["white-exarch"] },
          lod: { type: "int", min: 0, max: 1, optional: true },
        },
        handler: async () => ({
          contentType: "model/gltf-binary",
          body: previewGlb,
        }),
      },
      "pricing.evaluate": {
        mode: "server-only",
        requiredScopes: ["pricing:quote"],
        allowedOrigins: ["https://app.example.test"],
        replayWindowMs: 20_000,
        maxUses: 1,
        rateLimit: { max: 10, windowMs: 60_000 },
        redactFields: ["costBasisUsd", "privateFormulaSalt"],
        params: {
          seats: { type: "int", min: 1, max: 5000 },
          plan: { type: "enum", values: ["team", "enterprise"] },
          annual: { type: "boolean" },
          coupon: { type: "string", minLength: 4, maxLength: 16, pattern: /^[A-Z0-9_-]+$/, optional: true },
        },
        handler: async ({ params, subject }) => {
          const base = params.plan === "enterprise" ? 49 : 19;
          const discount = params.annual ? 0.85 : 1.0;
          const gross = Math.round(params.seats * base * discount);
          return {
            subject,
            quoteUsd: gross,
            costBasisUsd: Math.round(gross * 0.22),
            privateFormulaSalt: "SERVER_SECRET_NEVER_SENT",
          };
        },
      },
      "scene.leasedPack": {
        mode: "client-sealed",
        requiredScopes: ["scene:lease"],
        allowedOrigins: ["https://app.example.test"],
        maxUses: 1,
        rateLimit: { max: 5, windowMs: 60_000 },
        params: {
          packId: { type: "enum", values: ["lod1-material-pack"] },
        },
        handler: async () => ({
          assetBytes: Buffer.from(JSON.stringify({ rim: 1.45, bevel: 0.13 }), "utf8"),
        }),
      },
    },
  });
}

if (require.main === module) {
  (async () => {
    const secret = crypto.randomBytes(32);
    const gateway = createGateway(createAppPolicy({ enabled: true, signingSecret: secret }));
    await gateway.listen(0);
    try {
      const lease = gateway.issueLease({
        subject: "user_demo",
        scopes: ["pricing:quote"],
        origin: "https://app.example.test",
        action: "pricing.evaluate",
      });
      const client = createClient({
        baseUrl: gateway.url,
        origin: "https://app.example.test",
        leaseToken: lease,
      });
      const quote = await client.invoke("pricing.evaluate", {
        seats: 25,
        plan: "enterprise",
        annual: true,
      });
      console.log(JSON.stringify(quote));
    } finally {
      await gateway.close();
    }
  })();
}

module.exports = { createAppPolicy };
