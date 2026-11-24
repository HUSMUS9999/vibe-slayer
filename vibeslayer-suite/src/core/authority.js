"use strict";

const crypto = require("node:crypto");

const CONFIG = Object.freeze({
  VERSION: "0.8.0-beta.2",
  DEFAULT_ENABLED: false,
  DEFAULT_TTL_MS: 30_000,
  MAGIC_VSPK: "VSPK",
  MAGIC_VSRA: "VSRA",
  PRODUCTS: new Set(["web", "wasm", "spatial-3d", "native", "desktop", "mobile", "data-ai"]),
  PARAM_TYPES: new Set(["int", "number", "string", "boolean", "enum"]),
});

function vsError(code, message) {
  const err = new Error(`${code}: ${message}`);
  err.code = code;
  return err;
}

function validateParamRule(name, rule) {
  if (!rule || typeof rule !== "object" || !CONFIG.PARAM_TYPES.has(rule.type)) {
    throw vsError("INVALID_POLICY", `Unsupported param rule for ${name}`);
  }
  if (
    (rule.type === "int" || rule.type === "number") &&
    rule.min !== undefined &&
    rule.max !== undefined &&
    rule.min > rule.max
  ) {
    throw vsError("INVALID_POLICY", `min > max for ${name}`);
  }
  if (rule.type === "enum" && (!Array.isArray(rule.values) || rule.values.length === 0)) {
    throw vsError("INVALID_POLICY", `Empty enum for ${name}`);
  }
}

function defineSuitePolicy(raw) {
  if (!raw || typeof raw !== "object") {
    throw vsError("INVALID_POLICY", "Policy configuration object required");
  }
  const masterKey = Buffer.isBuffer(raw.masterKey)
    ? Buffer.from(raw.masterKey)
    : typeof raw.masterKey === "string"
      ? Buffer.from(raw.masterKey, "hex")
      : null;
  if (!masterKey || masterKey.length !== 32) {
    throw vsError("INVALID_POLICY", "masterKey must be 32 bytes");
  }
  if (!raw.signingPrivateKeyPem || !raw.signingPublicKeyPem) {
    throw vsError("INVALID_POLICY", "Ed25519 signing keypair PEMs required");
  }
  if (!raw.actions || typeof raw.actions !== "object" || Object.keys(raw.actions).length === 0) {
    throw vsError("INVALID_POLICY", "At least one action required");
  }

  const actions = {};
  for (const [name, spec] of Object.entries(raw.actions)) {
    if (!spec || !CONFIG.PRODUCTS.has(spec.product)) {
      throw vsError("INVALID_POLICY", `Unsupported product on action ${name}`);
    }
    const params = spec.params || {};
    for (const [pName, pRule] of Object.entries(params)) {
      validateParamRule(pName, pRule);
    }
    actions[name] = Object.freeze({
      name,
      product: spec.product,
      params: Object.freeze({ ...params }),
      allowedOrigins: Object.freeze([...(spec.allowedOrigins || [])]),
      requiredScopes: Object.freeze([...(spec.requiredScopes || [])]),
      ttlMs: spec.ttlMs ?? CONFIG.DEFAULT_TTL_MS,
      maxUses: spec.maxUses ?? 1,
      watermark: Boolean(spec.watermark),
    });
  }

  return Object.freeze({
    version: raw.version || CONFIG.VERSION,
    enabled: Boolean(raw.enabled ?? CONFIG.DEFAULT_ENABLED),
    masterKey,
    signingPrivateKeyPem: raw.signingPrivateKeyPem,
    signingPublicKeyPem: raw.signingPublicKeyPem,
    actions: Object.freeze(actions),
  });
}

function validateActionParams(rules, candidate) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw vsError("BAD_PARAMS", "Params must be an object");
  }
  for (const k of Object.keys(candidate)) {
    if (!Object.prototype.hasOwnProperty.call(rules, k)) {
      throw vsError("UNKNOWN_PARAM", `Unexpected parameter ${k}`);
    }
  }
  const clean = {};
  for (const [name, rule] of Object.entries(rules)) {
    const v = candidate[name];
    if (v === undefined) {
      if (rule.optional) continue;
      throw vsError("MISSING_PARAM", `Missing parameter ${name}`);
    }
    if (rule.type === "int") {
      if (!Number.isInteger(v)) throw vsError("BAD_PARAM_TYPE", `${name} must be integer`);
      if ((rule.min !== undefined && v < rule.min) || (rule.max !== undefined && v > rule.max)) {
        throw vsError("PARAM_OUT_OF_RANGE", `${name} out of range`);
      }
    } else if (rule.type === "number") {
      if (typeof v !== "number" || !Number.isFinite(v)) {
        throw vsError("BAD_PARAM_TYPE", `${name} must be finite number`);
      }
      if ((rule.min !== undefined && v < rule.min) || (rule.max !== undefined && v > rule.max)) {
        throw vsError("PARAM_OUT_OF_RANGE", `${name} out of range`);
      }
    } else if (rule.type === "string") {
      if (typeof v !== "string") throw vsError("BAD_PARAM_TYPE", `${name} must be string`);
      if (
        (rule.minLength !== undefined && v.length < rule.minLength) ||
        (rule.maxLength !== undefined && v.length > rule.maxLength)
      ) {
        throw vsError("PARAM_OUT_OF_RANGE", `${name} length out of bounds`);
      }
    } else if (rule.type === "boolean") {
      if (typeof v !== "boolean") throw vsError("BAD_PARAM_TYPE", `${name} must be boolean`);
    } else if (rule.type === "enum") {
      if (!rule.values.includes(v)) throw vsError("PARAM_OUT_OF_RANGE", `${name} invalid enum`);
    }
    clean[name] = v;
  }
  return clean;
}

function deriveAssetKey32(masterKey, domain, assetId, origin = "") {
  const info = `VSPK_KEY_V1|${domain}|${assetId}|${origin}`;
  return Buffer.from(crypto.hkdfSync("sha256", masterKey, Buffer.from(assetId, "utf8"), Buffer.from(info, "utf8"), 32));
}

function packVspk({ key32, domain, assetId, origin = "", cipher = "aes-256-gcm", plainBytes }) {
  const plain = Buffer.isBuffer(plainBytes) ? plainBytes : Buffer.from(plainBytes);
  const hdrJson = Buffer.from(JSON.stringify({ domain, assetId, origin }), "utf8");
  const aad = Buffer.from(`VSPK1|${domain}|${assetId}|${origin}`, "utf8");
  const iv = crypto.randomBytes(12);
  const cipherId = cipher === "chacha20-poly1305" ? 2 : 1;

  const enc = crypto.createCipheriv(cipher, key32, iv, { authTagLength: 16 });
  if (cipherId === 2) {
    enc.setAAD(aad, { plaintextLength: plain.length });
  } else {
    enc.setAAD(aad);
  }
  const ct = Buffer.concat([enc.update(plain), enc.final()]);
  const tag = enc.getAuthTag();

  const prefix = Buffer.alloc(36);
  prefix.write(CONFIG.MAGIC_VSPK, 0, "ascii");
  prefix.writeUInt8(1, 4);
  prefix.writeUInt8(cipherId, 5);
  prefix.writeUInt16LE(hdrJson.length, 6);
  iv.copy(prefix, 8);
  tag.copy(prefix, 20);

  return Buffer.concat([prefix, hdrJson, ct]);
}

function parseVspkHeader(vspkBytes) {
  const buf = Buffer.isBuffer(vspkBytes) ? vspkBytes : Buffer.from(vspkBytes);
  if (buf.length < 36 || buf.subarray(0, 4).toString("ascii") !== CONFIG.MAGIC_VSPK) {
    throw vsError("BAD_VSPK", "Invalid VSPK magic header");
  }
  const version = buf.readUInt8(4);
  const cipherId = buf.readUInt8(5);
  const hdrLen = buf.readUInt16LE(6);
  if (version !== 1 || (cipherId !== 1 && cipherId !== 2) || 36 + hdrLen > buf.length) {
    throw vsError("BAD_VSPK", "Malformed VSPK header bounds or version");
  }
  const iv = buf.subarray(8, 20);
  const tag = buf.subarray(20, 36);
  const header = JSON.parse(buf.subarray(36, 36 + hdrLen).toString("utf8"));
  if (!header || typeof header !== "object" || Array.isArray(header)) {
    throw vsError("BAD_VSPK", "Malformed VSPK JSON header");
  }
  const ciphertext = buf.subarray(36 + hdrLen);
  return { version, cipherId, iv, tag, header, ciphertext };
}

function unpackVspk({ vspkBytes, key32, expectedDomain, expectedOrigin }) {
  const { cipherId, iv, tag, header, ciphertext } = parseVspkHeader(vspkBytes);
  if (expectedDomain && header.domain !== expectedDomain) {
    throw vsError("DOMAIN_MISMATCH", `Expected ${expectedDomain}, got ${header.domain}`);
  }
  if (expectedOrigin !== undefined && header.origin !== expectedOrigin) {
    throw vsError("ORIGIN_DENIED", `Expected origin ${expectedOrigin}, got ${header.origin}`);
  }
  const algo = cipherId === 2 ? "chacha20-poly1305" : "aes-256-gcm";
  const aad = Buffer.from(`VSPK1|${header.domain}|${header.assetId}|${header.origin}`, "utf8");
  const dec = crypto.createDecipheriv(algo, key32, iv, { authTagLength: 16 });
  if (cipherId === 2) {
    dec.setAAD(aad, { plaintextLength: ciphertext.length });
  } else {
    dec.setAAD(aad);
  }
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(ciphertext), dec.final()]);
}

const SERVER_ONLY_GRANT_SEEDS = new WeakMap();

function createLeaseAuthority(policy) {
  const watermarkLedger = new Map();
  const authorityPublicKeySpkiB64 =
    policy.signingPublicKeyPem.includes("BEGIN")
      ? crypto
          .createPublicKey(policy.signingPublicKeyPem)
          .export({ format: "der", type: "spki" })
          .toString("base64url")
      : null;

  function checkPolicyAction(actionName, params, scopes = [], origin = "") {
    if (!policy.enabled) {
      throw vsError("POLICY_DISABLED", "Suite policy is disabled");
    }
    const act = policy.actions[actionName];
    if (!act) {
      throw vsError("UNKNOWN_ACTION", `Action not defined: ${actionName}`);
    }
    validateActionParams(act.params, params);
    if (act.allowedOrigins.length > 0 && !act.allowedOrigins.includes(origin)) {
      throw vsError("ORIGIN_DENIED", `Origin ${origin} denied for ${actionName}`);
    }
    for (const s of act.requiredScopes) {
      if (!scopes.includes(s)) {
        throw vsError("SCOPE_DENIED", `Missing scope ${s}`);
      }
    }
    return act;
  }

  function computeWatermarkCarrierSeed(assetId, watermarkIdHex) {
    return crypto
      .createHmac("sha256", policy.masterKey)
      .update(`VS_WM_CARRIER_V1|${assetId}|${watermarkIdHex}`)
      .digest();
  }

  function signGrantPayload(payloadObj) {
    const bodyB64 = Buffer.from(JSON.stringify(payloadObj), "utf8").toString("base64url");
    const sig = crypto.sign(null, Buffer.from(bodyB64, "utf8"), policy.signingPrivateKeyPem).toString("base64url");
    return `${bodyB64}.${sig}`;
  }

  function verifyGrantToken(token) {
    if (typeof token !== "string") {
      throw vsError("BAD_GRANT", "Malformed grant token");
    }
    const parts = token.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      throw vsError("BAD_GRANT", "Malformed grant token");
    }
    const [bodyB64, sigB64] = parts;
    const ok = crypto.verify(
      null,
      Buffer.from(bodyB64, "utf8"),
      policy.signingPublicKeyPem,
      Buffer.from(sigB64, "base64url")
    );
    if (!ok) {
      throw vsError("BAD_SIGNATURE", "Ed25519 signature verification failed");
    }
    const claims = JSON.parse(Buffer.from(bodyB64, "base64url").toString("utf8"));
    if (!claims || typeof claims !== "object" || !Number.isFinite(claims.exp)) {
      throw vsError("BAD_GRANT", "Grant token missing finite exp claim");
    }
    if (claims.exp <= Date.now()) {
      throw vsError("LEASE_EXPIRED", "Grant token expired");
    }
    return claims;
  }

  return {
    policy,
    deriveAssetKey(domain, assetId, origin = "") {
      return deriveAssetKey32(policy.masterKey, domain, assetId, origin);
    },
    computeWatermarkCarrierSeed,
    signGrantPayload,
    verifyGrantToken,
    resolveLeaker(watermarkIdHex) {
      return watermarkLedger.get(watermarkIdHex) || null;
    },
    authorizeAndWrapKey({
      action,
      params = {},
      subject,
      scopes = [],
      origin = "",
      assetId,
      clientEphemeralPublicKeySpkiB64,
    }) {
      const act = checkPolicyAction(action, params, scopes, origin);
      const now = Date.now();
      const jti = crypto.randomBytes(12).toString("hex");
      const watermarkIdHex = crypto
        .createHmac("sha256", policy.masterKey)
        .update(`WM_ID|${subject}|${jti}`)
        .digest("hex")
        .slice(0, 16);

      watermarkLedger.set(watermarkIdHex, {
        subject,
        action,
        assetId,
        origin,
        jti,
        issuedAt: now,
      });

      const contentKey = deriveAssetKey32(policy.masterKey, act.product, assetId, origin);
      const wmCarrierSeed = act.watermark ? computeWatermarkCarrierSeed(assetId, watermarkIdHex) : null;

      let wrapped = null;
      if (clientEphemeralPublicKeySpkiB64) {
        const clientPubKey = crypto.createPublicKey({
          key: Buffer.from(clientEphemeralPublicKeySpkiB64, "base64url"),
          format: "der",
          type: "spki",
        });
        const serverEph = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
        const sharedSecret = crypto.diffieHellman({
          privateKey: serverEph.privateKey,
          publicKey: clientPubKey,
        });
        const wrapSalt = Buffer.from(jti, "utf8");
        const wrapInfo = Buffer.from(`VS_ECDH_WRAP_V1|${act.product}|${assetId}|${origin}`, "utf8");
        const wrapKey = Buffer.from(crypto.hkdfSync("sha256", sharedSecret, wrapSalt, wrapInfo, 32));
        const wrapIv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", wrapKey, wrapIv, { authTagLength: 16 });
        cipher.setAAD(wrapInfo);
        const ct = Buffer.concat([cipher.update(contentKey), cipher.final()]);
        const tag = cipher.getAuthTag();
        wrapKey.fill(0);
        sharedSecret.fill(0);

        wrapped = {
          serverPublicKeySpkiB64: serverEph.publicKey
            .export({ format: "der", type: "spki" })
            .toString("base64url"),
          wrapIvB64: wrapIv.toString("base64url"),
          wrappedKeyWithTagB64: Buffer.concat([ct, tag]).toString("base64url"),
        };
      }
      contentKey.fill(0);

      const claims = {
        v: policy.version,
        jti,
        sub: subject,
        act: action,
        prd: act.product,
        aid: assetId,
        org: origin,
        iat: now,
        exp: now + act.ttlMs,
        wmId: watermarkIdHex,
        ecdh: wrapped,
      };

      const grantObj = {
        token: signGrantToken(signGrantPayload, claims),
        authorityPublicKeySpkiB64,
        watermarkIdHex,
        claims,
      };
      if (wmCarrierSeed || authorityPublicKeySpkiB64) {
        SERVER_ONLY_GRANT_SEEDS.set(grantObj, {
          wmCarrierSeed,
          masterKey: policy.masterKey,
          authorityPublicKeySpkiB64,
        });
      }
      return grantObj;
    },
    checkPolicyAction,
  };
}

function signGrantToken(fn, claims) {
  return fn(claims);
}

module.exports = {
  CONFIG,
  SERVER_ONLY_GRANT_SEEDS,
  vsError,
  defineSuitePolicy,
  validateActionParams,
  deriveAssetKey32,
  packVspk,
  parseVspkHeader,
  unpackVspk,
  createLeaseAuthority,
};
