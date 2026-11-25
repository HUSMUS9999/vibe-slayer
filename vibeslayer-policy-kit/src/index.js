"use strict";

const crypto = require("node:crypto");
const http = require("node:http");

const CONFIG = Object.freeze({
  VERSION: "0.6.0-beta.1",
  DEFAULT_ENABLED: false,
  DEFAULT_LEASE_TTL_MS: 30_000,
  DEFAULT_REPLAY_WINDOW_MS: 30_000,
  DEFAULT_RATE_WINDOW_MS: 60_000,
  DEFAULT_MAX_BODY_BYTES: 1_048_576,
  AES_ALGO: "aes-256-gcm",
  GCM_IV_BYTES: 12,
  GCM_TAG_BYTES: 16,
  MODES: new Set(["public-preview", "server-only", "client-sealed"]),
  ANTI_STEALTH_MODES: new Set(["off", "observe", "balanced", "strict"]),
  ANTI_STEALTH_THRESHOLDS: Object.freeze({ off: Infinity, observe: Infinity, balanced: 4, strict: 2 }),
  PARAM_TYPES: new Set(["int", "number", "string", "boolean", "enum"]),
});

function normalizeAntiStealth(val = "off") {
  const s = String(val ?? "off").trim().toLowerCase();
  if (!CONFIG.ANTI_STEALTH_MODES.has(s)) {
    throw policyError("INVALID_POLICY", 500, `Unsupported antiStealth mode: ${val}`);
  }
  return s;
}

function osFamilyFromStr(val) {
  const s = String(val || "").toLowerCase();
  if (!s) return null;
  if (s.includes("android")) return "android";
  if (s.includes("iphone") || s.includes("ipad") || s.includes("ipod")) return "ios";
  if (s.includes("windows") || s.startsWith("win") || s.includes("win64") || s.includes("wow64")) return "win";
  if (s.includes("macintosh") || s.includes("mac os") || s.startsWith("mac") || s === "macos") return "mac";
  if (s.includes("linux") || s.includes("x11")) return "linux";
  return null;
}

function buildStealthAttestation({
  mode = "off",
  actionName = "",
  origin = "",
  telemetry = {},
} = {}) {
  const m = normalizeAntiStealth(mode);
  if (m === "off") return null;
  if (m !== "observe" && (telemetry.webdriver || telemetry.cdpRuntimeEnable)) {
    throw policyError("AUTOMATION_DENIED", 403, "Automation or CDP Runtime.enable detected");
  }
  let s = 0;
  let f = 0;
  if (telemetry.webdriver || telemetry.cdpRuntimeEnable) { s += 4; f |= 64; }
  if ((telemetry.canvas2dUniqueColors ?? 1) > 1) { s += 2; f |= 1; }
  if ((telemetry.webglClearUniqueColors ?? 1) > 1) { s += 2; f |= 2; }
  if ((telemetry.silentAudioNonZeroSamples ?? 0) > 0) { s += 2; f |= 4; }
  if (telemetry.domRectSubpixelDrift) { s += 2; f |= 8; }
  if (telemetry.osFontLie) { s += 2; f |= 16; }
  if (telemetry.d3d11ExtMismatch) { s += 1; f |= 32; }
  const p = String(telemetry.platform || "");
  if (s >= CONFIG.ANTI_STEALTH_THRESHOLDS[m]) {
    throw policyError("STEALTH_BROWSER_DENIED", 403, "Anti-detect / stealth browser anomaly detected");
  }
  const d = crypto
    .createHash("sha256")
    .update(`VS_ATTEST_V1|${actionName}|${origin}|${s}|${f}|${p}`, "utf8")
    .digest("hex");
  return { s, f, p, d };
}

function verifyStealthRequest({ mode = "off", headers = {}, attest = null, actionName = "", origin = "" }) {
  const m = normalizeAntiStealth(mode);
  if (m === "off") return { mode: m, riskScore: 0, signals: [], blocked: false };
  const signals = [];
  let riskScore = 0;
  const ua = String(headers["user-agent"] || "");
  const chUa = String(headers["sec-ch-ua"] || "");
  const chPlat = String(headers["sec-ch-ua-platform"] || "");
  if (ua && chPlat) {
    const fUa = osFamilyFromStr(ua);
    const fCh = osFamilyFromStr(chPlat);
    if (fUa && fCh && fUa !== fCh) {
      signals.push("UA_CH_PLATFORM_MISMATCH");
      riskScore += 4;
      if (m !== "observe") {
        throw policyError("STEALTH_BROWSER_DENIED", 403, "HTTP User-Agent and Sec-CH-UA-Platform mismatch");
      }
    }
  }
  if (m === "strict" || m === "observe") {
    for (const hdr of [ua, chUa]) {
      const low = hdr.toLowerCase();
      for (const marker of ["headlesschrome", "playwright", "puppeteer", "phantomjs", "selenium", "webdriver"]) {
        if (low.includes(marker)) {
          signals.push("AUTOMATION_HEADER_MARKER");
          riskScore += 4;
          if (m === "strict") {
            throw policyError("AUTOMATION_DENIED", 403, "Headless or automation browser header blocked");
          }
          break;
        }
      }
    }
  }
  if (!attest) {
    if (m === "strict") {
      throw policyError("STEALTH_ATTEST_REQUIRED", 403, "Tier-4 anti-stealth attestation required");
    }
    return { mode: m, riskScore, signals, blocked: false };
  }
  if (
    typeof attest !== "object" ||
    !Number.isInteger(attest.s) || attest.s < 0 ||
    !Number.isInteger(attest.f) || attest.f < 0 ||
    typeof attest.p !== "string" ||
    typeof attest.d !== "string" || attest.d.length !== 64
  ) {
    if (m === "observe") {
      signals.push("STEALTH_ATTEST_INVALID");
      return { mode: m, riskScore: riskScore + 4, signals, blocked: false };
    }
    throw policyError("STEALTH_ATTEST_INVALID", 403, "Malformed anti-stealth attestation payload");
  }
  riskScore += attest.s;
  if (attest.s >= CONFIG.ANTI_STEALTH_THRESHOLDS[m]) {
    throw policyError("STEALTH_BROWSER_DENIED", 403, "Stealth / anti-detect browser denied");
  }
  const expected = crypto
    .createHash("sha256")
    .update(`VS_ATTEST_V1|${actionName}|${origin}|${attest.s}|${attest.f}|${attest.p}`, "utf8")
    .digest();
  let provided;
  try {
    provided = Buffer.from(attest.d, "hex");
  } catch {
    if (m === "observe") {
      signals.push("STEALTH_ATTEST_INVALID");
      return { mode: m, riskScore: riskScore + 4, signals, blocked: false };
    }
    throw policyError("STEALTH_ATTEST_INVALID", 403, "Invalid attestation hex digest");
  }
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
    if (m === "observe") {
      signals.push("STEALTH_ATTEST_DIGEST_MISMATCH");
      return { mode: m, riskScore: riskScore + 4, signals, blocked: false };
    }
    throw policyError("STEALTH_ATTEST_INVALID", 403, "Attestation digest verification failed");
  }
  const fJs = osFamilyFromStr(attest.p);
  if (fJs) {
    const fUa = osFamilyFromStr(ua);
    if (fUa && fUa !== "android" && fJs !== fUa) {
      signals.push("PLATFORM_UA_MISMATCH");
      riskScore += 4;
      if (m !== "observe") {
        throw policyError("STEALTH_BROWSER_DENIED", 403, "Platform attestation contradicts User-Agent");
      }
    }
    const fCh = osFamilyFromStr(chPlat);
    if (fCh && fCh !== "android" && fJs !== fCh) {
      signals.push("PLATFORM_CH_MISMATCH");
      riskScore += 4;
      if (m !== "observe") {
        throw policyError("STEALTH_BROWSER_DENIED", 403, "Platform attestation contradicts Sec-CH-UA-Platform");
      }
    }
  }
  return { mode: m, riskScore, signals, blocked: false };
}

function policyError(code, status, message) {
  const err = new Error(`${code}: ${message}`);
  err.code = code;
  err.status = status;
  return err;
}

function validateParamRule(name, rule) {
  if (!rule || typeof rule !== "object" || !CONFIG.PARAM_TYPES.has(rule.type)) {
    throw policyError("INVALID_POLICY", 500, `Unsupported param type for ${name}`);
  }
  if (
    (rule.type === "int" || rule.type === "number") &&
    rule.min !== undefined &&
    rule.max !== undefined &&
    rule.min > rule.max
  ) {
    throw policyError("INVALID_POLICY", 500, `Invalid min/max for ${name}`);
  }
  if (
    rule.type === "string" &&
    rule.minLength !== undefined &&
    rule.maxLength !== undefined &&
    rule.minLength > rule.maxLength
  ) {
    throw policyError("INVALID_POLICY", 500, `Invalid minLength/maxLength for ${name}`);
  }
  if (rule.type === "enum" && (!Array.isArray(rule.values) || rule.values.length === 0)) {
    throw policyError("INVALID_POLICY", 500, `Enum ${name} requires non-empty values`);
  }
}

function definePolicy(raw) {
  if (!raw || typeof raw !== "object") {
    throw policyError("INVALID_POLICY", 500, "Policy configuration object required");
  }
  const secret = Buffer.isBuffer(raw.signingSecret)
    ? Buffer.from(raw.signingSecret)
    : typeof raw.signingSecret === "string"
      ? Buffer.from(raw.signingSecret, "utf8")
      : null;
  if (!secret || secret.length < 32) {
    throw policyError("INVALID_POLICY", 500, "signingSecret must be at least 32 bytes");
  }
  if (!raw.actions || typeof raw.actions !== "object" || Object.keys(raw.actions).length === 0) {
    throw policyError("INVALID_POLICY", 500, "At least one action definition required");
  }

  const defaultAntiStealth = normalizeAntiStealth(raw.antiStealth ?? "off");
  const actions = Object.create(null);
  for (const [actionName, spec] of Object.entries(raw.actions)) {
    if (!spec || !CONFIG.MODES.has(spec.mode)) {
      throw policyError("INVALID_POLICY", 500, `Unsupported action mode for ${actionName}`);
    }
    if (typeof spec.handler !== "function") {
      throw policyError("INVALID_POLICY", 500, `Action ${actionName} requires handler`);
    }
    const params = spec.params || {};
    for (const [paramName, rule] of Object.entries(params)) {
      validateParamRule(paramName, rule);
    }
    actions[actionName] = Object.freeze({
      name: actionName,
      mode: spec.mode,
      antiStealth: normalizeAntiStealth(spec.antiStealth ?? defaultAntiStealth),
      params: Object.freeze({ ...params }),
      requiredScopes: Object.freeze([...(spec.requiredScopes || [])]),
      allowedOrigins: Object.freeze([...(spec.allowedOrigins || [])]),
      replayWindowMs: spec.replayWindowMs ?? CONFIG.DEFAULT_REPLAY_WINDOW_MS,
      maxUses: spec.maxUses ?? (spec.mode === "public-preview" ? Infinity : 1),
      rateLimit: spec.rateLimit
        ? Object.freeze({
            max: spec.rateLimit.max,
            windowMs: spec.rateLimit.windowMs ?? CONFIG.DEFAULT_RATE_WINDOW_MS,
          })
        : null,
      redactFields: Object.freeze([...(spec.redactFields || [])]),
      handler: spec.handler,
    });
  }

  return Object.freeze({
    version: raw.version || CONFIG.VERSION,
    enabled: Boolean(raw.enabled ?? CONFIG.DEFAULT_ENABLED),
    antiStealth: normalizeAntiStealth(raw.antiStealth ?? "off"),
    signingSecret: secret,
    defaultLeaseTtlMs: raw.defaultLeaseTtlMs ?? CONFIG.DEFAULT_LEASE_TTL_MS,
    maxBodyBytes: raw.maxBodyBytes ?? CONFIG.DEFAULT_MAX_BODY_BYTES,
    onDecision: typeof raw.onDecision === "function" ? raw.onDecision : null,
    actions: Object.freeze(actions),
  });
}

function validateActionParams(paramRules, candidate) {
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw policyError("BAD_PARAMS", 400, "Action params must be a JSON object");
  }
  for (const key of Object.keys(candidate)) {
    if (!Object.prototype.hasOwnProperty.call(paramRules, key)) {
      throw policyError("UNKNOWN_PARAM", 400, `Unexpected parameter: ${key}`);
    }
  }

  const out = {};
  for (const [name, rule] of Object.entries(paramRules)) {
    const val = Object.hasOwn(candidate, name) ? candidate[name] : undefined;
    if (val === undefined) {
      if (rule.optional) continue;
      throw policyError("MISSING_PARAM", 400, `Missing parameter: ${name}`);
    }
    if (rule.type === "int") {
      if (!Number.isInteger(val)) {
        throw policyError("BAD_PARAM_TYPE", 400, `${name} must be an integer`);
      }
      if ((rule.min !== undefined && val < rule.min) || (rule.max !== undefined && val > rule.max)) {
        throw policyError("PARAM_OUT_OF_RANGE", 400, `${name} outside [${rule.min}, ${rule.max}]`);
      }
    } else if (rule.type === "number") {
      if (typeof val !== "number" || !Number.isFinite(val)) {
        throw policyError("BAD_PARAM_TYPE", 400, `${name} must be a finite number`);
      }
      if ((rule.min !== undefined && val < rule.min) || (rule.max !== undefined && val > rule.max)) {
        throw policyError("PARAM_OUT_OF_RANGE", 400, `${name} outside [${rule.min}, ${rule.max}]`);
      }
    } else if (rule.type === "string") {
      if (typeof val !== "string") {
        throw policyError("BAD_PARAM_TYPE", 400, `${name} must be a string`);
      }
      if (
        (rule.minLength !== undefined && val.length < rule.minLength) ||
        (rule.maxLength !== undefined && val.length > rule.maxLength)
      ) {
        throw policyError("PARAM_OUT_OF_RANGE", 400, `${name} length out of bounds`);
      }
      if (rule.pattern && !rule.pattern.test(val)) {
        throw policyError("PARAM_PATTERN_MISMATCH", 400, `${name} failed pattern check`);
      }
    } else if (rule.type === "boolean") {
      if (typeof val !== "boolean") {
        throw policyError("BAD_PARAM_TYPE", 400, `${name} must be boolean`);
      }
    } else if (rule.type === "enum") {
      if (!rule.values.includes(val)) {
        throw policyError("PARAM_OUT_OF_RANGE", 400, `${name} not in allowed enum`);
      }
    }
    out[name] = val;
  }
  return out;
}

function signPayload(secret, payloadObj) {
  const body = Buffer.from(JSON.stringify(payloadObj), "utf8").toString("base64url");
  const mac = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${mac}`;
}

function verifySignedToken(secret, token) {
  if (typeof token !== "string" || !token.includes(".")) {
    throw policyError("MISSING_LEASE", 401, "Signed lease token required");
  }
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw policyError("BAD_SIGNATURE", 401, "Malformed lease token");
  }
  const [body, sig] = parts;
  const expected = crypto.createHmac("sha256", secret).update(body).digest();
  let provided;
  try {
    provided = Buffer.from(sig, "base64url");
  } catch {
    throw policyError("BAD_SIGNATURE", 401, "Malformed lease signature");
  }
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
    throw policyError("BAD_SIGNATURE", 401, "Lease signature mismatch");
  }
  try {
    return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    throw policyError("BAD_LEASE_PAYLOAD", 401, "Malformed lease JSON");
  }
}

function sealAssetAes256Gcm(plainBytes, keyBytes, aadText = "") {
  const plain = Buffer.isBuffer(plainBytes) ? plainBytes : Buffer.from(plainBytes);
  const key = Buffer.isBuffer(keyBytes) ? keyBytes : Buffer.from(keyBytes);
  if (key.length !== 32) {
    throw policyError("BAD_KEY", 500, "AES-256-GCM requires a 32-byte key");
  }
  const iv = crypto.randomBytes(CONFIG.GCM_IV_BYTES);
  const cipher = crypto.createCipheriv(CONFIG.AES_ALGO, key, iv, {
    authTagLength: CONFIG.GCM_TAG_BYTES,
  });
  if (aadText) cipher.setAAD(Buffer.from(aadText, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, tag, ciphertext, aad: aadText };
}

function unsealAssetAes256Gcm(envelope, keyBytes, expectedAadText = "") {
  if (!envelope || typeof envelope !== "object") {
    throw policyError("BAD_ENVELOPE", 400, "Missing AES-256-GCM envelope");
  }
  const key = Buffer.isBuffer(keyBytes) ? keyBytes : Buffer.from(keyBytes);
  if (key.length !== 32) {
    throw policyError("BAD_KEY", 400, "AES-256-GCM requires a 32-byte key");
  }
  const iv = Buffer.isBuffer(envelope.iv) ? envelope.iv : Buffer.from(String(envelope.iv || ""), "base64url");
  const tag = Buffer.isBuffer(envelope.tag) ? envelope.tag : Buffer.from(String(envelope.tag || ""), "base64url");
  if (iv.length !== CONFIG.GCM_IV_BYTES) {
    throw policyError("BAD_IV", 400, `AES-256-GCM requires a ${CONFIG.GCM_IV_BYTES}-byte IV`);
  }
  if (tag.length !== CONFIG.GCM_TAG_BYTES) {
    throw policyError("BAD_TAG", 400, `AES-256-GCM requires a ${CONFIG.GCM_TAG_BYTES}-byte auth tag`);
  }
  const ciphertext = Buffer.isBuffer(envelope.ciphertext)
    ? envelope.ciphertext
    : Buffer.from(String(envelope.ciphertext || ""), "base64url");
  const decipher = crypto.createDecipheriv(CONFIG.AES_ALGO, key, iv, {
    authTagLength: CONFIG.GCM_TAG_BYTES,
  });
  if (expectedAadText) decipher.setAAD(Buffer.from(expectedAadText, "utf8"));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function extractBoundsFromGlb(glbBytes) {
  const buf = Buffer.isBuffer(glbBytes) ? glbBytes : Buffer.from(glbBytes);
  if (buf.length < 20 || buf.subarray(0, 4).toString("ascii") !== "glTF") {
    throw policyError("INVALID_GLB", 400, "Input is not a glTF v2 binary");
  }
  const version = buf.readUInt32LE(4);
  const totalLen = buf.readUInt32LE(8);
  const jsonLen = buf.readUInt32LE(12);
  const chunkType = buf.readUInt32LE(16);
  if (version !== 2 || totalLen < 20 || totalLen > buf.length || chunkType !== 0x4e4f534a || 20 + jsonLen > totalLen) {
    throw policyError("INVALID_GLB", 400, "Malformed glTF v2 binary header or JSON chunk bounds");
  }
  let meta;
  try {
    meta = JSON.parse(buf.subarray(20, 20 + jsonLen).toString("utf8"));
  } catch {
    throw policyError("INVALID_GLB", 400, "Malformed JSON chunk in glTF binary");
  }
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
    throw policyError("INVALID_GLB", 400, "Invalid glTF metadata object");
  }
  for (const acc of Array.isArray(meta.accessors) ? meta.accessors : []) {
    if (
      acc &&
      acc.type === "VEC3" &&
      Array.isArray(acc.min) &&
      Array.isArray(acc.max) &&
      acc.min.length === 3 &&
      acc.max.length === 3 &&
      acc.min.every((v) => typeof v === "number" && Number.isFinite(v)) &&
      acc.max.every((v) => typeof v === "number" && Number.isFinite(v))
    ) {
      const scale = acc.componentType === 5122 && acc.normalized ? 1 / 32767 : 1;
      return {
        min: acc.min.map((v) => Number((v * scale).toFixed(4))),
        max: acc.max.map((v) => Number((v * scale).toFixed(4))),
      };
    }
  }
  return { min: [-0.5, -0.5, -0.5], max: [0.5, 0.5, 0.5] };
}

// Coarse preview geometry: right-handed glTF 2.0 (+Y up, +Z forward, -X..+X), 8 box corners, 12 triangles.
function buildBoundingBoxPreviewGlb(sourceGlbBytes, opts = {}) {
  const { min, max } = extractBoundsFromGlb(sourceGlbBytes);
  const [x0, y0, z0] = min;
  const [x1, y1, z1] = max;
  const positions = new Float32Array([
    x0, y0, z0, x1, y0, z0, x1, y1, z0, x0, y1, z0,
    x0, y0, z1, x1, y0, z1, x1, y1, z1, x0, y1, z1,
  ]);
  const indices = new Uint16Array([
    0, 2, 1, 0, 3, 2, 4, 5, 6, 4, 6, 7,
    0, 1, 5, 0, 5, 4, 2, 3, 7, 2, 7, 6,
    1, 2, 6, 1, 6, 5, 3, 0, 4, 3, 4, 7,
  ]);

  const posBuf = Buffer.from(positions.buffer);
  const idxBuf = Buffer.from(indices.buffer);
  let binChunk = Buffer.concat([posBuf, idxBuf]);
  if (binChunk.length % 4 !== 0) {
    binChunk = Buffer.concat([binChunk, Buffer.alloc(4 - (binChunk.length % 4))]);
  }

  const gltfJson = {
    asset: {
      version: "2.0",
      generator: opts.generator || `vibeslayer-policy-kit/${CONFIG.VERSION}`,
    },
    scene: 0,
    scenes: [{ nodes: [0] }],
    nodes: [{ name: opts.nodeName || "Releasable_Preview_Proxy", mesh: 0 }],
    meshes: [{ primitives: [{ attributes: { POSITION: 0 }, indices: 1, mode: 4 }] }],
    buffers: [{ byteLength: binChunk.length }],
    bufferViews: [
      { buffer: 0, byteOffset: 0, byteLength: posBuf.length, target: 34962 },
      { buffer: 0, byteOffset: posBuf.length, byteLength: idxBuf.length, target: 34963 },
    ],
    accessors: [
      {
        bufferView: 0,
        componentType: 5126,
        count: 8,
        type: "VEC3",
        min: [x0, y0, z0],
        max: [x1, y1, z1],
      },
      { bufferView: 1, componentType: 5123, count: indices.length, type: "SCALAR" },
    ],
  };

  let jsonChunk = Buffer.from(JSON.stringify(gltfJson), "utf8");
  if (jsonChunk.length % 4 !== 0) {
    jsonChunk = Buffer.concat([jsonChunk, Buffer.alloc(4 - (jsonChunk.length % 4), 0x20)]);
  }

  const totalLen = 12 + 8 + jsonChunk.length + 8 + binChunk.length;
  const header = Buffer.alloc(12);
  header.write("glTF", 0, "ascii");
  header.writeUInt32LE(2, 4);
  header.writeUInt32LE(totalLen, 8);

  const jsonHdr = Buffer.alloc(8);
  jsonHdr.writeUInt32LE(jsonChunk.length, 0);
  jsonHdr.writeUInt32LE(0x4e4f534a, 4);

  const binHdr = Buffer.alloc(8);
  binHdr.writeUInt32LE(binChunk.length, 0);
  binHdr.writeUInt32LE(0x004e4942, 4);

  return Buffer.concat([header, jsonHdr, jsonChunk, binHdr, binChunk]);
}

function redactResult(value, redactFields) {
  if (!value || typeof value !== "object" || Array.isArray(value) || redactFields.length === 0) {
    return value;
  }
  const clone = { ...value };
  for (const field of redactFields) {
    delete clone[field];
  }
  return clone;
}

function createGateway(policy) {
  const gatewaySecret = Buffer.from(policy.signingSecret);
  const leaseUses = new Map();
  const rateBuckets = new Map();
  let server = null;
  let baseUrl = null;

  const MAX_MAP_ENTRIES = 50_000;
  let reqCounter = 0;
  let lastPruneMs = 0;

  function pruneMaps(now) {
    reqCounter += 1;
    // Time-gated pruning eliminates per-request O(50k) scans when saturated (Loop 3 LOW-6)
    const periodic = (reqCounter & 255) === 0 && now - lastPruneMs >= 1_000;
    const saturatedDue = (leaseUses.size >= MAX_MAP_ENTRIES || rateBuckets.size >= MAX_MAP_ENTRIES) && now - lastPruneMs >= 5_000;
    if (!periodic && !saturatedDue) {
      return;
    }
    lastPruneMs = now;
    for (const [jti, entry] of leaseUses.entries()) {
      if (entry.exp <= now) leaseUses.delete(jti);
    }
    for (const [bucketKey, entry] of rateBuckets.entries()) {
      if (entry.resetAt <= now) rateBuckets.delete(bucketKey);
    }
  }

  function corsHeadersFor(action, reqOrigin) {
    if (!action || !reqOrigin) return {};
    if (action.allowedOrigins.length === 0 || action.allowedOrigins.includes(reqOrigin)) {
      return { "access-control-allow-origin": reqOrigin, vary: "Origin" };
    }
    return {};
  }

  function checkOrigin(action, originHeader) {
    if (action.allowedOrigins.length === 0) return;
    if (!originHeader || !action.allowedOrigins.includes(originHeader)) {
      throw policyError("ORIGIN_DENIED", 403, "Origin is not permitted for this action");
    }
  }

  function checkRate(action, subjectKey, now) {
    if (!action.rateLimit) return;
    const key = `${action.name}:${subjectKey}`;
    let bucket = rateBuckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      if (!bucket && rateBuckets.size >= MAX_MAP_ENTRIES) {
        throw policyError("RATE_LIMITER_SATURATED", 503, "Rate limiter capacity reached");
      }
      bucket = { count: 0, resetAt: now + action.rateLimit.windowMs };
      rateBuckets.set(key, bucket);
    }
    if (bucket.count >= action.rateLimit.max) {
      throw policyError("RATE_LIMITED", 429, `Rate limit exceeded for ${action.name}`);
    }
    bucket.count += 1;
  }

  function validateLeaseForAction(action, token, originHeader, now) {
    const claims = verifySignedToken(gatewaySecret, token);
    if (typeof claims.jti !== "string" || claims.jti.length === 0) {
      throw policyError("BAD_LEASE_PAYLOAD", 401, "Lease missing jti");
    }
    if (claims.exp <= now) {
      throw policyError("LEASE_EXPIRED", 401, "Lease has expired");
    }
    if (claims.act && claims.act !== action.name) {
      throw policyError("ACTION_MISMATCH", 403, "Lease is bound to a different action");
    }
    if (claims.org && claims.org !== originHeader) {
      throw policyError("ORIGIN_DENIED", 403, "Lease origin binding mismatch");
    }
    for (const reqScope of action.requiredScopes) {
      if (!Array.isArray(claims.scp) || !claims.scp.includes(reqScope)) {
        throw policyError("SCOPE_DENIED", 403, `Missing required scope ${reqScope}`);
      }
    }
    const maxUses = Math.min(action.maxUses, claims.max ?? action.maxUses);
    if (!leaseUses.has(claims.jti) && leaseUses.size >= MAX_MAP_ENTRIES) {
      throw policyError("REPLAY_CACHE_SATURATED", 503, "Lease replay cache capacity reached");
    }
    const state = leaseUses.get(claims.jti) || {
      uses: 0,
      exp: Math.max(claims.exp, now + action.replayWindowMs),
    };
    if (state.uses >= maxUses) {
      throw policyError("LEASE_REPLAYED", 409, "Lease token usage limit reached");
    }
    return { claims, state };
  }

  function consumeLeaseUse(claims, state) {
    state.uses += 1;
    leaseUses.set(claims.jti, state);
  }

  function readJsonBody(req) {
    if (req.body !== undefined && req.body !== null && typeof req.body === "object" && !Buffer.isBuffer(req.body)) {
      return Promise.resolve(req.body);
    }
    if (Buffer.isBuffer(req.rawBody)) {
      if (req.rawBody.length > policy.maxBodyBytes) {
        return Promise.reject(policyError("BODY_TOO_LARGE", 413, "Request payload exceeds policy limit"));
      }
      const raw = req.rawBody.toString("utf8");
      try {
        return Promise.resolve(raw ? JSON.parse(raw) : {});
      } catch {
        return Promise.reject(policyError("BAD_JSON", 400, "Invalid JSON request body"));
      }
    }
    return new Promise((resolve, reject) => {
      const chunks = [];
      let total = 0;
      let done = false;
      req.on("data", (chunk) => {
        if (done) return;
        total += chunk.length;
        if (total > policy.maxBodyBytes) {
          done = true;
          req.resume();
          reject(policyError("BODY_TOO_LARGE", 413, "Request payload exceeds policy limit"));
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => {
        if (done) return;
        done = true;
        const raw = Buffer.concat(chunks).toString("utf8");
        try {
          resolve(raw ? JSON.parse(raw) : {});
        } catch {
          reject(policyError("BAD_JSON", 400, "Invalid JSON request body"));
        }
      });
      req.on("error", (err) => {
        if (!done) {
          done = true;
          reject(err);
        }
      });
    });
  }

  function decodeActionName(encoded) {
    try {
      return decodeURIComponent(encoded);
    } catch {
      throw policyError("BAD_ACTION_ENCODING", 400, "Malformed percent-encoding in action path");
    }
  }

  async function dispatch(req, res, { prefix = "/v1/action/" } = {}) {
    const now = Date.now();
    pruneMaps(now);
    if (!policy.enabled) {
      res.writeHead(503, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, code: "POLICY_DISABLED" }));
      return;
    }

    const rawUrl = req.originalUrl || req.url || "/";
    const url = new URL(rawUrl, "http://localhost");
    if (req.method === "OPTIONS" && url.pathname.startsWith(prefix)) {
      const name = decodeActionName(url.pathname.slice(prefix.length));
      const optAction = Object.hasOwn(policy.actions, name) ? policy.actions[name] : null;
      const reqOrigin = req.headers.origin || "";
      if (optAction && reqOrigin && (optAction.allowedOrigins.length === 0 || optAction.allowedOrigins.includes(reqOrigin))) {
        res.writeHead(204, {
          "access-control-allow-origin": reqOrigin,
          "access-control-allow-methods": "POST, OPTIONS",
          "access-control-allow-headers": "content-type, authorization, x-vs-origin, x-vs-attest",
          "access-control-max-age": "600",
          vary: "Origin",
        });
        res.end();
        return;
      }
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, code: "ORIGIN_DENIED" }));
      return;
    }
    if (req.method !== "POST" || !url.pathname.startsWith(prefix)) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, code: "NOT_FOUND" }));
      return;
    }

    const actionName = decodeActionName(url.pathname.slice(prefix.length));
    const action = Object.hasOwn(policy.actions, actionName) ? policy.actions[actionName] : null;
    if (!action) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, code: "UNKNOWN_ACTION" }));
      return;
    }

    // Prefer genuine browser `Origin` header; only fall back to `x-vs-origin` for non-browser callers
    const browserOrigin = req.headers.origin || "";
    const originHeader = browserOrigin || req.headers["x-vs-origin"] || "";
    const corsHdrs = corsHeadersFor(action, browserOrigin);
    req._vsCorsHdrs = corsHdrs;
    checkOrigin(action, originHeader);
    const body = await readJsonBody(req);
    let attestObj = body && typeof body === "object" ? body.attest ?? null : null;
    if (!attestObj && req.headers["x-vs-attest"]) {
      try {
        attestObj = JSON.parse(String(req.headers["x-vs-attest"]));
      } catch {
        throw policyError("STEALTH_ATTEST_INVALID", 403, "Invalid x-vs-attest JSON header");
      }
    }
    const stealthVerdict = verifyStealthRequest({
      mode: action.antiStealth,
      headers: req.headers,
      attest: attestObj,
      actionName: action.name,
      origin: originHeader,
    });
    if (policy.onDecision) {
      try {
        policy.onDecision({
          action: action.name,
          origin: originHeader,
          antiStealth: action.antiStealth,
          riskScore: stealthVerdict.riskScore,
          signals: stealthVerdict.signals,
          blocked: false,
          ts: now,
        });
      } catch {
        // never break request handling from user telemetry hook
      }
    }
    let rawParamCandidate = body && typeof body === "object" && body.params !== undefined ? body.params : body;
    if (body && typeof body === "object" && body.params === undefined && Object.prototype.hasOwnProperty.call(body, "attest")) {
      const { attest: _ignoredAttest, ...restParams } = body;
      rawParamCandidate = restParams;
    }
    const cleanParams = validateActionParams(action.params, rawParamCandidate);

    let claims = { sub: "anonymous", jti: "public" };
    let pendingLease = null;
    if (action.mode !== "public-preview") {
      const auth = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      pendingLease = validateLeaseForAction(action, token, originHeader, now);
      claims = pendingLease.claims;
    }
    // Never fall back to attacker-controlled Origin/X-Vs-Origin for rate-limit bucketing (Loop 3 HIGH-4)
    const clientIp = String(req.socket?.remoteAddress || req.ip || "anon").replace(/^::ffff:/i, "");
    const rateSubject = action.mode === "public-preview" ? `ip:${clientIp}` : (claims.sub || clientIp);
    // Check rate limit BEFORE burning single-use lease jti (Loop 3 MED-11)
    checkRate(action, rateSubject, now);
    if (pendingLease) {
      consumeLeaseUse(pendingLease.claims, pendingLease.state);
    }

    const rawOut = await action.handler({
      params: cleanParams,
      subject: claims.sub,
      origin: originHeader,
      leaseId: claims.jti,
    });

    if (action.mode === "public-preview" && rawOut && Buffer.isBuffer(rawOut.body)) {
      res.writeHead(200, {
        ...corsHdrs,
        "content-type": rawOut.contentType || "application/octet-stream",
        "cache-control": "public, max-age=60",
      });
      res.end(rawOut.body);
      return;
    }

    if (action.mode === "client-sealed") {
      const assetBytes = Buffer.isBuffer(rawOut?.assetBytes)
        ? rawOut.assetBytes
        : Buffer.from(JSON.stringify(redactResult(rawOut, action.redactFields)), "utf8");
      const aad = `v=${policy.version};act=${action.name};jti=${claims.jti};org=${originHeader}`;
      const contentKey = crypto.hkdfSync(
        "sha256",
        gatewaySecret,
        Buffer.from(claims.jti, "utf8"),
        Buffer.from(aad, "utf8"),
        32
      );
      const keyBuf = Buffer.from(contentKey);
      const env = sealAssetAes256Gcm(assetBytes, keyBuf, aad);
      const resp = {
        ok: true,
        mode: "client-sealed",
        aad,
        leaseKey: keyBuf.toString("base64url"),
        iv: env.iv.toString("base64url"),
        tag: env.tag.toString("base64url"),
        ciphertext: env.ciphertext.toString("base64url"),
      };
      keyBuf.fill(0);
      res.writeHead(200, { ...corsHdrs, "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify(resp));
      return;
    }

    const safeData = redactResult(rawOut, action.redactFields);
    res.writeHead(200, { ...corsHdrs, "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify({ ok: true, data: safeData }));
  }

  function handleNodeRequest(req, res, opts) {
    return dispatch(req, res, opts).catch((err) => {
      const status = err.status || 500;
      const code = err.code || "INTERNAL_ERROR";
      if (policy.onDecision) {
        try {
          policy.onDecision({
            action: req.originalUrl || req.url || "",
            origin: req.headers?.origin || req.headers?.["x-vs-origin"] || "",
            blocked: true,
            code,
            status,
            ts: Date.now(),
          });
        } catch {}
      }
      if (!res.headersSent) {
        const safeErr = status >= 500 ? "Internal server error" : err.message;
        res.writeHead(status, { ...(req._vsCorsHdrs || {}), "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, code, error: safeErr }));
      }
    });
  }

  return {
    get url() {
      return baseUrl;
    },
    get policy() {
      return policy;
    },
    handleNodeRequest,
    issueLease({ subject, scopes = [], origin = "", action = "", ttlMs, maxUses }) {
      const now = Date.now();
      return signPayload(gatewaySecret, {
        jti: crypto.randomBytes(16).toString("base64url"),
        sub: subject,
        scp: scopes,
        org: origin,
        act: action,
        iat: now,
        exp: now + (ttlMs ?? policy.defaultLeaseTtlMs),
        max: maxUses,
      });
    },
    listen(port = 0, host = "127.0.0.1") {
      server = http.createServer((req, res) => {
        handleNodeRequest(req, res);
      });
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          const addr = server.address();
          baseUrl = `http://${host}:${addr.port}`;
          resolve(baseUrl);
        });
      });
    },
    async close() {
      leaseUses.clear();
      rateBuckets.clear();
      gatewaySecret.fill(0);
      if (!server) return;
      await new Promise((resolve) => server.close(() => resolve()));
      server = null;
      baseUrl = null;
    },
  };
}

function createClient({
  baseUrl,
  origin = "",
  leaseToken = "",
  antiStealth = "off",
  telemetry = null,
  extraHeaders = {},
  fetchImpl = globalThis.fetch,
}) {
  const stealthMode = normalizeAntiStealth(antiStealth);
  function headers() {
    const h = { "content-type": "application/json", ...extraHeaders };
    if (origin) h["x-vs-origin"] = origin;
    if (leaseToken) h.authorization = `Bearer ${leaseToken}`;
    return h;
  }

  async function postRaw(actionName, params) {
    const payload = { params };
    if (stealthMode !== "off") {
      payload.attest = buildStealthAttestation({
        mode: stealthMode,
        actionName,
        origin,
        telemetry: telemetry || {},
      });
    }
    const res = await fetchImpl(`${baseUrl}/v1/action/${encodeURIComponent(actionName)}`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      let detail = { code: `HTTP_${res.status}`, error: res.statusText };
      try {
        detail = await res.json();
      } catch {}
      throw policyError(detail.code || `HTTP_${res.status}`, res.status, detail.error || "Request failed");
    }
    return res;
  }

  return {
    async invoke(actionName, params = {}) {
      const res = await postRaw(actionName, params);
      const body = await res.json();
      return body.data;
    },
    async invokeBinary(actionName, params = {}) {
      const res = await postRaw(actionName, params);
      return Buffer.from(await res.arrayBuffer());
    },
    async invokeSealed(actionName, params = {}) {
      const res = await postRaw(actionName, params);
      const body = await res.json();
      const key = Buffer.from(body.leaseKey, "base64url");
      try {
        return unsealAssetAes256Gcm(body, key, body.aad);
      } finally {
        key.fill(0);
      }
    },
  };
}

/**
 * Express / Connect / Node `http` middleware adapter for a `createGateway(policy)` instance.
 * Handles `/v1/action/*` requests and delegates all other routes to `next()`.
 */
function createNodeMiddleware(gateway, { prefix = "/v1/action/" } = {}) {
  return function vibeslayerPolicyMiddleware(req, res, next) {
    const rawUrl = req.originalUrl || req.url || "/";
    if (rawUrl.startsWith(prefix)) {
      gateway.handleNodeRequest(req, res, { prefix });
      return;
    }
    if (typeof next === "function") next();
  };
}

/**
 * Web Fetch API adapter (`(request: Request) => Promise<Response>`) for Cloudflare Workers,
 * Deno, Bun, and Next.js Route Handlers backed by a `createGateway(policy)` instance.
 * Enforces `policy.maxBodyBytes` incrementally before buffering and handles null-body 204/304 statuses cleanly.
 */
function createFetchHandler(gateway, { prefix = "/v1/action/", getClientIp = null } = {}) {
  const { Readable } = require("node:stream");
  const maxBodyBytes = gateway.policy?.maxBodyBytes ?? CONFIG.DEFAULT_MAX_BODY_BYTES;
  const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

  return async function vibeslayerFetchHandler(request) {
    const url = new URL(request.url);
    const headers = {};
    request.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });

    // Compute CORS headers for early 400/413 responses so browsers read structured errors instead of opaque TypeErrors (Loop 4 LOW-5)
    let earlyCors = {};
    const browserOrigin = headers.origin || "";
    if (browserOrigin && url.pathname.startsWith(prefix)) {
      try {
        const actName = decodeURIComponent(url.pathname.slice(prefix.length));
        const act = Object.hasOwn(gateway.policy.actions, actName) ? gateway.policy.actions[actName] : null;
        if (act && (act.allowedOrigins.length === 0 || act.allowedOrigins.includes(browserOrigin))) {
          earlyCors = { "access-control-allow-origin": browserOrigin, vary: "Origin" };
        }
      } catch {}
    }

    let bodyBuf = Buffer.alloc(0);
    if (request.method !== "GET" && request.method !== "HEAD" && request.method !== "OPTIONS") {
      if (request.body && typeof request.body.getReader === "function") {
        const reader = request.body.getReader();
        const parts = [];
        let total = 0;
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > maxBodyBytes) {
              await reader.cancel().catch(() => {});
              return new Response(
                JSON.stringify({ ok: false, code: "BODY_TOO_LARGE", error: "Request payload exceeds policy limit" }),
                { status: 413, headers: { ...earlyCors, "content-type": "application/json" } }
              );
            }
            parts.push(Buffer.from(value));
          }
        } catch {
          return new Response(
            JSON.stringify({ ok: false, code: "BAD_BODY", error: "Failed reading request body" }),
            { status: 400, headers: { ...earlyCors, "content-type": "application/json" } }
          );
        }
        bodyBuf = Buffer.concat(parts);
      } else {
        const raw = Buffer.from(await request.arrayBuffer());
        if (raw.length > maxBodyBytes) {
          return new Response(
            JSON.stringify({ ok: false, code: "BODY_TOO_LARGE", error: "Request payload exceeds policy limit" }),
            { status: 413, headers: { ...earlyCors, "content-type": "application/json" } }
          );
        }
        bodyBuf = raw;
      }
    }

    const mockReq = Readable.from(bodyBuf.length > 0 ? [bodyBuf] : []);
    mockReq.method = request.method;
    mockReq.url = `${url.pathname}${url.search}`;
    mockReq.originalUrl = mockReq.url;
    mockReq.headers = headers;
    mockReq.ip = typeof getClientIp === "function" ? String(getClientIp(request) || "fetch-anon") : "fetch-anon";

    return new Promise((resolve) => {
      let status = 200;
      let respHeaders = {};
      const chunks = [];
      const mockRes = {
        headersSent: false,
        writeHead(code, hdrs = {}) {
          status = code;
          respHeaders = { ...hdrs };
          this.headersSent = true;
        },
        end(data) {
          if (data !== undefined) {
            chunks.push(Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8"));
          }
          try {
            const body = NULL_BODY_STATUSES.has(status) ? null : Buffer.concat(chunks);
            resolve(new Response(body, { status, headers: respHeaders }));
          } catch {
            resolve(
              new Response(JSON.stringify({ ok: false, code: "INTERNAL_ERROR" }), {
                status: 500,
                headers: { "content-type": "application/json" },
              })
            );
          }
        },
      };
      gateway.handleNodeRequest(mockReq, mockRes, { prefix });
    });
  };
}

module.exports = {
  CONFIG,
  definePolicy,
  validateActionParams,
  buildStealthAttestation,
  verifyStealthRequest,
  createGateway,
  createNodeMiddleware,
  createFetchHandler,
  createClient,
  buildBoundingBoxPreviewGlb,
  sealAssetAes256Gcm,
  unsealAssetAes256Gcm,
};
