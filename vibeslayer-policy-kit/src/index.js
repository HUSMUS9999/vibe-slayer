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
  ANTI_STEALTH_MODES: new Set(["off", "balanced", "strict"]),
  ANTI_STEALTH_THRESHOLDS: Object.freeze({ off: Infinity, balanced: 4, strict: 2 }),
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
  if (telemetry.webdriver || telemetry.cdpRuntimeEnable) {
    throw policyError("AUTOMATION_DENIED", 403, "Automation or CDP Runtime.enable detected");
  }
  let s = 0;
  let f = 0;
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
  if (mode === "off") return;
  const ua = String(headers["user-agent"] || "");
  const chUa = String(headers["sec-ch-ua"] || "");
  const chPlat = String(headers["sec-ch-ua-platform"] || "");
  if (ua && chPlat) {
    const fUa = osFamilyFromStr(ua);
    const fCh = osFamilyFromStr(chPlat);
    if (fUa && fCh && fUa !== fCh) {
      throw policyError("STEALTH_BROWSER_DENIED", 403, "HTTP User-Agent and Sec-CH-UA-Platform mismatch");
    }
  }
  if (mode === "strict") {
    for (const hdr of [ua, chUa]) {
      const low = hdr.toLowerCase();
      for (const marker of ["headlesschrome", "playwright", "puppeteer", "phantomjs", "selenium", "webdriver"]) {
        if (low.includes(marker)) {
          throw policyError("AUTOMATION_DENIED", 403, "Headless or automation browser header blocked");
        }
      }
    }
  }
  if (!attest) {
    if (mode === "strict") {
      throw policyError("STEALTH_ATTEST_REQUIRED", 403, "Tier-4 anti-stealth attestation required");
    }
    return;
  }
  if (
    typeof attest !== "object" ||
    !Number.isInteger(attest.s) || attest.s < 0 ||
    !Number.isInteger(attest.f) || attest.f < 0 ||
    typeof attest.p !== "string" ||
    typeof attest.d !== "string" || attest.d.length !== 64
  ) {
    throw policyError("STEALTH_ATTEST_INVALID", 403, "Malformed anti-stealth attestation payload");
  }
  if (attest.s >= CONFIG.ANTI_STEALTH_THRESHOLDS[mode]) {
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
    throw policyError("STEALTH_ATTEST_INVALID", 403, "Invalid attestation hex digest");
  }
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
    throw policyError("STEALTH_ATTEST_INVALID", 403, "Attestation digest verification failed");
  }
  const fJs = osFamilyFromStr(attest.p);
  if (fJs) {
    const fUa = osFamilyFromStr(ua);
    if (fUa && fUa !== "android" && fJs !== fUa) {
      throw policyError("STEALTH_BROWSER_DENIED", 403, "Platform attestation contradicts User-Agent");
    }
    const fCh = osFamilyFromStr(chPlat);
    if (fCh && fCh !== "android" && fJs !== fCh) {
      throw policyError("STEALTH_BROWSER_DENIED", 403, "Platform attestation contradicts Sec-CH-UA-Platform");
    }
  }
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
  const actions = {};
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
    const val = candidate[name];
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
  const key = Buffer.isBuffer(keyBytes) ? keyBytes : Buffer.from(keyBytes);
  const iv = Buffer.isBuffer(envelope.iv) ? envelope.iv : Buffer.from(envelope.iv, "base64url");
  const tag = Buffer.isBuffer(envelope.tag) ? envelope.tag : Buffer.from(envelope.tag, "base64url");
  const ciphertext = Buffer.isBuffer(envelope.ciphertext)
    ? envelope.ciphertext
    : Buffer.from(envelope.ciphertext, "base64url");
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
  const jsonLen = buf.readUInt32LE(12);
  const meta = JSON.parse(buf.subarray(20, 20 + jsonLen).toString("utf8"));
  for (const acc of meta.accessors || []) {
    if (acc.type === "VEC3" && Array.isArray(acc.min) && Array.isArray(acc.max)) {
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

  function pruneMaps(now) {
    for (const [jti, entry] of leaseUses.entries()) {
      if (entry.exp <= now) leaseUses.delete(jti);
    }
    for (const [bucketKey, entry] of rateBuckets.entries()) {
      if (entry.resetAt <= now) rateBuckets.delete(bucketKey);
    }
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
      bucket = { count: 0, resetAt: now + action.rateLimit.windowMs };
      rateBuckets.set(key, bucket);
    }
    if (bucket.count >= action.rateLimit.max) {
      throw policyError("RATE_LIMITED", 429, `Rate limit exceeded for ${action.name}`);
    }
    bucket.count += 1;
  }

  function verifyLeaseForAction(action, token, originHeader, now) {
    const claims = verifySignedToken(gatewaySecret, token);
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
    const state = leaseUses.get(claims.jti) || {
      uses: 0,
      exp: Math.max(claims.exp, now + action.replayWindowMs),
    };
    if (state.uses >= maxUses) {
      throw policyError("LEASE_REPLAYED", 409, "Lease token usage limit reached");
    }
    state.uses += 1;
    leaseUses.set(claims.jti, state);
    return claims;
  }

  function readJsonBody(req) {
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

  async function dispatch(req, res) {
    const now = Date.now();
    pruneMaps(now);
    if (!policy.enabled) {
      res.writeHead(503, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, code: "POLICY_DISABLED" }));
      return;
    }

    const url = new URL(req.url, "http://localhost");
    const prefix = "/v1/action/";
    if (req.method === "OPTIONS" && url.pathname.startsWith(prefix)) {
      const optAction = policy.actions[decodeURIComponent(url.pathname.slice(prefix.length))];
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

    const actionName = decodeURIComponent(url.pathname.slice(prefix.length));
    const action = policy.actions[actionName];
    if (!action) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, code: "UNKNOWN_ACTION" }));
      return;
    }

    // Prefer genuine browser `Origin` header; only fall back to `x-vs-origin` for non-browser callers
    const originHeader = req.headers.origin || req.headers["x-vs-origin"] || "";
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
    verifyStealthRequest({
      mode: action.antiStealth,
      headers: req.headers,
      attest: attestObj,
      actionName: action.name,
      origin: originHeader,
    });
    let rawParamCandidate = body && typeof body === "object" && body.params !== undefined ? body.params : body;
    if (body && typeof body === "object" && body.params === undefined && Object.prototype.hasOwnProperty.call(body, "attest")) {
      const { attest: _ignoredAttest, ...restParams } = body;
      rawParamCandidate = restParams;
    }
    const cleanParams = validateActionParams(action.params, rawParamCandidate);

    let claims = { sub: "anonymous", jti: "public" };
    if (action.mode !== "public-preview") {
      const auth = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      claims = verifyLeaseForAction(action, token, originHeader, now);
    }
    checkRate(action, claims.sub || originHeader || "anon", now);

    const rawOut = await action.handler({
      params: cleanParams,
      subject: claims.sub,
      origin: originHeader,
      leaseId: claims.jti,
    });

    if (action.mode === "public-preview" && rawOut && Buffer.isBuffer(rawOut.body)) {
      res.writeHead(200, {
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
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify(resp));
      return;
    }

    const safeData = redactResult(rawOut, action.redactFields);
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify({ ok: true, data: safeData }));
  }

  return {
    get url() {
      return baseUrl;
    },
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
        dispatch(req, res).catch((err) => {
          const status = err.status || 500;
          const code = err.code || "INTERNAL_ERROR";
          res.writeHead(status, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: false, code, error: err.message }));
        });
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

module.exports = {
  CONFIG,
  definePolicy,
  validateActionParams,
  buildStealthAttestation,
  verifyStealthRequest,
  createGateway,
  createClient,
  buildBoundingBoxPreviewGlb,
  sealAssetAes256Gcm,
  unsealAssetAes256Gcm,
};
