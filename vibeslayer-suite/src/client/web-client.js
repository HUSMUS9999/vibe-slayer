"use strict";

function getSubtle() {
  const s = globalThis.crypto?.subtle;
  if (!s) {
    throw new Error("WEBCRYPTO_UNAVAILABLE: WebCrypto subtle API requires HTTPS, localhost, or Node.js >= 20");
  }
  return s;
}

const ANTI_STEALTH_THRESHOLDS = Object.freeze({
  off: Infinity,
  balanced: 4,
  strict: 2,
});

function parseAntiStealthMode(mode = "off") {
  const norm = String(mode ?? "off").trim().toLowerCase();
  if (norm === "off" || norm === "none" || norm === "false" || norm === "0") return "off";
  if (norm === "balanced" || norm === "default") return "balanced";
  if (norm === "strict" || norm === "paranoid" || norm === "on" || norm === "true" || norm === "1") return "strict";
  throw new Error(`INVALID_ANTI_STEALTH_MODE: ${mode}`);
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

async function sha256HexClient(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await getSubtle().digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Evaluates Tier-4 stealth/anti-detect browser physics invariants (CloakBrowser, GoLogin,
 * AdsPower, noise-injecting Chromium forks) + CDP Runtime.enable & navigator.webdriver.
 * Safe in pure Node.js (returns clean score=0 unless explicit `telemetry` is supplied).
 */
async function collectStealthAttestation({
  mode = "off",
  ticket = "",
  publicKey = "",
  telemetry = null,
} = {}) {
  const m = parseAntiStealthMode(mode);
  if (m === "off") return null;
  const thresh = ANTI_STEALTH_THRESHOLDS[m];
  let s = 0;
  let f = 0;
  let plat = "";

  if (telemetry && typeof telemetry === "object") {
    if (telemetry.webdriver || telemetry.cdpRuntimeEnable) {
      throw new Error("AUTOMATION_DENIED");
    }
    if ((telemetry.canvas2dUniqueColors ?? 1) > 1) { s += 2; f |= 1; }
    if ((telemetry.webglClearUniqueColors ?? 1) > 1) { s += 2; f |= 2; }
    if ((telemetry.silentAudioNonZeroSamples ?? 0) > 0) { s += 2; f |= 4; }
    if (telemetry.domRectSubpixelDrift) { s += 2; f |= 8; }
    if (telemetry.osFontLie) { s += 2; f |= 16; }
    if (telemetry.d3d11ExtMismatch) { s += 1; f |= 32; }
    plat = String(telemetry.platform || "");
  } else if (typeof document !== "undefined") {
    if (typeof navigator !== "undefined" && navigator.webdriver) {
      throw new Error("AUTOMATION_DENIED");
    }
    if (m === "strict") {
      let cdpHit = false;
      try {
        const orig = Error.prepareStackTrace;
        Error.prepareStackTrace = () => { cdpHit = true; return ""; };
        console.debug(new Error());
        if (orig === undefined) delete Error.prepareStackTrace;
        else Error.prepareStackTrace = orig;
      } catch {}
      if (cdpHit) throw new Error("AUTOMATION_DENIED");
    }

    try {
      const c = document.createElement("canvas");
      c.width = 32; c.height = 32;
      const ctx = c.getContext("2d");
      if (ctx) {
        ctx.fillStyle = "#808080";
        ctx.fillRect(0, 0, 32, 32);
        const d = ctx.getImageData(0, 0, 32, 32).data;
        const r0 = d[0], g0 = d[1], b0 = d[2];
        for (let i = 4; i < d.length; i += 4) {
          if (d[i] !== r0 || d[i + 1] !== g0 || d[i + 2] !== b0) { s += 2; f |= 1; break; }
        }
      }
    } catch {}
    try {
      const c = document.createElement("canvas");
      c.width = 32; c.height = 32;
      const g = c.getContext("webgl2") || c.getContext("webgl");
      if (g) {
        g.disable(g.DITHER);
        g.clearColor(128 / 255, 128 / 255, 128 / 255, 1);
        g.clear(g.COLOR_BUFFER_BIT);
        const px = new Uint8Array(32 * 32 * 4);
        g.readPixels(0, 0, 32, 32, g.RGBA, g.UNSIGNED_BYTE, px);
        const r0 = px[0], g0 = px[1], b0 = px[2];
        for (let i = 4; i < px.length; i += 4) {
          if (px[i] !== r0 || px[i + 1] !== g0 || px[i + 2] !== b0) { s += 2; f |= 2; break; }
        }
        const ext = g.getExtension("WEBGL_debug_renderer_info");
        const ur = ext ? String(g.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "") : "";
        const exts = g.getSupportedExtensions() || [];
        if ((ur.includes("Direct3D11") || ur.includes("D3D11")) && (ur.includes("NVIDIA") || ur.includes("RTX")) && !exts.includes("KHR_parallel_shader_compile") && exts.length < 30) {
          s += 1; f |= 32;
        }
        const lose = g.getExtension("WEBGL_lose_context");
        if (lose) lose.loseContext();
      }
    } catch {}
    try {
      const OA = globalThis.OfflineAudioContext || globalThis.webkitOfflineAudioContext;
      if (OA) {
        const ac = new OA(1, 256, 44100);
        const ab = ac.createBuffer(1, 256, 44100);
        const sr = ac.createBufferSource();
        sr.buffer = ab; sr.connect(ac.destination); sr.start(0);
        const ch = (await ac.startRendering()).getChannelData(0);
        for (let i = 0; i < ch.length; i++) {
          if (ch[i] !== 0) { s += 2; f |= 4; break; }
        }
      }
    } catch {}
    try {
      const dpr = (typeof window !== "undefined" && window.devicePixelRatio) || 1;
      if (Math.abs(dpr - Math.round(dpr)) < 1e-6 && document.body) {
        const dv = document.createElement("div");
        dv.style.cssText = "position:fixed;left:10px;top:20px;width:100px;height:50px;margin:0;padding:0;border:0;visibility:hidden";
        document.body.appendChild(dv);
        const r = dv.getBoundingClientRect();
        dv.remove();
        if (Math.abs(r.left - 10) > 1e-3 || Math.abs(r.top - 20) > 1e-3 || Math.abs(r.width - 100) > 1e-3 || Math.abs(r.height - 50) > 1e-3) {
          s += 2; f |= 8;
        }
      }
    } catch {}
    try {
      const pl = String((typeof navigator !== "undefined" && navigator.platform) || "");
      const up = String((typeof navigator !== "undefined" && navigator.userAgentData && navigator.userAgentData.platform) || "");
      if (document.body && (pl.startsWith("Win") || up === "Windows" || pl === "MacIntel" || up === "macOS")) {
        const sp = document.createElement("span");
        sp.textContent = "mmmmmmmmmmlliWWWW1234567890";
        sp.style.cssText = "position:fixed;left:-9999px;top:0;font-size:72px;white-space:nowrap;visibility:hidden";
        document.body.appendChild(sp);
        const mw = (ff) => { sp.style.fontFamily = ff; return sp.offsetWidth; };
        const base = mw("monospace");
        const list = (pl.startsWith("Win") || up === "Windows")
          ? ['"Segoe UI",monospace', '"Tahoma",monospace', '"Consolas",monospace', '"Calibri",monospace']
          : ['"Helvetica Neue",monospace', '"Geneva",monospace', '"Menlo",monospace'];
        let diff = 0;
        for (const ff of list) if (mw(ff) !== base) diff++;
        sp.remove();
        if (diff === 0) { s += 2; f |= 16; }
      }
      plat = pl;
    } catch {}
  }

  if (s >= thresh) {
    throw new Error("STEALTH_BROWSER_DENIED");
  }
  const d = await sha256HexClient(`VS_ATTEST_V1|${ticket}|${publicKey}|${s}|${f}|${plat}`);
  return { s, f, p: plat, d };
}

async function verifyStealthAttestation({
  mode = "off",
  headers = {},
  attest = null,
  ticket = "",
  publicKey = "",
} = {}) {
  const m = parseAntiStealthMode(mode);
  if (m === "off") return { ok: true };
  const lower = {};
  for (const [k, v] of Object.entries(headers || {})) {
    lower[k.toLowerCase()] = String(v ?? "");
  }
  const ua = lower["user-agent"] || "";
  const chUa = lower["sec-ch-ua"] || "";
  const chPlat = lower["sec-ch-ua-platform"] || "";

  if (ua && chPlat) {
    const fUa = osFamilyFromStr(ua);
    const fCh = osFamilyFromStr(chPlat);
    if (fUa && fCh && fUa !== fCh) throw new Error("STEALTH_BROWSER_DENIED");
  }
  if (m === "strict") {
    for (const hdr of [ua, chUa]) {
      const l = hdr.toLowerCase();
      for (const marker of ["headlesschrome", "playwright", "puppeteer", "phantomjs", "selenium", "webdriver"]) {
        if (l.includes(marker)) throw new Error("AUTOMATION_DENIED");
      }
    }
  }
  if (!attest) {
    if (m === "strict") throw new Error("STEALTH_ATTEST_REQUIRED");
    return { ok: true };
  }
  if (
    typeof attest !== "object" ||
    !Number.isInteger(attest.s) || attest.s < 0 ||
    !Number.isInteger(attest.f) || attest.f < 0 ||
    typeof attest.p !== "string" ||
    typeof attest.d !== "string" || attest.d.length !== 64
  ) {
    throw new Error("STEALTH_ATTEST_INVALID");
  }
  if (attest.s >= ANTI_STEALTH_THRESHOLDS[m]) {
    throw new Error("STEALTH_BROWSER_DENIED");
  }
  const expected = await sha256HexClient(`VS_ATTEST_V1|${ticket}|${publicKey}|${attest.s}|${attest.f}|${attest.p}`);
  if (attest.d !== expected) {
    throw new Error("STEALTH_ATTEST_INVALID");
  }
  const fJs = osFamilyFromStr(attest.p);
  if (fJs) {
    const fUa = osFamilyFromStr(ua);
    if (fUa && fUa !== "android" && fJs !== fUa) throw new Error("STEALTH_BROWSER_DENIED");
    const fCh = osFamilyFromStr(chPlat);
    if (fCh && fCh !== "android" && fJs !== fCh) throw new Error("STEALTH_BROWSER_DENIED");
  }
  return { ok: true, score: attest.s, flags: attest.f };
}

function parseClientVspk(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  if (b.length < 36 || b.subarray(0, 4).toString("ascii") !== "VSPK") {
    throw new Error("BAD_VSPK");
  }
  const version = b.readUInt8(4);
  const cipherId = b.readUInt8(5);
  const hdrLen = b.readUInt16LE(6);
  if (version !== 1 || (cipherId !== 1 && cipherId !== 2) || 36 + hdrLen > b.length) {
    throw new Error("BAD_VSPK_HEADER");
  }
  const iv = b.subarray(8, 20);
  const tag = b.subarray(20, 36);
  const header = JSON.parse(b.subarray(36, 36 + hdrLen).toString("utf8"));
  if (!header || typeof header !== "object" || Array.isArray(header)) {
    throw new Error("BAD_VSPK_HEADER");
  }
  const ciphertext = b.subarray(36 + hdrLen);
  return { version, cipherId, iv, tag, header, ciphertext };
}

async function verifyGrantEd25519Client(grant, authorityPublicKeySpkiB64) {
  const pubSpkiB64 = authorityPublicKeySpkiB64;
  if (!grant || typeof grant.token !== "string" || typeof pubSpkiB64 !== "string" || !pubSpkiB64) {
    throw new Error("MISSING_GRANT_SIGNATURE_KEY");
  }
  const parts = grant.token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error("MALFORMED_GRANT_TOKEN");
  }
  const [bodyB64, sigB64] = parts;
  const verifyKey = await getSubtle().importKey(
    "spki",
    Buffer.from(pubSpkiB64, "base64url"),
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  const valid = await getSubtle().verify(
    { name: "Ed25519" },
    verifyKey,
    Buffer.from(sigB64, "base64url"),
    Buffer.from(bodyB64, "utf8")
  );
  if (!valid) {
    throw new Error("BAD_GRANT_SIGNATURE");
  }
  const claims = JSON.parse(Buffer.from(bodyB64, "base64url").toString("utf8"));
  if (!claims || typeof claims !== "object" || !Number.isFinite(claims.exp)) {
    throw new Error("MALFORMED_GRANT_CLAIMS");
  }
  if (claims.exp <= Date.now()) {
    throw new Error("LEASE_EXPIRED");
  }
  return claims;
}

async function createBrowserEphemeralSession({ antiStealth = "off", ticket = "", telemetry = null } = {}) {
  const kp = await getSubtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const spki = Buffer.from(await getSubtle().exportKey("spki", kp.publicKey));
  const publicKeySpkiB64 = spki.toString("base64url");
  const attest = await collectStealthAttestation({
    mode: antiStealth,
    ticket,
    publicKey: publicKeySpkiB64,
    telemetry,
  });
  return {
    privateKey: kp.privateKey,
    publicKey: kp.publicKey,
    privateKeyExtractable: kp.privateKey.extractable,
    publicKeySpkiB64,
    attest,
  };
}

async function unsealVspkClient({
  vspkBytes,
  grant,
  session,
  expectedProduct,
  expectedOrigin,
  authorityPublicKeySpkiB64,
  antiStealth = "off",
  telemetry = null,
}) {
  if (parseAntiStealthMode(antiStealth) !== "off") {
    await collectStealthAttestation({
      mode: antiStealth,
      ticket: grant?.claims?.jti || grant?.jti || "",
      publicKey: session?.publicKeySpkiB64 || "",
      telemetry,
    });
  }
  const { cipherId, iv, tag, header, ciphertext } = parseClientVspk(vspkBytes);
  if (cipherId !== 1) {
    throw new Error("UNSUPPORTED_WEBCRYPTO_CIPHER");
  }
  const claims = await verifyGrantEd25519Client(grant, authorityPublicKeySpkiB64);

  if (header.domain !== expectedProduct || claims.prd !== expectedProduct) {
    throw new Error("DOMAIN_MISMATCH");
  }
  if (header.assetId !== claims.aid) {
    throw new Error("ASSET_MISMATCH");
  }
  if (expectedOrigin !== undefined && (header.origin !== expectedOrigin || claims.org !== expectedOrigin)) {
    throw new Error("ORIGIN_DENIED");
  }
  if (claims.exp <= Date.now()) {
    throw new Error("LEASE_EXPIRED");
  }
  if (
    !claims.ecdh ||
    typeof claims.ecdh.serverPublicKeySpkiB64 !== "string" ||
    typeof claims.ecdh.wrapIvB64 !== "string" ||
    typeof claims.ecdh.wrappedKeyWithTagB64 !== "string" ||
    typeof claims.jti !== "string"
  ) {
    throw new Error("MALFORMED_GRANT_CLAIMS");
  }

  const sub = getSubtle();
  const serverPub = await sub.importKey(
    "spki",
    Buffer.from(claims.ecdh.serverPublicKeySpkiB64, "base64url"),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const sharedBits = await sub.deriveBits({ name: "ECDH", public: serverPub }, session.privateKey, 256);
  const hkdfBase = await sub.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  new Uint8Array(sharedBits).fill(0);

  const wrapInfo = Buffer.from(`VS_ECDH_WRAP_V1|${claims.prd}|${claims.aid}|${claims.org}`, "utf8");
  const wrapKey = await sub.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: Buffer.from(claims.jti, "utf8"), info: wrapInfo },
    hkdfBase,
    { name: "AES-GCM", length: 256 },
    false,
    ["unwrapKey"]
  );

  const contentKey = await sub.unwrapKey(
    "raw",
    Buffer.from(claims.ecdh.wrappedKeyWithTagB64, "base64url"),
    wrapKey,
    {
      name: "AES-GCM",
      iv: Buffer.from(claims.ecdh.wrapIvB64, "base64url"),
      additionalData: wrapInfo,
      tagLength: 128,
    },
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  const aad = Buffer.from(`VSPK1|${header.domain}|${header.assetId}|${header.origin}`, "utf8");
  const plainAb = await sub.decrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    contentKey,
    Buffer.concat([ciphertext, tag])
  );
  return Buffer.from(plainAb);
}

module.exports = {
  parseAntiStealthMode,
  collectStealthAttestation,
  verifyStealthAttestation,
  createBrowserEphemeralSession,
  verifyGrantEd25519Client,
  unsealVspkClient,
};
