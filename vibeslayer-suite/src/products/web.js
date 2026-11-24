"use strict";

const { webcrypto } = require("node:crypto");
const { SERVER_ONLY_GRANT_SEEDS, packVspk, parseVspkHeader, vsError } = require("../core/authority.js");
const {
  verifyGrantEd25519Client,
  collectStealthAttestation,
  verifyStealthAttestation,
  parseAntiStealthMode,
} = require("../client/web-client.js");

const subtle = globalThis.crypto?.subtle || webcrypto.subtle;

function resolvePinnedGrantPublicKey(grant, callerPubKey) {
  if (callerPubKey !== undefined) {
    return callerPubKey;
  }
  const serverCtx = grant && typeof grant === "object" ? SERVER_ONLY_GRANT_SEEDS.get(grant) : null;
  return serverCtx?.authorityPublicKeySpkiB64;
}

function packWebAsset({ authority, assetId, origin, plainBytes }) {
  const key = authority.deriveAssetKey("web", assetId, origin);
  try {
    const vspkBytes = packVspk({
      key32: key,
      domain: "web",
      assetId,
      origin,
      cipher: "aes-256-gcm",
      plainBytes,
    });
    return { assetId, origin, vspkBytes };
  } finally {
    key.fill(0);
  }
}

async function createBrowserEphemeralSession({ antiStealth = "off", ticket = "", telemetry = null } = {}) {
  const kp = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false, // Non-extractable private key in WebCrypto!
    ["deriveBits"]
  );
  const spki = Buffer.from(await subtle.exportKey("spki", kp.publicKey));
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

async function deriveNonExtractableContentKey({
  grant,
  session,
  expectedProduct,
  expectedOrigin,
  authorityPublicKeySpkiB64,
}) {
  const pinnedPub = resolvePinnedGrantPublicKey(grant, authorityPublicKeySpkiB64);
  const claims = await verifyGrantEd25519Client(grant, pinnedPub);
  if (!claims || typeof claims !== "object" || !Number.isFinite(claims.exp)) {
    throw vsError("BAD_GRANT", "Grant token missing finite exp claim");
  }
  if (expectedProduct && claims.prd !== expectedProduct) {
    throw vsError("PRODUCT_MISMATCH", `Grant product ${claims.prd} !== ${expectedProduct}`);
  }
  if (expectedOrigin !== undefined && claims.org !== expectedOrigin) {
    throw vsError("ORIGIN_DENIED", `Grant origin ${claims.org} !== ${expectedOrigin}`);
  }
  if (claims.exp <= Date.now()) {
    throw vsError("LEASE_EXPIRED", "Session grant expired");
  }
  if (
    !claims.ecdh ||
    typeof claims.ecdh.serverPublicKeySpkiB64 !== "string" ||
    typeof claims.ecdh.wrapIvB64 !== "string" ||
    typeof claims.ecdh.wrappedKeyWithTagB64 !== "string" ||
    typeof claims.jti !== "string"
  ) {
    throw vsError("BAD_GRANT", "Grant token missing ECDH wrap claims");
  }

  const serverPub = await subtle.importKey(
    "spki",
    Buffer.from(claims.ecdh.serverPublicKeySpkiB64, "base64url"),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const sharedBits = await subtle.deriveBits(
    { name: "ECDH", public: serverPub },
    session.privateKey,
    256
  );
  const hkdfBase = await subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  new Uint8Array(sharedBits).fill(0);

  const wrapInfo = Buffer.from(`VS_ECDH_WRAP_V1|${claims.prd}|${claims.aid}|${claims.org}`, "utf8");
  const wrapKey = await subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: Buffer.from(claims.jti, "utf8"),
      info: wrapInfo,
    },
    hkdfBase,
    { name: "AES-GCM", length: 256 },
    false,
    ["unwrapKey"]
  );

  // Unwrap content key directly into a non-extractable WebCrypto AES-GCM key!
  const contentCryptoKey = await subtle.unwrapKey(
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
    false, // Content key is ALSO non-extractable from WebCrypto!
    ["decrypt"]
  );

  return { contentCryptoKey, claims };
}

async function unsealVspkWithWebCrypto({
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
      ticket: grant?.jti || "",
      publicKey: session?.publicKeySpkiB64 || "",
      telemetry,
    });
  }
  const { cipherId, iv, tag, header, ciphertext } = parseVspkHeader(vspkBytes);
  if (cipherId !== 1) {
    throw vsError("UNSUPPORTED_CIPHER", "WebCrypto unseal expects AES-256-GCM");
  }
  const pinnedPub = resolvePinnedGrantPublicKey(grant, authorityPublicKeySpkiB64);
  const verifiedClaims = await verifyGrantEd25519Client(grant, pinnedPub);
  if (!Number.isFinite(verifiedClaims.exp)) {
    throw vsError("BAD_GRANT", "Grant token missing finite exp claim");
  }
  if (header.domain !== expectedProduct || verifiedClaims.prd !== expectedProduct) {
    throw vsError("DOMAIN_MISMATCH", `VSPK domain ${header.domain} !== ${expectedProduct}`);
  }
  if (expectedOrigin !== undefined && (header.origin !== expectedOrigin || verifiedClaims.org !== expectedOrigin)) {
    throw vsError("ORIGIN_DENIED", `VSPK origin ${header.origin} !== ${expectedOrigin}`);
  }
  if (header.assetId !== verifiedClaims.aid) {
    throw vsError("ASSET_MISMATCH", `VSPK assetId ${header.assetId} !== ${verifiedClaims.aid}`);
  }
  const { contentCryptoKey, claims } = await deriveNonExtractableContentKey({
    grant,
    session,
    expectedProduct,
    expectedOrigin,
    authorityPublicKeySpkiB64: pinnedPub,
  });
  if (header.assetId !== claims.aid) {
    throw vsError("ASSET_MISMATCH", `VSPK assetId ${header.assetId} !== ${claims.aid}`);
  }

  const aad = Buffer.from(`VSPK1|${header.domain}|${header.assetId}|${header.origin}`, "utf8");
  const ctWithTag = Buffer.concat([ciphertext, tag]);
  const plainAb = await subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    contentCryptoKey,
    ctWithTag
  );
  return Buffer.from(plainAb);
}

async function unsealWebAssetWithSession({
  vspkBytes,
  grant,
  session,
  expectedOrigin,
  authorityPublicKeySpkiB64,
  antiStealth = "off",
  telemetry = null,
}) {
  return unsealVspkWithWebCrypto({
    vspkBytes,
    grant,
    session,
    expectedProduct: "web",
    expectedOrigin,
    authorityPublicKeySpkiB64,
    antiStealth,
    telemetry,
  });
}

module.exports = {
  packWebAsset,
  createBrowserEphemeralSession,
  deriveNonExtractableContentKey,
  unsealVspkWithWebCrypto,
  unsealWebAssetWithSession,
  collectStealthAttestation,
  verifyStealthAttestation,
  parseAntiStealthMode,
};
