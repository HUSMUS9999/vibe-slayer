"use strict";

const crypto = require("node:crypto");
const { CONFIG, SERVER_ONLY_GRANT_SEEDS, deriveAssetKey32, vsError } = require("../core/authority.js");
const { parseVsraForGrant, unsealWeightChunkClient } = require("../client/data-ai-client.js");

const TENSOR_CHIPS = 1024;
const EPSILON = 2e-6;

function tensorChipIndexAndSign(seed32, chipIdx, len) {
  const h = crypto
    .createHash("sha256")
    .update(seed32)
    .update(Buffer.from([chipIdx & 0xff, (chipIdx >> 8) & 0xff]))
    .digest();
  const bucket = Math.floor(len / TENSOR_CHIPS);
  const idx = chipIdx * bucket + (h.readUInt32LE(0) % bucket);
  const sign = (h[4] & 1) === 0 ? 1 : -1;
  return { idx, sign };
}

/*
 * `VSRA` v1 Random-Access Chunked AEAD Container:
 * Layout:
 *   [0..4]   "VSRA"
 *   [4..8]   chunkBytes (uint32LE)
 *   [8..12]  chunkCount (uint32LE)
 *   [12..16] tensorIdByteLen (uint32LE)
 *   [16..16+idLen] tensorId UTF-8
 *   Followed by `chunkCount` fixed-stride records, each:
 *     [0..4]   plainLen (uint32LE)
 *     [4..16]  nonce12
 *     [16..32] tag16
 *     [32..32+chunkBytes] ciphertext (zero-padded to chunkBytes for O(1) offset math)
 */
function packRandomAccessWeights({ authority, tensorId, plainBytes, chunkBytes = 65536 }) {
  if (typeof tensorId !== "string" || tensorId.length === 0) {
    throw vsError("BAD_VSRA", "Non-empty tensorId required");
  }
  if (!Number.isInteger(chunkBytes) || chunkBytes <= 0 || (chunkBytes & 3) !== 0) {
    throw vsError("BAD_VSRA", "chunkBytes must be a positive multiple of 4");
  }
  const plain = Buffer.isBuffer(plainBytes) ? plainBytes : Buffer.from(plainBytes);
  if (plain.length === 0 || (plain.length & 3) !== 0) {
    throw vsError("BAD_VSRA", "plainBytes must be non-empty FP32-aligned bytes");
  }
  const chunkCount = Math.ceil(plain.length / chunkBytes);
  const idBuf = Buffer.from(tensorId, "utf8");

  const hdr = Buffer.alloc(16 + idBuf.length);
  hdr.write(CONFIG.MAGIC_VSRA, 0, "ascii");
  hdr.writeUInt32LE(chunkBytes, 4);
  hdr.writeUInt32LE(chunkCount, 8);
  hdr.writeUInt32LE(idBuf.length, 12);
  idBuf.copy(hdr, 16);

  const recordStride = 32 + chunkBytes;
  const records = Buffer.alloc(chunkCount * recordStride);

  for (let c = 0; c < chunkCount; c++) {
    const slice = plain.subarray(c * chunkBytes, Math.min(plain.length, (c + 1) * chunkBytes));
    const chunkKey = authority.deriveAssetKey("data-ai", `${tensorId}#${c}`, "");
    const nonce = crypto.randomBytes(12);
    const aad = Buffer.from(`VSRA_V1|${tensorId}|${c}`, "utf8");
    const cipher = crypto.createCipheriv("chacha20-poly1305", chunkKey, nonce, { authTagLength: 16 });
    cipher.setAAD(aad, { plaintextLength: slice.length });
    const ct = Buffer.concat([cipher.update(slice), cipher.final()]);
    const tag = cipher.getAuthTag();
    chunkKey.fill(0);

    const recOff = c * recordStride;
    records.writeUInt32LE(slice.length, recOff);
    nonce.copy(records, recOff + 4);
    tag.copy(records, recOff + 16);
    ct.copy(records, recOff + 32);
  }

  return {
    tensorId,
    chunkBytes,
    chunkCount,
    vspkRaBytes: Buffer.concat([hdr, records]),
  };
}

function issueChunkLease({ authority, action, params, subject, scopes, tensorId, chunkIndex }) {
  const act = authority.checkPolicyAction(action, params, scopes, "");
  const jti = crypto.randomBytes(10).toString("hex");
  const watermarkIdHex = crypto
    .createHmac("sha256", authority.policy.masterKey)
    .update(`AI_WM|${subject}|${jti}`)
    .digest("hex")
    .slice(0, 16);

  // Issue a fresh per-lease chunk key so clients can never decrypt the raw unwatermarked VSRA container directly.
  const leaseChunkKey = crypto.randomBytes(32);
  const wmSeed = act.watermark
    ? authority.computeWatermarkCarrierSeed(`${tensorId}#${chunkIndex}`, watermarkIdHex)
    : null;

  const grantObj = {
    subject,
    tensorId,
    chunkIndex,
    jti,
    watermarkIdHex,
    chunkKeyHex: leaseChunkKey.toString("hex"),
  };
  leaseChunkKey.fill(0);
  SERVER_ONLY_GRANT_SEEDS.set(grantObj, {
    masterKey: authority.policy.masterKey,
    wmSeed,
  });
  return grantObj;
}

// Server-side per-lease watermarking: decrypts static chunk, embeds traitor watermark, and re-encrypts under per-lease key.
function sealWatermarkedChunkForGrant({ masterKey, authority, vspkRaBytes, grant, wmSeed }) {
  const resolvedMasterKey = masterKey || authority?.policy?.masterKey;
  if (!Buffer.isBuffer(resolvedMasterKey) || resolvedMasterKey.length !== 32) {
    throw vsError("BAD_MASTER_KEY", "32-byte masterKey required");
  }
  if (!grant || typeof grant.chunkKeyHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(grant.chunkKeyHex)) {
    throw vsError("BAD_GRANT", "32-byte hex chunkKeyHex required");
  }
  const {
    buf,
    chunkCount,
    idLen,
    tensorId,
    recordStride,
    recOff,
    plainLen,
    nonce,
    tag,
    ct,
  } = parseVsraForGrant(vspkRaBytes, grant);

  const staticChunkKey = deriveAssetKey32(resolvedMasterKey, "data-ai", `${tensorId}#${grant.chunkIndex}`, "");
  const leaseKey = Buffer.from(grant.chunkKeyHex, "hex");
  const aad = Buffer.from(`VSRA_V1|${tensorId}|${grant.chunkIndex}`, "utf8");
  let plain = null;
  let wmPlain = null;
  try {
    const dec = crypto.createDecipheriv("chacha20-poly1305", staticChunkKey, nonce, { authTagLength: 16 });
    dec.setAAD(aad, { plaintextLength: plainLen });
    dec.setAuthTag(tag);
    plain = Buffer.concat([dec.update(ct), dec.final()]);

    wmPlain = Buffer.from(plain);
    const floatCount = wmPlain.byteLength / 4;
    const serverSeed = SERVER_ONLY_GRANT_SEEDS.get(grant)?.wmSeed || null;
    const resolvedSeed = wmSeed !== undefined ? wmSeed : serverSeed;
    if (resolvedSeed && floatCount >= TENSOR_CHIPS) {
      const floats = new Float32Array(wmPlain.buffer, wmPlain.byteOffset, floatCount);
      for (let c = 0; c < TENSOR_CHIPS; c++) {
        const { idx, sign } = tensorChipIndexAndSign(resolvedSeed, c, floats.length);
        floats[idx] = Math.fround(floats[idx] + sign * EPSILON);
      }
    }

    const newNonce = crypto.randomBytes(12);
    const enc = crypto.createCipheriv("chacha20-poly1305", leaseKey, newNonce, { authTagLength: 16 });
    enc.setAAD(aad, { plaintextLength: wmPlain.length });
    const newCt = Buffer.concat([enc.update(wmPlain), enc.final()]);
    const newTag = enc.getAuthTag();

    const hdrEnd = 16 + idLen;
    const out = Buffer.alloc(hdrEnd + chunkCount * recordStride);
    buf.subarray(0, hdrEnd).copy(out, 0);
    out.writeUInt32LE(plainLen, recOff);
    newNonce.copy(out, recOff + 4);
    newTag.copy(out, recOff + 16);
    newCt.copy(out, recOff + 32);
    return out;
  } finally {
    staticChunkKey.fill(0);
    leaseKey.fill(0);
    if (plain) plain.fill(0);
    if (wmPlain) wmPlain.fill(0);
  }
}

function unsealWeightChunk({ vspkRaBytes, grant }) {
  const serverCtx = grant && typeof grant === "object" ? SERVER_ONLY_GRANT_SEEDS.get(grant) : null;
  if (serverCtx && serverCtx.masterKey) {
    const sealed = sealWatermarkedChunkForGrant({
      masterKey: serverCtx.masterKey,
      vspkRaBytes,
      grant,
      wmSeed: serverCtx.wmSeed,
    });
    return unsealWeightChunkClient({ vspkRaBytes: sealed, grant });
  }
  return unsealWeightChunkClient({ vspkRaBytes, grant });
}

function extractTensorWatermark({
  authority,
  tensorId,
  chunkIndex,
  baseFloats,
  leakedFloats,
  candidateWatermarkIds,
}) {
  if (!baseFloats || !leakedFloats || baseFloats.length < TENSOR_CHIPS || leakedFloats.length < baseFloats.length) {
    throw vsError("VSRA_TOO_SMALL", "Float buffers must contain at least TENSOR_CHIPS elements");
  }
  let bestId = null;
  let bestRatio = -1;

  for (const wmId of candidateWatermarkIds) {
    const seed = authority.computeWatermarkCarrierSeed(`${tensorId}#${chunkIndex}`, wmId);
    let matches = 0;
    for (let c = 0; c < TENSOR_CHIPS; c++) {
      const { idx, sign } = tensorChipIndexAndSign(seed, c, baseFloats.length);
      const diff = leakedFloats[idx] - baseFloats[idx];
      if ((sign > 0 && diff > 0) || (sign < 0 && diff < 0)) {
        matches += 1;
      }
    }
    seed.fill(0);
    const ratio = matches / TENSOR_CHIPS;
    if (ratio > bestRatio) {
      bestRatio = ratio;
      bestId = wmId;
    }
  }

  return {
    matchedWatermarkIdHex: bestId,
    bitMatchRatio: bestRatio,
  };
}

module.exports = {
  packRandomAccessWeights,
  issueChunkLease,
  sealWatermarkedChunkForGrant,
  unsealWeightChunk,
  extractTensorWatermark,
};
