"use strict";

const crypto = require("node:crypto");
const { SERVER_ONLY_GRANT_SEEDS, deriveAssetKey32, packVspk, unpackVspk, vsError } = require("../core/authority.js");
const { unsealToGpuBuffersClient } = require("../client/spatial3d-client.js");

const CHIPS_TOTAL = 1024;
const WM_AMPLITUDE = 4;

function parseGlbChunks(glbBytes) {
  const buf = Buffer.isBuffer(glbBytes) ? glbBytes : Buffer.from(glbBytes);
  if (buf.length < 28 || buf.subarray(0, 4).toString("ascii") !== "glTF") {
    throw vsError("INVALID_GLB", "Expected glTF 2.0 binary container");
  }
  const jsonLen = buf.readUInt32LE(12);
  const binHeaderOff = 20 + jsonLen;
  if (binHeaderOff + 8 > buf.length) {
    throw vsError("TRUNCATED_GLB", "Truncated glTF JSON/BIN header");
  }
  const jsonObj = JSON.parse(buf.subarray(20, binHeaderOff).toString("utf8"));
  const binLen = buf.readUInt32LE(binHeaderOff);
  if (binHeaderOff + 8 + binLen > buf.length) {
    throw vsError("TRUNCATED_GLB", "Truncated glTF BIN chunk");
  }
  const binChunk = buf.subarray(binHeaderOff + 8, binHeaderOff + 8 + binLen);
  return { jsonObj, binChunk };
}

function chipIndexAndSign(carrierSeed32, chipIdx, arrayLen) {
  if (arrayLen < CHIPS_TOTAL) {
    throw vsError("VS3D_TOO_SMALL", "Position stream shorter than CHIPS_TOTAL");
  }
  const digest = crypto
    .createHash("sha256")
    .update(carrierSeed32)
    .update(Buffer.from([chipIdx & 0xff, (chipIdx >> 8) & 0xff]))
    .digest();
  const bucketSize = Math.floor(arrayLen / CHIPS_TOTAL);
  const idx = chipIdx * bucketSize + (digest.readUInt32LE(0) % bucketSize);
  const sign = (digest[4] & 1) === 0 ? 1 : -1;
  return { idx, sign };
}

// Right-handed glTF 2.0 coordinate convention (+Y up, +Z forward); int16 SNORM [-32767, 32767].
function cookGlbToProtectedStream({ authority, modelId, origin, glbBytes }) {
  const { jsonObj, binChunk } = parseGlbChunks(glbBytes);

  let vertexCount = 4096;
  let indexCount = 12288;
  let boundsMin = [-32767, -32767, -32767];
  let boundsMax = [32767, 32767, 32767];

  for (const acc of jsonObj.accessors || []) {
    if (acc.type === "SCALAR" && acc.count > 0) {
      indexCount = acc.count;
    }
    if (acc.type === "VEC3" && acc.count > 0 && Array.isArray(acc.max)) {
      vertexCount = acc.count;
      boundsMin = acc.min;
      boundsMax = acc.max;
    }
  }

  const strippedDescriptor = {
    v: 2,
    vertexCount,
    indexCount,
    boundsMin,
    boundsMax,
    bufferViewCount: (jsonObj.bufferViews || []).length,
    accessorCount: (jsonObj.accessors || []).length,
  };

  // Keyed base geometry + keyed stream mask so `gpuStreamBytes` cannot be inverted to recover `ownerRef`!
  const geomSecret = crypto
    .createHmac("sha256", authority.policy.masterKey)
    .update(`VS3D_KEYED_GEOM_V2|${modelId}`)
    .digest();
  const streamMask = crypto
    .createHmac("sha256", authority.policy.masterKey)
    .update(`VS3D_AUX_STREAM_V2|${modelId}`)
    .digest();

  const coordLen = Math.max(vertexCount * 3, CHIPS_TOTAL * 4);
  const ownerRef = new Int16Array(coordLen);
  for (let i = 0; i < coordLen; i++) {
    const srcByte = binChunk.length > 0 ? binChunk[i % binChunk.length] : (i & 0xff);
    const k = geomSecret[i & 31];
    const rawVal = ((((srcByte ^ k) * 257 + ((i * 73) & 0xffff)) & 0xffff) - 32768);
    ownerRef[i] = Math.max(-32750, Math.min(32750, rawVal));
  }
  geomSecret.fill(0);

  const cookedAuxStream = Buffer.alloc(binChunk.length);
  for (let i = 0; i < binChunk.length; i++) {
    cookedAuxStream[i] = binChunk[i] ^ streamMask[i & 31];
  }
  streamMask.fill(0);

  const descBuf = Buffer.from(JSON.stringify(strippedDescriptor), "utf8");
  const posBytes = Buffer.from(ownerRef.buffer, ownerRef.byteOffset, ownerRef.byteLength);

  const hdr = Buffer.alloc(16);
  hdr.write("VS3D", 0, "ascii");
  hdr.writeUInt32LE(descBuf.length, 4);
  hdr.writeUInt32LE(posBytes.length, 8);
  hdr.writeUInt32LE(cookedAuxStream.length, 12);

  const vs3dPlain = Buffer.concat([hdr, descBuf, posBytes, cookedAuxStream]);
  cookedAuxStream.fill(0);
  const key = authority.deriveAssetKey("spatial-3d", modelId, origin);
  try {
    const vspkBytes = packVspk({
      key32: key,
      domain: "spatial-3d",
      assetId: modelId,
      origin,
      cipher: "aes-256-gcm",
      plainBytes: vs3dPlain,
    });
    vs3dPlain.fill(0);
    return {
      modelId,
      origin,
      vspkBytes,
      ownerReferencePositionsInt16: ownerRef,
      vertexCount,
      indexCount,
    };
  } finally {
    key.fill(0);
  }
}

// Server-side per-lease watermarking: embeds chips BEFORE shipping to client so client never sees unwatermarked ownerRef or wmSeed!
function sealWatermarkedStreamForGrant({ masterKey, vspkBytes, grant, wmCarrierSeed }) {
  const { aid, org } = grant.claims;
  const key = deriveAssetKey32(masterKey, "spatial-3d", aid, org);
  const plain = unpackVspk({
    vspkBytes,
    key32: key,
    expectedDomain: "spatial-3d",
    expectedOrigin: org,
  });
  try {
    if (plain.length < 16 || plain.subarray(0, 4).toString("ascii") !== "VS3D") {
      throw vsError("BAD_VS3D", "Invalid cooked VS3D payload");
    }
    const descLen = plain.readUInt32LE(4);
    const posByteLen = plain.readUInt32LE(8);
    const binByteLen = plain.readUInt32LE(12);
    const posStart = 16 + descLen;
    const binStart = posStart + posByteLen;
    if ((posByteLen & 1) !== 0 || binStart + binByteLen > plain.length) {
      throw vsError("TRUNCATED_VS3D", "Truncated VS3D buffer");
    }

    const alignedPos = Buffer.from(plain.subarray(posStart, binStart));
    const posArr = new Int16Array(alignedPos.buffer, alignedPos.byteOffset, posByteLen / 2);
    if (posArr.length < CHIPS_TOTAL) {
      throw vsError("VS3D_TOO_SMALL", "Position stream shorter than CHIPS_TOTAL");
    }
    for (let c = 0; c < CHIPS_TOTAL; c++) {
      const { idx, sign } = chipIndexAndSign(wmCarrierSeed, c, posArr.length);
      const val = posArr[idx] + sign * WM_AMPLITUDE;
      posArr[idx] = Math.max(-32750, Math.min(32750, val));
    }
    alignedPos.copy(plain, posStart);

    return packVspk({
      key32: key,
      domain: "spatial-3d",
      assetId: aid,
      origin: org,
      cipher: "aes-256-gcm",
      plainBytes: plain,
    });
  } finally {
    plain.fill(0);
    key.fill(0);
  }
}

async function unsealToGpuBuffers({
  vspkBytes,
  grant,
  session,
  expectedOrigin,
  authorityPublicKeySpkiB64,
}) {
  let deliveredVspk = vspkBytes;
  const serverCtx = grant && typeof grant === "object" ? SERVER_ONLY_GRANT_SEEDS.get(grant) : null;
  if (serverCtx && serverCtx.wmCarrierSeed) {
    deliveredVspk = sealWatermarkedStreamForGrant({
      masterKey: serverCtx.masterKey,
      vspkBytes,
      grant,
      wmCarrierSeed: serverCtx.wmCarrierSeed,
    });
  }
  const pinnedPub =
    authorityPublicKeySpkiB64 !== undefined
      ? authorityPublicKeySpkiB64
      : serverCtx?.authorityPublicKeySpkiB64;
  return unsealToGpuBuffersClient({
    vspkBytes: deliveredVspk,
    grant,
    session,
    expectedOrigin,
    authorityPublicKeySpkiB64: pinnedPub,
  });
}

function bpskChipSlot(carrierSeed32, chipIdx, totalLen) {
  if (totalLen < CHIPS_TOTAL) {
    throw vsError("VS3D_TOO_SMALL", "Position stream shorter than CHIPS_TOTAL");
  }
  const msg = Buffer.allocUnsafe(34);
  carrierSeed32.copy(msg, 0, 0, 32);
  msg[32] = chipIdx & 0xff;
  msg[33] = (chipIdx >> 8) & 0xff;
  const h = crypto.createHash("sha256").update(msg).digest();
  const bucket = Math.floor(totalLen / CHIPS_TOTAL);
  const idx = chipIdx * bucket + (h.readUInt32LE(0) % bucket);
  const carrierPol = (h[4] & 1) === 0 ? 1 : -1;
  return { idx, carrierPol };
}

function parseWmId64({ watermarkIdHex, wmIdU64 }) {
  if (wmIdU64 !== undefined && wmIdU64 !== null) {
    return BigInt.asUintN(64, BigInt(wmIdU64));
  }
  if (typeof watermarkIdHex === "string" && /^[0-9a-fA-F]{1,16}$/.test(watermarkIdHex)) {
    return BigInt.asUintN(64, BigInt(`0x${watermarkIdHex.padStart(16, "0")}`));
  }
  throw vsError("BAD_WM_ID", "Valid 64-bit watermarkIdHex or wmIdU64 required");
}

function embedLeaseWatermark64({
  authority,
  masterKey,
  modelId,
  positionsInt16,
  watermarkIdHex,
  wmIdU64,
}) {
  const key = masterKey || authority?.policy?.masterKey;
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw vsError("BAD_MASTER_KEY", "32-byte masterKey required");
  }
  if (!positionsInt16 || positionsInt16.length < CHIPS_TOTAL) {
    throw vsError("VS3D_TOO_SMALL", "Position stream shorter than CHIPS_TOTAL");
  }
  const id64 = parseWmId64({ watermarkIdHex, wmIdU64 });
  const out = new Int16Array(positionsInt16);
  const carrierSeed = crypto
    .createHmac("sha256", key)
    .update(`VS_WM64_BPSK_V1|${modelId}`)
    .digest();
  try {
    for (let c = 0; c < CHIPS_TOTAL; c++) {
      const bitIdx = c >> 4;
      const bitPol = ((id64 >> BigInt(bitIdx)) & 1n) === 1n ? 1 : -1;
      const { idx, carrierPol } = bpskChipSlot(carrierSeed, c, out.length);
      const delta = bitPol * carrierPol * WM_AMPLITUDE;
      out[idx] = Math.max(-32750, Math.min(32750, out[idx] + delta));
    }
    return {
      positionsInt16: out,
      wmIdU64: id64,
      watermarkIdHex: id64.toString(16).padStart(16, "0"),
    };
  } finally {
    carrierSeed.fill(0);
  }
}

function decodeLeaseWatermark64O1({
  authority,
  masterKey,
  modelId,
  basePositionsInt16,
  ownerReferencePositionsInt16,
  capturedPositionsInt16,
}) {
  const key = masterKey || authority?.policy?.masterKey;
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw vsError("BAD_MASTER_KEY", "32-byte masterKey required");
  }
  const basePos = basePositionsInt16 || ownerReferencePositionsInt16;
  if (!basePos || !capturedPositionsInt16 || basePos.length < CHIPS_TOTAL || capturedPositionsInt16.length < basePos.length) {
    throw vsError("VS3D_TOO_SMALL", "Invalid position buffers for 64-bit watermark decoding");
  }
  const carrierSeed = crypto
    .createHmac("sha256", key)
    .update(`VS_WM64_BPSK_V1|${modelId}`)
    .digest();
  let decoded = 0n;
  let totalAbsConf = 0;
  const maxPerBit = 16 * WM_AMPLITUDE;
  const maxClamp = WM_AMPLITUDE * 2;
  try {
    for (let bitIdx = 0; bitIdx < 64; bitIdx++) {
      let softSum = 0;
      for (let sub = 0; sub < 16; sub++) {
        const c = (bitIdx << 4) + sub;
        const { idx, carrierPol } = bpskChipSlot(carrierSeed, c, basePos.length);
        const obs = Math.max(-maxClamp, Math.min(maxClamp, capturedPositionsInt16[idx] - basePos[idx]));
        softSum += obs * carrierPol;
      }
      if (softSum >= 0) {
        decoded |= 1n << BigInt(bitIdx);
      }
      totalAbsConf += Math.min(1, Math.abs(softSum) / maxPerBit);
    }
  } finally {
    carrierSeed.fill(0);
  }
  const decodedHex = decoded.toString(16).padStart(16, "0");
  return {
    decodedWatermarkIdHex: decodedHex,
    wmIdU64: decoded,
    meanChipConfidence: totalAbsConf / 64,
    leakerRecord: authority ? authority.resolveLeaker(decodedHex) : null,
  };
}

function extractLeaseWatermark({
  authority,
  modelId,
  basePositionsInt16,
  capturedPositionsInt16,
  candidateWatermarkIds,
}) {
  if (
    !basePositionsInt16 ||
    !capturedPositionsInt16 ||
    basePositionsInt16.length < CHIPS_TOTAL ||
    capturedPositionsInt16.length < basePositionsInt16.length
  ) {
    throw vsError("VS3D_TOO_SMALL", "Invalid position buffers for watermark extraction");
  }

  let bestId = null;
  let bestScore = -Infinity;
  const maxClamp = WM_AMPLITUDE * 2;
  const normDenom = CHIPS_TOTAL * WM_AMPLITUDE;

  for (const wmId of candidateWatermarkIds) {
    const seed = authority.computeWatermarkCarrierSeed(modelId, wmId);
    let dot = 0;
    for (let c = 0; c < CHIPS_TOTAL; c++) {
      const { idx, sign } = chipIndexAndSign(seed, c, basePositionsInt16.length);
      const observedDelta = capturedPositionsInt16[idx] - basePositionsInt16[idx];
      const clamped = Math.max(-maxClamp, Math.min(maxClamp, observedDelta));
      dot += clamped * sign;
    }
    seed.fill(0);
    const corr = Math.max(-1, Math.min(1, dot / normDenom));
    if (corr > bestScore) {
      bestScore = corr;
      bestId = wmId;
    }
  }

  return {
    matchedWatermarkIdHex: bestId,
    bitMatchRatio: bestScore,
    leakerRecord: bestId ? authority.resolveLeaker(bestId) : null,
  };
}

module.exports = {
  WM_AMPLITUDE,
  cookGlbToProtectedStream,
  sealWatermarkedStreamForGrant,
  unsealToGpuBuffers,
  embedLeaseWatermark64,
  decodeLeaseWatermark64O1,
  extractLeaseWatermark,
};
