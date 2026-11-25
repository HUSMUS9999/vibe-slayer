"use strict";

const crypto = require("node:crypto");

const DTYPE_CODE_TO_STR = Object.freeze({
  0: "RAW",
  1: "F32",
  2: "BF16",
  3: "F16",
  4: "F8_E4M3",
  5: "F8_E5M2",
  6: "I8",
  7: "U8",
  8: "I4",
});

const MAX_CHUNK_BYTES = 64 * 1024 * 1024;
const MAX_META_BYTES = 16 * 1024 * 1024;
const MAX_F32_RANGES = 2048;

function validateF32Ranges(rawRanges, maxByteLimit) {
  if (!Array.isArray(rawRanges) || rawRanges.length > MAX_F32_RANGES) {
    throw new Error("BAD_VSRA");
  }
  const clean = [];
  let prevEnd = 0;
  for (const r of rawRanges) {
    if (!r || typeof r !== "object" || Array.isArray(r)) throw new Error("BAD_VSRA");
    const { start, end } = r;
    if (
      typeof start !== "number" ||
      typeof end !== "number" ||
      !Number.isSafeInteger(start) ||
      !Number.isSafeInteger(end) ||
      start < prevEnd ||
      end <= start ||
      ((end - start) & 3) !== 0 ||
      end > maxByteLimit
    ) {
      throw new Error("BAD_VSRA");
    }
    clean.push({ start, end });
    prevEnd = end;
  }
  return clean;
}

/**
 * Parses either legacy `VSRA` (v1) or metadata-authenticated `VSR2` (v2) random-access containers.
 */
function parseVsraForGrant(vspkRaBytes, grant) {
  const buf = Buffer.isBuffer(vspkRaBytes) ? vspkRaBytes : Buffer.from(vspkRaBytes);
  if (buf.length < 16) {
    throw new Error("BAD_VSRA");
  }
  const magic = buf.subarray(0, 4).toString("ascii");
  const isV2 = magic === "VSR2";
  if (magic !== "VSRA" && !isV2) {
    throw new Error("BAD_VSRA");
  }
  const chunkBytes = buf.readUInt32LE(4);
  const chunkCount = buf.readUInt32LE(8);
  const idLen = buf.readUInt32LE(12);
  if (chunkBytes === 0 || chunkBytes > MAX_CHUNK_BYTES || (chunkBytes & 3) !== 0 || chunkCount === 0) {
    throw new Error("BAD_VSRA");
  }

  let hdrEnd;
  let tensorId;
  let dtype = "RAW";
  let isSafetensors = false;
  let f32Ranges = [];
  let metaHashHex = "";

  if (!isV2) {
    hdrEnd = 16 + idLen;
    if (hdrEnd > buf.length) throw new Error("BAD_VSRA");
    tensorId = buf.subarray(16, hdrEnd).toString("utf8");
  } else {
    if (buf.length < 22 + idLen) throw new Error("BAD_VSRA");
    const dtypeCode = buf[16];
    isSafetensors = buf[17] === 1;
    const metaLen = buf.readUInt32LE(18);
    if (metaLen > MAX_META_BYTES) throw new Error("BAD_VSRA");
    hdrEnd = 22 + idLen + metaLen;
    if (!Number.isSafeInteger(hdrEnd) || hdrEnd > buf.length) throw new Error("BAD_VSRA");
    dtype = DTYPE_CODE_TO_STR[dtypeCode] || "RAW";
    tensorId = buf.subarray(22, 22 + idLen).toString("utf8");
    const metaSlice = buf.subarray(22 + idLen, hdrEnd);
    metaHashHex = crypto.createHash("sha256").update(metaSlice).digest("hex");
    if (metaLen > 0) {
      let parsedMeta;
      try {
        parsedMeta = JSON.parse(metaSlice.toString("utf8"));
      } catch {
        throw new Error("BAD_VSRA");
      }
      if (!parsedMeta || typeof parsedMeta !== "object" || Array.isArray(parsedMeta)) {
        throw new Error("BAD_VSRA");
      }
      if (parsedMeta.f32Ranges !== undefined) {
        const maxByteLimit = chunkCount * chunkBytes;
        f32Ranges = validateF32Ranges(parsedMeta.f32Ranges, maxByteLimit);
      }
    }
  }

  if (
    !grant ||
    tensorId !== grant.tensorId ||
    !Number.isInteger(grant.chunkIndex) ||
    grant.chunkIndex < 0 ||
    grant.chunkIndex >= chunkCount
  ) {
    throw new Error("CHUNK_RANGE");
  }

  const recordStride = 32 + chunkBytes;
  const expectedTotalBytes = hdrEnd + chunkCount * recordStride;
  if (!Number.isSafeInteger(expectedTotalBytes) || expectedTotalBytes > buf.length) {
    throw new Error("BAD_VSRA");
  }
  const recOff = hdrEnd + grant.chunkIndex * recordStride;
  if (!Number.isSafeInteger(recOff) || recOff + 32 + chunkBytes > buf.length) {
    throw new Error("BAD_VSRA");
  }
  const plainLen = buf.readUInt32LE(recOff);
  if (plainLen === 0 || plainLen > chunkBytes) {
    throw new Error("BAD_VSRA");
  }
  const nonce = buf.subarray(recOff + 4, recOff + 16);
  const tag = buf.subarray(recOff + 16, recOff + 32);
  const ct = buf.subarray(recOff + 32, recOff + 32 + plainLen);
  // Binds chunkBytes, chunkCount, dtype, isSafetensors, AND SHA-256(metaBuf) into AEAD AAD!
  const aadPrefix = isV2
    ? `VSR2|${tensorId}|${grant.chunkIndex}|${chunkBytes}|${chunkCount}|${dtype}|${isSafetensors ? 1 : 0}|${metaHashHex}`
    : `VSRA_V1|${tensorId}|${grant.chunkIndex}`;

  return {
    buf,
    magic,
    isV2,
    hdrEnd,
    chunkBytes,
    chunkCount,
    idLen,
    tensorId,
    dtype,
    isSafetensors,
    f32Ranges,
    metaHashHex,
    aadPrefix,
    recordStride,
    recOff,
    plainLen,
    nonce,
    tag,
    ct,
  };
}

/**
 * O(1)-memory client unseal for a single sealed chunk record (`VSR1`) produced by
 * `sealSingleChunkForGrant`. Returns raw `Buffer` (safe for `.safetensors`, BF16, FP16, FP8, INT4, and F32).
 */
function unsealSingleChunkBytesClient({ sealedChunk, grant }) {
  const buf = Buffer.isBuffer(sealedChunk) ? sealedChunk : Buffer.from(sealedChunk);
  if (buf.length < 38 || buf.subarray(0, 4).toString("ascii") !== "VSR1") {
    throw new Error("BAD_VSR1");
  }
  if (!grant || typeof grant.chunkKeyHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(grant.chunkKeyHex)) {
    throw new Error("BAD_GRANT");
  }
  const plainLen = buf.readUInt32LE(4);
  const dtypeCode = buf[8];
  const flags = buf[9];
  const isV2Aad = (flags & 1) === 1;
  const isSafetensors = (flags & 2) === 2;
  const dtype = DTYPE_CODE_TO_STR[dtypeCode] || "RAW";
  if (plainLen === 0 || 38 + plainLen !== buf.length) {
    throw new Error("BAD_VSR1");
  }
  const nonce = buf.subarray(10, 22);
  const tag = buf.subarray(22, 38);
  const ct = buf.subarray(38, 38 + plainLen);
  const key = Buffer.from(grant.chunkKeyHex, "hex");
  const aad = Buffer.from(
    isV2Aad
      ? `VSR1_V2|${grant.tensorId}|${grant.chunkIndex}|${dtype}|${isSafetensors ? 1 : 0}|${plainLen}`
      : `VSRA_V1|${grant.tensorId}|${grant.chunkIndex}`,
    "utf8"
  );
  try {
    const dec = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    dec.setAAD(aad, { plaintextLength: plainLen });
    dec.setAuthTag(tag);
    return Buffer.concat([dec.update(ct), dec.final()]);
  } finally {
    key.fill(0);
  }
}

function unsealWeightChunkBytesClient({ vspkRaBytes, grant }) {
  const { aadPrefix, plainLen, nonce, tag, ct } = parseVsraForGrant(vspkRaBytes, grant);
  if (!grant || typeof grant.chunkKeyHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(grant.chunkKeyHex)) {
    throw new Error("BAD_GRANT");
  }
  const key = Buffer.from(grant.chunkKeyHex, "hex");
  const aad = Buffer.from(aadPrefix, "utf8");
  try {
    const dec = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    dec.setAAD(aad, { plaintextLength: plainLen });
    dec.setAuthTag(tag);
    return Buffer.concat([dec.update(ct), dec.final()]);
  } finally {
    key.fill(0);
  }
}

function unsealWeightChunkClient({ vspkRaBytes, grant }) {
  const parsed = parseVsraForGrant(vspkRaBytes, grant);
  const plain = unsealWeightChunkBytesClient({ vspkRaBytes, grant });
  if (parsed.isV2 && (parsed.dtype !== "F32" || parsed.isSafetensors)) {
    return plain;
  }
  if ((plain.byteLength & 3) !== 0) {
    plain.fill(0);
    throw new Error("NON_FP32_CHUNK_USE_BYTES_API");
  }
  const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  const floats = new Float32Array(plain.byteLength / 4);
  for (let i = 0; i < floats.length; i++) {
    floats[i] = view.getFloat32(i * 4, true);
  }
  plain.fill(0);
  return floats;
}

module.exports = {
  DTYPE_CODE_TO_STR,
  parseVsraForGrant,
  unsealWeightChunkClient,
  unsealWeightChunkBytesClient,
  unsealSingleChunkBytesClient,
};
