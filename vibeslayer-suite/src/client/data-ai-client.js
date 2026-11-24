"use strict";

const crypto = require("node:crypto");

function parseVsraForGrant(vspkRaBytes, grant) {
  const buf = Buffer.isBuffer(vspkRaBytes) ? vspkRaBytes : Buffer.from(vspkRaBytes);
  if (buf.length < 16 || buf.subarray(0, 4).toString("ascii") !== "VSRA") {
    throw new Error("BAD_VSRA");
  }
  const chunkBytes = buf.readUInt32LE(4);
  const chunkCount = buf.readUInt32LE(8);
  const idLen = buf.readUInt32LE(12);
  if (chunkBytes === 0 || (chunkBytes & 3) !== 0 || chunkCount === 0) {
    throw new Error("BAD_VSRA");
  }
  if (16 + idLen > buf.length) {
    throw new Error("BAD_VSRA");
  }
  const tensorId = buf.subarray(16, 16 + idLen).toString("utf8");
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
  const expectedTotalBytes = 16 + idLen + chunkCount * recordStride;
  if (!Number.isSafeInteger(expectedTotalBytes) || expectedTotalBytes > buf.length) {
    throw new Error("BAD_VSRA");
  }
  const recOff = 16 + idLen + grant.chunkIndex * recordStride;
  if (!Number.isSafeInteger(recOff) || recOff + 32 + chunkBytes > buf.length) {
    throw new Error("BAD_VSRA");
  }
  const plainLen = buf.readUInt32LE(recOff);
  if (plainLen === 0 || plainLen > chunkBytes || (plainLen & 3) !== 0) {
    throw new Error("BAD_VSRA");
  }
  const nonce = buf.subarray(recOff + 4, recOff + 16);
  const tag = buf.subarray(recOff + 16, recOff + 32);
  const ct = buf.subarray(recOff + 32, recOff + 32 + plainLen);
  return {
    buf,
    chunkBytes,
    chunkCount,
    idLen,
    tensorId,
    recordStride,
    recOff,
    plainLen,
    nonce,
    tag,
    ct,
  };
}

function unsealWeightChunkClient({ vspkRaBytes, grant }) {
  const { tensorId, plainLen, nonce, tag, ct } = parseVsraForGrant(vspkRaBytes, grant);
  if (!grant || typeof grant.chunkKeyHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(grant.chunkKeyHex)) {
    throw new Error("BAD_GRANT");
  }

  const key = Buffer.from(grant.chunkKeyHex, "hex");
  const aad = Buffer.from(`VSRA_V1|${tensorId}|${grant.chunkIndex}`, "utf8");
  let plain;
  try {
    const dec = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    dec.setAAD(aad, { plaintextLength: plainLen });
    dec.setAuthTag(tag);
    plain = Buffer.concat([dec.update(ct), dec.final()]);
  } finally {
    key.fill(0);
  }

  const floats = new Float32Array(plain.byteLength / 4);
  floats.set(new Float32Array(plain.buffer, plain.byteOffset, plain.byteLength / 4));
  plain.fill(0);
  return floats;
}

module.exports = { parseVsraForGrant, unsealWeightChunkClient };
