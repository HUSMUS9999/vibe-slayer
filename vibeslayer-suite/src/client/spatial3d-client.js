"use strict";

const { unsealVspkClient } = require("./web-client.js");

async function unsealToGpuBuffersClient({
  vspkBytes,
  grant,
  session,
  expectedOrigin,
  authorityPublicKeySpkiB64,
}) {
  const plain = await unsealVspkClient({
    vspkBytes,
    grant,
    session,
    expectedProduct: "spatial-3d",
    expectedOrigin,
    authorityPublicKeySpkiB64,
  });
  try {
    if (plain.length < 16 || plain.subarray(0, 4).toString("ascii") !== "VS3D") {
      throw new Error("BAD_VS3D");
    }
    const descLen = plain.readUInt32LE(4);
    const posByteLen = plain.readUInt32LE(8);
    const binByteLen = plain.readUInt32LE(12);
    const posStart = 16 + descLen;
    const binStart = posStart + posByteLen;
    if ((posByteLen & 1) !== 0 || binStart + binByteLen > plain.length) {
      throw new Error("TRUNCATED_VS3D");
    }

    const desc = JSON.parse(plain.subarray(16, posStart).toString("utf8"));
    const alignedPosBuf = Buffer.from(plain.subarray(posStart, binStart));
    const positionsInt16 = new Int16Array(
      alignedPosBuf.buffer,
      alignedPosBuf.byteOffset,
      posByteLen / 2
    );

    return {
      vertexCount: desc.vertexCount,
      indexCount: desc.indexCount,
      boundsMin: desc.boundsMin,
      boundsMax: desc.boundsMax,
      positionsInt16,
      gpuStreamBytes: Buffer.from(plain.subarray(binStart, binStart + binByteLen)),
    };
  } finally {
    plain.fill(0);
  }
}

module.exports = { unsealToGpuBuffersClient };
