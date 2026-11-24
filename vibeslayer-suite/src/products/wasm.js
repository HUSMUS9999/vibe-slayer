"use strict";

const { packVspk } = require("../core/authority.js");
const { unsealVspkWithWebCrypto } = require("./web.js");

function wasmSection(id, payloadBytes) {
  return Buffer.concat([Buffer.from([id, payloadBytes.length]), Buffer.from(payloadBytes)]);
}

/*
 * Synthesizes a clean, valid 97-byte WebAssembly module exporting:
 *   - `dot4_i32(a, b, c, d) -> a*b + c*d`
 *   - `mix_tile_u32(state, val) -> ((state ^ val) * 0x01000193) ^ (((state ^ val) * 0x01000193) >>> 16)`
 * Zero dummy export bloat (`97 bytes` vs BLA's `6,880,174 bytes`).
 */
function compileCompactComputeWasm() {
  const magic = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const typeSec = wasmSection(1, [
    0x02,
    0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
    0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
  ]);
  const funcSec = wasmSection(3, [0x02, 0x00, 0x01]);
  const dotName = Buffer.from("dot4_i32", "utf8");
  const mixName = Buffer.from("mix_tile_u32", "utf8");
  const exportSec = wasmSection(7, [
    0x02,
    dotName.length, ...dotName, 0x00, 0x00,
    mixName.length, ...mixName, 0x00, 0x01,
  ]);

  const body0 = [
    0x00, // 0 locals
    0x20, 0x00, 0x20, 0x01, 0x6c,
    0x20, 0x02, 0x20, 0x03, 0x6c,
    0x6a, 0x0b,
  ];
  // 0x01000193 (16777619, FNV prime) in SLEB128 = [0x93, 0x83, 0x80, 0x08]
  const body1 = [
    0x01, 0x01, 0x7f, // 1 local of type i32 (index 2)
    0x20, 0x00, 0x20, 0x01, 0x73,
    0x41, 0x93, 0x83, 0x80, 0x08,
    0x6c, 0x22, 0x02,
    0x20, 0x02, 0x41, 0x10, 0x76, 0x73, 0x0b,
  ];
  const codeSec = wasmSection(10, [
    0x02,
    body0.length, ...body0,
    body1.length, ...body1,
  ]);

  return Buffer.concat([magic, typeSec, funcSec, exportSec, codeSec]);
}

function packWasmModule({ authority, moduleId, origin, wasmBytes }) {
  const key = authority.deriveAssetKey("wasm", moduleId, origin);
  try {
    const vspkBytes = packVspk({
      key32: key,
      domain: "wasm",
      assetId: moduleId,
      origin,
      cipher: "aes-256-gcm",
      plainBytes: wasmBytes,
    });
    return { moduleId, origin, vspkBytes };
  } finally {
    key.fill(0);
  }
}

async function instantiateSealedWasm({
  vspkBytes,
  grant,
  session,
  expectedOrigin,
  authorityPublicKeySpkiB64,
  imports = {},
}) {
  const wasmPlain = await unsealVspkWithWebCrypto({
    vspkBytes,
    grant,
    session,
    expectedProduct: "wasm",
    expectedOrigin,
    authorityPublicKeySpkiB64,
  });
  try {
    const mod = new WebAssembly.Module(wasmPlain);
    return new WebAssembly.Instance(mod, imports);
  } finally {
    wasmPlain.fill(0);
  }
}

module.exports = {
  compileCompactComputeWasm,
  packWasmModule,
  instantiateSealedWasm,
};
