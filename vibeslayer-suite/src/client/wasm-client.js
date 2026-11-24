"use strict";

const { unsealVspkClient } = require("./web-client.js");

async function instantiateSealedWasmClient({
  vspkBytes,
  grant,
  session,
  expectedOrigin,
  authorityPublicKeySpkiB64,
  imports = {},
}) {
  const wasmPlain = await unsealVspkClient({
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

module.exports = { instantiateSealedWasmClient };
