"use strict";

const authorityMod = require("./core/authority.js");
const webProduct = require("./products/web.js");
const wasmProduct = require("./products/wasm.js");
const spatial3dProduct = require("./products/spatial3d.js");
const nativeProduct = require("./products/native.js");
const desktopProduct = require("./products/desktop.js");
const mobileProduct = require("./products/mobile.js");
const dataAiProduct = require("./products/dataAi.js");
const autoProtect = require("./auto.js");

module.exports = {
  ...authorityMod,
  webProduct,
  wasmProduct,
  spatial3dProduct,
  nativeProduct,
  desktopProduct,
  mobileProduct,
  dataAiProduct,
  autoProtect,
};
