"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { vsError } = require("../core/authority.js");

const TEMPLATE_C = path.resolve(__dirname, "../../native_src/vs_native_template.c");

function parseElf64Layout(elfBuf) {
  if (elfBuf.subarray(0, 4).toString("hex") !== "7f454c46") {
    throw vsError("NOT_ELF64", "Invalid ELF magic");
  }
  const ePhoff = Number(elfBuf.readBigUInt64LE(32));
  const eShoff = Number(elfBuf.readBigUInt64LE(40));
  const ePhentsize = elfBuf.readUInt16LE(54);
  const ePhnum = elfBuf.readUInt16LE(56);
  const eShentsize = elfBuf.readUInt16LE(58);
  const eShnum = elfBuf.readUInt16LE(60);
  const eShstrndx = elfBuf.readUInt16LE(62);

  // Hash all PT_LOAD (p_type=1) executable (PF_X=1) segments exactly as compute_live_rx_sha256 does in RAM!
  const sha = crypto.createHash("sha256");
  let rxFound = false;
  for (let i = 0; i < ePhnum; i++) {
    const off = ePhoff + i * ePhentsize;
    const pType = elfBuf.readUInt32LE(off);
    const pFlags = elfBuf.readUInt32LE(off + 4);
    const pOffset = Number(elfBuf.readBigUInt64LE(off + 8));
    const pFilesz = Number(elfBuf.readBigUInt64LE(off + 32));
    if (pType === 1 && (pFlags & 1) !== 0) {
      sha.update(elfBuf.subarray(pOffset, pOffset + pFilesz));
      rxFound = true;
    }
  }
  if (!rxFound) throw vsError("NO_RX_SEGMENT", "No executable PT_LOAD segment found");

  const shStrOff = Number(elfBuf.readBigUInt64LE(eShoff + eShstrndx * eShentsize + 24));
  const shStrSize = Number(elfBuf.readBigUInt64LE(eShoff + eShstrndx * eShentsize + 32));
  const strTab = elfBuf.subarray(shStrOff, shStrOff + shStrSize);

  let vsblobOffset = -1;
  let textOffset = -1;
  let textAddr = 0;
  let textSize = 0;
  let symtabOffset = -1;
  let symtabSize = 0;
  let symtabEntSize = 24;
  let symStrOffset = -1;
  let symStrSize = 0;

  for (let i = 0; i < eShnum; i++) {
    const soff = eShoff + i * eShentsize;
    const nameIdx = elfBuf.readUInt32LE(soff);
    let end = nameIdx;
    while (end < strTab.length && strTab[end] !== 0) end++;
    const name = strTab.subarray(nameIdx, end).toString("ascii");
    const shType = elfBuf.readUInt32LE(soff + 4);
    const shAddr = Number(elfBuf.readBigUInt64LE(soff + 16));
    const fileOff = Number(elfBuf.readBigUInt64LE(soff + 24));
    const size = Number(elfBuf.readBigUInt64LE(soff + 32));
    const shLink = elfBuf.readUInt32LE(soff + 40);
    const shEntSize = Number(elfBuf.readBigUInt64LE(soff + 56));
    if (name === ".vsblob") vsblobOffset = fileOff;
    if (name === ".text") {
      textOffset = fileOff;
      textAddr = shAddr;
      textSize = size;
    }
    if (shType === 2 && name === ".symtab") {
      symtabOffset = fileOff;
      symtabSize = size;
      symtabEntSize = shEntSize || 24;
      const strSoff = eShoff + shLink * eShentsize;
      symStrOffset = Number(elfBuf.readBigUInt64LE(strSoff + 24));
      symStrSize = Number(elfBuf.readBigUInt64LE(strSoff + 32));
    }
  }
  if (vsblobOffset < 0 || textOffset < 0) {
    throw vsError("MISSING_ELF_SECTIONS", "Expected .vsblob and .text sections");
  }

  let patchableTextFileOffset = textOffset + Math.floor(textSize / 2);
  if (symtabOffset >= 0 && symStrOffset >= 0 && symStrOffset + symStrSize <= elfBuf.length) {
    const symStr = elfBuf.subarray(symStrOffset, symStrOffset + symStrSize);
    for (let pos = 0; pos + symtabEntSize <= symtabSize; pos += symtabEntSize) {
      const off = symtabOffset + pos;
      const stName = elfBuf.readUInt32LE(off);
      const stValue = Number(elfBuf.readBigUInt64LE(off + 8));
      const stSize = Number(elfBuf.readBigUInt64LE(off + 16));
      if (stName < symStr.length && stValue >= textAddr && stValue < textAddr + textSize) {
        let sEnd = stName;
        while (sEnd < symStr.length && symStr[sEnd] !== 0) sEnd++;
        if (symStr.subarray(stName, sEnd).toString("ascii") === "vs_hot_kernel_compute" && stSize > 8) {
          patchableTextFileOffset = textOffset + (stValue - textAddr) + 8;
          break;
        }
      }
    }
  }

  return {
    rxSha256Hex: sha.digest("hex"),
    vsblobOffset,
    textOffset,
    textSize,
    patchableTextFileOffset,
  };
}

function buildProtectedElf({ authority, outDir, binaryName = "vs_protected_elf", assetId, plainPayload }) {
  const plain = Buffer.isBuffer(plainPayload) ? plainPayload : Buffer.from(plainPayload);
  if (plain.length === 0 || plain.length > 4096) {
    throw vsError("PAYLOAD_BOUNDS", "Native embedded payload must be 1..4096 bytes");
  }
  fs.mkdirSync(outDir, { recursive: true });
  const elfPath = path.join(outDir, binaryName);

  execFileSync("gcc", [
    "-O2", "-fno-inline", "-fPIE", "-pie",
    "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-fcf-protection=full",
    "-Wl,-z,relro,-z,now,-z,ibt,-z,shstk",
    "-Wall", "-Wextra",
    TEMPLATE_C, "-o", elfPath,
  ]);

  const elfBuf = fs.readFileSync(elfPath);
  const layout = parseElf64Layout(elfBuf);

  const leaseRootKey = authority.deriveAssetKey("native", assetId, "");
  const infoStr = `VS_NATIVE_ELF_V1|${assetId}|${layout.rxSha256Hex}`;
  const contentKey = Buffer.from(
    crypto.hkdfSync("sha256", leaseRootKey, Buffer.from(assetId, "utf8"), Buffer.from(infoStr, "utf8"), 32)
  );
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("chacha20-poly1305", contentKey, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(infoStr, "utf8"), { plaintextLength: plain.length });
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  contentKey.fill(0);
  leaseRootKey.fill(0);

  // Patch `.vsblob` in-place (CSPRNG-padded 4096B ciphertext slot so section entropy is ~7.95 bits/byte!)
  const blobBuf = Buffer.alloc(8 + 4 + 12 + 16 + 64 + 4096);
  crypto.randomBytes(4096).copy(blobBuf, 104);
  blobBuf.write("VSBLB001", 0, "ascii");
  blobBuf.writeUInt32LE(ct.length, 8);
  nonce.copy(blobBuf, 12);
  tag.copy(blobBuf, 24);
  Buffer.from(assetId, "utf8").copy(blobBuf, 40, 0, Math.min(63, assetId.length));
  ct.copy(blobBuf, 104);
  blobBuf.copy(elfBuf, layout.vsblobOffset);

  fs.writeFileSync(elfPath, elfBuf, { mode: 0o755 });
  const postLayout = parseElf64Layout(fs.readFileSync(elfPath));
  if (postLayout.rxSha256Hex !== layout.rxSha256Hex) {
    throw vsError("RX_MUTATED", "Unexpected RX segment change during .vsblob sealing");
  }
  execFileSync("strip", ["-s", elfPath]);

  return {
    elfPath,
    bytes: elfBuf.length,
    textSectionSha256Hex: layout.rxSha256Hex,
    patchableTextFileOffset: layout.patchableTextFileOffset,
  };
}

function issueNativeLease({
  authority,
  action,
  params,
  subject,
  scopes,
  assetId,
  textSectionSha256Hex,
}) {
  authority.checkPolicyAction(action, params, scopes, "");
  if (!/^[a-f0-9]{64}$/.test(textSectionSha256Hex)) {
    throw vsError("BAD_TEXT_HASH", "64-hex RX segment SHA-256 required");
  }
  const leaseRootKey = authority.deriveAssetKey("native", assetId, "");
  try {
    return leaseRootKey.toString("hex");
  } finally {
    leaseRootKey.fill(0);
  }
}

module.exports = {
  buildProtectedElf,
  issueNativeLease,
};
