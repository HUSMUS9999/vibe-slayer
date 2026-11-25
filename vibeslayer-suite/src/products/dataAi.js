"use strict";

const crypto = require("node:crypto");
const { SERVER_ONLY_GRANT_SEEDS, deriveAssetKey32, vsError } = require("../core/authority.js");
const {
  parseVsraForGrant,
  unsealWeightChunkClient,
  unsealWeightChunkBytesClient,
  unsealSingleChunkBytesClient,
} = require("../client/data-ai-client.js");

const TENSOR_CHIPS = 1024;
const EPSILON = 2e-6;
const WATERMARK_DETECTION_THRESHOLD = 0.65; // Z = 9.6, P_FP < 1e-21 on 1,024 chips (HIGH-18)

const DTYPE_STR_TO_CODE = Object.freeze({
  RAW: 0,
  F32: 1,
  BF16: 2,
  F16: 3,
  F8_E4M3: 4,
  F8_E5M2: 5,
  I8: 6,
  U8: 7,
  I4: 8,
});

/**
 * Strictly parses a `.safetensors` container (`u64_le header_len || JSON header || tensor data`):
 * - Rejects type-coerced/negative/non-safe-integer offsets, empty `{}` headers, non-4-byte-aligned
 *   F32 spans, and overlapping tensor intervals (`HIGH-16`).
 */
function parseSafetensorsLayout(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 10) {
    return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
  }
  const headerLenBig = buf.readBigUInt64LE(0);
  if (headerLenBig < 2n || headerLenBig > 100_000_000n) {
    return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
  }
  const headerLen = Number(headerLenBig);
  const dataStart = 8 + headerLen;
  if (!Number.isSafeInteger(dataStart) || dataStart > buf.length) {
    return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
  }
  const rawHdr = buf.subarray(8, dataStart);
  if (rawHdr[0] !== 0x7b /* '{' */) {
    return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
  }
  let meta;
  try {
    meta = JSON.parse(rawHdr.toString("utf8"));
  } catch {
    return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
  }
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) {
    return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
  }
  const tensors = [];
  for (const [name, entry] of Object.entries(meta)) {
    if (name === "__metadata__") continue;
    if (
      !entry ||
      typeof entry !== "object" ||
      typeof entry.dtype !== "string" ||
      !Array.isArray(entry.data_offsets) ||
      entry.data_offsets.length !== 2
    ) {
      return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
    }
    const rawStart = entry.data_offsets[0];
    const rawEnd = entry.data_offsets[1];
    if (
      typeof rawStart !== "number" ||
      typeof rawEnd !== "number" ||
      !Number.isSafeInteger(rawStart) ||
      !Number.isSafeInteger(rawEnd) ||
      rawStart < 0 ||
      rawEnd < rawStart
    ) {
      return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
    }
    const start = dataStart + rawStart;
    const end = dataStart + rawEnd;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || end > buf.length) {
      return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
    }
    if (entry.dtype === "F32" && ((end - start) & 3) !== 0) {
      return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
    }
    tensors.push({ name, dtype: entry.dtype, start, end });
  }
  if (tensors.length === 0) {
    return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
  }
  // Sort and strictly reject overlapping tensor intervals (prevents BF16/INT4 corruption!)
  tensors.sort((a, b) => a.start - b.start || a.end - b.end);
  for (let i = 1; i < tensors.length; i++) {
    if (tensors[i].start < tensors[i - 1].end) {
      return { isSafetensors: false, dataStart: 0, tensors: [], f32Ranges: [] };
    }
  }
  const f32Ranges = tensors
    .filter((t) => t.dtype === "F32" && t.end - t.start >= TENSOR_CHIPS * 4)
    .map((t) => ({ start: t.start, end: t.end }));

  return { isSafetensors: true, dataStart, tensors, f32Ranges };
}

function deriveSubSeed(seed32, rangeIndex) {
  if (rangeIndex === 0) return seed32;
  return crypto
    .createHash("sha256")
    .update(seed32)
    .update(`|R${rangeIndex}`)
    .digest();
}

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

/**
 * ULP-safe perturbation guaranteed >= 8 × ulp(v) across all finite IEEE-754 f32 weights (`MED-11`).
 */
function watermarkDeltaForFloat(v) {
  return Math.max(EPSILON, Math.abs(v) * 1e-6);
}

/**
 * Applies dtype-safe watermark perturbation using unaligned-safe little-endian `DataView`
 * across ALL validated F32 tensor slices in the chunk (`MED-11`, `MED-12`, `HIGH-17`).
 */
function applyDtypeSafeWatermark(wmPlain, { chunkIndex, chunkBytes, wmSeed, dtype = "RAW", safetensorsLayout = null }) {
  if (!wmSeed) return false;
  const chunkGlobalStart = chunkIndex * chunkBytes;
  const chunkGlobalEnd = chunkGlobalStart + wmPlain.byteLength;

  if (safetensorsLayout && safetensorsLayout.isSafetensors) {
    let embedded = false;
    const ranges = safetensorsLayout.f32Ranges || [];
    for (let rIdx = 0; rIdx < ranges.length; rIdx++) {
      const r = ranges[rIdx];
      const ovStart = Math.max(chunkGlobalStart, r.start);
      const ovEnd = Math.min(chunkGlobalEnd, r.end);
      if (ovEnd <= ovStart) continue;
      const relStart = ovStart - r.start;
      const alignSkip = (4 - (relStart & 3)) & 3;
      const alignedGlobalStart = ovStart + alignSkip;
      const availBytes = ovEnd - alignedGlobalStart;
      const floatCount = Math.floor(availBytes / 4);
      if (floatCount >= TENSOR_CHIPS) {
        const localOff = alignedGlobalStart - chunkGlobalStart;
        const view = new DataView(wmPlain.buffer, wmPlain.byteOffset + localOff, floatCount * 4);
        const subSeed = deriveSubSeed(wmSeed, rIdx);
        for (let c = 0; c < TENSOR_CHIPS; c++) {
          const { idx, sign } = tensorChipIndexAndSign(subSeed, c, floatCount);
          const v = view.getFloat32(idx * 4, true);
          if (Number.isFinite(v)) {
            const next = Math.fround(v + sign * watermarkDeltaForFloat(v));
            if (Number.isFinite(next)) {
              view.setFloat32(idx * 4, next, true);
            }
          }
        }
        embedded = true;
      }
    }
    return embedded;
  }

  // Raw tensor buffer: only perturb when explicitly F32 and 4-byte aligned (fail closed on RAW/BF16/FP16!)
  if (dtype !== "F32" || (wmPlain.byteLength & 3) !== 0) {
    return false;
  }
  const floatCount = wmPlain.byteLength / 4;
  if (floatCount < TENSOR_CHIPS) return false;
  const view = new DataView(wmPlain.buffer, wmPlain.byteOffset, floatCount * 4);
  for (let c = 0; c < TENSOR_CHIPS; c++) {
    const { idx, sign } = tensorChipIndexAndSign(wmSeed, c, floatCount);
    const v = view.getFloat32(idx * 4, true);
    if (Number.isFinite(v)) {
      const next = Math.fround(v + sign * watermarkDeltaForFloat(v));
      if (Number.isFinite(next)) {
        view.setFloat32(idx * 4, next, true);
      }
    }
  }
  return true;
}

const MAX_CHUNK_BYTES = 64 * 1024 * 1024;

/*
 * `VSR2` Random-Access Chunked AEAD Container (`HIGH-17`, Loop 3 `CRIT-1`):
 * Persists `dtype`, `isSafetensors`, and validated `f32Ranges` in the container header and binds
 * `chunkBytes`, `chunkCount`, `dtype`, `isSafetensors`, AND `SHA-256(metaBuf)` into every chunk's
 * AEAD AAD so header/range tampering is cryptographically rejected before watermarking!
 */
function packRandomAccessWeights({ authority, tensorId, plainBytes, chunkBytes = 65536, dtype = "F32" }) {
  if (typeof tensorId !== "string" || tensorId.length === 0) {
    throw vsError("BAD_VSRA", "Non-empty tensorId required");
  }
  if (!Number.isInteger(chunkBytes) || chunkBytes <= 0 || chunkBytes > MAX_CHUNK_BYTES || (chunkBytes & 3) !== 0) {
    throw vsError("BAD_VSRA", "chunkBytes must be a positive multiple of 4 (<= 64 MiB)");
  }
  if (!Object.hasOwn(DTYPE_STR_TO_CODE, dtype)) {
    throw vsError("BAD_VSRA", `Unsupported dtype: ${dtype}`);
  }
  const plain = Buffer.isBuffer(plainBytes) ? plainBytes : Buffer.from(plainBytes);
  if (plain.length === 0) {
    throw vsError("BAD_VSRA", "plainBytes must be non-empty");
  }
  const safetensorsLayout = parseSafetensorsLayout(plain);
  const effDtype = safetensorsLayout.isSafetensors ? "RAW" : dtype;
  if (!safetensorsLayout.isSafetensors && effDtype === "F32" && (plain.length & 3) !== 0) {
    throw vsError("BAD_VSRA", "Raw F32 plainBytes must be 4-byte aligned (or pass dtype/safetensors)");
  }

  const chunkCount = Math.ceil(plain.length / chunkBytes);
  const idBuf = Buffer.from(tensorId, "utf8");
  if (safetensorsLayout.isSafetensors && safetensorsLayout.f32Ranges.length > 2048) {
    throw vsError("BAD_VSRA", "Safetensors F32 tensor count exceeds maximum supported ranges (2048)");
  }
  const metaBuf = safetensorsLayout.isSafetensors
    ? Buffer.from(JSON.stringify({ f32Ranges: safetensorsLayout.f32Ranges }), "utf8")
    : Buffer.alloc(0);
  if (metaBuf.length > 16 * 1024 * 1024) {
    throw vsError("BAD_VSRA", "VSR2 metadata exceeds 16 MiB cap");
  }
  const metaHashHex = crypto.createHash("sha256").update(metaBuf).digest("hex");

  const hdr = Buffer.alloc(22 + idBuf.length + metaBuf.length);
  hdr.write("VSR2", 0, "ascii");
  hdr.writeUInt32LE(chunkBytes, 4);
  hdr.writeUInt32LE(chunkCount, 8);
  hdr.writeUInt32LE(idBuf.length, 12);
  hdr[16] = DTYPE_STR_TO_CODE[effDtype];
  hdr[17] = safetensorsLayout.isSafetensors ? 1 : 0;
  hdr.writeUInt32LE(metaBuf.length, 18);
  idBuf.copy(hdr, 22);
  if (metaBuf.length > 0) metaBuf.copy(hdr, 22 + idBuf.length);

  const recordStride = 32 + chunkBytes;
  const records = Buffer.alloc(chunkCount * recordStride);

  for (let c = 0; c < chunkCount; c++) {
    const slice = plain.subarray(c * chunkBytes, Math.min(plain.length, (c + 1) * chunkBytes));
    const chunkKey = authority.deriveAssetKey("data-ai", `${tensorId}#${c}`, "");
    const nonce = crypto.randomBytes(12);
    const aad = Buffer.from(
      `VSR2|${tensorId}|${c}|${chunkBytes}|${chunkCount}|${effDtype}|${safetensorsLayout.isSafetensors ? 1 : 0}|${metaHashHex}`,
      "utf8"
    );
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
    dtype: effDtype,
    safetensorsLayout,
    vspkRaBytes: Buffer.concat([hdr, records]),
  };
}

function issueChunkLease({
  authority,
  action,
  params,
  subject,
  scopes,
  tensorId,
  chunkIndex,
  dtype = null,
  safetensorsLayout = null,
}) {
  const act = authority.checkPolicyAction(action, params, scopes, "");
  const jti = crypto.randomBytes(10).toString("hex");
  const watermarkIdHex = crypto
    .createHmac("sha256", authority.policy.masterKey)
    .update(`AI_WM|${subject}|${jti}`)
    .digest("hex")
    .slice(0, 16);

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
    dtype,
    safetensorsLayout,
  });
  return grantObj;
}

function decryptWatermarkAndReencryptChunk({
  resolvedMasterKey,
  vspkRaBytes,
  grant,
  wmSeed,
  dtype,
  safetensorsLayout,
  singleChunkWire = false,
}) {
  const parsed = parseVsraForGrant(vspkRaBytes, grant);
  const { tensorId, chunkBytes, plainLen, nonce, tag, ct, aadPrefix } = parsed;
  const staticChunkKey = deriveAssetKey32(resolvedMasterKey, "data-ai", `${tensorId}#${grant.chunkIndex}`, "");
  const leaseKey = Buffer.from(grant.chunkKeyHex, "hex");
  const storageAad = Buffer.from(aadPrefix, "utf8");
  let plain = null;
  let wmPlain = null;
  try {
    const dec = crypto.createDecipheriv("chacha20-poly1305", staticChunkKey, nonce, { authTagLength: 16 });
    dec.setAAD(storageAad, { plaintextLength: plainLen });
    dec.setAuthTag(tag);
    plain = Buffer.concat([dec.update(ct), dec.final()]);

    wmPlain = Buffer.from(plain);
    const serverCtx = SERVER_ONLY_GRANT_SEEDS.get(grant);
    const resolvedSeed = wmSeed !== undefined ? wmSeed : serverCtx?.wmSeed || null;
    // Prefer container-authenticated VSR2 metadata; fail closed to "RAW" if unspecified (HIGH-17)
    const resolvedDtype = parsed.isV2 ? parsed.dtype : (dtype ?? serverCtx?.dtype ?? "RAW");
    const resolvedLayout = parsed.isV2
      ? { isSafetensors: parsed.isSafetensors, f32Ranges: parsed.f32Ranges }
      : (safetensorsLayout ?? serverCtx?.safetensorsLayout ?? null);

    const watermarked = applyDtypeSafeWatermark(wmPlain, {
      chunkIndex: grant.chunkIndex,
      chunkBytes,
      wmSeed: resolvedSeed,
      dtype: resolvedDtype,
      safetensorsLayout: resolvedLayout,
    });

    const outAad = singleChunkWire && parsed.isV2
      ? Buffer.from(
          `VSR1_V2|${tensorId}|${grant.chunkIndex}|${parsed.dtype}|${parsed.isSafetensors ? 1 : 0}|${wmPlain.length}`,
          "utf8"
        )
      : storageAad;

    const newNonce = crypto.randomBytes(12);
    const enc = crypto.createCipheriv("chacha20-poly1305", leaseKey, newNonce, { authTagLength: 16 });
    enc.setAAD(outAad, { plaintextLength: wmPlain.length });
    const newCt = Buffer.concat([enc.update(wmPlain), enc.final()]);
    const newTag = enc.getAuthTag();

    return { parsed, plainLen, newNonce, newTag, newCt, watermarked };
  } finally {
    staticChunkKey.fill(0);
    leaseKey.fill(0);
    if (plain) plain.fill(0);
    if (wmPlain) wmPlain.fill(0);
  }
}

/**
 * O(1)-memory server-side chunk re-sealing (`38 + plainLen` bytes).
 * Wire format: `VSR1 || plainLen(u32LE) || dtypeCode(u8) || flags(u8) || nonce12 || tag16 || ct`.
 */
function sealSingleChunkForGrant({ masterKey, authority, vspkRaBytes, grant, wmSeed, dtype, safetensorsLayout }) {
  const resolvedMasterKey = masterKey || authority?.policy?.masterKey;
  if (!Buffer.isBuffer(resolvedMasterKey) || resolvedMasterKey.length !== 32) {
    throw vsError("BAD_MASTER_KEY", "32-byte masterKey required");
  }
  if (!grant || typeof grant.chunkKeyHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(grant.chunkKeyHex)) {
    throw vsError("BAD_GRANT", "32-byte hex chunkKeyHex required");
  }
  const { parsed, plainLen, newNonce, newTag, newCt } = decryptWatermarkAndReencryptChunk({
    resolvedMasterKey,
    vspkRaBytes,
    grant,
    wmSeed,
    dtype,
    safetensorsLayout,
    singleChunkWire: true,
  });
  const out = Buffer.allocUnsafe(38 + plainLen);
  out.write("VSR1", 0, "ascii");
  out.writeUInt32LE(plainLen, 4);
  out[8] = DTYPE_STR_TO_CODE[parsed.dtype] ?? 0;
  out[9] = (parsed.isV2 ? 1 : 0) | (parsed.isSafetensors ? 2 : 0);
  newNonce.copy(out, 10);
  newTag.copy(out, 22);
  newCt.copy(out, 38);
  return out;
}

function sealWatermarkedChunkForGrant({ masterKey, authority, vspkRaBytes, grant, wmSeed, dtype, safetensorsLayout }) {
  const resolvedMasterKey = masterKey || authority?.policy?.masterKey;
  if (!Buffer.isBuffer(resolvedMasterKey) || resolvedMasterKey.length !== 32) {
    throw vsError("BAD_MASTER_KEY", "32-byte masterKey required");
  }
  if (!grant || typeof grant.chunkKeyHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(grant.chunkKeyHex)) {
    throw vsError("BAD_GRANT", "32-byte hex chunkKeyHex required");
  }
  const { parsed, plainLen, newNonce, newTag, newCt } = decryptWatermarkAndReencryptChunk({
    resolvedMasterKey,
    vspkRaBytes,
    grant,
    wmSeed,
    dtype,
    safetensorsLayout,
  });
  const { buf, hdrEnd, chunkCount, recordStride, recOff } = parsed;
  const out = Buffer.alloc(hdrEnd + chunkCount * recordStride);
  buf.subarray(0, hdrEnd).copy(out, 0);
  out.writeUInt32LE(plainLen, recOff);
  newNonce.copy(out, recOff + 4);
  newTag.copy(out, recOff + 16);
  newCt.copy(out, recOff + 32);
  return out;
}

function unsealWeightChunk({ vspkRaBytes, grant }) {
  const serverCtx = grant && typeof grant === "object" ? SERVER_ONLY_GRANT_SEEDS.get(grant) : null;
  if (serverCtx && serverCtx.masterKey) {
    const parsed = parseVsraForGrant(vspkRaBytes, grant);
    const sealedSingle = sealSingleChunkForGrant({
      masterKey: serverCtx.masterKey,
      vspkRaBytes,
      grant,
      wmSeed: serverCtx.wmSeed,
      dtype: serverCtx.dtype,
      safetensorsLayout: serverCtx.safetensorsLayout,
    });
    const plain = unsealSingleChunkBytesClient({ sealedChunk: sealedSingle, grant });
    const resolvedDtype = parsed.isV2 ? parsed.dtype : (serverCtx.dtype ?? "F32");
    const resolvedSf = parsed.isV2 ? parsed.isSafetensors : Boolean(serverCtx.safetensorsLayout?.isSafetensors);
    if (resolvedDtype !== "F32" || resolvedSf || (plain.byteLength & 3) !== 0) {
      return plain;
    }
    const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
    const floats = new Float32Array(plain.byteLength / 4);
    for (let i = 0; i < floats.length; i++) {
      floats[i] = view.getFloat32(i * 4, true);
    }
    plain.fill(0);
    return floats;
  }
  return unsealWeightChunkClient({ vspkRaBytes, grant });
}

/**
 * Extracts & verifies a tenant watermark with a strict `>= 0.65` detection threshold (`HIGH-18`).
 * Supports BOTH flat `Float32Array` chunks (`baseFloats`/`leakedFloats`) AND complete
 * `.safetensors` buffers (`baseBytes`/`leakedBytes` + `chunkBytes` + `safetensorsLayout`, `CRIT-08`)!
 */
function extractTensorWatermark({
  authority,
  tensorId,
  chunkIndex = 0,
  baseFloats,
  leakedFloats,
  baseBytes,
  leakedBytes,
  chunkBytes = 65536,
  safetensorsLayout = null,
  candidateWatermarkIds,
  threshold = WATERMARK_DETECTION_THRESHOLD,
}) {
  // Layout-aware `.safetensors` / raw-Buffer extraction path (CRIT-08)
  if (baseBytes && leakedBytes) {
    const baseBuf = Buffer.isBuffer(baseBytes) ? baseBytes : Buffer.from(baseBytes);
    const leakBuf = Buffer.isBuffer(leakedBytes) ? leakedBytes : Buffer.from(leakedBytes);
    const layout = safetensorsLayout || parseSafetensorsLayout(baseBuf);
    if (!layout.isSafetensors || layout.f32Ranges.length === 0) {
      return { matchedWatermarkIdHex: null, detected: false, bitMatchRatio: 0 };
    }
    const chunkGlobalStart = chunkIndex * chunkBytes;
    const chunkGlobalEnd = Math.min(baseBuf.length, chunkGlobalStart + chunkBytes);
    if (leakBuf.length < chunkGlobalEnd) {
      throw vsError("VSRA_TOO_SMALL", "leakedBytes must cover the inspected chunk range");
    }
    let bestId = null;
    let bestRatio = 0;

    for (const wmId of candidateWatermarkIds) {
      const seed = authority.computeWatermarkCarrierSeed(`${tensorId}#${chunkIndex}`, wmId);
      let matches = 0;
      let totalChips = 0;
      for (let rIdx = 0; rIdx < layout.f32Ranges.length; rIdx++) {
        const r = layout.f32Ranges[rIdx];
        const ovStart = Math.max(chunkGlobalStart, r.start);
        const ovEnd = Math.min(chunkGlobalEnd, r.end);
        if (ovEnd <= ovStart) continue;
        const relStart = ovStart - r.start;
        const alignSkip = (4 - (relStart & 3)) & 3;
        const alignedGlobalStart = ovStart + alignSkip;
        const floatCount = Math.floor((ovEnd - alignedGlobalStart) / 4);
        if (floatCount < TENSOR_CHIPS) continue;

        const baseView = new DataView(baseBuf.buffer, baseBuf.byteOffset + alignedGlobalStart, floatCount * 4);
        const leakView = new DataView(leakBuf.buffer, leakBuf.byteOffset + alignedGlobalStart, floatCount * 4);
        const subSeed = deriveSubSeed(seed, rIdx);
        for (let c = 0; c < TENSOR_CHIPS; c++) {
          const { idx, sign } = tensorChipIndexAndSign(subSeed, c, floatCount);
          const diff = leakView.getFloat32(idx * 4, true) - baseView.getFloat32(idx * 4, true);
          if ((sign > 0 && diff > 0) || (sign < 0 && diff < 0)) matches += 1;
          totalChips += 1;
        }
      }
      seed.fill(0);
      const ratio = totalChips > 0 ? matches / totalChips : 0;
      if (ratio > bestRatio) {
        bestRatio = ratio;
        bestId = wmId;
      }
    }
    const detected = bestRatio >= threshold;
    return {
      matchedWatermarkIdHex: detected ? bestId : null,
      detected,
      bitMatchRatio: bestRatio,
    };
  }

  // Flat Float32Array path
  if (!baseFloats || !leakedFloats || baseFloats.length < TENSOR_CHIPS || leakedFloats.length < baseFloats.length) {
    throw vsError("VSRA_TOO_SMALL", "Float buffers must contain at least TENSOR_CHIPS elements");
  }
  let bestId = null;
  let bestRatio = 0;

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

  const detected = bestRatio >= threshold;
  return {
    matchedWatermarkIdHex: detected ? bestId : null,
    detected,
    bitMatchRatio: bestRatio,
  };
}

module.exports = {
  WATERMARK_DETECTION_THRESHOLD,
  parseSafetensorsLayout,
  packRandomAccessWeights,
  issueChunkLease,
  sealSingleChunkForGrant,
  sealWatermarkedChunkForGrant,
  unsealWeightChunk,
  unsealWeightChunkClient,
  unsealWeightChunkBytesClient,
  unsealSingleChunkBytesClient,
  extractTensorWatermark,
};
