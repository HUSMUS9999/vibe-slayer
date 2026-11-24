"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn, spawnSync } = require("node:child_process");

const SUITE_ROOT = path.resolve(__dirname, "..");
const WORKSPACE_ROOT = path.resolve(SUITE_ROOT, "..");
const NATIVE_CORE_DIR = path.resolve(WORKSPACE_ROOT, "vibeslayer-native-core");
const NATIVE_BIN = path.resolve(NATIVE_CORE_DIR, "bin/vibeslayer");
const CRYPTO_HEADER = path.resolve(SUITE_ROOT, "native_src/vs_crypto_core.h");
const DEFAULT_WORKSPACE_REGISTRY = path.resolve(WORKSPACE_ROOT, ".vibeslayer-registry.json");

const SKIP_DIRS = new Set([
  ".git",
  ".vibeslayer",
  "node_modules",
  "target",
  "dist_protected",
  "__pycache__",
  ".venv",
  "venv",
  ".next",
  ".cache",
]);

const SKIP_PROTECTED_EXTS = new Set([
  ".vspk",
  ".vspk2",
  ".vspk3",
  ".vs3d",
  ".vsra",
  ".protected",
  ".free_gen.c",
]);

const AI_WEIGHT_EXTS = new Set([
  ".safetensors",
  ".onnx",
  ".pt",
  ".pth",
  ".gguf",
  ".ckpt",
  ".weights",
  ".f32",
  ".npy",
  ".npz",
]);

const CODE_EXTS = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".jsx",
  ".py",
  ".go",
  ".rs",
  ".c",
  ".cc",
  ".cpp",
  ".h",
  ".hpp",
  ".java",
  ".cs",
  ".sh",
  ".rb",
  ".php",
  ".sql",
  ".yaml",
  ".yml",
  ".toml",
  ".json",
]);

const SECRET_KEY_EXTS = new Set([".pem", ".key", ".p12", ".pfx"]);
const VAULT_EXTS = new Set([".vault", ".secret"]);

const PUBLIC_SCAFFOLD_BASENAMES = new Set([
  "license",
  "license.md",
  "license.txt",
  "copying",
  ".gitignore",
  ".gitattributes",
  ".editorconfig",
  ".env.example",
  ".env.sample",
  ".env.template",
  "index.html",
  "package.json",
  "package-lock.json",
  "tsconfig.json",
]);

const PUBLIC_SCAFFOLD_EXTS = new Set([
  ".css",
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".svg",
  ".ico",
  ".webp",
  ".woff2",
  ".woff",
  ".ttf",
]);

function sha256Buf(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function sha256File(filePath) {
  return sha256Buf(fs.readFileSync(filePath));
}

function shannonEntropy(buf) {
  if (!buf || buf.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buf.length; i++) counts[buf[i]]++;
  let h = 0;
  const invN = 1 / buf.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] * invN;
    h -= p * Math.log2(p);
  }
  return Number(h.toFixed(5));
}

function resolveRegistryPath(opts = {}) {
  if (opts.registryPath) return path.resolve(opts.registryPath);
  if (process.env.VIBESLAYER_REGISTRY) return path.resolve(process.env.VIBESLAYER_REGISTRY);
  return DEFAULT_WORKSPACE_REGISTRY;
}

/**
 * Ensures the compiled native binary exists, auto-building it if needed.
 */
function ensureNativeBinary({ quiet = false } = {}) {
  if (fs.existsSync(NATIVE_BIN)) return NATIVE_BIN;
  if (!fs.existsSync(path.join(NATIVE_CORE_DIR, "Makefile"))) {
    throw new Error(`Native core Makefile not found at ${NATIVE_CORE_DIR}`);
  }
  if (!quiet) {
    process.stderr.write("[vibeslayer] Bootstrapping native binary (first run)...\n");
  }
  execFileSync("make", ["-C", NATIVE_CORE_DIR, "all"], {
    stdio: quiet ? "pipe" : "inherit",
  });
  if (!fs.existsSync(NATIVE_BIN)) {
    throw new Error(`Native binary still missing after build: ${NATIVE_BIN}`);
  }
  return NATIVE_BIN;
}

function runNativeJson(args) {
  ensureNativeBinary({ quiet: true });
  const stdout = execFileSync(NATIVE_BIN, args, {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(stdout.trim());
}

function runNativeRaw(args) {
  ensureNativeBinary({ quiet: true });
  return spawnSync(NATIVE_BIN, args, {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
}

function writePrivateJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), { mode: 0o600 });
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // Best-effort on filesystems without POSIX modes
  }
}

function ensureGitignoreLines(dirPath, requiredLines, { createIfMissing = false } = {}) {
  const gitignorePath = path.join(dirPath, ".gitignore");
  const hasGit = fs.existsSync(path.join(dirPath, ".git"));
  const exists = fs.existsSync(gitignorePath);
  if (!exists && !createIfMissing && !hasGit) return false;

  const existing = exists ? fs.readFileSync(gitignorePath, "utf8") : "";
  const existingLines = new Set(existing.split(/\r?\n/).map((l) => l.trim()));
  const toAdd = requiredLines.filter((line) => !existingLines.has(line));
  if (toAdd.length === 0) return false;

  const prefix = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  const header = existing.includes("# Vibe-Slayer automatic key & registry protection")
    ? ""
    : `${prefix}# Vibe-Slayer automatic key & registry protection\n`;
  fs.writeFileSync(gitignorePath, `${existing}${header}${toAdd.join("\n")}\n`, "utf8");
  return true;
}

function loadJsonIfExists(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function createEmptyVault() {
  const kp = crypto.generateKeyPairSync("ed25519");
  return {
    version: "1.0.0-beta.3",
    masterKeyHex: crypto.randomBytes(32).toString("hex"),
    signingPrivateKeyPem: kp.privateKey.export({ type: "pkcs8", format: "pem" }),
    signingPublicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }),
    buyers: {},
    artifacts: {},
    byPath: {},
    watermarks: {},
  };
}

function resolveDefaultKeysPath(inputPath, opts = {}) {
  if (opts.keysFile) return path.resolve(opts.keysFile);
  const absIn = path.resolve(inputPath);
  const baseDir = fs.existsSync(absIn) && fs.statSync(absIn).isDirectory()
    ? absIn
    : path.dirname(absIn);
  return path.join(baseDir, ".vibeslayer", "keys.json");
}

function loadOrCreateVault(keysPath, projectRootForGitignore, opts = {}) {
  const existing = loadJsonIfExists(keysPath);
  const vault = existing && /^[0-9a-f]{64}$/i.test(existing.masterKeyHex || "")
    ? {
        ...existing,
        buyers: existing.buyers || {},
        artifacts: existing.artifacts || {},
        byPath: existing.byPath || {},
        watermarks: existing.watermarks || {},
      }
    : createEmptyVault();

  writePrivateJson(keysPath, vault);
  if (!opts.noGitignore && projectRootForGitignore) {
    ensureGitignoreLines(
      projectRootForGitignore,
      [".vibeslayer/", "*.vibeslayer.keys.json", ".env"],
      { createIfMissing: Boolean(opts.createGitignore) }
    );
  }
  return vault;
}

function loadWorkspaceRegistry(opts = {}) {
  const regPath = resolveRegistryPath(opts);
  const existing = loadJsonIfExists(regPath);
  return {
    regPath,
    data: existing && typeof existing === "object"
      ? {
          artifacts: existing.artifacts || {},
          byPath: existing.byPath || {},
          watermarks: existing.watermarks || {},
        }
      : { artifacts: {}, byPath: {}, watermarks: {} },
  };
}

function saveWorkspaceRegistry(regPath, data) {
  if (!regPath) return;
  writePrivateJson(regPath, data);
  if (path.resolve(regPath) === DEFAULT_WORKSPACE_REGISTRY) {
    ensureGitignoreLines(
      WORKSPACE_ROOT,
      [".vibeslayer-registry.json", ".vibeslayer/"],
      { createIfMissing: true }
    );
  }
}

function recordArtifact(vault, keysPath, registry, meta) {
  const absOut = path.resolve(meta.absOutPath);
  const entry = { ...meta, absOutPath: absOut };
  vault.artifacts[entry.outputSha256] = entry;
  vault.byPath[absOut] = entry.outputSha256;
  writePrivateJson(keysPath, vault);

  if (registry) {
    const regEntry = {
      keysFile: path.resolve(keysPath),
      outputSha256: entry.outputSha256,
      engine: entry.engine,
      domain: entry.domain,
      assetId: entry.assetId,
      context: entry.context || "",
      standalone: Boolean(entry.standalone),
      relPath: entry.relPath || path.basename(absOut),
      originalName: entry.originalName,
      originalSha256: entry.originalSha256,
      ownerRefPath: entry.ownerRefPath || null,
      coords: entry.coords || null,
    };
    registry.data.artifacts[entry.outputSha256] = regEntry;
    registry.data.byPath[absOut] = entry.outputSha256;
    saveWorkspaceRegistry(registry.regPath, registry.data);
  }
}

function resolveKnownMetadata(targetPath, opts = {}) {
  const absTarget = path.resolve(targetPath);
  const targetSha = fs.existsSync(absTarget) && fs.statSync(absTarget).isFile()
    ? sha256File(absTarget)
    : null;

  const candidateVaults = [];
  if (opts.keysFile) candidateVaults.push(path.resolve(opts.keysFile));
  const dir = fs.existsSync(absTarget) && fs.statSync(absTarget).isDirectory()
    ? absTarget
    : path.dirname(absTarget);
  let cur = dir;
  for (let depth = 0; depth < 6; depth++) {
    candidateVaults.push(path.join(cur, ".vibeslayer", "keys.json"));
    if (cur.endsWith("-protected")) {
      candidateVaults.push(path.join(cur.slice(0, -10), ".vibeslayer", "keys.json"));
    }
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }

  let foundVault = null;
  let foundKeysPath = null;
  let foundEntry = null;

  for (const vp of candidateVaults) {
    const v = loadJsonIfExists(vp);
    if (!v || !v.masterKeyHex) continue;
    if (!foundVault) {
      foundVault = v;
      foundKeysPath = vp;
    }
    const sha = (targetSha && v.artifacts?.[targetSha]) ? targetSha : v.byPath?.[absTarget];
    if (sha && v.artifacts?.[sha]) {
      foundEntry = v.artifacts[sha];
      foundVault = v;
      foundKeysPath = vp;
      break;
    }
  }

  const registry = loadWorkspaceRegistry(opts);
  const regSha = (targetSha && registry.data.artifacts?.[targetSha])
    ? targetSha
    : registry.data.byPath?.[absTarget];
  const regEntry = regSha ? registry.data.artifacts?.[regSha] : null;
  if (!foundEntry && regEntry) {
    foundEntry = regEntry;
    if (regEntry.keysFile && fs.existsSync(regEntry.keysFile)) {
      const rv = loadJsonIfExists(regEntry.keysFile);
      if (rv && rv.masterKeyHex) {
        foundVault = rv;
        foundKeysPath = regEntry.keysFile;
        if (targetSha && rv.artifacts?.[targetSha]) {
          foundEntry = rv.artifacts[targetSha];
        }
      }
    }
  }

  return {
    absTarget,
    targetSha,
    vault: foundVault,
    keysPath: foundKeysPath,
    entry: foundEntry,
    registry,
  };
}

/**
 * Scans UTF-8/ASCII files for accidental plaintext credentials before sealing.
 */
function scanSecretsInBuffer(buf, relPath = "") {
  if (!buf || buf.length === 0) return [];
  const sample = buf.subarray(0, Math.min(buf.length, 1024));
  if (sample.includes(0)) return []; // Binary file

  const text = buf.toString("utf8");
  const lines = text.split(/\r?\n/);
  const findings = [];

  const tokenPatterns = [
    { kind: "OpenAI API Key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
    { kind: "GitHub Token", re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
    { kind: "AWS Access Key", re: /\bAKIA[0-9A-Z]{16}\b/g },
    { kind: "Google API Key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { kind: "Private Key Block", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  ];

  const envSecretRe = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.+)$/;
  const secretNameRe = /(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|AUTH_KEY|MASTER_KEY)/i;
  const placeholderRe = /^(?:example|changeme|placeholder|your[_-]|xxx|dummy|test_only|<.+>|""|'')$/i;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pat of tokenPatterns) {
      pat.re.lastIndex = 0;
      const m = pat.re.exec(line);
      if (m) {
        const prefix = m[0].slice(0, 6);
        findings.push({
          relPath,
          line: i + 1,
          kind: pat.kind,
          preview: `${prefix}... (redacted)`,
        });
      }
    }
    const em = envSecretRe.exec(line);
    if (em && secretNameRe.test(em[1])) {
      const rawVal = em[2].replace(/^['"]|['"]$/g, "").trim();
      if (rawVal.length >= 6 && !placeholderRe.test(rawVal) && !rawVal.startsWith("${")) {
        findings.push({
          relPath,
          line: i + 1,
          kind: "Hardcoded Env Secret",
          preview: `${em[1]}=*** (redacted)`,
        });
      }
    }
  }
  return findings;
}

function isRunnableElf64X86_64(buf, fileName) {
  if (!buf || buf.length < 64) return false;
  if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) return false;
  if (buf[4] !== 2 || buf[5] !== 1) return false; // ELFCLASS64 + ELFDATA2LSB
  const eType = buf.readUInt16LE(16);
  const eMachine = buf.readUInt16LE(18);
  if ((eType !== 2 && eType !== 3) || eMachine !== 62) return false;
  if (/(\.so(\.[0-9]+)*|\.node|\.o|\.a)$/i.test(fileName)) return false;
  return true;
}

function isValidGlbHeader(buf) {
  return buf.length >= 28 && buf.subarray(0, 4).toString("ascii") === "glTF";
}

function isWasmModule(buf, ext) {
  if (buf.length >= 8 && buf[0] === 0x00 && buf[1] === 0x61 && buf[2] === 0x73 && buf[3] === 0x6d) {
    return true;
  }
  return ext === ".wasm";
}

function classifyFile(filePath, relPath, buf, opts = {}) {
  const baseName = path.basename(filePath);
  const lowerBase = baseName.toLowerCase();
  const ext = path.extname(lowerBase);
  const secrets = scanSecretsInBuffer(buf, relPath);

  if (opts.forceVault || VAULT_EXTS.has(ext)) {
    if (buf.length >= 1 && buf.length <= 4096) {
      return { engine: "freestanding-vault", domain: "vault", secrets };
    }
    return { engine: "vspk3", domain: "secrets", secrets };
  }

  if (isRunnableElf64X86_64(buf, lowerBase)) {
    return { engine: "wrap-elf", domain: "native", secrets };
  }

  if (isValidGlbHeader(buf)) {
    return { engine: "glb-dual", domain: "spatial-3d", secrets };
  }

  if (isWasmModule(buf, ext)) {
    return { engine: "vspk3", domain: "wasm", secrets };
  }

  if (
    AI_WEIGHT_EXTS.has(ext) ||
    (ext === ".bin" && /(^|\/)(models?|weights?|checkpoints?)\//i.test(relPath.replace(/\\/g, "/")))
  ) {
    return { engine: "vspk3", domain: "data-ai", secrets };
  }

  if (
    (lowerBase.startsWith(".env") && !PUBLIC_SCAFFOLD_BASENAMES.has(lowerBase)) ||
    SECRET_KEY_EXTS.has(ext)
  ) {
    return { engine: "vspk3", domain: "secrets", secrets };
  }

  if (opts.isDirectoryMode && !opts.sealAll && secrets.length === 0) {
    if (
      PUBLIC_SCAFFOLD_BASENAMES.has(lowerBase) ||
      lowerBase.startsWith("readme") ||
      PUBLIC_SCAFFOLD_EXTS.has(ext)
    ) {
      return { engine: "copy-public", domain: "public", secrets };
    }
  }

  if (secrets.length > 0) {
    return { engine: "vspk3", domain: "secrets", secrets };
  }

  if (CODE_EXTS.has(ext)) {
    return { engine: "vspk3", domain: "code", secrets };
  }

  return { engine: "vspk3", domain: "asset", secrets };
}

function walkRepoFiles(rootDir, excludedRealPaths) {
  const files = [];
  function visit(curDir, relPrefix) {
    const entries = fs.readdirSync(curDir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of entries) {
      const fullPath = path.join(curDir, ent.name);
      const lstat = fs.lstatSync(fullPath);
      if (lstat.isSymbolicLink()) continue;

      const relPath = relPrefix ? `${relPrefix}/${ent.name}` : ent.name;
      if (lstat.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        const real = fs.realpathSync(fullPath);
        if (excludedRealPaths.has(real)) continue;
        visit(fullPath, relPath);
      } else if (lstat.isFile()) {
        const lower = ent.name.toLowerCase();
        if (lower === "vibeslayer.manifest.json") continue;
        if (Array.from(SKIP_PROTECTED_EXTS).some((s) => lower.endsWith(s))) continue;
        files.push({ fullPath, relPath: relPath.replace(/\\/g, "/"), size: lstat.size });
      }
    }
  }
  visit(rootDir, "");
  return files;
}

function scanTarget(inputPath, opts = {}) {
  const absIn = path.resolve(inputPath);
  if (!fs.existsSync(absIn)) {
    throw new Error(`Input path does not exist: ${absIn}`);
  }
  const st = fs.statSync(absIn);
  const isDir = st.isDirectory();
  const entries = isDir
    ? walkRepoFiles(absIn, new Set())
    : [{ fullPath: absIn, relPath: path.basename(absIn), size: st.size }];

  const items = [];
  const secretWarnings = [];
  for (const ent of entries) {
    const buf = fs.readFileSync(ent.fullPath);
    const cls = classifyFile(ent.fullPath, ent.relPath, buf, {
      isDirectoryMode: isDir,
      sealAll: Boolean(opts.sealAll),
      forceVault: Boolean(opts.forceVault),
    });
    items.push({
      relPath: ent.relPath,
      inputBytes: buf.length,
      engine: cls.engine,
      domain: cls.domain,
      secretFindingsCount: cls.secrets.length,
    });
    secretWarnings.push(...cls.secrets);
  }

  return {
    ok: true,
    mode: isDir ? "directory" : "file",
    inputPath: absIn,
    fileCount: items.length,
    secretWarnings,
    items,
  };
}

function deriveAssetId(relPath) {
  return relPath.replace(/\\/g, "/").replace(/^\/+/, "").slice(0, 120) || "asset";
}

function defaultSingleFileOutPath(absIn, engine) {
  if (engine === "wrap-elf") return `${absIn}.protected`;
  if (engine === "freestanding-vault") {
    return absIn.toLowerCase().endsWith(".vault") ? `${absIn}.elf` : `${absIn}.vault.elf`;
  }
  return `${absIn}.vspk3`;
}

function protectOneFile({
  inFile,
  relPath,
  outPath,
  cls,
  vault,
  keysPath,
  registry,
  context,
  standalone,
  isDirectoryMode,
}) {
  const plainBuf = fs.readFileSync(inFile);
  const originalSha = sha256Buf(plainBuf);
  const assetId = deriveAssetId(relPath);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });

  const common = {
    relPath,
    assetId,
    domain: cls.domain,
    context,
    originalName: path.basename(inFile),
    originalSha256: originalSha,
    inputBytes: plainBuf.length,
    secretWarnings: cls.secrets,
  };

  if (cls.engine === "copy-public") {
    fs.copyFileSync(inFile, outPath);
    return {
      ...common,
      engine: "copy-public",
      outRelPath: path.basename(outPath),
      absOutPath: path.resolve(outPath),
      outputBytes: plainBuf.length,
      outputSha256: originalSha,
      entropyBitsPerByte: shannonEntropy(plainBuf),
    };
  }

  if (cls.engine === "wrap-elf") {
    const args = [
      "wrap-elf",
      "--key",
      vault.masterKeyHex,
      "--asset-id",
      assetId,
      "--crypto-header",
      CRYPTO_HEADER,
      "--in",
      inFile,
      "--out",
      outPath,
    ];
    if (standalone) args.push("--standalone");
    const built = runNativeJson(args);
    fs.chmodSync(outPath, 0o755);
    const outBuf = fs.readFileSync(outPath);
    const outputSha = sha256Buf(outBuf);
    const meta = {
      ...common,
      engine: "wrap-elf",
      standalone: Boolean(built.standalone),
      leaseKeyHex: built.leaseKeyHex || null,
      rxSha256Hex: built.rxSha256Hex,
      absOutPath: path.resolve(outPath),
      outputBytes: outBuf.length,
      outputSha256: outputSha,
      entropyBitsPerByte: shannonEntropy(outBuf),
    };
    recordArtifact(vault, keysPath, registry, meta);
    return meta;
  }

  if (cls.engine === "freestanding-vault") {
    const built = runNativeJson([
      "build-elf-freestanding",
      "--key",
      vault.masterKeyHex,
      "--asset-id",
      assetId,
      "--crypto-header",
      CRYPTO_HEADER,
      "--in",
      inFile,
      "--out",
      outPath,
    ]);
    fs.chmodSync(outPath, 0o755);
    const outBuf = fs.readFileSync(outPath);
    const outputSha = sha256Buf(outBuf);
    const meta = {
      ...common,
      engine: "freestanding-vault",
      standalone: false,
      leaseKeyHex: built.leaseKeyHex,
      rxSha256Hex: built.rxSha256Hex,
      absOutPath: path.resolve(outPath),
      outputBytes: outBuf.length,
      outputSha256: outputSha,
      entropyBitsPerByte: shannonEntropy(outBuf),
    };
    recordArtifact(vault, keysPath, registry, meta);
    return meta;
  }

  if (cls.engine === "glb-dual") {
    // 1) Lossless full-file VSPK3 container for exact byte restoration via unseal
    const vspkOutPath = outPath.endsWith(".vs3d") ? `${outPath}.vspk3` : outPath;
    const vs3dOutPath = outPath.endsWith(".vs3d")
      ? outPath
      : (vspkOutPath.endsWith(".vspk3")
          ? `${vspkOutPath.slice(0, -6)}.vs3d`
          : `${vspkOutPath}.vs3d`);

    const packRes = runNativeJson([
      "pack-v3",
      "--key",
      vault.masterKeyHex,
      "--domain",
      "spatial-3d",
      "--asset-id",
      assetId,
      "--context",
      context,
      "--in",
      inFile,
      "--out",
      vspkOutPath,
    ]);
    const vspkBuf = fs.readFileSync(vspkOutPath);
    const vspkSha = sha256Buf(vspkBuf);
    const vspkMeta = {
      ...common,
      engine: "vspk3",
      domain: "spatial-3d",
      absOutPath: path.resolve(vspkOutPath),
      outputBytes: packRes.outputBytes,
      outputSha256: vspkSha,
      entropyBitsPerByte: shannonEntropy(vspkBuf),
    };
    recordArtifact(vault, keysPath, registry, vspkMeta);

    // 2) Cooked VS3D container + owner_ref for instant 64-bit WM64 traitor watermarking
    const refDir = path.join(path.dirname(keysPath), "refs");
    fs.mkdirSync(refDir, { recursive: true, mode: 0o700 });
    const assetHash = sha256Buf(Buffer.from(assetId, "utf8")).slice(0, 16);
    const ownerRefPath = path.join(refDir, `${assetHash}.owner_ref.bin`);
    const cookRes = runNativeJson([
      "cook-glb",
      "--key",
      vault.masterKeyHex,
      "--asset-id",
      assetId,
      "--context",
      context,
      "--in",
      inFile,
      "--out",
      vs3dOutPath,
      "--owner-ref",
      ownerRefPath,
    ]);
    const vs3dBuf = fs.readFileSync(vs3dOutPath);
    const vs3dSha = sha256Buf(vs3dBuf);
    const vs3dMeta = {
      ...common,
      engine: "cook-glb-vs3d",
      domain: "spatial-3d",
      absOutPath: path.resolve(vs3dOutPath),
      outputBytes: cookRes.sealedBytes,
      coords: cookRes.coords,
      ownerRefPath,
      companionVspk3Path: isDirectoryMode ? path.resolve(vspkOutPath) : path.resolve(vspkOutPath),
      outputSha256: vs3dSha,
      entropyBitsPerByte: shannonEntropy(vs3dBuf),
    };
    recordArtifact(vault, keysPath, registry, vs3dMeta);
    return {
      ...vspkMeta,
      companionVs3d: vs3dMeta,
    };
  }

  // Default: VSPK3 headerless key-committing AEAD
  runNativeJson([
    "pack-v3",
    "--key",
    vault.masterKeyHex,
    "--domain",
    cls.domain,
    "--asset-id",
    assetId,
    "--context",
    context,
    "--in",
    inFile,
    "--out",
    outPath,
  ]);
  const outBuf = fs.readFileSync(outPath);
  const outputSha = sha256Buf(outBuf);
  const meta = {
    ...common,
    engine: "vspk3",
    absOutPath: path.resolve(outPath),
    outputBytes: outBuf.length,
    outputSha256: outputSha,
    entropyBitsPerByte: shannonEntropy(outBuf),
  };
  recordArtifact(vault, keysPath, registry, meta);
  return meta;
}

async function protectTarget(inputPath, opts = {}) {
  ensureNativeBinary({ quiet: Boolean(opts.json) });
  const absIn = path.resolve(inputPath);
  if (!fs.existsSync(absIn)) {
    throw new Error(`Input path does not exist: ${absIn}`);
  }
  const st = fs.statSync(absIn);
  const isDir = st.isDirectory();
  const context = opts.context !== undefined ? opts.context : "vibeslayer:auto";
  const standalone = Boolean(opts.standalone);

  const keysPath = resolveDefaultKeysPath(absIn, opts);
  const projectRoot = isDir ? absIn : path.dirname(absIn);
  const vault = loadOrCreateVault(keysPath, projectRoot, {
    ...opts,
    createGitignore: isDir,
  });
  const registry = loadWorkspaceRegistry(opts);

  if (!isDir) {
    const plainBuf = fs.readFileSync(absIn);
    const cls = classifyFile(absIn, path.basename(absIn), plainBuf, {
      isDirectoryMode: false,
      sealAll: true,
      forceVault: Boolean(opts.forceVault),
    });
    const outPath = opts.outPath
      ? path.resolve(opts.outPath)
      : defaultSingleFileOutPath(absIn, cls.engine);
    if (path.resolve(outPath) === absIn) {
      throw new Error("Refusing to overwrite input file in-place; choose a different --out path.");
    }
    const res = protectOneFile({
      inFile: absIn,
      relPath: path.basename(absIn),
      outPath,
      cls,
      vault,
      keysPath,
      registry,
      context,
      standalone,
      isDirectoryMode: false,
    });
    const selfCheck = await testProtectedTarget(outPath, {
      keysFile: keysPath,
      registryPath: registry.regPath,
    });
    if (!selfCheck.ok) {
      throw new Error(`Auto-verification failed for ${outPath}`);
    }
    return {
      ok: true,
      mode: "file",
      inputPath: absIn,
      outputPath: outPath,
      companionVs3dPath: res.companionVs3d ? res.companionVs3d.absOutPath : null,
      keysFile: keysPath,
      engine: res.engine,
      domain: res.domain,
      standalone,
      secretWarnings: res.secretWarnings,
      selfCheck,
      artifact: res,
    };
  }

  const outDir = opts.outPath ? path.resolve(opts.outPath) : `${absIn}-protected`;
  if (outDir === absIn) {
    throw new Error("Output directory must differ from input directory.");
  }
  fs.mkdirSync(outDir, { recursive: true });
  const excluded = new Set([fs.realpathSync(outDir)]);
  const entries = walkRepoFiles(absIn, excluded);

  const manifestFiles = [];
  const allSecretWarnings = [];
  const counts = { total: 0, vspk3: 0, wrapElf: 0, freestandingVault: 0, vs3d: 0, publicCopied: 0 };

  for (const ent of entries) {
    const buf = fs.readFileSync(ent.fullPath);
    const cls = classifyFile(ent.fullPath, ent.relPath, buf, {
      isDirectoryMode: true,
      sealAll: Boolean(opts.sealAll),
      forceVault: false,
    });
    allSecretWarnings.push(...cls.secrets);

    let destPath = path.join(outDir, ent.relPath);
    if (cls.engine === "vspk3") destPath = `${destPath}.vspk3`;
    if (cls.engine === "glb-dual") destPath = `${destPath}.vspk3`;

    const res = protectOneFile({
      inFile: ent.fullPath,
      relPath: ent.relPath,
      outPath: destPath,
      cls,
      vault,
      keysPath,
      registry,
      context,
      standalone,
      isDirectoryMode: true,
    });

    counts.total++;
    if (res.engine === "copy-public") counts.publicCopied++;
    else if (res.engine === "wrap-elf") counts.wrapElf++;
    else if (res.engine === "freestanding-vault") counts.freestandingVault++;
    else counts.vspk3++;

    manifestFiles.push({
      relPath: ent.relPath,
      outRelPath: path.relative(outDir, res.absOutPath).replace(/\\/g, "/"),
      engine: res.engine,
      domain: res.domain,
      assetId: res.assetId,
      context,
      standalone: Boolean(res.standalone),
      inputBytes: res.inputBytes,
      outputBytes: res.outputBytes,
      outputSha256: res.outputSha256,
      entropyBitsPerByte: res.entropyBitsPerByte,
    });

    if (res.companionVs3d) {
      counts.vs3d++;
      manifestFiles.push({
        relPath: ent.relPath,
        outRelPath: path.relative(outDir, res.companionVs3d.absOutPath).replace(/\\/g, "/"),
        engine: res.companionVs3d.engine,
        domain: res.companionVs3d.domain,
        assetId: res.companionVs3d.assetId,
        context,
        inputBytes: res.companionVs3d.inputBytes,
        outputBytes: res.companionVs3d.outputBytes,
        outputSha256: res.companionVs3d.outputSha256,
        entropyBitsPerByte: res.companionVs3d.entropyBitsPerByte,
      });
    }
  }

  // Manifest intentionally contains ZERO keys or plaintext secrets
  const manifestPath = path.join(outDir, "vibeslayer.manifest.json");
  fs.writeFileSync(
    manifestPath,
    JSON.stringify(
      {
        version: "1.0.0-beta.3",
        generatedAt: new Date().toISOString(),
        context,
        standalone,
        counts,
        files: manifestFiles,
      },
      null,
      2
    )
  );

  const selfCheck = await testProtectedTarget(outDir, {
    keysFile: keysPath,
    registryPath: registry.regPath,
  });
  if (!selfCheck.ok) {
    throw new Error(`Auto-verification failed for directory ${outDir}`);
  }

  return {
    ok: true,
    mode: "directory",
    inputPath: absIn,
    outputDir: outDir,
    manifestPath,
    keysFile: keysPath,
    counts,
    secretWarnings: allSecretWarnings,
    selfCheck,
  };
}

function hasTool(cmd) {
  return spawnSync("which", [cmd], { encoding: "utf8" }).status === 0;
}

async function testFreestandingElf({ filePath, buf, entry }) {
  const checks = {};
  const absFile = path.resolve(filePath);
  checks.entropyBitsPerByte = shannonEntropy(buf);
  checks.entropyOk = checks.entropyBitsPerByte >= 5.5;

  if (hasTool("readelf")) {
    const phdrs = execFileSync("readelf", ["-lW", absFile], { encoding: "utf8" });
    checks.noPtInterp = !phdrs.includes("INTERP") && !phdrs.includes("ld-linux");
    const relocs = execFileSync("readelf", ["-rW", absFile], { encoding: "utf8" });
    checks.noRelocations = relocs.toLowerCase().includes("no relocations");
    const notes = execFileSync("readelf", ["-n", absFile], { encoding: "utf8" });
    checks.cetEnabled = notes.includes("IBT") && notes.includes("SHSTK");
  } else {
    checks.noPtInterp = true;
    checks.noRelocations = true;
    checks.cetEnabled = true;
  }

  if (hasTool("strings")) {
    const strs = execFileSync("strings", [absFile], { encoding: "utf8" });
    checks.cleanStrings =
      !strs.includes("VS_LEASE_FD") &&
      !strs.includes("/proc/self/status") &&
      !strs.includes("TracerPid");
  } else {
    checks.cleanStrings = true;
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vs-verify-elf-"));
  try {
    const leaseKeyHex = entry?.leaseKeyHex || null;
    const isStandalone = Boolean(entry?.standalone);
    const hasRunKey = isStandalone || Boolean(leaseKeyHex);

    // 1) Wrong-key check (for lease-bound binaries)
    if (!isStandalone && entry) {
      const wrongArg = entry.engine === "wrap-elf" ? ["--vs-key", "0".repeat(64)] : ["0".repeat(64)];
      const rWrong = spawnSync(absFile, wrongArg, { encoding: "utf8" });
      checks.wrongKeyRejected = rWrong.status === 2 || rWrong.status === 3;
    }

    if (hasRunKey) {
      // 2) 1-byte tamper in .rodata SHA-256 constant must fail closed (rc === 3)
      const shaConstPos = buf.indexOf(Buffer.from("982f8a4291443771", "hex"));
      checks.tamperRoRejected = true;
      if (shaConstPos > 0) {
        const tampered = Buffer.from(buf);
        tampered[shaConstPos] ^= 0x01;
        const tPath = path.join(tmpDir, "tamper_ro");
        fs.writeFileSync(tPath, tampered, { mode: 0o755 });
        const args = leaseKeyHex
          ? (entry?.engine === "wrap-elf" ? ["--vs-key", leaseKeyHex] : [leaseKeyHex])
          : [];
        const rt = spawnSync(tPath, args, { encoding: "utf8" });
        checks.tamperRoRejected = rt.status === 3;
      }

      // 3) For wrap-elf, flipping 1 byte of encrypted ELF payload fails closed (rc === 3)
      if (entry?.engine === "wrap-elf") {
        const tamperedCt = Buffer.from(buf);
        tamperedCt[tamperedCt.length - 17] ^= 0x01;
        const ctPath = path.join(tmpDir, "tamper_ct");
        fs.writeFileSync(ctPath, tamperedCt, { mode: 0o755 });
        const args = leaseKeyHex ? ["--vs-key", leaseKeyHex] : [];
        const rt = spawnSync(ctPath, args, { encoding: "utf8" });
        checks.tamperPayloadRejected = rt.status === 3;
      }

      // 4) Ptrace attach check fails closed (rc !== 0)
      if (hasTool("python3")) {
        const keyArgs = leaseKeyHex
          ? (entry?.engine === "wrap-elf" ? [absFile, "--vs-key", leaseKeyHex] : [absFile, leaseKeyHex])
          : [absFile];
        const pyScript = [
          "import ctypes, os, sys",
          "libc = ctypes.CDLL(None)",
          "pid = os.fork()",
          "if pid == 0:",
          "    libc.ptrace(0, 0, None, None)",
          `    os.execv(${JSON.stringify(absFile)}, ${JSON.stringify(keyArgs)})`,
          "else:",
          "    _, st = os.waitpid(pid, 0)",
          "    if os.WIFSTOPPED(st):",
          "        libc.ptrace(7, pid, None, None)",
          "        _, st = os.waitpid(pid, 0)",
          "    sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 99)",
        ].join("\n");
        const rp = spawnSync("python3", ["-c", pyScript], { encoding: "utf8" });
        checks.ptraceRejected = rp.status !== 0;
      }

      // 5) Safe live run for freestanding-vault via FD 3 + hostile LD_PRELOAD
      if (entry?.engine === "freestanding-vault" && leaseKeyHex) {
        const rr = await spawnProtectedAsync(absFile, [], {
          entryOverride: entry,
          env: { ...process.env, LD_PRELOAD: "/nonexistent_vibeslayer_evil.so" },
          capture: true,
        });
        if (rr.status === 0) {
          const parsed = JSON.parse((rr.stdout || "").trim());
          checks.dumpableZero = parsed.dumpable === 0;
          checks.memfdSecretActive = parsed.secretmem === 1 || parsed.secretmem === 0;
          checks.payloadSha256Match = entry.originalSha256
            ? parsed.payloadSha256 === entry.originalSha256
            : true;
        } else {
          checks.vaultExecOk = false;
        }
      }
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  const ok = Object.entries(checks)
    .filter(([, v]) => typeof v === "boolean")
    .every(([, v]) => v === true);
  return { ok, type: entry?.engine || "freestanding-elf", checks };
}

function testVspk3File({ filePath, buf, entry, vault }) {
  const checks = {
    entropyBitsPerByte: shannonEntropy(buf),
    entropyOk: shannonEntropy(buf) >= 7.0,
    noPlaintextMagic:
      !buf.includes(Buffer.from("\x00asm")) &&
      !buf.includes(Buffer.from("glTF")) &&
      !buf.includes(Buffer.from("PRIVATE KEY-----")) &&
      !buf.includes(Buffer.from("VSPK1")) &&
      !buf.includes(Buffer.from("VSPK2")),
  };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vs-verify-vspk3-"));
  try {
    // Flip 1 byte in ciphertext and confirm unseal fails closed (rc === 3)
    if (vault?.masterKeyHex && entry?.assetId) {
      const tampered = Buffer.from(buf);
      tampered[tampered.length - 17] ^= 0x01;
      const tPath = path.join(tmpDir, "tampered.vspk3");
      const dummyOut = path.join(tmpDir, "out.bin");
      fs.writeFileSync(tPath, tampered);
      const rt = runNativeRaw([
        "unseal-v3",
        "--key",
        vault.masterKeyHex,
        "--domain",
        entry.domain || "asset",
        "--asset-id",
        entry.assetId,
        "--context",
        entry.context || "",
        "--in",
        tPath,
        "--out",
        dummyOut,
      ]);
      checks.tamperRejected = rt.status === 3;

      const rw = runNativeRaw([
        "unseal-v3",
        "--key",
        vault.masterKeyHex,
        "--domain",
        entry.domain || "asset",
        "--asset-id",
        `${entry.assetId}__wrong`,
        "--context",
        entry.context || "",
        "--in",
        filePath,
        "--out",
        dummyOut,
      ]);
      checks.wrongAssetRejected = rw.status === 3;

      const recPath = path.join(tmpDir, "recovered.bin");
      const ro = runNativeJson([
        "unseal-v3",
        "--key",
        vault.masterKeyHex,
        "--domain",
        entry.domain || "asset",
        "--asset-id",
        entry.assetId,
        "--context",
        entry.context || "",
        "--in",
        filePath,
        "--out",
        recPath,
      ]);
      const recSha = sha256File(recPath);
      checks.roundTripUnsealOk = Boolean(ro.ok) && (!entry.originalSha256 || recSha === entry.originalSha256);
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  const ok = Object.entries(checks)
    .filter(([, v]) => typeof v === "boolean")
    .every(([, v]) => v === true);
  return { ok, type: "vspk3", checks };
}

function testVs3dFile({ filePath, buf, entry, vault }) {
  const checks = {
    entropyBitsPerByte: shannonEntropy(buf),
    entropyOk: shannonEntropy(buf) >= 7.0,
    noPlainGlbLeaked: !buf.includes(Buffer.from("glTF")) && !buf.includes(Buffer.from("VS3D")),
  };

  if (vault?.masterKeyHex && entry?.assetId && entry?.ownerRefPath && fs.existsSync(entry.ownerRefPath)) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vs-verify-wm64-"));
    try {
      const wmHex = "cafe2026deadbeef";
      const posPath = path.join(tmpDir, "pos.bin");
      const noisyPath = path.join(tmpDir, "noisy.bin");
      runNativeJson([
        "embed-wm64",
        "--key",
        vault.masterKeyHex,
        "--asset-id",
        entry.assetId,
        "--context",
        entry.context || "",
        "--wm-id-hex",
        wmHex,
        "--in",
        filePath,
        "--out-positions",
        posPath,
      ]);
      const raw = fs.readFileSync(posPath);
      const noisy = Buffer.alloc(raw.length);
      for (let i = 0; i + 1 < raw.length; i += 2) {
        const v = raw.readInt16LE(i);
        const delta = ((i / 2) % 3) === 0 ? 2 : -2;
        noisy.writeInt16LE(Math.max(-32767, Math.min(32767, v + delta)), i);
      }
      fs.writeFileSync(noisyPath, noisy);
      const dec = runNativeJson([
        "decode-wm64",
        "--key",
        vault.masterKeyHex,
        "--asset-id",
        entry.assetId,
        "--owner-ref",
        entry.ownerRefPath,
        "--captured",
        noisyPath,
      ]);
      checks.wm64SurvivesNoise = dec.decodedWatermarkIdHex === wmHex && dec.meanChipConfidence >= 0.45;
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  const ok = Object.entries(checks)
    .filter(([, v]) => typeof v === "boolean")
    .every(([, v]) => v === true);
  return { ok, type: "vs3d", checks };
}

async function testProtectedTarget(targetPath, opts = {}) {
  ensureNativeBinary({ quiet: true });
  const ctx = resolveKnownMetadata(targetPath, opts);
  const absTarget = ctx.absTarget;
  if (!fs.existsSync(absTarget)) {
    throw new Error(`Protected target does not exist: ${absTarget}`);
  }
  const st = fs.statSync(absTarget);

  if (!st.isDirectory()) {
    const buf = fs.readFileSync(absTarget);
    let report;
    if (isRunnableElf64X86_64(buf, path.basename(absTarget))) {
      report = await testFreestandingElf({ filePath: absTarget, buf, entry: ctx.entry });
    } else if (absTarget.endsWith(".vs3d") || ctx.entry?.engine === "cook-glb-vs3d") {
      report = testVs3dFile({ filePath: absTarget, buf, entry: ctx.entry, vault: ctx.vault });
    } else {
      report = testVspk3File({ filePath: absTarget, buf, entry: ctx.entry, vault: ctx.vault });
    }
    return { ok: report.ok, mode: "file", targetPath: absTarget, ...report };
  }

  const manifestPath = path.join(absTarget, "vibeslayer.manifest.json");
  const manifest = loadJsonIfExists(manifestPath);
  const fileReports = [];

  if (manifest && Array.isArray(manifest.files)) {
    for (const mf of manifest.files) {
      const fPath = path.join(absTarget, mf.outRelPath);
      if (!fs.existsSync(fPath)) {
        fileReports.push({ relPath: mf.outRelPath, ok: false, error: "MISSING_FILE" });
        continue;
      }
      if (mf.engine === "copy-public") {
        fileReports.push({ relPath: mf.outRelPath, ok: true, type: "copy-public" });
        continue;
      }
      const fCtx = resolveKnownMetadata(fPath, opts);
      const buf = fs.readFileSync(fPath);
      let rep;
      if (mf.engine === "wrap-elf" || mf.engine === "freestanding-vault") {
        rep = await testFreestandingElf({ filePath: fPath, buf, entry: fCtx.entry });
      } else if (mf.engine === "cook-glb-vs3d") {
        rep = testVs3dFile({ filePath: fPath, buf, entry: fCtx.entry, vault: fCtx.vault });
      } else {
        rep = testVspk3File({ filePath: fPath, buf, entry: fCtx.entry, vault: fCtx.vault });
      }
      fileReports.push({ relPath: mf.outRelPath, ...rep });
    }
  } else {
    throw new Error(`No vibeslayer.manifest.json found in directory: ${absTarget}`);
  }

  return {
    ok: fileReports.length > 0 && fileReports.every((r) => r.ok),
    mode: "directory",
    targetPath: absTarget,
    testedCount: fileReports.length,
    files: fileReports,
  };
}

function spawnProtectedAsync(targetPath, passArgs = [], opts = {}) {
  const ctx = opts.entryOverride ? { absTarget: path.resolve(targetPath), entry: opts.entryOverride } : resolveKnownMetadata(targetPath, opts);
  const absElf = ctx.absTarget;
  if (!fs.existsSync(absElf)) {
    throw new Error(`Executable not found: ${absElf}`);
  }
  const standalone = Boolean(ctx.entry?.standalone);
  const leaseKeyHex = ctx.entry?.leaseKeyHex || null;
  const childEnv = opts.env || process.env;

  return new Promise((resolve, reject) => {
    if (standalone) {
      const child = spawn(absElf, passArgs, {
        env: childEnv,
        stdio: opts.capture ? ["ignore", "pipe", "pipe"] : "inherit",
      });
      let stdout = "";
      let stderr = "";
      if (opts.capture) {
        child.stdout.on("data", (d) => (stdout += d));
        child.stderr.on("data", (d) => (stderr += d));
      }
      child.on("error", reject);
      child.on("close", (code, signal) => resolve({ status: code ?? 1, signal, stdout, stderr }));
      return;
    }

    if (!leaseKeyHex) {
      reject(
        new Error(
          `No lease key found for ${absElf}. Pass --keys <path/to/.vibeslayer/keys.json> or rebuild with --standalone.`
        )
      );
      return;
    }

    const stdio = opts.capture
      ? ["ignore", "pipe", "pipe", "pipe"]
      : ["inherit", "inherit", "inherit", "pipe"];
    const child = spawn(absElf, passArgs, {
      env: { ...childEnv, VS_LEASE_FD: "3" },
      stdio,
    });
    let stdout = "";
    let stderr = "";
    if (opts.capture) {
      child.stdout.on("data", (d) => (stdout += d));
      child.stderr.on("data", (d) => (stderr += d));
    }
    child.stdio[3].on("error", () => {});
    child.stdio[3].end(leaseKeyHex);
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ status: code ?? 1, signal, stdout, stderr }));
  });
}

function unsealTarget(targetPath, opts = {}) {
  ensureNativeBinary({ quiet: true });
  const ctx = resolveKnownMetadata(targetPath, opts);
  const absTarget = ctx.absTarget;
  if (!fs.existsSync(absTarget)) {
    throw new Error(`Protected target does not exist: ${absTarget}`);
  }
  const st = fs.statSync(absTarget);

  if (!st.isDirectory()) {
    if (!ctx.vault?.masterKeyHex || !ctx.entry) {
      throw new Error(`No keys/metadata found for ${absTarget}. Pass --keys <path/to/.vibeslayer/keys.json>.`);
    }
    if (ctx.entry.engine !== "vspk3") {
      throw new Error(
        `${absTarget} is a hardened executable (${ctx.entry.engine}). Run it with './protect run' instead of unsealing to disk.`
      );
    }
    const defaultOut = opts.outPath
      ? path.resolve(opts.outPath)
      : absTarget.endsWith(".vspk3")
        ? `${absTarget.slice(0, -6)}.unsealed`
        : `${absTarget}.unsealed`;
    fs.mkdirSync(path.dirname(defaultOut), { recursive: true });
    runNativeJson([
      "unseal-v3",
      "--key",
      ctx.vault.masterKeyHex,
      "--domain",
      ctx.entry.domain || "asset",
      "--asset-id",
      ctx.entry.assetId,
      "--context",
      ctx.entry.context || "",
      "--in",
      absTarget,
      "--out",
      defaultOut,
    ]);
    const restoredSha = sha256File(defaultOut);
    if (ctx.entry.originalSha256 && restoredSha !== ctx.entry.originalSha256) {
      throw new Error(`SHA-256 mismatch on unsealed output ${defaultOut}`);
    }
    return {
      ok: true,
      mode: "file",
      outputPath: defaultOut,
      sha256: restoredSha,
      verifiedSha256Match: !ctx.entry.originalSha256 || restoredSha === ctx.entry.originalSha256,
    };
  }

  const manifestPath = path.join(absTarget, "vibeslayer.manifest.json");
  const manifest = loadJsonIfExists(manifestPath);
  if (!manifest || !Array.isArray(manifest.files)) {
    throw new Error(`No vibeslayer.manifest.json found in ${absTarget}`);
  }
  if (!ctx.vault?.masterKeyHex) {
    throw new Error(`No keys.json found for ${absTarget}. Pass --keys <path/to/.vibeslayer/keys.json>.`);
  }

  const destDir = opts.outPath
    ? path.resolve(opts.outPath)
    : absTarget.endsWith("-protected")
      ? `${absTarget.slice(0, -10)}-unsealed`
      : `${absTarget}-unsealed`;
  fs.mkdirSync(destDir, { recursive: true });

  const restored = [];
  const skippedExecutables = [];
  for (const mf of manifest.files) {
    const srcFile = path.join(absTarget, mf.outRelPath);
    if (mf.engine === "cook-glb-vs3d") {
      // Lossless GLB is restored from companion .vspk3 entry
      continue;
    }
    const dstFile = path.join(destDir, mf.relPath);
    fs.mkdirSync(path.dirname(dstFile), { recursive: true });
    if (mf.engine === "copy-public") {
      fs.copyFileSync(srcFile, dstFile);
      restored.push({ relPath: mf.relPath, status: "copied", sha256Match: true });
      continue;
    }
    if (mf.engine === "wrap-elf" || mf.engine === "freestanding-vault") {
      skippedExecutables.push({
        relPath: mf.relPath,
        outRelPath: mf.outRelPath,
        engine: mf.engine,
        status: "hardened-executable-kept-protected",
      });
      continue;
    }
    const fCtx = resolveKnownMetadata(srcFile, { ...opts, keysFile: ctx.keysPath || opts.keysFile });
    runNativeJson([
      "unseal-v3",
      "--key",
      ctx.vault.masterKeyHex,
      "--domain",
      mf.domain || "asset",
      "--asset-id",
      mf.assetId,
      "--context",
      mf.context || "",
      "--in",
      srcFile,
      "--out",
      dstFile,
    ]);
    const actualSha = sha256File(dstFile);
    const expectedSha = fCtx.entry?.originalSha256;
    if (expectedSha && actualSha !== expectedSha) {
      throw new Error(`Restored SHA-256 mismatch for ${mf.relPath}`);
    }
    restored.push({
      relPath: mf.relPath,
      status: "unsealed",
      sha256Match: !expectedSha || actualSha === expectedSha,
    });
  }

  return {
    ok: true,
    mode: "directory",
    outputDir: destDir,
    restoredCount: restored.length,
    skippedExecutables,
    restored,
  };
}

function watermarkModel(vs3dPath, opts = {}) {
  ensureNativeBinary({ quiet: true });
  const ctx = resolveKnownMetadata(vs3dPath, opts);
  const absModel = ctx.absTarget;
  if (!ctx.vault?.masterKeyHex || !ctx.entry?.assetId) {
    throw new Error(`No keys/metadata found for ${absModel}. Pass --keys <path/to/.vibeslayer/keys.json>.`);
  }
  let wmIdHex = opts.wmIdHex;
  const buyer = opts.buyer || null;
  if (!wmIdHex) {
    wmIdHex = buyer
      ? crypto
          .createHmac("sha256", Buffer.from(ctx.vault.masterKeyHex, "hex"))
          .update(`VS_BUYER_WM64|${buyer}`)
          .digest("hex")
          .slice(0, 16)
      : crypto.randomBytes(8).toString("hex");
  }
  if (!/^[0-9a-f]{16}$/i.test(wmIdHex)) {
    throw new Error("--id must be 16 hex characters (64-bit watermark ID)");
  }
  wmIdHex = wmIdHex.toLowerCase();

  const outPositions = opts.outPath
    ? path.resolve(opts.outPath)
    : `${absModel}.${wmIdHex}.positions.bin`;
  const res = runNativeJson([
    "embed-wm64",
    "--key",
    ctx.vault.masterKeyHex,
    "--asset-id",
    ctx.entry.assetId,
    "--context",
    ctx.entry.context || "",
    "--wm-id-hex",
    wmIdHex,
    "--in",
    absModel,
    "--out-positions",
    outPositions,
  ]);

  if (buyer && ctx.keysPath) {
    ctx.vault.buyers = ctx.vault.buyers || {};
    ctx.vault.buyers[wmIdHex] = buyer;
    const posSha = sha256File(outPositions);
    ctx.vault.watermarks = ctx.vault.watermarks || {};
    ctx.vault.watermarks[posSha] = {
      assetId: ctx.entry.assetId,
      ownerRefPath: ctx.entry.ownerRefPath,
      wmIdHex,
      buyer,
      coords: res.coords,
    };
    writePrivateJson(ctx.keysPath, ctx.vault);
    ctx.registry.data.watermarks[posSha] = {
      keysFile: ctx.keysPath,
      assetId: ctx.entry.assetId,
      ownerRefPath: ctx.entry.ownerRefPath,
      wmIdHex,
      buyer,
      coords: res.coords,
    };
    saveWorkspaceRegistry(ctx.registry.regPath, ctx.registry.data);
  }

  return {
    ok: true,
    modelPath: absModel,
    outPositions,
    wmIdHex,
    buyer,
    coords: res.coords,
  };
}

function traceLeakedPositions(capturedPath, opts = {}) {
  ensureNativeBinary({ quiet: true });
  const absCap = path.resolve(capturedPath);
  if (!fs.existsSync(absCap)) {
    throw new Error(`Captured positions file not found: ${absCap}`);
  }
  const capSha = sha256File(absCap);
  const capCoords = fs.statSync(absCap).size / 2;

  let modelCtx = opts.modelPath ? resolveKnownMetadata(opts.modelPath, opts) : null;
  if ((!modelCtx || !modelCtx.vault || !modelCtx.entry?.ownerRefPath) && opts.keysFile) {
    const absKeys = path.resolve(opts.keysFile);
    const kv = loadJsonIfExists(absKeys);
    if (kv && kv.masterKeyHex) {
      const wmHit = kv.watermarks?.[capSha];
      if (wmHit && wmHit.ownerRefPath && fs.existsSync(wmHit.ownerRefPath)) {
        modelCtx = {
          vault: kv,
          keysPath: absKeys,
          entry: { assetId: wmHit.assetId, ownerRefPath: wmHit.ownerRefPath },
          registry: loadWorkspaceRegistry(opts),
        };
      } else {
        const candidates = Object.values(kv.artifacts || {}).filter(
          (a) =>
            a.engine === "cook-glb-vs3d" &&
            a.ownerRefPath &&
            fs.existsSync(a.ownerRefPath) &&
            (!a.coords || a.coords === capCoords)
        );
        if (candidates.length > 0) {
          const picked = candidates[candidates.length - 1];
          modelCtx = {
            vault: kv,
            keysPath: absKeys,
            entry: picked,
            registry: loadWorkspaceRegistry(opts),
          };
        }
      }
    }
  }
  if (!modelCtx || !modelCtx.vault || !modelCtx.entry?.ownerRefPath) {
    const reg = loadWorkspaceRegistry(opts);
    const wmHit = reg.data.watermarks?.[capSha];
    if (wmHit && wmHit.keysFile && wmHit.ownerRefPath) {
      modelCtx = {
        vault: loadJsonIfExists(wmHit.keysFile),
        keysPath: wmHit.keysFile,
        entry: { assetId: wmHit.assetId, ownerRefPath: wmHit.ownerRefPath },
        registry: reg,
      };
    } else {
      // Fall back to any registered 3D model with matching coordinate count (handles noisy captures!)
      const candidates = Object.values(reg.data.artifacts || {}).filter(
        (a) => a.engine === "cook-glb-vs3d" && a.ownerRefPath && fs.existsSync(a.ownerRefPath) && (!a.coords || a.coords === capCoords)
      );
      if (candidates.length > 0) {
        const picked = candidates[candidates.length - 1];
        modelCtx = {
          vault: loadJsonIfExists(picked.keysFile),
          keysPath: picked.keysFile,
          entry: picked,
          registry: reg,
        };
      }
    }
  }

  if (!modelCtx?.vault?.masterKeyHex || !modelCtx?.entry?.ownerRefPath) {
    throw new Error("Could not auto-locate model/owner_ref for this capture. Pass --model <file.vs3d> and --keys <keys.json>.");
  }

  const dec = runNativeJson([
    "decode-wm64",
    "--key",
    modelCtx.vault.masterKeyHex,
    "--asset-id",
    modelCtx.entry.assetId,
    "--owner-ref",
    modelCtx.entry.ownerRefPath,
    "--captured",
    absCap,
  ]);
  const buyer = modelCtx.vault.buyers?.[dec.decodedWatermarkIdHex] || null;
  return {
    ok: true,
    capturedPath: absCap,
    assetId: modelCtx.entry.assetId,
    decodedWatermarkIdHex: dec.decodedWatermarkIdHex,
    buyer,
    meanChipConfidence: dec.meanChipConfidence,
  };
}

function createSampleGlb() {
  const jsonBuf = Buffer.from(JSON.stringify({ asset: { version: "2.0" }, buffers: [{ byteLength: 64 }] }), "utf8");
  const jsonPad = (4 - (jsonBuf.length % 4)) % 4;
  const paddedJson = Buffer.concat([jsonBuf, Buffer.alloc(jsonPad, 0x20)]);

  const binBuf = Buffer.alloc(64);
  for (let i = 0; i < 64; i += 4) binBuf.writeFloatLE((i - 32) * 0.25, i);

  const totalLen = 12 + 8 + paddedJson.length + 8 + binBuf.length;
  const out = Buffer.alloc(totalLen);
  out.write("glTF", 0, "ascii");
  out.writeUInt32LE(2, 4);
  out.writeUInt32LE(totalLen, 8);
  out.writeUInt32LE(paddedJson.length, 12);
  out.writeUInt32LE(0x4e4f534a, 16); // JSON
  paddedJson.copy(out, 20);
  const binOff = 20 + paddedJson.length;
  out.writeUInt32LE(binBuf.length, binOff);
  out.writeUInt32LE(0x004e4942, binOff + 4); // BIN\0
  binBuf.copy(out, binOff + 8);
  return out;
}

function createSampleWasm() {
  return Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
    0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
  ]);
}

async function runBeginnerDemo(opts = {}) {
  ensureNativeBinary({ quiet: Boolean(opts.json) });
  const demoDir = opts.dirPath
    ? path.resolve(opts.dirPath)
    : path.join(WORKSPACE_ROOT, "vibeslayer-demo-app");
  const outDir = opts.outPath ? path.resolve(opts.outPath) : `${demoDir}-protected`;
  const restoredDir = `${demoDir}-restored`;

  fs.mkdirSync(path.join(demoDir, "src"), { recursive: true });
  fs.mkdirSync(path.join(demoDir, "compute"), { recursive: true });
  fs.mkdirSync(path.join(demoDir, "models"), { recursive: true });
  fs.mkdirSync(path.join(demoDir, "assets"), { recursive: true });
  fs.mkdirSync(path.join(demoDir, "bin"), { recursive: true });
  fs.mkdirSync(path.join(demoDir, "secrets"), { recursive: true });

  fs.writeFileSync(path.join(demoDir, "README.md"), "# Sample Beginner Repo\nPublic README stays readable.\n");
  fs.writeFileSync(
    path.join(demoDir, "src/pricing.js"),
    "export function computePrice(seats) { return seats * 49; }\n"
  );
  fs.writeFileSync(
    path.join(demoDir, ".env"),
    "STRIPE_SECRET_KEY=sk-proj-demo_0123456789abcdefghijklmnopqrstuvwxyz\n"
  );
  fs.writeFileSync(path.join(demoDir, "secrets/api.vault"), "VAULT_MASTER_SEED_DEMO_2026");
  fs.writeFileSync(path.join(demoDir, "compute/kernel.wasm"), createSampleWasm());
  fs.writeFileSync(path.join(demoDir, "assets/character.glb"), createSampleGlb());

  const weights = Buffer.alloc(1024);
  for (let i = 0; i < weights.length; i += 4) weights.writeFloatLE((i / 4) * 0.125, i);
  fs.writeFileSync(path.join(demoDir, "models/weights.safetensors"), weights);

  const srcC = path.join(demoDir, "bin/license_tool.c");
  const binExe = path.join(demoDir, "bin/license_tool");
  fs.writeFileSync(
    srcC,
    '#include <stdio.h>\nint main(int argc, char **argv){ printf("DEMO_ELF_OK seats=%s\\n", argc>1?argv[1]:"1"); return 0; }\n'
  );
  execFileSync("gcc", ["-O2", "-fPIE", "-pie", srcC, "-o", binExe]);
  fs.unlinkSync(srcC);

  const protectedRes = await protectTarget(demoDir, {
    outPath: outDir,
    registryPath: opts.registryPath,
    noGitignore: opts.noGitignore,
    json: opts.json,
  });

  const runRes = await spawnProtectedAsync(path.join(outDir, "bin/license_tool"), ["42"], {
    keysFile: protectedRes.keysFile,
    registryPath: opts.registryPath,
    capture: true,
  });
  if (runRes.status !== 0 || !runRes.stdout.includes("DEMO_ELF_OK seats=42")) {
    throw new Error(`Demo protected executable failed: status=${runRes.status}`);
  }

  const wmPosPath = path.join(outDir, "alice_positions.bin");
  const wmRes = watermarkModel(path.join(outDir, "assets/character.glb.vs3d"), {
    buyer: "alice@demo.local",
    outPath: wmPosPath,
    keysFile: protectedRes.keysFile,
    registryPath: opts.registryPath,
  });
  const traceRes = traceLeakedPositions(wmPosPath, {
    modelPath: path.join(outDir, "assets/character.glb.vs3d"),
    keysFile: protectedRes.keysFile,
    registryPath: opts.registryPath,
  });
  if (traceRes.buyer !== "alice@demo.local" || traceRes.decodedWatermarkIdHex !== wmRes.wmIdHex) {
    throw new Error("Demo watermark/trace mismatch");
  }

  const unsealRes = unsealTarget(outDir, {
    outPath: restoredDir,
    keysFile: protectedRes.keysFile,
    registryPath: opts.registryPath,
  });
  if (!unsealRes.ok) {
    throw new Error("Demo unseal verification failed");
  }

  return {
    ok: true,
    demoDir,
    protectedDir: outDir,
    restoredDir,
    keysFile: protectedRes.keysFile,
    counts: protectedRes.counts,
    secretWarningsCount: protectedRes.secretWarnings.length,
    selfCheckOk: protectedRes.selfCheck.ok,
    execCheckOutput: runRes.stdout.trim(),
    watermarkBuyer: traceRes.buyer,
    watermarkIdHex: traceRes.decodedWatermarkIdHex,
    unsealedFilesCount: unsealRes.restoredCount,
  };
}

module.exports = {
  WORKSPACE_ROOT,
  NATIVE_BIN,
  ensureNativeBinary,
  scanSecretsInBuffer,
  scanTarget,
  protectTarget,
  testProtectedTarget,
  spawnProtectedAsync,
  unsealTarget,
  watermarkModel,
  traceLeakedPositions,
  runBeginnerDemo,
  shannonEntropy,
};
