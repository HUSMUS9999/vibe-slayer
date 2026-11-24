#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  deriveAssetKey32,
  packVspk,
  parseVspkHeader,
  unpackVspk,
} = require("../src/core/authority.js");
const auto = require("../src/auto.js");

const KNOWN_COMMANDS = new Set([
  "init-keys",
  "pack",
  "verify",
  "protect",
  "auto",
  "scan",
  "test",
  "verify-auto",
  "run",
  "unseal",
  "watermark",
  "trace",
  "demo",
  "help",
  "--help",
  "-h",
]);

function argVal(args, flag, fallback = undefined) {
  const idx = args.indexOf(flag);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : fallback;
}

function parseAutoFlags(args) {
  const opts = {
    outPath: undefined,
    keysFile: undefined,
    registryPath: undefined,
    context: undefined,
    buyer: undefined,
    wmIdHex: undefined,
    modelPath: undefined,
    dirPath: undefined,
    standalone: false,
    sealAll: false,
    forceVault: false,
    noGitignore: false,
    json: false,
  };
  const positionals = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if ((a === "-o" || a === "--out") && i + 1 < args.length) {
      opts.outPath = args[++i];
    } else if (a === "--keys" && i + 1 < args.length) {
      opts.keysFile = args[++i];
    } else if (a === "--registry" && i + 1 < args.length) {
      opts.registryPath = args[++i];
    } else if (a === "--context" && i + 1 < args.length) {
      opts.context = args[++i];
    } else if (a === "--buyer" && i + 1 < args.length) {
      opts.buyer = args[++i];
    } else if (a === "--id" && i + 1 < args.length) {
      opts.wmIdHex = args[++i];
    } else if (a === "--model" && i + 1 < args.length) {
      opts.modelPath = args[++i];
    } else if (a === "--dir" && i + 1 < args.length) {
      opts.dirPath = args[++i];
    } else if (a === "--standalone") {
      opts.standalone = true;
    } else if (a === "--seal-all") {
      opts.sealAll = true;
    } else if (a === "--vault") {
      opts.forceVault = true;
    } else if (a === "--no-gitignore") {
      opts.noGitignore = true;
    } else if (a === "--json") {
      opts.json = true;
    } else {
      positionals.push(a);
    }
  }
  return { opts, positionals };
}

function parseRunArgs(args) {
  const opts = { keysFile: undefined, registryPath: undefined };
  const dashIdx = args.indexOf("--");
  const head = dashIdx >= 0 ? args.slice(0, dashIdx) : args;
  const tail = dashIdx >= 0 ? args.slice(dashIdx + 1) : [];

  let targetPath = null;
  const headPass = [];
  for (let i = 0; i < head.length; i++) {
    const a = head[i];
    if (a === "--keys" && i + 1 < head.length) {
      opts.keysFile = head[++i];
    } else if (a === "--registry" && i + 1 < head.length) {
      opts.registryPath = head[++i];
    } else if (!targetPath) {
      targetPath = a;
    } else {
      headPass.push(a);
    }
  }
  return { targetPath, passArgs: [...headPass, ...tail], opts };
}

function printHelp() {
  console.log(`vibeslayer-suite CLI (v0.8.0-beta.2)

Protect a file or an entire repo in one command:
  vs <file-or-folder> [-o <output>] [--standalone] [--seal-all] [--vault]

Everyday commands:
  vs demo                       Build, protect, test, run, watermark, and unseal a sample repo
  vs scan <dir>                 Dry-run audit: see file classifications & secret warnings
  vs <dir>                      Protect repo into <dir>-protected + auto-verify every output
  vs <file>                     Auto-protect file (.protected, .vspk3, .vs3d, or .vault.elf)
  vs test <protected>           Verify encryption, tamper rejection, ptrace rejection & CET
  vs run <protected-bin> [-- args...]   Run a protected executable safely (FD 3 lease key)
  vs unseal <protected> [-o <dest>]     Restore original files and check every SHA-256
  vs watermark <file.vs3d> --buyer "alice@co" [-o pos.bin]
  vs trace <pos.bin> [--model <file.vs3d>]

Common options:
  --standalone       Allow wrapped executables to run without .vibeslayer/keys.json
  --seal-all         In repo mode, encrypt public files (README, CSS, etc.) too
  --vault            Force small secrets (<=4096B) into memfd_secret ELF vault
  --keys <file>      Use a custom keys.json instead of auto .vibeslayer/keys.json
  --json             Machine-readable JSON output`);
}

function printWarnings(warnings) {
  if (!warnings || warnings.length === 0) return;
  console.log(`\n[!] Secret Scanner Warnings (${warnings.length} found — sealed in protected output):`);
  for (const w of warnings.slice(0, 15)) {
    console.log(`    - ${w.relPath}:${w.line} [${w.kind}] ${w.preview}`);
  }
  if (warnings.length > 15) {
    console.log(`    ... and ${warnings.length - 15} more`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    printHelp();
    return;
  }

  const first = args[0];
  if (first === "help" || first === "--help" || first === "-h") {
    printHelp();
    return;
  }

  // Backward-compatible legacy commands used by manual keyfile workflows & tests
  if (first === "init-keys") {
    const outDir = argVal(args, "--out", process.cwd());
    fs.mkdirSync(outDir, { recursive: true });
    const kp = crypto.generateKeyPairSync("ed25519");
    const keyFile = path.join(outDir, "vibeslayer.keys.json");
    fs.writeFileSync(
      keyFile,
      JSON.stringify(
        {
          version: "0.8.0-beta.2",
          masterKeyHex: crypto.randomBytes(32).toString("hex"),
          signingPrivateKeyPem: kp.privateKey.export({ type: "pkcs8", format: "pem" }),
          signingPublicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }),
        },
        null,
        2
      ),
      { mode: 0o600 }
    );
    console.log(JSON.stringify({ ok: true, keyFile }));
    return;
  }

  if (first === "pack" && argVal(args, "--keyfile")) {
    const keys = JSON.parse(fs.readFileSync(argVal(args, "--keyfile"), "utf8"));
    const inPath = argVal(args, "--in");
    const outPath = argVal(args, "--out");
    const domain = argVal(args, "--domain", "web");
    const assetId = argVal(args, "--asset-id");
    const origin = argVal(args, "--origin", "");
    const plain = fs.readFileSync(inPath);
    const key32 = deriveAssetKey32(Buffer.from(keys.masterKeyHex, "hex"), domain, assetId, origin);
    const vspk = packVspk({ key32, domain, assetId, origin, cipher: "aes-256-gcm", plainBytes: plain });
    key32.fill(0);
    fs.writeFileSync(outPath, vspk);
    console.log(
      JSON.stringify({
        ok: true,
        domain,
        assetId,
        inputBytes: plain.length,
        outputBytes: vspk.length,
        sha256: crypto.createHash("sha256").update(vspk).digest("hex"),
      })
    );
    return;
  }

  if (first === "verify" && argVal(args, "--keyfile")) {
    const keys = JSON.parse(fs.readFileSync(argVal(args, "--keyfile"), "utf8"));
    const inPath = argVal(args, "--in");
    const domain = argVal(args, "--domain", "web");
    const assetId = argVal(args, "--asset-id");
    const origin = argVal(args, "--origin", "");
    const vspk = fs.readFileSync(inPath);
    const hdr = parseVspkHeader(vspk);
    const key32 = deriveAssetKey32(Buffer.from(keys.masterKeyHex, "hex"), domain, assetId, origin);
    const plain = unpackVspk({ vspkBytes: vspk, key32, expectedDomain: domain, expectedOrigin: origin });
    key32.fill(0);
    const plainSha256 = crypto.createHash("sha256").update(plain).digest("hex");
    plain.fill(0);
    console.log(
      JSON.stringify({
        ok: true,
        aeadVerified: true,
        header: hdr.header,
        decryptedBytes: vspk.length,
        plainSha256,
      })
    );
    return;
  }

  const isExplicitCmd = KNOWN_COMMANDS.has(first);
  const cmd = isExplicitCmd ? first : "protect";
  const rest = isExplicitCmd ? args.slice(1) : args;

  if (cmd === "run") {
    const { targetPath, passArgs, opts } = parseRunArgs(rest);
    if (!targetPath) {
      throw new Error("Usage: ./protect run <protected-executable> [-- args...]");
    }
    const res = await auto.spawnProtectedAsync(targetPath, passArgs, opts);
    process.exitCode = res.status;
    return;
  }

  const { opts, positionals } = parseAutoFlags(rest);
  const target = positionals[0];

  if (cmd === "protect" || cmd === "auto") {
    if (!target) {
      throw new Error("Usage: ./protect <file-or-dir> [-o <output>] [--standalone] [--seal-all]");
    }
    const res = await auto.protectTarget(target, opts);
    if (opts.json) {
      console.log(JSON.stringify(res, null, 2));
      return;
    }
    if (res.mode === "file") {
      console.log(`[+] Protected (${res.engine}, ${res.domain}): ${res.outputPath}`);
      if (res.companionVs3dPath) {
        console.log(`[+] Watermarkable 3D stream: ${res.companionVs3dPath}`);
      }
      console.log(`[+] Keys saved (0600, gitignored): ${res.keysFile}`);
      console.log(`[+] Self-test verified: PASS (entropy ${res.selfCheck.checks.entropyBitsPerByte} bits/B)`);
      printWarnings(res.secretWarnings);
      console.log("\nNext commands you can run:");
      console.log(`  ./protect test ${JSON.stringify(res.outputPath)}`);
      if (res.engine === "wrap-elf" || res.engine === "freestanding-vault") {
        console.log(`  ./protect run ${JSON.stringify(res.outputPath)}`);
      } else {
        console.log(`  ./protect unseal ${JSON.stringify(res.outputPath)}`);
      }
      if (res.companionVs3dPath) {
        console.log(`  ./protect watermark ${JSON.stringify(res.companionVs3dPath)} --buyer "alice"`);
      }
    } else {
      console.log(`[+] Protected repo (${res.counts.total} files): ${res.outputDir}`);
      console.log(
        `    Engines: vspk3=${res.counts.vspk3}, wrap-elf=${res.counts.wrapElf}, vault-elf=${res.counts.freestandingVault}, vs3d=${res.counts.vs3d}, public=${res.counts.publicCopied}`
      );
      console.log(`[+] Manifest (no secrets): ${res.manifestPath}`);
      console.log(`[+] Keys saved (0600, gitignored): ${res.keysFile}`);
      console.log(`[+] Auto-verification across ${res.selfCheck.testedCount} outputs: PASS`);
      printWarnings(res.secretWarnings);
      console.log("\nNext commands you can run:");
      console.log(`  ./protect test ${JSON.stringify(res.outputDir)}`);
      console.log(`  ./protect unseal ${JSON.stringify(res.outputDir)}`);
    }
    return;
  }

  if (cmd === "scan") {
    if (!target) throw new Error("Usage: ./protect scan <file-or-dir>");
    const res = auto.scanTarget(target, opts);
    if (opts.json) {
      console.log(JSON.stringify(res, null, 2));
      return;
    }
    console.log(`[+] Scan (${res.mode}): ${res.inputPath} (${res.fileCount} files)`);
    for (const item of res.items.slice(0, 25)) {
      console.log(`    - ${item.relPath} (${item.inputBytes} B) -> ${item.engine} [${item.domain}]`);
    }
    if (res.items.length > 25) console.log(`    ... and ${res.items.length - 25} more`);
    printWarnings(res.secretWarnings);
    return;
  }

  if (cmd === "test" || cmd === "verify-auto") {
    if (!target) throw new Error("Usage: ./protect test <protected-file-or-dir>");
    const res = await auto.testProtectedTarget(target, opts);
    if (opts.json) {
      console.log(JSON.stringify(res, null, 2));
    } else if (res.mode === "file") {
      console.log(`[${res.ok ? "PASS" : "FAIL"}] ${res.targetPath} (${res.type})`);
      for (const [k, v] of Object.entries(res.checks || {})) {
        console.log(`    - ${k}: ${v}`);
      }
    } else {
      console.log(`[${res.ok ? "PASS" : "FAIL"}] ${res.targetPath} (${res.testedCount} files verified)`);
      for (const f of res.files) {
        console.log(`    - ${f.ok ? "PASS" : "FAIL"} ${f.relPath} (${f.type})`);
      }
    }
    if (!res.ok) process.exitCode = 1;
    return;
  }

  if (cmd === "unseal") {
    if (!target) throw new Error("Usage: ./protect unseal <protected-file-or-dir> [-o <dest>]");
    const res = auto.unsealTarget(target, opts);
    if (opts.json) {
      console.log(JSON.stringify(res, null, 2));
      return;
    }
    if (res.mode === "file") {
      console.log(`[+] Unsealed & SHA-256 verified: ${res.outputPath}`);
    } else {
      console.log(`[+] Unsealed ${res.restoredCount} files into: ${res.outputDir}`);
      if (res.skippedExecutables.length > 0) {
        console.log(`    Note: ${res.skippedExecutables.length} hardened executable(s) kept protected (use './protect run <file>')`);
      }
    }
    return;
  }

  if (cmd === "watermark") {
    if (!target) throw new Error("Usage: ./protect watermark <model.vs3d> [--buyer <name> | --id <16hex>]");
    const res = auto.watermarkModel(target, opts);
    if (opts.json) {
      console.log(JSON.stringify(res, null, 2));
      return;
    }
    console.log(`[+] Embedded 64-bit WM64 watermark (${res.wmIdHex}${res.buyer ? ` / buyer=${res.buyer}` : ""})`);
    console.log(`[+] Output positions: ${res.outPositions}`);
    console.log(`    Test trace: ./protect trace ${JSON.stringify(res.outPositions)}`);
    return;
  }

  if (cmd === "trace") {
    if (!target) throw new Error("Usage: ./protect trace <positions.bin> [--model <file.vs3d>]");
    const res = auto.traceLeakedPositions(target, opts);
    if (opts.json) {
      console.log(JSON.stringify(res, null, 2));
      return;
    }
    console.log(`[+] Traced WM64 ID: ${res.decodedWatermarkIdHex}${res.buyer ? ` (buyer: ${res.buyer})` : ""}`);
    console.log(`    Mean chip confidence: ${res.meanChipConfidence}`);
    return;
  }

  if (cmd === "demo") {
    const res = await auto.runBeginnerDemo(opts);
    if (opts.json) {
      console.log(JSON.stringify(res, null, 2));
      return;
    }
    console.log(`[+] Sample beginner repo created:   ${res.demoDir}`);
    console.log(`[+] Protected repo output:          ${res.protectedDir}`);
    console.log(`[+] Restored (unsealed) repo copy:  ${res.restoredDir}`);
    console.log(`[+] Keys saved (0600, gitignored):  ${res.keysFile}`);
    console.log(
      `[+] Verified end-to-end: test=PASS, exec=${JSON.stringify(res.execCheckOutput)}, watermark=${res.watermarkBuyer} (${res.watermarkIdHex}), unsealed=${res.unsealedFilesCount} files`
    );
    console.log("\nTry inspecting the protected files yourself:");
    console.log(`  ./protect test ${JSON.stringify(res.protectedDir)}`);
    console.log(`  ./protect run ${JSON.stringify(path.join(res.protectedDir, "bin/license_tool"))} 99`);
    return;
  }

  console.error(`Unknown command: ${first}`);
  printHelp();
  process.exitCode = 1;
}

main().catch((err) => {
  console.error(`[error] ${err && err.message ? err.message : String(err)}`);
  process.exitCode = 1;
});
