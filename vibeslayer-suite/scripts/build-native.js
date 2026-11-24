"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const SRC = path.join(ROOT, "native_src");
const OUT = path.join(ROOT, "dist_bin");

function buildNativeArtifacts() {
  fs.mkdirSync(OUT, { recursive: true });

  const soPath = path.join(OUT, "libvsmobile.so");
  const mobileRunnerPath = path.join(OUT, "vs_mobile_runner");
  const enclaveElfPath = path.join(OUT, "vs_desktop_enclave");
  const enclaveWinPath = path.join(OUT, "vs_desktop_enclave_win64.exe");

  execFileSync("gcc", [
    "-O3", "-fPIC", "-shared", "-fvisibility=hidden",
    "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-fcf-protection=full",
    "-Wl,-z,relro,-z,now,-z,ibt,-z,shstk",
    "-Wall", "-Wextra",
    path.join(SRC, "vs_mobile_jni.c"),
    "-o", soPath,
  ], { stdio: "inherit" });
  execFileSync("strip", ["--strip-unneeded", soPath], { stdio: "inherit" });

  execFileSync("gcc", [
    "-O3", "-fPIE", "-pie",
    "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-fcf-protection=full",
    "-Wl,-z,relro,-z,now,-z,ibt,-z,shstk",
    "-Wall", "-Wextra",
    path.join(SRC, "vs_mobile_runner.c"),
    "-ldl",
    "-o", mobileRunnerPath,
  ], { stdio: "inherit" });
  execFileSync("strip", ["-s", mobileRunnerPath], { stdio: "inherit" });

  execFileSync("gcc", [
    "-O3", "-s", "-fPIE", "-pie",
    "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-fcf-protection=full",
    "-Wl,-z,relro,-z,now,-z,ibt,-z,shstk",
    "-Wall", "-Wextra",
    path.join(SRC, "vs_desktop_enclave.c"),
    "-o", enclaveElfPath,
  ], { stdio: "inherit" });
  execFileSync("strip", ["-s", enclaveElfPath], { stdio: "inherit" });

  try {
    execFileSync("x86_64-w64-mingw32-gcc", [
      "-O3", "-s", "-Wall", "-Wextra",
      path.join(SRC, "vs_desktop_enclave.c"),
      "-o", enclaveWinPath,
    ], { stdio: "inherit" });
  } catch {
    // Optional cross-compiler
  }

  return {
    soPath,
    mobileRunnerPath,
    enclaveElfPath,
    enclaveWinExists: fs.existsSync(enclaveWinPath),
    enclaveWinPath,
  };
}

if (require.main === module) {
  console.log(JSON.stringify(buildNativeArtifacts(), null, 2));
}

module.exports = { buildNativeArtifacts };
