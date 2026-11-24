use std::env;
use std::fs;
use std::path::PathBuf;
use vibeslayer_core::{
    auto_cli, build_protected_elf, build_protected_elf_elite, build_protected_elf_freestanding,
    cook_glb_vspk2, decode_wm64_o1, embed_wm64_for_lease, hex_decode, hex_encode, pack_vspk2,
    pack_vspk3, secure_zero, sha256, trace_glb_watermark, unseal_glb_for_lease, unseal_vspk2,
    unseal_vspk2_for_asset, unseal_vspk3_owned, wrap_elf_freestanding, VERSION,
};

fn arg_val(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|x| x == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn parse_typed_arg<T: std::str::FromStr>(args: &[String], flag: &str) -> Result<Option<T>, String> {
    match arg_val(args, flag) {
        Some(v) => v
            .parse::<T>()
            .map(Some)
            .map_err(|_| format!("Invalid {flag} '{v}': failed to parse number")),
        None => Ok(None),
    }
}

fn req_arg(args: &[String], flag: &str) -> Result<String, String> {
    arg_val(args, flag).ok_or_else(|| format!("Missing required argument {flag}"))
}

fn parse_key32(hex: &str) -> Result<[u8; 32], String> {
    let mut v = hex_decode(hex).map_err(|e| format!("Invalid --key hex: {e}"))?;
    if v.len() != 32 {
        secure_zero(&mut v);
        return Err("--key must be 32 bytes (64 hex chars)".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    secure_zero(&mut v);
    Ok(out)
}

fn default_suite_native_path(rel: &str) -> Result<PathBuf, String> {
    if let Some(ws) = auto_cli::detect_workspace_root() {
        let candidate = ws.join(rel);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    let exe_dir = env::current_exe().map_err(|e| format!("current_exe failed: {e}"))?;
    let mut cur = exe_dir.parent();
    while let Some(dir) = cur {
        let candidate = dir.join(rel);
        if candidate.exists() {
            return Ok(candidate);
        }
        cur = dir.parent();
    }
    let root = exe_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| "Unable to locate workspace root from executable path".to_string())?;
    Ok(root.join(rel))
}

fn to_i16_le(bytes: &[u8]) -> Result<Vec<i16>, String> {
    if bytes.len() % 2 != 0 {
        return Err("Coordinate stream byte length must be a multiple of 2".to_string());
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect())
}

fn run(args: &[String]) -> Result<i32, (i32, String)> {
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");

    if matches!(cmd, "ask" | "do" | "nl" | "explain") {
        let force_dry = cmd == "explain";
        let (sentence, dry_run, as_json) =
            vibeslayer_core::nl_cli::parse_nl_cli_args(&args[2..], force_dry);
        let plan = vibeslayer_core::nl_cli::compile_natural_language(&sentence)
            .map_err(|e| (1, e))?;
        if dry_run {
            if as_json {
                println!("{}", vibeslayer_core::nl_cli::format_plan_json(&plan, true));
            } else {
                vibeslayer_core::nl_cli::print_plan_human(&plan, true);
            }
            return Ok(0);
        }
        if !as_json {
            vibeslayer_core::nl_cli::print_plan_human(&plan, false);
        }
        let mut synthetic = Vec::with_capacity(plan.argv.len() + 2);
        synthetic.push(
            args.first()
                .cloned()
                .unwrap_or_else(|| "vibe-slayer".to_string()),
        );
        synthetic.extend(plan.argv.iter().cloned());
        if as_json && !synthetic.iter().any(|x| x == "--json") {
            synthetic.push("--json".to_string());
        }
        return run(&synthetic);
    }

    if matches!(
        cmd,
        "protect"
            | "auto"
            | "scan"
            | "test"
            | "verify-auto"
            | "run"
            | "watermark"
            | "trace"
            | "demo"
            | "website"
            | "serve"
            | "help"
            | "--help"
            | "-h"
    ) {
        return auto_cli::run_beginner_subcommand(cmd, &args[2..]);
    }
    if cmd == "unseal" && !args.iter().any(|a| a == "--key" || a == "--in") {
        return auto_cli::run_beginner_subcommand("unseal", &args[2..]);
    }

    match cmd {
        "version" => {
            println!("{{\"version\":\"{}\"}}", VERSION);
            Ok(0)
        }
        "pack" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let domain = arg_val(args, "--domain").unwrap_or_else(|| "default".to_string());
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let context = arg_val(args, "--context").unwrap_or_default();
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let out_path = req_arg(args, "--out").map_err(|e| (1, e))?;

            let mut plain = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --in: {e}"))
            })?;
            let vspk = pack_vspk2(&key, &domain, &asset_id, &context, &plain);
            secure_zero(&mut key);
            secure_zero(&mut plain);
            let vspk = vspk.map_err(|e| (1, format!("pack failed: {e}")))?;
            fs::write(&out_path, &vspk).map_err(|e| (1, format!("Failed writing --out: {e}")))?;
            println!(
                "{{\"ok\":true,\"inputBytes\":{},\"outputBytes\":{},\"sha256\":\"{}\"}}",
                plain.len(),
                vspk.len(),
                hex_encode(&sha256(&vspk))
            );
            Ok(0)
        }
        "unseal" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let domain = arg_val(args, "--domain").unwrap_or_else(|| "default".to_string());
            let asset_id = arg_val(args, "--asset-id");
            let context = arg_val(args, "--context").unwrap_or_default();
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let out_path = req_arg(args, "--out").map_err(|e| (1, e))?;

            let vspk = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --in: {e}"))
            })?;
            let res = match asset_id.as_deref() {
                Some(aid) => unseal_vspk2_for_asset(&key, &domain, aid, &context, &vspk),
                None => unseal_vspk2(&key, &domain, &context, &vspk),
            };
            secure_zero(&mut key);
            let mut plain = res.map_err(|e| (3, format!("unseal failed: {e}")))?;
            let plain_len = plain.len();
            let wr = fs::write(&out_path, &plain);
            secure_zero(&mut plain);
            wr.map_err(|e| (1, format!("Failed writing --out: {e}")))?;
            println!("{{\"ok\":true,\"plainBytes\":{}}}", plain_len);
            Ok(0)
        }
        "pack-v3" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let domain = arg_val(args, "--domain").unwrap_or_else(|| "default".to_string());
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let context = arg_val(args, "--context").unwrap_or_default();
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let out_path = req_arg(args, "--out").map_err(|e| (1, e))?;

            let mut plain = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --in: {e}"))
            })?;
            let plain_len = plain.len();
            let res = pack_vspk3(&key, &domain, &asset_id, &context, &plain);
            secure_zero(&mut key);
            secure_zero(&mut plain);
            let vspk = res.map_err(|e| (1, format!("pack-v3 failed: {e}")))?;
            fs::write(&out_path, &vspk).map_err(|e| (1, format!("Failed writing --out: {e}")))?;
            println!(
                "{{\"ok\":true,\"inputBytes\":{},\"outputBytes\":{},\"sha256\":\"{}\"}}",
                plain_len,
                vspk.len(),
                hex_encode(&sha256(&vspk))
            );
            Ok(0)
        }
        "unseal-v3" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let domain = arg_val(args, "--domain").unwrap_or_else(|| "default".to_string());
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let context = arg_val(args, "--context").unwrap_or_default();
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let out_path = req_arg(args, "--out").map_err(|e| (1, e))?;

            let vspk = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --in: {e}"))
            })?;
            let res = unseal_vspk3_owned(&key, &domain, &asset_id, &context, vspk);
            secure_zero(&mut key);
            let mut plain = res.map_err(|e| (3, format!("unseal-v3 failed: {e}")))?;
            let plain_len = plain.len();
            let wr = fs::write(&out_path, &plain);
            secure_zero(&mut plain);
            wr.map_err(|e| (1, format!("Failed writing --out: {e}")))?;
            println!("{{\"ok\":true,\"plainBytes\":{}}}", plain_len);
            Ok(0)
        }
        "cook-glb" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let context = arg_val(args, "--context").unwrap_or_default();
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let out_path = req_arg(args, "--out").map_err(|e| (1, e))?;
            let ref_path = req_arg(args, "--owner-ref").map_err(|e| (1, e))?;

            let glb = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading GLB: {e}"))
            })?;
            let res = cook_glb_vspk2(&key, &asset_id, &context, &glb);
            secure_zero(&mut key);
            let (sealed, owner_ref) = res.map_err(|e| (1, format!("cook-glb failed: {e}")))?;
            fs::write(&out_path, &sealed).map_err(|e| (1, format!("Failed writing sealed GLB: {e}")))?;
            let mut ref_bytes = Vec::with_capacity(owner_ref.len() * 2);
            for v in &owner_ref {
                ref_bytes.extend_from_slice(&v.to_le_bytes());
            }
            fs::write(&ref_path, &ref_bytes)
                .map_err(|e| (1, format!("Failed writing --owner-ref: {e}")))?;
            println!(
                "{{\"ok\":true,\"sealedBytes\":{},\"coords\":{}}}",
                sealed.len(),
                owner_ref.len()
            );
            Ok(0)
        }
        "unseal-glb-lease" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let context = arg_val(args, "--context").unwrap_or_default();
            let lease_id = req_arg(args, "--lease-id").map_err(|e| (1, e))?;
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let out_pos = req_arg(args, "--out-positions").map_err(|e| (1, e))?;

            let vspk = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --in: {e}"))
            })?;
            let res = unseal_glb_for_lease(&key, &asset_id, &context, &lease_id, &vspk);
            secure_zero(&mut key);
            let positions = res.map_err(|e| (1, format!("unseal-glb failed: {e}")))?;
            let mut out = Vec::with_capacity(positions.len() * 2);
            for v in &positions {
                out.extend_from_slice(&v.to_le_bytes());
            }
            fs::write(&out_pos, &out)
                .map_err(|e| (1, format!("Failed writing --out-positions: {e}")))?;
            println!("{{\"ok\":true,\"coords\":{}}}", positions.len());
            Ok(0)
        }
        "trace-glb" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let ref_path = req_arg(args, "--owner-ref").map_err(|e| (1, e))?;
            let cap_path = req_arg(args, "--captured").map_err(|e| (1, e))?;
            let cands_raw = req_arg(args, "--candidates").map_err(|e| (1, e))?;

            let ref_bytes = fs::read(&ref_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --owner-ref: {e}"))
            })?;
            let cap_bytes = fs::read(&cap_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --captured: {e}"))
            })?;
            let owner_ref = to_i16_le(&ref_bytes).map_err(|e| {
                secure_zero(&mut key);
                (1, e)
            })?;
            let captured = to_i16_le(&cap_bytes).map_err(|e| {
                secure_zero(&mut key);
                (1, e)
            })?;
            let candidates: Vec<String> = cands_raw.split(',').map(|s| s.to_string()).collect();
            let res = trace_glb_watermark(&key, &asset_id, &owner_ref, &captured, &candidates);
            secure_zero(&mut key);
            let (matched, ratio) = res.ok_or_else(|| (1, "No matching candidate".to_string()))?;
            println!(
                "{{\"ok\":true,\"matchedLeaseId\":\"{}\",\"chipMatchRatio\":{:.6}}}",
                matched, ratio
            );
            Ok(0)
        }
        "build-elf" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let out_path = PathBuf::from(req_arg(args, "--out").map_err(|e| (1, e))?);
            let template_c = match arg_val(args, "--template") {
                Some(p) => PathBuf::from(p),
                None => default_suite_native_path("vibeslayer-suite/native_src/vs_native_template.c")
                    .map_err(|e| {
                        secure_zero(&mut key);
                        (1, e)
                    })?,
            };
            let mut plain = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --in: {e}"))
            })?;
            let res = build_protected_elf(&key, &template_c, &asset_id, &plain, &out_path);
            secure_zero(&mut key);
            secure_zero(&mut plain);
            let (lease_hex, rx_hex) = res.map_err(|e| (1, format!("build-elf failed: {e}")))?;
            println!(
                "{{\"ok\":true,\"leaseKeyHex\":\"{}\",\"rxSha256Hex\":\"{}\"}}",
                lease_hex, rx_hex
            );
            Ok(0)
        }
        "build-elf-elite" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let out_path = PathBuf::from(req_arg(args, "--out").map_err(|e| (1, e))?);
            let crypto_hdr = match arg_val(args, "--crypto-header") {
                Some(p) => PathBuf::from(p),
                None => default_suite_native_path("vibeslayer-suite/native_src/vs_crypto_core.h")
                    .map_err(|e| {
                        secure_zero(&mut key);
                        (1, e)
                    })?,
            };
            let mut plain = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --in: {e}"))
            })?;
            let res = build_protected_elf_elite(&key, &crypto_hdr, &asset_id, &plain, &out_path);
            secure_zero(&mut key);
            secure_zero(&mut plain);
            let (lease_hex, rx_hex) =
                res.map_err(|e| (1, format!("build-elf-elite failed: {e}")))?;
            println!(
                "{{\"ok\":true,\"leaseKeyHex\":\"{}\",\"rxSha256Hex\":\"{}\"}}",
                lease_hex, rx_hex
            );
            Ok(0)
        }
        "build-elf-freestanding" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let out_path = PathBuf::from(req_arg(args, "--out").map_err(|e| (1, e))?);
            let crypto_hdr = match arg_val(args, "--crypto-header") {
                Some(p) => PathBuf::from(p),
                None => default_suite_native_path("vibeslayer-suite/native_src/vs_crypto_core.h")
                    .unwrap_or_else(|_| PathBuf::new()),
            };
            let mut plain = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --in: {e}"))
            })?;
            let res =
                build_protected_elf_freestanding(&key, &crypto_hdr, &asset_id, &plain, &out_path);
            secure_zero(&mut key);
            secure_zero(&mut plain);
            let (lease_hex, rx_hex) =
                res.map_err(|e| (1, format!("build-elf-freestanding failed: {e}")))?;
            println!(
                "{{\"ok\":true,\"leaseKeyHex\":\"{}\",\"rxSha256Hex\":\"{}\"}}",
                lease_hex, rx_hex
            );
            Ok(0)
        }
        "wrap-elf" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let out_path = PathBuf::from(req_arg(args, "--out").map_err(|e| (1, e))?);
            let standalone = args.iter().any(|x| x == "--standalone");
            let crypto_hdr = match arg_val(args, "--crypto-header") {
                Some(p) => PathBuf::from(p),
                None => default_suite_native_path("vibeslayer-suite/native_src/vs_crypto_core.h")
                    .unwrap_or_else(|_| PathBuf::new()),
            };
            let mut plain = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --in: {e}"))
            })?;
            let res = wrap_elf_freestanding(
                &key,
                &crypto_hdr,
                &asset_id,
                &plain,
                standalone,
                &out_path,
            );
            secure_zero(&mut key);
            secure_zero(&mut plain);
            let (lease_hex, rx_hex) = res.map_err(|e| (1, format!("wrap-elf failed: {e}")))?;
            println!(
                "{{\"ok\":true,\"standalone\":{},\"leaseKeyHex\":\"{}\",\"rxSha256Hex\":\"{}\"}}",
                if standalone { "true" } else { "false" },
                lease_hex,
                rx_hex
            );
            Ok(0)
        }
        "embed-wm64" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let context = arg_val(args, "--context").unwrap_or_default();
            let wm_hex = req_arg(args, "--wm-id-hex").map_err(|e| (1, e))?;
            let wm_bytes = hex_decode(&wm_hex).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Invalid --wm-id-hex: {e}"))
            })?;
            let wm_arr: [u8; 8] = wm_bytes.try_into().map_err(|_| {
                secure_zero(&mut key);
                (1, "--wm-id-hex must be 16 hex chars (8 bytes)".to_string())
            })?;
            let wm_u64 = u64::from_be_bytes(wm_arr);
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let out_pos = req_arg(args, "--out-positions").map_err(|e| (1, e))?;

            let vspk = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --in: {e}"))
            })?;
            let res = embed_wm64_for_lease(&key, &asset_id, &context, wm_u64, &vspk);
            secure_zero(&mut key);
            let positions = res.map_err(|e| (1, format!("embed-wm64 failed: {e}")))?;
            let mut out = Vec::with_capacity(positions.len() * 2);
            for v in &positions {
                out.extend_from_slice(&v.to_le_bytes());
            }
            fs::write(&out_pos, &out)
                .map_err(|e| (1, format!("Failed writing --out-positions: {e}")))?;
            println!("{{\"ok\":true,\"coords\":{}}}", positions.len());
            Ok(0)
        }
        "decode-wm64" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let asset_id = req_arg(args, "--asset-id").map_err(|e| (1, e))?;
            let ref_path = req_arg(args, "--owner-ref").map_err(|e| (1, e))?;
            let cap_path = req_arg(args, "--captured").map_err(|e| (1, e))?;

            let ref_bytes = fs::read(&ref_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --owner-ref: {e}"))
            })?;
            let cap_bytes = fs::read(&cap_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading --captured: {e}"))
            })?;
            let owner_ref = to_i16_le(&ref_bytes).map_err(|e| {
                secure_zero(&mut key);
                (1, e)
            })?;
            let captured = to_i16_le(&cap_bytes).map_err(|e| {
                secure_zero(&mut key);
                (1, e)
            })?;
            let res = decode_wm64_o1(&key, &asset_id, &owner_ref, &captured);
            secure_zero(&mut key);
            let (wm_u64, conf) = res.map_err(|e| (1, format!("decode-wm64 failed: {e}")))?;
            println!(
                "{{\"ok\":true,\"decodedWatermarkIdHex\":\"{:016x}\",\"meanChipConfidence\":{:.6}}}",
                wm_u64, conf
            );
            Ok(0)
        }
        "homo-keygen" => {
            let sk_path = req_arg(args, "--sk").map_err(|e| (1, e))?;
            let pk_path = req_arg(args, "--pk").map_err(|e| (1, e))?;
            let (sk, pk) = vibeslayer_core::encrypted_compute::homo_keygen()
                .map_err(|e| (1, format!("homo-keygen failed: {e}")))?;
            let mut sk_bytes = vibeslayer_core::encrypted_compute::serialize_secret_key(&sk);
            let pk_bytes = vibeslayer_core::encrypted_compute::serialize_public_key(&pk);
            let wr_sk = fs::write(&sk_path, &sk_bytes);
            secure_zero(&mut sk_bytes);
            wr_sk.map_err(|e| (1, format!("Failed writing --sk: {e}")))?;
            fs::write(&pk_path, &pk_bytes).map_err(|e| (1, format!("Failed writing --pk: {e}")))?;
            println!(
                "{{\"ok\":true,\"ringDegree\":{},\"skBytes\":{},\"pkEvkBytes\":{}}}",
                vibeslayer_core::encrypted_compute::RING_N,
                8 + vibeslayer_core::encrypted_compute::RING_N,
                pk_bytes.len()
            );
            Ok(0)
        }
        "homo-encrypt" => {
            let pk_path = req_arg(args, "--pk").map_err(|e| (1, e))?;
            let val_str = req_arg(args, "--value").map_err(|e| (1, e))?;
            let val: i64 = val_str
                .parse()
                .map_err(|_| (1, format!("Invalid integer --value: {val_str}")))?;
            let out_path = req_arg(args, "--out").map_err(|e| (1, e))?;
            let pk_raw = fs::read(&pk_path).map_err(|e| (1, format!("Failed reading --pk: {e}")))?;
            let pk = vibeslayer_core::encrypted_compute::deserialize_public_key(&pk_raw)
                .map_err(|e| (1, e))?;
            let ct = vibeslayer_core::encrypted_compute::homo_encrypt_scalar(&pk, val)
                .map_err(|e| (1, e))?;
            let ct_bytes = vibeslayer_core::encrypted_compute::serialize_ciphertext(&ct);
            fs::write(&out_path, &ct_bytes).map_err(|e| (1, format!("Failed writing --out: {e}")))?;
            println!(
                "{{\"ok\":true,\"ciphertextBytes\":{},\"sha256\":\"{}\"}}",
                ct_bytes.len(),
                hex_encode(&sha256(&ct_bytes))
            );
            Ok(0)
        }
        "homo-eval" => {
            let pk_path = req_arg(args, "--pk").map_err(|e| (1, e))?;
            let op = req_arg(args, "--op").map_err(|e| (1, e))?;
            let out_path = req_arg(args, "--out").map_err(|e| (1, e))?;
            let pk_raw = fs::read(&pk_path).map_err(|e| (1, format!("Failed reading --pk: {e}")))?;
            let pk = vibeslayer_core::encrypted_compute::deserialize_public_key(&pk_raw)
                .map_err(|e| (1, e))?;
            let load_ct = |flag: &str| -> Result<vibeslayer_core::encrypted_compute::HomoCiphertext, (i32, String)> {
                let p = req_arg(args, flag).map_err(|e| (1, e))?;
                let raw = fs::read(&p).map_err(|e| (1, format!("Failed reading {flag}: {e}")))?;
                vibeslayer_core::encrypted_compute::deserialize_ciphertext(&raw).map_err(|e| (1, e))
            };
            let res_ct = match op.as_str() {
                "add" => {
                    let a = load_ct("--a")?;
                    let b = load_ct("--b")?;
                    vibeslayer_core::encrypted_compute::homo_add(&a, &b)
                }
                "sub" => {
                    let a = load_ct("--a")?;
                    let b = load_ct("--b")?;
                    vibeslayer_core::encrypted_compute::homo_sub(&a, &b)
                }
                "mul" => {
                    let a = load_ct("--a")?;
                    let b = load_ct("--b")?;
                    vibeslayer_core::encrypted_compute::homo_mul_encrypted(&pk, &a, &b)
                }
                "quad" => {
                    let x = load_ct("--x")?;
                    let c2 = load_ct("--c2")?;
                    let c1 = load_ct("--c1")?;
                    let c0 = load_ct("--c0")?;
                    vibeslayer_core::encrypted_compute::homo_eval_quadratic_encrypted(
                        &pk, &x, &c2, &c1, &c0,
                    )
                }
                _ => return Err((1, format!("Unsupported --op '{op}' (use add|sub|mul|quad)"))),
            };
            let ct_bytes = vibeslayer_core::encrypted_compute::serialize_ciphertext(&res_ct);
            fs::write(&out_path, &ct_bytes).map_err(|e| (1, format!("Failed writing --out: {e}")))?;
            println!(
                "{{\"ok\":true,\"op\":\"{}\",\"secretKeyUsed\":false,\"ciphertextBytes\":{}}}",
                op,
                ct_bytes.len()
            );
            Ok(0)
        }
        "homo-decrypt" => {
            let sk_path = req_arg(args, "--sk").map_err(|e| (1, e))?;
            let in_path = req_arg(args, "--in").map_err(|e| (1, e))?;
            let mut sk_raw = fs::read(&sk_path).map_err(|e| (1, format!("Failed reading --sk: {e}")))?;
            let sk_res = vibeslayer_core::encrypted_compute::deserialize_secret_key(&sk_raw);
            secure_zero(&mut sk_raw);
            let sk = sk_res.map_err(|e| (1, e))?;
            let ct_raw = fs::read(&in_path).map_err(|e| (1, format!("Failed reading --in: {e}")))?;
            let ct = vibeslayer_core::encrypted_compute::deserialize_ciphertext(&ct_raw)
                .map_err(|e| (1, e))?;
            let val = vibeslayer_core::encrypted_compute::homo_decrypt_scalar(&sk, &ct);
            println!("{{\"ok\":true,\"value\":{}}}", val);
            Ok(0)
        }
        "init-config" => {
            let preset = match arg_val(args, "--preset") {
                Some(p) => vibeslayer_core::params::SecurityPreset::parse(&p).map_err(|e| (1, e))?,
                None => vibeslayer_core::params::SecurityPreset::Balanced,
            };
            let out_path = PathBuf::from(
                arg_val(args, "-o")
                    .or_else(|| arg_val(args, "--out"))
                    .unwrap_or_else(|| "vibeslayer.config.json".to_string()),
            );
            let body = vibeslayer_core::params::build_default_config_template(preset);
            if let Some(parent) = out_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)
                        .map_err(|e| (1, format!("Failed creating config dir: {e}")))?;
                }
            }
            fs::write(&out_path, body.as_bytes())
                .map_err(|e| (1, format!("Failed writing config '{}': {e}", out_path.display())))?;
            println!(
                "{{\"ok\":true,\"preset\":\"{}\",\"configFile\":\"{}\"}}",
                preset.as_str(),
                out_path.display()
            );
            Ok(0)
        }
        "shield-3d" => {
            let in_path = match arg_val(args, "--in") {
                Some(p) => p,
                None => args
                    .get(2)
                    .filter(|s| !s.starts_with('-'))
                    .cloned()
                    .ok_or_else(|| (1, "Missing GLB path (--in <file.glb> or positional)".to_string()))?,
            };
            let out_dir = PathBuf::from(
                arg_val(args, "--out")
                    .or_else(|| arg_val(args, "-o"))
                    .unwrap_or_else(|| format!("{in_path}.shielded")),
            );
            let cfg_json = match arg_val(args, "--config") {
                Some(p) => Some(
                    vibeslayer_core::params::load_config_json(&PathBuf::from(p))
                        .map_err(|e| (1, e))?,
                ),
                None => None,
            };
            let cli_preset = arg_val(args, "--preset");
            let preset = vibeslayer_core::params::detect_preset_from_sources(
                cli_preset.as_deref(),
                cfg_json.as_ref(),
                "shield3d",
            )
            .map_err(|e| (1, e))?;
            let mut sparams = vibeslayer_core::params::Shield3dParams::from_preset(preset);
            if let Some(ref cfg) = cfg_json {
                sparams.apply_json(cfg).map_err(|e| (1, e))?;
            }
            if let Some(gs) = parse_typed_arg::<usize>(args, "--gpu-stages").map_err(|e| (1, e))? {
                sparams.gpu_stages = gs;
            }
            if let Some(cp) = parse_typed_arg::<f32>(args, "--chaff-pct").map_err(|e| (1, e))? {
                sparams.chaff_pct = cp;
            }
            if let Some(md) = parse_typed_arg::<usize>(args, "--max-tex-dim").map_err(|e| (1, e))? {
                sparams.max_tex_dim = md;
            }
            if let Some(tg) = parse_typed_arg::<usize>(args, "--tile-grid").map_err(|e| (1, e))? {
                sparams.tile_grid = tg;
            }
            if let Some(pm) = arg_val(args, "--png-mode") {
                sparams.png_mode =
                    vibeslayer_core::params::PngMode::parse(&pm).map_err(|e| (1, e))?;
            }
            if let Some(tf) = arg_val(args, "--tex-format") {
                sparams.tex_format =
                    vibeslayer_core::params::TexFormat::parse(&tf).map_err(|e| (1, e))?;
            }
            if let Some(tq) = parse_typed_arg::<u8>(args, "--tex-quality").map_err(|e| (1, e))? {
                sparams.tex_quality = tq;
            }
            if let Some(kf) = arg_val(args, "--key-file") {
                sparams.key_file = Some(PathBuf::from(kf));
            }
            sparams.validate().map_err(|e| (1, e))?;

            let asset_id = arg_val(args, "--asset-id").unwrap_or_else(|| {
                PathBuf::from(&in_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("mesh-3d")
                    .to_string()
            });
            let mut key = match arg_val(args, "--key") {
                Some(kh) => parse_key32(&kh).map_err(|e| (1, e))?,
                None => {
                    let mut k = [0u8; 32];
                    vibeslayer_core::os_random_bytes(&mut k).map_err(|e| (1, e))?;
                    k
                }
            };
            let glb = fs::read(&in_path).map_err(|e| {
                secure_zero(&mut key);
                (1, format!("Failed reading GLB: {e}"))
            })?;
            let summary = vibeslayer_core::encrypted_compute::build_shield_3d_bundle_with_params(
                &key, &asset_id, &glb, &out_dir, &sparams,
            );
            let viewer_info = if summary.is_ok() {
                vibeslayer_core::shield_viewer::build_interactive_viewer_assets_with_params(
                    &key,
                    &asset_id,
                    &glb,
                    &out_dir,
                    &sparams,
                )
                .unwrap_or(None)
            } else {
                None
            };
            let verify = if summary.is_ok() {
                let sb = fs::read(out_dir.join("model.vsshield")).unwrap_or_default();
                Some(vibeslayer_core::encrypted_compute::verify_shield_3d_gpu_exec(
                    &key, &asset_id, &glb, &sb,
                ))
            } else {
                None
            };
            secure_zero(&mut key);
            let s = summary.map_err(|e| (1, format!("shield-3d failed: {e}")))?;
            let (real_ok, chaff_ok, max_err) = verify
                .unwrap()
                .map_err(|e| (1, format!("shield-3d verify failed: {e}")))?;
            let (full_real, full_chaff, tex_cnt) =
                viewer_info.unwrap_or((s.real_triangles, s.chaff_triangles, 0));
            let resolved_key_path = sparams
                .key_file
                .clone()
                .unwrap_or_else(|| out_dir.join(".vsshield.key"));
            let params_json = vibeslayer_core::mini_json::to_json_compact(&sparams.to_json());
            println!(
                "{{\"ok\":true,\"preset\":\"{}\",\"outDir\":\"{}\",\"keyFile\":\"{}\",\"realTriangles\":{},\"chaffTriangles\":{},\"fullMeshTriangles\":{},\"fullChaffTriangles\":{},\"encryptedTextures\":{},\"totalEncryptedVertices\":{},\"shieldBytes\":{},\"shaderBytes\":{},\"verifiedRealVerts\":{},\"verifiedChaffClipped\":{},\"maxClipSpaceError\":{:.8},\"params\":{}}}",
                sparams.preset.as_str(),
                out_dir.display(),
                resolved_key_path.display(),
                s.real_triangles,
                s.chaff_triangles,
                full_real,
                full_chaff,
                tex_cnt,
                s.total_vertices_emitted,
                s.shield_bin_bytes,
                s.shader_bytes,
                real_ok,
                chaff_ok,
                max_err,
                params_json
            );
            Ok(0)
        }
        "serve-3d" => {
            let dir_str = match arg_val(args, "--dir") {
                Some(d) => d,
                None => args
                    .get(2)
                    .filter(|s| !s.starts_with('-'))
                    .cloned()
                    .ok_or_else(|| (1, "Usage: vibe-slayer serve-3d <shielded_dir> [--preset fast|balanced|paranoid] [--config <cfg.json>] [--addr 127.0.0.1:8790] [--origin http://127.0.0.1:8790] [--title <name>] [--watermark on|off] [--wm-strength 1.2] [--csp strict|relaxed|off] [--anti-hook on|off] [--key-file <path>] [--auth-secret <tok>] [--auth-hmac-key <64-hex>] [--trust-proxy <ip1,ip2>]".to_string()))?,
            };
            let cfg_json = match arg_val(args, "--config") {
                Some(p) => Some(
                    vibeslayer_core::params::load_config_json(&PathBuf::from(p))
                        .map_err(|e| (1, e))?,
                ),
                None => None,
            };
            let cli_preset = arg_val(args, "--preset");
            let preset = vibeslayer_core::params::detect_preset_from_sources(
                cli_preset.as_deref(),
                cfg_json.as_ref(),
                "serve3d",
            )
            .map_err(|e| (1, e))?;
            let mut rparams = vibeslayer_core::params::Serve3dParams::from_preset(preset);
            if let Some(ref cfg) = cfg_json {
                rparams.apply_json(cfg).map_err(|e| (1, e))?;
            }
            if let Some(a) = arg_val(args, "--addr") {
                rparams.addr = a;
            }
            if let Some(o) = arg_val(args, "--origin") {
                rparams.origin = Some(o);
            }
            if let Some(kf) = arg_val(args, "--key-file") {
                rparams.key_file = Some(PathBuf::from(kf));
            }
            if let Some(s) = arg_val(args, "--auth-secret") {
                rparams.auth_secret = Some(s);
            }
            if let Some(h) = arg_val(args, "--auth-hmac-key") {
                rparams.auth_hmac_key = Some(h);
            }
            if let Some(tp) = arg_val(args, "--trust-proxy") {
                rparams.trust_proxy = Some(tp);
            }
            if let Some(t) = arg_val(args, "--title") {
                rparams.title = Some(t);
            }
            if let Some(w) = arg_val(args, "--watermark") {
                rparams.watermark =
                    vibeslayer_core::params::parse_bool_flag(&w, "--watermark")
                        .map_err(|e| (1, e))?;
            }
            if let Some(ws) = parse_typed_arg::<f32>(args, "--wm-strength").map_err(|e| (1, e))? {
                rparams.wm_strength = ws;
            }
            if let Some(ah) = arg_val(args, "--anti-hook") {
                rparams.anti_hook =
                    vibeslayer_core::params::parse_bool_flag(&ah, "--anti-hook")
                        .map_err(|e| (1, e))?;
            }
            if let Some(ac) = arg_val(args, "--anti-cdp") {
                rparams.anti_cdp =
                    vibeslayer_core::params::parse_bool_flag(&ac, "--anti-cdp")
                        .map_err(|e| (1, e))?;
            }
            if let Some(ast) = arg_val(args, "--anti-stealth") {
                rparams.anti_stealth =
                    vibeslayer_core::params::AntiStealthMode::parse(&ast)
                        .map_err(|e| (1, e))?;
            }
            if let Some(csp) = arg_val(args, "--csp") {
                rparams.csp =
                    vibeslayer_core::params::CspMode::parse(&csp).map_err(|e| (1, e))?;
            }
            if let Some(cj) = parse_typed_arg::<f32>(args, "--camera-jitter").map_err(|e| (1, e))? {
                rparams.camera_jitter = cj;
            }
            if let Some(tt) = parse_typed_arg::<u64>(args, "--ticket-ttl").map_err(|e| (1, e))? {
                rparams.ticket_ttl_sec = tt;
            }
            if let Some(st) = parse_typed_arg::<u64>(args, "--session-ttl").map_err(|e| (1, e))? {
                rparams.session_ttl_sec = st;
            }
            if let Some(cb) = parse_typed_arg::<usize>(args, "--camera-budget").map_err(|e| (1, e))? {
                rparams.camera_budget = cb;
            }
            if let Some(ab) = parse_typed_arg::<usize>(args, "--asset-budget").map_err(|e| (1, e))? {
                rparams.asset_budget = ab;
            }
            if let Some(ml) =
                parse_typed_arg::<usize>(args, "--max-leases-per-min").map_err(|e| (1, e))?
            {
                rparams.max_leases_per_min = ml;
            }
            if let Some(ms) = parse_typed_arg::<usize>(args, "--max-sessions").map_err(|e| (1, e))? {
                rparams.max_sessions = ms;
            }
            if let Some(mc) =
                parse_typed_arg::<usize>(args, "--max-conns-per-ip").map_err(|e| (1, e))?
            {
                rparams.max_conns_per_ip = mc;
            }
            if let Some(mt) =
                parse_typed_arg::<usize>(args, "--max-tex-concurrency").map_err(|e| (1, e))?
            {
                rparams.max_tex_concurrency = mt;
            }
            if let Some(ht) =
                parse_typed_arg::<u64>(args, "--header-timeout-ms").map_err(|e| (1, e))?
            {
                rparams.header_timeout_ms = ht;
            }
            if let Some(bt) =
                parse_typed_arg::<u64>(args, "--body-timeout-ms").map_err(|e| (1, e))?
            {
                rparams.body_timeout_ms = bt;
            }
            if let Some(wk) = parse_typed_arg::<usize>(args, "--workers").map_err(|e| (1, e))? {
                rparams.workers = wk;
            }
            if let Some(rm) = arg_val(args, "--mode") {
                rparams.render_mode =
                    vibeslayer_core::params::RenderMode3d::parse(&rm).map_err(|e| (1, e))?;
            }
            if let Some(sw) = parse_typed_arg::<usize>(args, "--stream-width").map_err(|e| (1, e))? {
                rparams.stream_width = sw;
            }
            if let Some(sh) = parse_typed_arg::<usize>(args, "--stream-height").map_err(|e| (1, e))? {
                rparams.stream_height = sh;
            }
            if let Some(sq) = parse_typed_arg::<u8>(args, "--stream-quality").map_err(|e| (1, e))? {
                rparams.stream_quality = sq;
            }
            rparams.validate().map_err(|e| (1, e))?;

            vibeslayer_core::shield_viewer::serve_shielded_3d_viewer_with_params(
                &PathBuf::from(dir_str),
                &rparams,
            )
            .map_err(|e| (1, e))?;
            Ok(0)
        }
        "trace-shield-3d" => {
            let dir_str = req_arg(args, "--dir").map_err(|e| (1, e))?;
            let wp_path = req_arg(args, "--ripped-wp").map_err(|e| (1, e))?;
            let key_file = arg_val(args, "--key-file").map(PathBuf::from);
            let raw = fs::read(&wp_path)
                .map_err(|e| (1, format!("Failed reading --ripped-wp: {e}")))?;
            if raw.len() % 12 != 0 {
                return Err((1, "--ripped-wp byte length must be a multiple of 12 (i32 x,y,z)".to_string()));
            }
            let mut wp = Vec::with_capacity(raw.len() / 12);
            for ch in raw.chunks_exact(12) {
                wp.push([
                    i32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]),
                    i32::from_le_bytes([ch[4], ch[5], ch[6], ch[7]]),
                    i32::from_le_bytes([ch[8], ch[9], ch[10], ch[11]]),
                ]);
            }
            let (wm64, conf) = vibeslayer_core::shield_viewer::decode_shield_v2_wm64_from_ripped_wp(
                &PathBuf::from(&dir_str),
                key_file.as_deref(),
                &wp,
            )
            .map_err(|e| (1, e))?;
            println!(
                "{{\"ok\":true,\"decodedWm64Hex\":\"{:016x}\",\"meanConfidence\":{:.6}}}",
                wm64, conf
            );
            Ok(0)
        }
        "trace-stream-frame" => {
            let dir_str = req_arg(args, "--dir").map_err(|e| (1, e))?;
            let rgb_path = req_arg(args, "--rgb").map_err(|e| (1, e))?;
            let width = parse_typed_arg::<usize>(args, "--width")
                .map_err(|e| (1, e))?
                .ok_or_else(|| (1, "Missing required argument --width".to_string()))?;
            let height = parse_typed_arg::<usize>(args, "--height")
                .map_err(|e| (1, e))?
                .ok_or_else(|| (1, "Missing required argument --height".to_string()))?;
            let key_file = arg_val(args, "--key-file").map(PathBuf::from);
            let rgb = fs::read(&rgb_path)
                .map_err(|e| (1, format!("Failed reading --rgb: {e}")))?;
            let (wm64, conf) = vibeslayer_core::raster_stream::decode_stream_frame_rgb_wm64(
                &PathBuf::from(&dir_str),
                key_file.as_deref(),
                &rgb,
                width,
                height,
            )
            .map_err(|e| (1, e))?;
            println!(
                "{{\"ok\":true,\"decodedWm64Hex\":\"{:016x}\",\"meanConfidence\":{:.6}}}",
                wm64, conf
            );
            Ok(0)
        }
        "mint-token" => {
            let key_hex = req_arg(args, "--key").map_err(|e| (1, e))?;
            let mut key = parse_key32(&key_hex).map_err(|e| (1, e))?;
            let buyer = req_arg(args, "--buyer").map_err(|e| {
                secure_zero(&mut key);
                (1, e)
            })?;
            let ttl = parse_typed_arg::<u64>(args, "--ttl")
                .map_err(|e| {
                    secure_zero(&mut key);
                    (1, e)
                })?
                .unwrap_or(3600);
            let tok_res = vibeslayer_core::web_runtime::mint_signed_auth_token(&key, &buyer, ttl);
            secure_zero(&mut key);
            let tok = tok_res.map_err(|e| (1, e))?;
            println!(
                "{{\"ok\":true,\"buyerId\":\"{}\",\"ttlSeconds\":{},\"token\":\"{}\"}}",
                buyer, ttl, tok
            );
            Ok(0)
        }
        _ if !cmd.starts_with('-') => auto_cli::run_beginner_subcommand("protect", &args[1..]),
        _ => Err((
            1,
            "Usage: vibe-slayer <target|demo|scan|test|run|unseal|watermark|trace|website|serve|help>".to_string(),
        )),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match run(&args) {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err((code, msg)) => {
            eprintln!("{msg}");
            std::process::exit(code);
        }
    }
}
