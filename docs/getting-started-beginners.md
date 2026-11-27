# Beginner's Guide: Using Vibe-Slayer in Plain English

[← Back to README](../README.md) · [Web & Web Components](./web-and-web-components.md) · [3D Shield](./3d-shield-and-stream.md) · [CLI & Configuration](./cli-and-configuration.md) · [Vision & Benchmarks](./vision-and-benchmarks.md)

You do **not** need to be a cryptography or reverse-engineering expert to protect your website, Web Components, 3D models, source code, or Linux binaries.

Vibe-Slayer includes a **built-in natural-language command translator** (`ask` and `explain`) that runs offline in Rust. You describe what you want in everyday language, Vibe-Slayer shows you the exact command and explains every flag clearly, and then runs it.

---

## 1. Try It Safely First (Dry-Run Preview)

Use `./vibe-slayer explain "..."` anytime you want to see what Vibe-Slayer *would* do without modifying a single file:

```bash
./vibe-slayer explain "protect my website ./dist and block stealth browsers on port 8080"
```

Example output:
```text
[vibe-slayer natural language]
  You asked: "protect my website ./dist and block stealth browsers on port 8080"
  Goal:      Encrypt website & Web Components in ./dist -> ./dist-protected
  Command:   ./vibe-slayer website ./dist -o ./dist-protected --preset paranoid --origin http://127.0.0.1:8080 --anti-stealth strict
  Why:
    - Paranoid preset selected for maximum defense (strict anti-stealth, anti-CDP, JS rtKey hardening, server-rendered 3D stream)
    - --anti-stealth strict: blocks anti-detect / stealth browsers (e.g. CloakBrowser) via 6 rendering & OS invariants before any lease or Custom Element mounts
  Next step:
    ./vibe-slayer serve ./dist-protected --preset paranoid --addr 127.0.0.1:8080 --origin http://127.0.0.1:8080 --anti-stealth strict
  Mode:      DRY-RUN (remove --dry-run or use './vibe-slayer ask ...' to execute)
```

When you are happy with the plan, change `explain` to **`ask`** (or **`do`**) to run it!

---

## 2. Everyday Natural-Language Recipes

### Want to see how everything works in 10 seconds?
```bash
./vibe-slayer ask "show me a demo"
```
Creates a temporary sandbox project, scans for leaked secrets, encrypts code & a compiled binary & a 3D model, runs all security checks, traces a watermarked leak, and restores everything cleanly.

### Protect a Website or Web Components App (and Block Stealth Browsers)
```bash
# Step 1: Encrypt your site & Web Components
./vibe-slayer ask "protect my website ./dist and block stealth browsers on port 8080"

# Step 2: Start the local runtime server
./vibe-slayer ask "serve my protected website ./dist-protected on port 8080"
```

Need a higher tolerance threshold (`balanced`, `score >= 4`) for single-signal privacy extensions while still blocking multi-invariant anti-detect browsers?
```bash
./vibe-slayer ask "protect my website ./dist and block stealth browsers in balanced mode"
```
*(Note: browsers that simultaneously randomize Canvas, WebGL, and Audio — such as Brave Shields Aggressive, Tor Browser, or Firefox `privacy.resistFingerprinting` — can score `4–6`; use `--anti-stealth off` if your audience relies on those.)*

Deploying behind Nginx, Caddy, or Cloudflare?
```bash
./vibe-slayer ask "serve my protected website ./dist-protected on port 8080 behind nginx"
```

### Protect & Stream a 3D `.glb` Model (Geometry Stays on the Server)
```bash
# Step 1: Cook encrypted 3D bundle (keeps master key outside the bundle folder at ./hero.glb.vsshield.key)
./vibe-slayer ask "stream my 3d model ./hero.glb without sending geometry"

# Step 2: Start the server-rendered encrypted pixel stream viewer (auto-detects ./hero.glb.vsshield.key)
./vibe-slayer ask "serve my 3d model ./hero.glb.shielded on port 8790 without sending geometry"
```

Want native 60 FPS WebGL2 GPU rendering instead of server streaming?
```bash
./vibe-slayer ask "serve my 3d model ./hero.glb.shielded in webgl gpu mode on port 8790"
```

### Protect a Source Repository, `.env` Secrets, or Linux Binary
```bash
# 1. Check for accidentally exposed API keys first (read-only)
./vibe-slayer ask "scan ./my-repo for leaked api keys"

# 2. Protect the whole repository (automatically creates 0600 keys vault & updates .gitignore)
./vibe-slayer ask "protect ./my-repo"

# 3. Verify encryption, tamper rejection, and lossless recovery
./vibe-slayer ask "verify ./my-repo-protected"

# 4. Restore files back to plaintext anytime
./vibe-slayer ask "restore ./my-repo-protected to ./my-repo-restored"
```

Protect a standalone Linux executable so it runs directly without needing `./vibe-slayer run`:
```bash
./vibe-slayer ask "protect ./my_program standalone"
```

### Watermark & Trace a Leaked 3D Asset
```bash
# Tag a cooked 3D model for a specific customer
./vibe-slayer ask "watermark ./my-repo-protected/model.glb.vs3d for buyer alice"

# Trace a leaked 2D stream screenshot (converted to raw RGB) back to the leaker
./vibe-slayer ask "trace leaked frame ./frame.rgb 960x640 from ./hero.glb.shielded"
```

### Generate an Editable Config File
```bash
./vibe-slayer ask "create a paranoid config file"
```

---

## 3. Which Preset Should I Pick?

If you prefer explicit flags over plain English, every command accepts just **one preset flag** (`--preset`):

| I want... | Use this preset | What it turns on automatically |
| :--- | :--- | :--- |
| **Local dev / Playwright CI tests** | `--preset fast` | Fast encryption, relaxed CSP, anti-automation probes off so automated tests pass |
| **Public consumer website / 60 FPS WebGL** | `--preset balanced` *(default)* | Strict CSP, anti-CDP, balanced anti-stealth (`score >= 4`), 60 FPS GPU 3D |
| **Paid SaaS, Web Components, High-Value 3D IP** | `--preset paranoid` | Runtime-keyed `rtKey` JS hardening, optional `96 KB` decoy VM (`--js-bloat-kb`), inline Web Component stealth guard, strict server verification, server-rendered encrypted 3D pixel streaming |

---

## 4. Safety Checklist for Beginners

1. **Never commit `.vibeslayer/keys.json` or `.vsshield.key` to Git**: Vibe-Slayer automatically adds `.vibeslayer/` and `.env` to `.gitignore` and sets `0600` file permissions.
2. **Keep backups of your original source code**: Protected outputs (`*-protected`, `*.vspk3`, `*.shielded`) are created **alongside** your originals — Vibe-Slayer never deletes your source directory.
3. **Always run `explain` before `ask` if unsure**: Adding `--dry-run` (or using `explain`) prints the exact command and plain-English explanation without touching disk.
4. **Need machine-readable JSON for scripts or AI workflows?** Add `--json` to any `explain` or `ask` command.
