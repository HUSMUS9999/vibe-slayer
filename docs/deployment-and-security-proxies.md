# Production Deployment, Reverse Proxies & Security Proxies

[← Back to README](../README.md) · [Beginner's Guide](./getting-started-beginners.md) · [Web & Web Components](./web-and-web-components.md) · [CLI & Configuration](./cli-and-configuration.md) · [Threat Model](./threat-model-and-benchmarks.md)

`vibe-slayer serve` and `vibe-slayer serve-3d` embed a custom multi-threaded Rust HTTP/1.1 server designed to sit cleanly behind production reverse proxies (Nginx, Caddy, Cloudflare, AWS ALB) as well as intercepting security proxies (Caido, Burp Suite, mitmproxy) without spurious `400 Bad Request` errors.

> **Concurrency Architecture Note:** `serve` and `serve-3d` use a blocking worker-thread pool (`--workers`, auto-sized to `32–64`). Always terminate TLS and client HTTP/2–HTTP/3 keep-alive connections at Nginx/Caddy/Cloudflare in front of `vibe-slayer`, and configure a short upstream keep-alive idle timeout (`--header-timeout-ms 2000`) so idle browser sockets do not pin worker threads.

---

## 1. RFC 9112 HTTP/1.1 & Proxy Compliance

The built-in Rust HTTP/1.1 parser implements the following proxy-critical behaviors:

| Capability | Behavior |
| :--- | :--- |
| **Chunked Request Bodies (RFC 9112 §7.1)** | Fully decodes `Transfer-Encoding: chunked` POST bodies (including chunk extensions `;ext=val` and trailers) for `/__vibeslayer/lease`, `/__vibeslayer/stream-init`, `/__vibeslayer/frame`, and `/__vibeslayer/camera`, keeping HTTP/1.1 `keep-alive` connections synchronized. |
| **Request Smuggling Defense (RFC 9112 §6.3)** | Rejects any request carrying both `Content-Length` and `Transfer-Encoding` with `400 CL_TE_SMUGGLING_REJECTED` and closes the socket immediately. |
| **Absolute-Form Proxy URIs (RFC 9112 §3.2.2)** | Normalizes `GET http://host:port/path HTTP/1.1` sent by forward/intercepting HTTP proxies into `/path`. |
| **`Expect: 100-continue`** | Responds immediately with `HTTP/1.1 100 Continue` so proxies and `curl` never stall waiting for timeout. |
| **Health Probes** | Both `GET /__vibeslayer/health` and `HEAD /__vibeslayer/health` return `200 OK` (`{"ok":true}` for `GET`, empty body for `HEAD`). |
| **Bounds & Slowloris Hardening** | Rejects oversized headers (`431`) and bodies (`413`), enforces `--header-timeout-ms` and `--body-timeout-ms`, and caps concurrent connections per IP (`--max-conns-per-ip`). |

---

## 2. Reverse Proxy Setup (`--trust-proxy` & `--origin`)

Never expose `vibe-slayer` directly on port 80/443 without TLS. Terminate TLS at Nginx, Caddy, or a load balancer, bind `vibe-slayer` to loopback (`127.0.0.1`), and pass `--trust-proxy 127.0.0.1` so per-IP tickets, rate limits, and `Origin` checks evaluate the real client IP (`X-Forwarded-For`) and external hostname (`X-Forwarded-Host`).

### Nginx Example (Website or 3D Encrypted Stream)

```nginx
server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate     /etc/letsencrypt/live/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Connection "";
        proxy_buffering off;
    }
}
```

Start Vibe-Slayer behind Nginx:

```bash
./vibe-slayer serve ./my-site-protected \
  --preset paranoid \
  --addr 127.0.0.1:8080 \
  --origin https://app.example.com \
  --trust-proxy 127.0.0.1
```

### Caddy Example (Automatic HTTPS)

```caddyfile
app.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-Host {host}
        header_up X-Forwarded-Proto {scheme}
        flush_interval -1
    }
}
```

> **Security Warning**: Only list IPs you control in `--trust-proxy` (e.g. `127.0.0.1` or your private VPC load-balancer IP). If `--trust-proxy` is unset, `X-Forwarded-For` and `X-Forwarded-Host` are strictly ignored so external attackers cannot spoof client IPs or bypass `Origin` checks.

---

## 3. Testing Through Intercepting Security Proxies (Caido / Burp)

When auditing a localhost Vibe-Slayer server through Caido or Burp Suite (`127.0.0.1:8080`):
1. Launch Chrome with `--proxy-server=http://127.0.0.1:8080 --proxy-bypass-list="<-loopback>"` so loopback traffic actually traverses the proxy.
2. Start `vibe-slayer serve` / `serve-3d` on a distinct port (e.g. `127.0.0.1:8790`).
3. Because `vibe-slayer` decodes `Transfer-Encoding: chunked` POSTs and normalizes absolute-form proxy URIs, `/__vibeslayer/lease`, `/__vibeslayer/stream-init`, `/__vibeslayer/frame`, and `/__vibeslayer/camera` all succeed with `200 OK` through intercepting proxies without disabling security checks.

---

## 4. Key & Secret Hygiene Checklist

1. **Keep `.vsshield.key` Outside the Bundle Directory**: Always pass `--key-file /etc/vibeslayer/keys/<asset>.key` (`chmod 0600`) to both `shield-3d` and `serve-3d` rather than leaving `.vsshield.key` inside the served bundle directory.
2. **Never Commit `.vibeslayer/keys.json`**: `vibe-slayer` automatically adds `.vibeslayer/`, `*.vibeslayer.keys.json`, and `.env` to `.gitignore`. Keep key vaults in a secrets manager or restricted host directory.
3. **Pass Auth Secrets via Environment Variables**: Prefer `VIBESLAYER_AUTH_HMAC_KEY` or `VIBESLAYER_AUTH_SECRET` over CLI arguments so secrets do not appear in `ps aux` process listings.
4. **Pin `--origin` in Production**: Always set `--origin https://your-domain.com` explicitly (or via `VIBESLAYER_ORIGIN`) so leases can only be unwrapped on your exact origin.
5. **Tune Concurrency for Hardware**:
   - `--workers 0` auto-sizes to `clamp(cpu_cores * 4, 32, 64)`.
   - For high-traffic `--mode stream` deployments, scale horizontally behind a sticky-session load balancer (each session ID lives in server RAM; bind sessions to a backend via IP hash or cookie affinity).
   - For CI or corporate NAT offices sharing one egress IP, raise `--max-leases-per-min` and `--max-conns-per-ip` accordingly.

---

## 5. Error Code Troubleshooting Quick Reference

| HTTP Status / Error Code | Cause | Fix |
| :--- | :--- | :--- |
| `400 CL_TE_SMUGGLING_REJECTED` | Request carried both `Content-Length` and `Transfer-Encoding` headers | Fix broken upstream proxy/client; RFC 9112 §6.3 forbids sending both |
| `403 ORIGIN_DENIED` | Browser `Origin` header did not match `--origin` (or `X-Forwarded-Host` with `--trust-proxy`) | Set `--origin https://your-domain.com` and forward `X-Forwarded-Host` from a trusted proxy IP |
| `403 TICKET_REPLAYED_OR_INVALID` | Single-use `<meta name="vs-ticket">` expired (`--ticket-ttl`), was replayed, or client IP changed behind an untrusted proxy | Pass `--trust-proxy <proxy-ip>` so real client IP stays consistent; increase `--ticket-ttl` if slow networks time out |
| `403 STEALTH_ATTEST_REQUIRED` | `--anti-stealth strict` enabled on server, but client did not send `attest` | Ensure the bundle was built with `--anti-stealth strict` (or `--preset paranoid`) matching `serve` |
| `403 STEALTH_ATTEST_INVALID` | SHA-256 attestation digest did not match `(ticket, clientPublicKeyHex, score, flags, platform)` | Verify no middleware mutated request JSON fields or ticket |
| `403 STEALTH_BROWSER_DENIED` | Anti-detect browser invariants triggered (e.g. CloakBrowser) or OS headers contradicted (`Linux` UA + `Windows` Client Hint) | Expected for anti-detect browsers; if multi-API privacy browsers (Brave Shields Aggressive / Tor / Firefox RFP) must be allowed, set `--anti-stealth off` |
| `403 AUTOMATION_DENIED` | `navigator.webdriver`, CDP `Runtime.enable`, or `HeadlessChrome`/`Playwright`/`Puppeteer` UA detected | Expected for automated scrapers; use `--preset fast` or `--anti-cdp off --anti-stealth off` in CI test environments |
| `429 RATE_LIMITED` | Client IP exceeded `--max-leases-per-min` | Raise `--max-leases-per-min` for shared corporate NAT / CI IPs, and ensure `--trust-proxy` is configured so all users don't share the reverse proxy's IP |
| `Error: VS_RUNTIME_KEY_REQUIRED` | Hardened `.js`/`.mjs` module executed offline without a live ECDH lease binding `Symbol.for("vs_rt_<siteId>")` | Expected anti-ripper defense; serve the bundle through `vibe-slayer serve` |
