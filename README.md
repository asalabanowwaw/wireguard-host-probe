# WireGuard automatic VPS setup and minimal panel

## Diana dashboard

The panel now has an original anime night-city design with night/dawn themes, responsive navigation, a live overview and device management. Existing native WireGuard installs, clients, keys, DNS/connection presets and authentication are retained. Upgrade with `sudo wg-auto-update`, then refresh the browser.

New tools include:

- Client pause/resume without deleting keys, rename, search/filter/sort, and bulk pause/resume for up to 64 selected clients.
- Authenticated WireGuard QR SVG display/download, generated locally by the `qrencode` utility installed with the VPN setup. QR codes contain the private client configuration and are never sent to an external QR service.
- Sampled server receive/send rates and a rolling traffic chart. Rates start at zero until a second sample is available. Counters are current WireGuard counters, not lifetime totals. Counter resets produce zero rather than negative rates. History is in-memory, limited to 60 samples and collected on status requests.
- Recent-handshake badges and explanatory hints for paused clients, no/stale handshakes, low-MTU IPv4-only exports, and repeated peer endpoint changes. These are observations and troubleshooting hints, not proof of internet access or network optimization. A recent handshake is labelled "Recently seen", not "Online".
- Secret-free recent client activity, stored under `/etc/wireguard/wg-auto-panel/activity.json` with the latest 80 entries retained.
- Shecan DNS as a built-in choice alongside the existing resolvers; all custom presets and local tuner import/export remain available.

The user selected a compatible native-backend upgrade rather than a Docker migration. Features are inspired by [wg-easy](https://github.com/wg-easy/wg-easy); no upstream source or artwork is copied. See [UPSTREAM.md](UPSTREAM.md).

UI source lives in `web/panel-shell.html`, `web/panel.css`, and `web/panel.js`. Run `python build_panel.py` after changing those sources or `assets/anime-hero.webp`; it builds the self-contained `panel.html` used by the existing updater. Artwork and the final generation prompt are in `assets/`. No npm dependencies, public CDNs or external font requests are required on the VPS.

Backend checks: `python -m unittest -v test_panel.py test_local_app.py`. Browser workflow checks use development-only Playwright (`node test_panel_ui.cjs`, optionally set `PLAYWRIGHT_MODULE` and `BROWSER_EXE`). The browser test intercepts all API requests with explicit fake fixtures and never accesses a real VPN. It exercises desktop/mobile layout and client management workflows; fixture traffic is not production measurement data.

## Panel and updates

The installer now includes a minimal Python panel for the native WireGuard VPS installation. If you used the previous installer, run the same installation command again: it keeps your existing server keys and imports the original client. The Node.js hosting probe remains separate and unchanged.

Panel features:

- Create one client per device, download `.conf` files, and revoke access immediately.
- View handshake timestamps and traffic counters.
- Change the advertised endpoint hostname/IP, advertised port, DNS and MTU for client exports.
- Install project updates with a button or `sudo wg-auto-update`.
- Tune each client separately with connection profiles, custom MTU/keepalive and optional DNS overrides.
- Save, edit and delete reusable connection and DNS presets; built-in DNS choices include Cloudflare, Google and Quad9.
- Export native WireGuard configs, v2rayN/v2rayNG WireGuard links, or full Xray custom JSON configurations.

### Reusable presets

Use **Saved presets** to create a named connection preset (MTU and keepalive) or DNS preset (one to three IP addresses). Saving the same name updates that preset. Select it in a client's **Network profile**, then save the client and re-import its configuration. Connection and DNS selections are independent: a client can inherit the default MTU while using its own DNS preset. Saving or deleting a preset does not alter clients that already used it; settings are copied when explicitly applied. Existing clients and saved presets survive project updates. Deleting a connection preset keeps the applied values on clients as custom settings.

### v2rayN and v2rayNG exports

Each client has **Copy v2ray link**, **v2ray link file**, and **Xray JSON** actions in addition to the native `.conf` download.

- For a recent v2rayN or v2rayNG, copy the `wireguard://` link and use the app's import-from-clipboard action. If using the text download, copy its contents rather than the authenticated panel download URL.
- For full configuration import, download **Xray JSON**, import it as a custom configuration, and select a current Xray core. This is a complete JSON config, not an outbound fragment. It accepts HTTP and SOCKS with UDP on mixed port 10808, plus HTTP on 10809, all on the client's loopback interface. This matches current v2rayN's mixed listener convention; change these local ports if another program is using them. Enable the client's VPN/TUN or system proxy as appropriate to route application traffic.
- Link exports carry the selected DNS, MTU, client address, keys and server endpoint. The current client URI parsers do not expose persistent keepalive, so use JSON or native WireGuard if retaining this setting is required. Full JSON retains `keepAlive` and uses Xray's userspace WireGuard outbound. App-side settings may affect routing or imported fields.
- These are alternative ways to use the same WireGuard server, not VLESS/VMess conversions or obfuscation. IPv6 internet remains unavailable; JSON explicitly blocks IPv6 destinations. Create a separate client for each device, and do not run multiple apps simultaneously with the same client keys.
- Links and JSON contain private client credentials. They require panel login, are served with `Cache-Control: no-store`, and should not be published.

Format references: [v2rayN WireGuard parser](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/Fmt/WireguardFmt.cs), [v2rayNG WireGuard parser](https://github.com/2dust/v2rayNG/blob/master/V2rayNG/app/src/main/java/com/v2ray/ang/fmt/WireguardFmt.kt), [Xray WireGuard outbound](https://xtls.github.io/en/config/outbounds/wireguard.html). Compatibility is based on these current formats; mobile/desktop GUI imports and end-to-end connectivity still need testing on the user's app versions.

### Connection diagnostics and compatibility export

Select **Check VPS networking** to check the service, IPv4 forwarding, outbound route, this installer's host firewall rules, return traffic rules, NAT and the VPS's HTTPS internet access. Checks are read-only. Missing expected rules are flagged, but other rules may also affect traffic; a successful rule check does not prove the entire firewall accepts packets. Provider firewalls and client routes cannot be verified by these server checks.

**v2rayN compatibility** exports a conservative custom Xray configuration using MTU 1280, keepalive 25 and Cloudflare DNS, without changing saved client settings. The first inbound is mixed HTTP/SOCKS on 10808, matching current v2rayN defaults. Older custom exports used SOCKS-only on this port; a client sending HTTP there could fail even when WireGuard handshakes succeeded. Use a recent Xray core with mixed inbound support.

### PC application: measured connection trials

The VPS panel remains hosted on your public VPS. The companion PC tuner is a separate localhost application at **http://127.0.0.1:8788**, using Python 3.10+ and the official Xray core. No Python packages are required. On Windows x64, install its core once:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup-local.ps1
```

The script downloads the official [XTLS/Xray-core](https://github.com/XTLS/Xray-core) release into `%LOCALAPPDATA%\WireGuardNetworkTuner\tools` and verifies the release asset's SHA256 digest when GitHub supplies one. Binaries are not committed or bundled into this repository. Then double-click **Start local tuner.cmd**, run `python local_app.py`, or `npm run local`. Stop the console process to stop the app. The source and launcher can be copied to any folder; the native VPN service does not need to run on your PC.

Import a one-peer `.conf`, `wireguard://` link or our Xray JSON export. Private keys remain in memory except for short-lived, user-private temporary config files required by Xray; those files are removed after each trial. Reports and exported presets contain no keys. Exported client configs/links do contain keys. The UI binds only to loopback, validates the Host header and requires a per-process API token to prevent other websites from controlling scans.

**Check baseline only** tests direct HTTPS and the existing local HTTP proxy on port 10809. These do not test the imported client: that proxy may be serving a different VPN/profile. Direct requests bypass the system HTTP proxy, but still follow any active VPN/TUN route. A failed proxy test can also mean a different local port is configured; it does not automatically prove the VPN server is broken. The full imported-client trial is the tunnel test.

For **full trials**, stop other apps using the imported client or create a separate test client first. The app starts isolated Xray processes with ephemeral local HTTP ports. It tests combinations of MTU 1280/1360/1420 plus the imported client MTU when different and DNS 1.1.1.1/8.8.8.8/9.9.9.9. Each trial makes two HTTPS IP checks through WireGuard and, when connected, a 512 KiB sample download using Cloudflare's [documented speed-test endpoint](https://github.com/cloudflare/speedtest). At most roughly 6 MB of download payload is requested, excluding protocol overhead. It does not change Windows routes, firewall settings, system proxy settings or installed WireGuard tunnels.

Only trials with both successful HTTPS checks and a successful download can be recommended. Results rank the small observed download samples, not the theoretical maximum line speed. HTTP timings include tunnel setup, DNS, TCP and TLS, so they are not raw ping latency or isolated DNS timings. Keepalive remains fixed at 25 seconds and is not benchmarked. Repeat trials to account for noise; if all fail, the app also tries an HTTPS IP address without DNS and reports handshake initiation/reply counts from temporary core logs. Only counts are exposed, not raw debug logs. ISP blocking, keys, endpoint reachability and server forwarding must be fixed before tuning can help. Credential-free reports are saved in `%LOCALAPPDATA%\WireGuardNetworkTuner\last-report.json`. They are restored only when the app starts with the same endpoint/address/settings summary and SHA256 client-credential fingerprint; raw keys are not stored in reports. Reimporting a client clears old recommendations.

Export a tuned `.conf`, v2ray link, Xray JSON, or a credential-free measured preset file. In the VPS panel use **Import measured preset**, then explicitly apply the saved connection and DNS presets to a client and re-import its config.

Research alternatives: [Wire-Seek](https://github.com/yeya/wire-seek) provides ICMP-based path MTU discovery, and [dnspyre](https://github.com/Tantalor93/dnspyre) benchmarks DNS resolvers. This app uses official Xray for actual tunnel trials rather than claiming ICMP path estimates or direct DNS timing alone establish the best VPN settings. No source code from those two tools is bundled.

Tests: `python -m unittest -v test_panel.py test_local_app.py`. The current JSON export is also checked with official Xray's `run -test` validator.

### Per-client network settings

Expand **Network profile** under a client. Compatibility uses MTU 1280; Balanced tries 1360; Larger packets tries 1420. These presets are starting points for testing, not measurements of the client's route or promises of faster speeds. Smaller MTUs can help on constrained paths; larger MTUs can improve efficiency only when the entire path supports them. Custom mode allows MTU 1280–1420, keepalive 0–120 seconds and up to three DNS IP addresses. The less-idle-traffic preset disables keepalive; NAT mappings may then expire while idle. WireGuard's general NAT keepalive guidance is 25 seconds: https://www.wireguard.com/quickstart/ .

Saving a profile changes only that client's future config downloads. Its keys, address and server peer remain the same, and other clients are unaffected. Download and re-import the updated config on the device, reconnect, then compare real download/upload performance and reliability. Try one change at a time. Select **Use panel defaults** to remove the override. The VPS cannot infer an optimal end-to-end MTU, client-side DNS latency, packet loss or throughput from WireGuard handshake timestamps/counters alone. A client-side test is needed for measured optimization.

### Open the panel

The panel is hosted directly on your VPS over HTTPS, on port **8787**. Open:

```bash
https://YOUR_VPS_IP:8787
```

No SSH tunnel is required. Username: **admin**. Retrieve the generated password on the VPS:

```bash
sudo cat /etc/wireguard/wg-auto-panel/password
```

The installer generates a self-signed TLS certificate automatically, so the browser displays a certificate warning on first access. Allow **TCP 8787** in your VPS provider's cloud firewall if one is enabled; the service adds its own host firewall rule automatically. Config downloads contain private keys and authentication is required for all panel pages and API routes. Public HTTPS access supports concurrent connections, serializes VPN changes, and limits failed password attempts per IP.

If you installed the earlier tunnel-only panel, rerun the curl installation command below once to migrate to public HTTPS. Use that command for this migration rather than the old updater, which expects an HTTP-only health check. Your password, keys and clients are retained. Later upgrades work through the update button or `sudo wg-auto-update`.

If logs show `ssl.SSLError: [SSL: HTTP_REQUEST]` from `127.0.0.1` during an update, the old updater is checking the new HTTPS server using HTTP. Recover by downloading the new updater directly, bypassing the installed older copy:

```bash
curl -fsSL https://raw.githubusercontent.com/asalabanowwaw/wireguard-host-probe/main/update.sh -o /tmp/wg-auto-recover.sh && sudo bash /tmp/wg-auto-recover.sh --install
```

This re-applies the public HTTPS service, host firewall rule and HTTPS health check without replacing VPN keys or client records. Re-running the latest updater repairs service setup even when its application version is already current. Plain HTTP browser requests now redirect to HTTPS and do not display a login prompt until the encrypted connection is established.

Changing the advertised endpoint does not change the server's actual listening port or create another server. For example, advertising port 443 requires a working UDP port mapping from public 443 to the server's current listening port. Existing imported configs do not update themselves: download and import a replacement after changing settings. Revocation disconnects the peer; the old `/root/wireguard-client.conf` file may still exist but no longer grants access once its peer is revoked.

### Update without redeploying

```bash
sudo wg-auto-update
```

Or select **Install latest update** in the panel. The update runs in a separate systemd job, validates a downloaded GitHub commit, switches the application directory and restarts only the panel. It preserves `/etc/wireguard/wgauto0.conf` and `/etc/wireguard/wg-auto-panel/`, including keys, client records and credentials. A failed panel startup restores the previous application version when available. Updates do not reboot the VPS or restart active WireGuard tunnels. Downloads require access to GitHub's API/codeload endpoints; API rate limits or network failures abort before switching versions.

```bash
sudo systemctl status wg-auto-panel
sudo journalctl -u wg-auto-panel -n 50
sudo journalctl -u 'wg-auto-update-*' -n 50
```

Server/client configs are backed up before client modifications; failed runtime changes attempt to restore the prior config and state. Updates cannot fix cloud firewall blocks or ISP filtering. The panel manages this installer's `wgauto0` interface, preserving unrelated imported peer blocks. It does not manage arbitrary existing wg-easy installations.

Developer checks: `python -m unittest -v test_panel.py`, `python -m py_compile panel.py`, `bash -n install.sh`, `bash -n update.sh`. Tests use a simulated WireGuard backend; live VPS installation and end-to-end client connectivity still need verification.

## Automatic VPS installer

On a Debian 12/13 or Ubuntu 22.04/24.04 VPS with root/sudo access and systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/asalabanowwaw/wireguard-host-probe/main/install.sh -o /tmp/wg-auto-install.sh && sudo bash /tmp/wg-auto-install.sh
```

No interactive configuration is needed. The script installs distribution packages, detects the public IPv4 and outbound interface, chooses an unused private subnet, generates unique server/client keys, adds scoped firewall/NAT rules, enables forwarding and starts WireGuard on UDP 51820 at boot. It writes `/root/wireguard-client.conf` with root-only permissions and displays a QR code to import in the official WireGuard app. The QR code is a private credential. Use a separate peer/key for each device; this installer creates one client.

This installs native WireGuard, not the wg-easy web panel. Re-running preserves the generated client. It refuses to replace an unrelated existing `wgauto0.conf`. Provider-level firewalls and routers cannot be configured by the installer: permit inbound UDP 51820 in the provider panel if necessary. A public IPv4 reachable on that port is required. Optionally set `WG_ENDPOINT` and `WG_PORT` before running the script to override detection/defaults. IPv4 internet is supported; `::/0` captures IPv6 on the client so it is not intentionally routed outside the VPN, but this installer does not provide IPv6 internet. Client OS routing behavior must still be verified.

Check status with `sudo wg show wgauto0`. Download the config over your existing SSH/SFTP connection, or scan the QR code. There is no public config download endpoint. The installer verifies server startup; a client handshake and internet test are still required. Linux syntax and static checks are performed during development; live VPS verification is required before claiming end-to-end success.

A dependency-free Node.js application for checking whether Bot-Hosting can support a future wg-easy deployment. This is a standalone diagnostic tool, not a fork of wg-easy and not a working VPN. No networking settings are changed and no credentials or environment variables are included in reports.

## Deploy on Bot-Hosting

1. Select Node.js 18 or newer and import this repository.
2. Entry file: `index.js`. Start command: `npm start` (or `node index.js`). No packages are needed.
3. Set `PORT` to the hosting-assigned port unless the host already sets `PORT` or `SERVER_PORT`.
4. Set `ADMIN_TOKEN` to a long random password in the host's environment settings. If omitted, a temporary token is printed in the private console and changes on restart.
5. Start the deployment. The private console prints the capability report. `/health` returns a public health check.
6. Retrieve the full report over HTTPS with `Authorization: Bearer <ADMIN_TOKEN>` at `/report`. Do not put the token into a URL or publish it.

## Public UDP test

The app binds UDP on the same numeric port as HTTP. Binding locally does not establish that the provider publishes UDP. Fetch `/report` to obtain a random `udp.challenge`, then send that exact text from a different machine to the deployment's node hostname and assigned UDP port. A successful arrival increments `verifiedPackets`. A web HTTPS subdomain may route HTTP only; use the node hostname for UDP.

Example on a separate computer with Node.js (replace the three placeholders):

```js
const d = require('node:dgram').createSocket('udp4');
d.on('message', m => { console.log(m.toString()); d.close(); });
d.send(Buffer.from('CHALLENGE'), Number('ASSIGNED_PORT'), 'NODE_HOSTNAME');
setTimeout(() => { try { d.close(); } catch {} }, 5000);
```

## Interpret results

- `netAdmin: false`: standard wg-easy cannot create its network interface in this container.
- A missing `wg`, `ip`, or `iptables` indicates missing utilities, which might be installable; this does not grant kernel capabilities.
- `tunDeviceExists` reports presence only, not permission to open or configure TUN.
- Successful inbound UDP is necessary for a normal public endpoint but does not prove WireGuard handshakes, NAT, forwarding or internet access.
- Full feasibility still requires an isolated interface-creation test and end-to-end VPN testing. This app deliberately does not alter interfaces or firewall rules.

Local console-only check: `npm run check`.

### MTU below 1280

Custom client settings, defaults and saved presets accept MTU 576?1420. The Small packets preset uses 1200. Below 1280, native `.conf` exports include only the IPv4 default route and a warning: IPv6 is not captured and can bypass the VPN unless disabled or blocked on the client. This follows IPv6's minimum link MTU of 1280 (RFC 8200). Existing configurations at 1280 or above retain their original routes. Xray JSON continues to block IPv6 destinations regardless of MTU; share-link routing depends on the importing application. The local tuner accepts low-MTU files and includes the imported MTU in its trials. Low values are diagnostic options, not guaranteed performance improvements.
