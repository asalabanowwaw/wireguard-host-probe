# WireGuard automatic VPS setup and minimal panel

## Panel and updates

The installer now includes a minimal Python panel for the native WireGuard VPS installation. If you used the previous installer, run the same installation command again: it keeps your existing server keys and imports the original client. The Node.js hosting probe remains separate and unchanged.

Panel features:

- Create one client per device, download `.conf` files, and revoke access immediately.
- View handshake timestamps and traffic counters.
- Change the advertised endpoint hostname/IP, advertised port, DNS and MTU for client exports.
- Install project updates with a button or `sudo wg-auto-update`.

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
