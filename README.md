# WireGuard host probe

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
