'use strict';
const http = require('node:http');
const fs = require('node:fs');
const dgram = require('node:dgram');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

function read(path) { try { return fs.readFileSync(path, 'utf8').trim(); } catch { return null; } }
function command(name, args) {
  const r = spawnSync(name, args, { encoding: 'utf8', timeout: 3000 });
  return { available: !r.error, success: r.status === 0, output: (r.stdout || r.stderr || r.error?.code || '').trim().slice(0, 1200) };
}
function inspect() {
  const status = read('/proc/self/status');
  const caps = status?.match(/^CapEff:\s*(\w+)/m)?.[1];
  const netAdmin = caps ? Boolean(BigInt('0x' + caps) & (1n << 12n)) : null;
  return {
    platform: process.platform, node: process.version,
    uid: process.getuid?.() ?? null, netAdmin,
    tunDeviceExists: fs.existsSync('/dev/net/tun'),
    ipv4Forwarding: read('/proc/sys/net/ipv4/ip_forward'),
    tools: { wg: command('wg', ['--version']), ip: command('ip', ['-Version']), iptables: command('iptables', ['--version']) },
    assessment: netAdmin === false ? 'Standard wg-easy networking is blocked: NET_ADMIN is absent.' : 'Further interface creation, routing, NAT and external UDP checks are required.',
    note: 'This is a deployment probe, not a VPN or config generator. A local UDP bind does not prove public UDP reachability.'
  };
}
if (process.argv.includes('--check')) {
  console.log(JSON.stringify(inspect(), null, 2));
} else {
  const port = Number(process.env.PORT || process.env.SERVER_PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT/SERVER_PORT');
  const token = process.env.ADMIN_TOKEN || crypto.randomBytes(24).toString('hex');
  const challenge = crypto.randomBytes(16).toString('hex');
  const udp = dgram.createSocket('udp4');
  const udpStatus = { bound: false, port, verifiedPackets: 0, lastVerifiedAt: null };
  udp.on('error', e => { udpStatus.error = e.code; });
  udp.on('listening', () => { udpStatus.bound = true; });
  udp.on('message', (msg, remote) => {
    if (msg.toString() !== challenge) return;
    udpStatus.verifiedPackets++;
    udpStatus.lastVerifiedAt = new Date().toISOString();
    udp.send(Buffer.from('ok'), remote.port, remote.address);
  });
  udp.bind(port, '0.0.0.0');
  const report = inspect();
  console.log(JSON.stringify(report, null, 2));
  if (!process.env.ADMIN_TOKEN) console.log('Temporary ADMIN_TOKEN (set your own environment variable): ' + token);
  const server = http.createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    if (req.url === '/health') { res.end('{"ok":true}'); return; }
    const supplied = Buffer.from(req.headers.authorization || '');
    const expected = Buffer.from('Bearer ' + token);
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
      res.writeHead(401); res.end('{"error":"Send Authorization: Bearer <ADMIN_TOKEN>"}'); return;
    }
    if (req.url !== '/' && req.url !== '/report') { res.writeHead(404); res.end('{}'); return; }
    res.end(JSON.stringify({ ...report, udp: { ...udpStatus, challenge, instructions: 'From another machine send the exact challenge as a UDP packet to the node hostname and assigned port. Then fetch this report again. A verified packet proves inbound UDP only.' } }, null, 2));
  });
  server.listen(port, '0.0.0.0', () => console.log('Probe HTTP and UDP port: ' + port));
  function stop() { server.close(); try { udp.close(); } catch {} }
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
}
