#!/usr/bin/env node
// K1 kapsam bekçisi. İstek atan tüm scriptler checkUrl/guardedFetch kullanır; scope dışı hedef KODLA reddedilir.
import dns from 'node:dns/promises';
import net from 'node:net';
import http from 'node:http';
import fs from 'node:fs';
import { vtPath, readJson, writeJson, ensureDir, parseArgs, isMain, die, info, maskSecrets, nowIso } from './lib/common.mjs';

const HELP = `scope-guard.mjs — Visual Tester kapsam bekçisi (K1)

Kullanım:
  node scope-guard.mjs --check <url> [--json]     Hedef kapsamda mı? (çıkış 0=izinli, 2=reddedildi)
  node scope-guard.mjs --init --target <url> --confirm [--not-production] [--env staging]
                                                   Staging hedefini .visual-tester/scope.json'a ekler
  node scope-guard.mjs --show                      Etkin kapsamı gösterir
  node scope-guard.mjs --canary [--port 8089] [--host 127.0.0.1]
                                                   SSRF/XXE için yerel canary dinleyici (log: .visual-tester/canary.log)

Varsayılan izinli: localhost, 127.0.0.0/8, ::1, *.localhost, host.docker.internal,
Docker iç ağı (172.16.0.0/12, tek etiketli compose servis adları). Bulut metadata adresleri her zaman reddedilir.
Modül olarak: import { checkUrl, assertInScope, guardedFetch } from './scope-guard.mjs'`;

const SCOPE_FILE = vtPath('scope.json');
const METADATA_HOSTS = new Set([
  'metadata.google.internal', 'metadata', 'metadata.azure.com', 'instance-data',
  'instance-data.ec2.internal', 'metadata.tencentyun.com', 'metadata.packet.net',
]);
const SCHEMES = new Set(['http:', 'https:', 'ws:', 'wss:']);
const TEST_LABEL = /(^|[.-])(staging|stage|stg|dev|develop|test|testing|qa|uat|preview|sandbox|demo|local)([.-]|$)/i;

export class ScopeError extends Error {}

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, o) => ((acc << 8) + Number(o)) >>> 0, 0);
}
function inCidr4(ip, cidr) {
  const [base, bits] = cidr.split('/');
  const n = Number(bits);
  const mask = n === 0 ? 0 : (0xffffffff << (32 - n)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

// 'metadata' | 'loopback' | 'docker' | 'private' | 'public' | 'unspecified' | 'invalid'
export function classifyIp(ipRaw) {
  const ip = String(ipRaw).replace(/^\[|\]$/g, '').toLowerCase();
  if (net.isIPv4(ip)) {
    if (inCidr4(ip, '169.254.0.0/16') || ip === '100.100.100.200' || ip === '192.0.0.192') return 'metadata';
    if (inCidr4(ip, '127.0.0.0/8')) return 'loopback';
    if (ip === '0.0.0.0') return 'unspecified';
    if (inCidr4(ip, '172.16.0.0/12')) return 'docker';
    if (inCidr4(ip, '10.0.0.0/8') || inCidr4(ip, '192.168.0.0/16') || inCidr4(ip, '100.64.0.0/10')) return 'private';
    return 'public';
  }
  if (net.isIPv6(ip)) {
    if (ip === '::1') return 'loopback';
    if (ip === '::') return 'unspecified';
    const mapped = ip.match(/^::ffff:(.+)$/);
    if (mapped) {
      const rest = mapped[1];
      if (net.isIPv4(rest)) return classifyIp(rest);
      const hex = rest.split(':');
      if (hex.length === 2) {
        const n = (parseInt(hex[0], 16) << 16 | parseInt(hex[1], 16)) >>> 0;
        return classifyIp([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'));
      }
    }
    if (ip.startsWith('fd00:ec2:') || ip.startsWith('fe80:')) return 'metadata';
    if (/^f[cd]/.test(ip)) return 'private';
    return 'public';
  }
  return 'invalid';
}

export function loadScope() {
  const s = readJson(SCOPE_FILE, null) || {};
  return {
    targets: Array.isArray(s.targets) ? s.targets : [],
    ownerConfirmed: s.owner_confirmed === true,
    allowDocker: s.allow_docker_network !== false,
    deny: Array.isArray(s.deny) ? s.deny : [],
    raw: s,
  };
}

function defaultPort(protocol) {
  return protocol === 'https:' || protocol === 'wss:' ? '443' : '80';
}

function matchesTarget(u, target) {
  let t;
  try { t = new URL(target); } catch { return false; }
  if (u.hostname.toLowerCase() !== t.hostname.toLowerCase()) return false;
  if (t.port && (u.port || defaultPort(u.protocol)) !== t.port) return false;
  const base = t.pathname.replace(/\/+$/, '');
  return !base || u.pathname === base || u.pathname.startsWith(base + '/');
}

function isDefaultHost(host) {
  return host === 'localhost' || host.endsWith('.localhost') || host === 'host.docker.internal';
}

async function resolveAll(host) {
  const res = await dns.lookup(host, { all: true, verbatim: true });
  return res.map((r) => r.address);
}

// Döner: { ok, reason, url, rule }
export async function checkUrl(rawUrl, { resolve = true, scope = loadScope() } = {}) {
  let u;
  try { u = new URL(rawUrl); } catch { return { ok: false, reason: `Geçersiz URL: ${rawUrl}` }; }
  if (!SCHEMES.has(u.protocol)) return { ok: false, reason: `İzin verilmeyen şema: ${u.protocol}` };
  if (u.username || u.password) return { ok: false, reason: 'URL içinde kimlik bilgisi kabul edilmez (K8).' };
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  const out = (ok, reason, rule) => ({ ok, reason, rule, url: u.href });

  if (METADATA_HOSTS.has(host)) return out(false, `Bulut metadata hedefi yasak: ${host}`);
  for (const d of scope.deny) if (matchesTarget(u, d)) return out(false, `scope.json deny listesinde: ${d}`);

  const literal = net.isIP(host) ? classifyIp(host) : null;
  if (literal === 'metadata') return out(false, `Bulut metadata/link-local adres yasak: ${host}`);
  if (literal === 'loopback' || literal === 'unspecified') return out(true, 'loopback', 'default');
  if (literal === 'docker' && scope.allowDocker) return out(true, 'Docker iç ağı', 'default');

  const explicit = scope.ownerConfirmed && scope.targets.some((t) => matchesTarget(u, t));
  if (scope.targets.length && !scope.ownerConfirmed && scope.targets.some((t) => matchesTarget(u, t))) {
    return out(false, 'scope.json hedefi var ama sahiplik onayı (owner_confirmed) yok. `--init --confirm` ile onaylayın.');
  }
  if (literal && !explicit) return out(false, `Kapsam dışı IP (${literal}): ${host}. Staging ise scope.json'a ekleyin.`);

  const singleLabel = !literal && !host.includes('.');
  if (!explicit && !isDefaultHost(host) && !singleLabel) {
    return out(false, `Kapsam dışı hedef: ${host}. Yalnızca kendi projeniz; staging için scope-guard --init.`);
  }
  if (host === 'localhost' || host.endsWith('.localhost')) return out(true, 'localhost', 'default');
  if (!resolve) return out(explicit, explicit ? 'scope.json hedefi (DNS kontrolsüz)' : 'DNS kontrolü gerekli', explicit ? 'scope' : undefined);

  let addrs;
  try { addrs = await resolveAll(host); } catch (e) { return out(false, `DNS çözümlenemedi (${host}): ${e.code || e.message}`); }
  const classes = addrs.map(classifyIp);
  if (classes.includes('metadata')) return out(false, `${host} metadata/link-local adrese çözülüyor (DNS rebinding?): ${addrs.join(', ')}`);
  if (explicit) return out(true, 'scope.json hedefi (sahiplik onaylı)', 'scope');
  const localOk = classes.every((c) => c === 'loopback' || (c === 'docker' && scope.allowDocker));
  if (localOk) return out(true, `yerel/Docker ağı (${addrs.join(', ')})`, 'default');
  return out(false, `${host} yerel olmayan adrese çözülüyor (${addrs.join(', ')}); scope dışı.`);
}

export async function assertInScope(url, opts) {
  const r = await checkUrl(url, opts);
  if (!r.ok) throw new ScopeError(`K1 kapsam reddi: ${r.reason}`);
  return r;
}

// Basit hız sınırı: DoS benzeri yükü kodla engeller (varsayılan ~20 istek/sn).
const MIN_INTERVAL = 1000 / Math.max(1, Number(process.env.VT_MAX_RPS || 20));
let nextSlot = 0;
async function throttle() {
  const now = Date.now();
  const wait = Math.max(0, nextSlot - now);
  nextSlot = Math.max(now, nextSlot) + MIN_INTERVAL;
  if (wait) await new Promise((r) => setTimeout(r, wait));
}

// Kapsam kontrollü fetch. Yönlendirmeler elle izlenir; her adım yeniden kontrol edilir.
export async function guardedFetch(url, options = {}) {
  const { maxRedirects = 5, followRedirects = true, ...init } = options;
  let current = url;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    await assertInScope(current);
    await throttle();
    const res = await fetch(current, { ...init, redirect: 'manual' });
    const loc = res.headers.get('location');
    if (!followRedirects || res.status < 300 || res.status >= 400 || !loc) return res;
    current = new URL(loc, current).href;
    if (res.status === 303 || ((res.status === 301 || res.status === 302) && init.method && init.method !== 'GET' && init.method !== 'HEAD')) {
      init.method = 'GET';
      delete init.body;
    }
  }
  throw new ScopeError(`Çok fazla yönlendirme (> ${maxRedirects}): ${url}`);
}

function startCanary(port, host) {
  if (classifyIp(host) !== 'loopback' && host !== '0.0.0.0') die('Canary yalnızca yerel adreste dinler (127.0.0.1 veya Docker için 0.0.0.0).');
  ensureDir(vtPath());
  const logFile = vtPath('canary.log');
  const server = http.createServer((req, res) => {
    let size = 0;
    req.on('data', (c) => { size += c.length; });
    req.on('end', () => {
      const entry = {
        at: nowIso(), method: req.method, url: req.url, from: req.socket.remoteAddress,
        ua: req.headers['user-agent'] || '', bytes: size,
        headers: maskSecrets(JSON.stringify(req.headers)),
      };
      fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
      info(`canary isabet: ${req.method} ${req.url} ← ${entry.from}`);
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('vt-canary-ok\n');
    });
  });
  server.listen(port, host, () => {
    info(`Canary dinleniyor: http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}/vt-canary/<ID>  (Docker içinden: http://host.docker.internal:${port}/vt-canary/<ID>)`);
    info(`Log: ${logFile}  · Durdurmak için Ctrl+C`);
  });
  server.on('error', (e) => die(`Canary başlatılamadı: ${e.message}`));
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { flags: ['json', 'init', 'confirm', 'notProduction', 'show', 'canary', 'help'] });
  if (args.help || process.argv.length <= 2) { console.log(HELP); return; }

  if (args.check) {
    const r = await checkUrl(String(args.check));
    if (args.json) console.log(JSON.stringify(r));
    else console.log(`${r.ok ? 'İZİNLİ' : 'REDDEDİLDİ'}: ${args.check} — ${r.reason}`);
    process.exit(r.ok ? 0 : 2);
  }

  if (args.init) {
    if (!args.target) die('--target <url> gerekli.');
    let u;
    try { u = new URL(String(args.target)); } catch { die(`Geçersiz URL: ${args.target}`); }
    if (!args.confirm) die('Sahiplik onayı gerekli: kullanıcı "bu sistemin sahibiyim/izinliyim" dediyse --confirm ekleyin.');
    if (METADATA_HOSTS.has(u.hostname) || classifyIp(u.hostname) === 'metadata') die('Metadata hedefi kapsama eklenemez.');
    if (!TEST_LABEL.test(u.hostname) && !args.notProduction) {
      die(`"${u.hostname}" bir test ortamı adına benzemiyor. Canlı üretim YASAK (K1). Bunun staging/test olduğunu kullanıcı açıkça teyit ettiyse --not-production ekleyin.`);
    }
    const cur = readJson(SCOPE_FILE, {});
    const targets = Array.from(new Set([...(cur.targets || []), u.origin + u.pathname.replace(/\/+$/, '')]));
    writeJson(SCOPE_FILE, {
      version: 1, ...cur, targets, owner_confirmed: true,
      confirmation: 'Bu sistemin sahibiyim/izinliyim (kullanıcı onayı)',
      confirmed_at: nowIso(), environment: args.env || cur.environment || 'staging',
      allow_docker_network: cur.allow_docker_network !== false, deny: cur.deny || [],
    });
    info(`Kapsama eklendi: ${targets.join(', ')} → ${SCOPE_FILE}`);
    return;
  }

  if (args.show) {
    const s = loadScope();
    console.log(JSON.stringify({ file: SCOPE_FILE, default: ['localhost', '127.0.0.0/8', '::1', '*.localhost', 'host.docker.internal', s.allowDocker ? 'Docker iç ağı' : null].filter(Boolean), targets: s.targets, owner_confirmed: s.ownerConfirmed, deny: s.deny }, null, 2));
    return;
  }

  if (args.canary) {
    startCanary(Number(args.port || 8089), String(args.host || '127.0.0.1'));
    return;
  }
  console.log(HELP);
}

if (isMain(import.meta.url)) main().catch((e) => die(e.message));
