#!/usr/bin/env node
// Rol × endpoint erişim matrisi: beklenen (expect.json) ile gerçeği karşılaştırır. IDOR için her uç,
// onu gözlemleyen rolün örnek URL'iyle diğer rollerden de istenir. Yazma metodları varsayılan kapalı (K7).
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { guardedFetch, checkUrl } from './scope-guard.mjs';
import { vtPath, readJson, writeJson, ensureDir, parseArgs, isMain, die, info, normalizePath, maskSecrets, nowIso } from './lib/common.mjs';

const HELP = `authz-matrix.mjs — rol × endpoint erişim matrisi

Kullanım:
  node authz-matrix.mjs --base <url> [--inventory .visual-tester/inventory.json] [--endpoints <dosya>]
                        [--roles .visual-tester/roles.json] [--expect .visual-tester/expect.json]
                        [--methods GET,HEAD] [--allow-write] [--save-bodies] [--out <önek>]

Girdi:
  --endpoints   Ek uç listesi: [{"method":"GET","path":"/api/users/1"}] (ör. code-routes'tan somut örnekler)
  --roles       Rol adları; oturum .visual-tester/auth/<rol>.json (inventory.mjs üretir) veya rol.headers
                ör. {"name":"apiUser","headers":{"Authorization":"env:VT_API_TOKEN"}}
  --expect      {"rules":[{"pattern":"^/admin","allow":["admin"]},{"pattern":"^/api/orders/:id","allow":["owner","admin"]},
                          {"pattern":"^/api/public","allow":["*"]},{"pattern":"^/api/me","allow":["authenticated"]}]}
                "owner" = uçu gözlemleyen rol (IDOR denetimi). Eşleşmeyen uç "bilinmiyor" olarak işaretlenir.
  --allow-write POST/PUT/PATCH/DELETE gönderir; yalnızca .visual-tester/db/latest snapshot varsa çalışır (K7).

Çıktı: .visual-tester/authz-matrix.json ve .md. UNEXPECTED_ALLOW satırları doğrulanacak bulgu adaylarıdır.`;

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);
const LOGIN_HINT = /(login|signin|sign-in|giris|giriş|auth)/i;

function envValue(v) {
  if (typeof v === 'string' && v.startsWith('env:')) {
    const val = process.env[v.slice(4)];
    if (val === undefined) die(`Ortam değişkeni tanımlı değil: ${v.slice(4)}`);
    return val;
  }
  return v;
}

function cookieHeaderFor(state, url) {
  if (!state || !Array.isArray(state.cookies)) return '';
  const u = new URL(url);
  const now = Date.now() / 1000;
  return state.cookies.filter((c) => {
    const d = (c.domain || '').replace(/^\./, '').toLowerCase();
    const hostOk = u.hostname === d || u.hostname.endsWith('.' + d);
    const pathOk = u.pathname.startsWith(c.path || '/');
    const secureOk = !c.secure || u.protocol === 'https:' || u.hostname === 'localhost';
    const alive = !c.expires || c.expires < 0 || c.expires > now;
    return hostOk && pathOk && secureOk && alive;
  }).map((c) => `${c.name}=${c.value}`).join('; ');
}

function classify(res) {
  const s = res.status;
  if (s >= 200 && s < 300) return 'allow';
  if (s === 401 || s === 403) return 'deny';
  if (s >= 300 && s < 400) return LOGIN_HINT.test(res.headers.get('location') || '') ? 'deny' : 'redirect';
  if (s === 404) return 'notfound';
  if (s === 405) return 'method';
  if (s >= 500) return 'error';
  return 'other';
}

function expectationFor(rules, method, normPath, role, observedBy) {
  for (const r of rules) {
    if (r.method && r.method.toUpperCase() !== method) continue;
    if (!new RegExp(r.pattern).test(normPath)) continue;
    const allow = r.allow || [];
    if (allow.includes('*')) return 'allow';
    if (allow.includes(role)) return 'allow';
    if (allow.includes('authenticated') && role !== 'anon') return 'allow';
    if (allow.includes('owner') && observedBy.includes(role)) return 'allow';
    return 'deny';
  }
  return 'unknown';
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { flags: ['allowWrite', 'saveBodies', 'help'] });
  if (args.help || !args.base) { console.log(HELP); if (!args.help) process.exit(1); return; }
  const base = new URL(String(args.base)).href;
  const sc = await checkUrl(base);
  if (!sc.ok) die(`K1: ${sc.reason}`, 2);

  const methods = new Set(String(args.methods || 'GET,HEAD').toUpperCase().split(','));
  const unsafe = [...methods].filter((m) => !SAFE.has(m));
  if (unsafe.length && !args.allowWrite) die(`Yazma metodları (${unsafe.join(',')}) için --allow-write gerekli (K7).`);
  if (args.allowWrite && !fs.existsSync(vtPath('db', 'latest'))) die('K7: --allow-write öncesi db-snapshot.sh ile snapshot alın (.visual-tester/db/latest yok).');

  const rolesCfg = readJson(String(args.roles || vtPath('roles.json')), { roles: [{ name: 'anon' }] }).roles;
  const roles = rolesCfg.map((r) => {
    const sp = vtPath('auth', `${r.name}.json`);
    return { name: r.name, state: fs.existsSync(sp) ? readJson(sp) : null, headers: Object.fromEntries(Object.entries(r.headers || {}).map(([k, v]) => [k, envValue(v)])) };
  });
  if (!roles.some((r) => r.name === 'anon')) roles.unshift({ name: 'anon', state: null, headers: {} });

  // Uçları topla: inventory (gözlemleyen rol + somut örnek) + ek liste.
  const eps = new Map();
  const add = (method, examplePath, observedBy) => {
    const m = method.toUpperCase();
    if (!methods.has(m)) return;
    const key = `${m} ${normalizePath(examplePath)}`;
    const e = eps.get(key) || { method: m, path: normalizePath(examplePath), example: examplePath, observedBy: [] };
    if (observedBy && !e.observedBy.includes(observedBy)) e.observedBy.push(observedBy);
    eps.set(key, e);
  };
  const invFile = String(args.inventory || vtPath('inventory.json'));
  if (fs.existsSync(invFile)) {
    const inv = readJson(invFile);
    for (const [rname, rr] of Object.entries(inv.roles || {})) {
      for (const e of rr.endpoints || []) add(e.method, (e.examples && e.examples[0]) || e.path, rname);
      for (const p of rr.pages || []) if (!p.error) add('GET', p.url, rname);
    }
  }
  if (args.endpoints) for (const e of readJson(String(args.endpoints))) add(e.method || 'GET', e.path, e.observedBy || null);
  if (!eps.size) die('Uç bulunamadı. Önce inventory.mjs çalıştırın veya --endpoints verin.');

  const rules = args.expect || fs.existsSync(vtPath('expect.json')) ? readJson(String(args.expect || vtPath('expect.json'))).rules || [] : [];
  const bodyDir = args.saveBodies ? ensureDir(vtPath('evidence', 'authz')) : null;
  const rows = [];
  for (const e of eps.values()) {
    if (e.example.includes(':id')) { rows.push({ ...e, skipped: 'somut örnek yok (:id)' }); continue; }
    const url = new URL(e.example, base).href;
    const row = { method: e.method, path: e.path, example: e.example, observedBy: e.observedBy, results: {} };
    for (const role of roles) {
      const headers = { ...role.headers, 'x-vt-scan': 'visual-tester' };
      const cookie = cookieHeaderFor(role.state, url);
      if (cookie) headers.cookie = cookie;
      if (!SAFE.has(e.method)) headers['content-type'] = 'application/json';
      let res;
      try {
        res = await guardedFetch(url, { method: e.method, headers, followRedirects: false, body: SAFE.has(e.method) ? undefined : '{}' });
      } catch (err) {
        row.results[role.name] = { error: err.message.slice(0, 160) };
        continue;
      }
      const buf = Buffer.from(await res.arrayBuffer());
      const hash = crypto.createHash('sha256').update(buf).digest('hex').slice(0, 16);
      const actual = classify(res);
      const expected = expectationFor(rules, e.method, e.path, role.name, e.observedBy);
      let verdict = 'OK';
      if (expected === 'unknown') verdict = 'REVIEW';
      else if (expected === 'deny' && actual === 'allow') verdict = 'UNEXPECTED_ALLOW';
      else if (expected === 'allow' && actual === 'deny') verdict = 'UNEXPECTED_DENY';
      row.results[role.name] = { status: res.status, actual, expected, verdict, bytes: buf.length, hash };
      if (bodyDir && verdict === 'UNEXPECTED_ALLOW') {
        const f = path.join(bodyDir, `${role.name}_${e.method}_${e.path.replace(/[^\w]+/g, '_')}.txt`);
        fs.writeFileSync(f, maskSecrets(`${e.method} ${e.example}\nrole=${role.name} status=${res.status}\n\n${buf.toString('utf8').slice(0, 4000)}`));
        row.results[role.name].evidence = f;
      }
    }
    // IDOR sinyali: sahip olmayan rol, sahibinin aldığı aynı gövdeyi alıyor mu?
    for (const [rn, rres] of Object.entries(row.results)) {
      if (!rres.hash || e.observedBy.includes(rn)) continue;
      const owner = e.observedBy.map((o) => row.results[o]).find((x) => x && x.hash);
      if (owner && owner.actual === 'allow' && rres.actual === 'allow' && rres.hash === owner.hash && rres.bytes > 2) rres.body_same_as_owner = true;
    }
    rows.push(row);
  }

  const outBase = String(args.out || vtPath('authz-matrix'));
  writeJson(`${outBase}.json`, { generated_at: nowIso(), base, roles: roles.map((r) => r.name), methods: [...methods], rows });
  const roleNames = roles.map((r) => r.name);
  const sym = (x) => (!x ? '—' : x.error ? 'ERR' : `${x.status}${x.verdict === 'UNEXPECTED_ALLOW' ? ' ⚠️' : x.verdict === 'UNEXPECTED_DENY' ? ' ✋' : x.verdict === 'REVIEW' ? ' ?' : ''}${x.body_same_as_owner ? ' =' : ''}`);
  const md = [
    `# Rol × endpoint matrisi (${nowIso()})`, '',
    '⚠️ beklenmeyen erişim · ✋ beklenmeyen ret · ? beklenti tanımsız · = sahibiyle aynı gövde (IDOR sinyali)', '',
    `| Uç | ${roleNames.join(' | ')} |`, `|---|${roleNames.map(() => '---').join('|')}|`,
    ...rows.filter((r) => !r.skipped).map((r) => `| \`${r.method} ${r.path}\` | ${roleNames.map((n) => sym(r.results[n])).join(' | ')} |`),
  ];
  const skipped = rows.filter((r) => r.skipped);
  if (skipped.length) md.push('', `Atlanan (${skipped.length}): ${skipped.slice(0, 20).map((r) => `${r.method} ${r.path}`).join(', ')}`);
  fs.writeFileSync(`${outBase}.md`, md.join('\n') + '\n');

  const flat = rows.flatMap((r) => Object.entries(r.results || {}).map(([rn, x]) => ({ ...x, role: rn, ep: `${r.method} ${r.path}` })));
  const ua = flat.filter((x) => x.verdict === 'UNEXPECTED_ALLOW');
  const idor = flat.filter((x) => x.body_same_as_owner);
  info(`${rows.length} uç × ${roleNames.length} rol · UNEXPECTED_ALLOW: ${ua.length} · UNEXPECTED_DENY: ${flat.filter((x) => x.verdict === 'UNEXPECTED_DENY').length} · REVIEW: ${flat.filter((x) => x.verdict === 'REVIEW').length} · IDOR sinyali: ${idor.length}`);
  for (const x of ua.slice(0, 10)) info(`  ⚠️ ${x.role} → ${x.ep} (${x.status})${x.body_same_as_owner ? ' [sahibiyle aynı gövde]' : ''}`);
  if (ua.length > 10) info(`  ... ve ${ua.length - 10} tane daha`);
  info(`Çıktı: ${outBase}.md / .json`);
}

if (isMain(import.meta.url)) main().catch((e) => die(e.stack || e.message));
