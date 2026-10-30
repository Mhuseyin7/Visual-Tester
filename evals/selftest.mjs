#!/usr/bin/env node
// Skill'in kendisine saldırı testleri (deterministik kısım): scope kaçışı, yönlendirme kaçışı, sır maskeleme,
// K3/K4 durum makinesi, yıkıcı buton filtresi, state/hash ile devam. Ağ: yalnızca 127.0.0.1 üzerinde geçici sunucu.
// Kullanım: node evals/selftest.mjs   (çıkış 0 = hepsi geçti)
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCRIPTS = path.join(HERE, '..', 'scripts');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'vt-selftest-'));
process.env.VT_DIR = path.join(TMP, '.visual-tester');

const { checkUrl, guardedFetch } = await import(new URL('../scripts/scope-guard.mjs', import.meta.url));
const { maskSecrets } = await import(new URL('../scripts/lib/common.mjs', import.meta.url));

const results = [];
const t = (group, name, ok, detail = '') => results.push({ group, name, ok: !!ok, detail });

// 1) Scope kaçışı
const mustBlock = [
  ['canlı görünen URL', 'https://app.mycompany.com/admin'],
  ['canlı görünen URL (www)', 'https://www.example-shop.com'],
  ['özel IP aralığı 10/8', 'http://10.0.0.5/'],
  ['özel IP aralığı 192.168/16', 'http://192.168.1.10:8080/'],
  ['genel IP', 'http://8.8.8.8/'],
  ['AWS metadata', 'http://169.254.169.254/latest/meta-data/'],
  ['AWS metadata (ondalık)', 'http://2852039166/latest/'],
  ['AWS metadata (IPv6)', 'http://[fd00:ec2::254]/'],
  ['IPv4-mapped metadata', 'http://[::ffff:169.254.169.254]/'],
  ['GCP metadata', 'http://metadata.google.internal/computeMetadata/v1/'],
  ['Alibaba metadata', 'http://100.100.100.200/latest/meta-data/'],
  ['DNS ile localhost\'a çözülen dış alan (localtest.me)', 'http://localtest.me:3000/'],
  ['DNS ile localhost\'a çözülen dış alan (nip.io)', 'http://127.0.0.1.nip.io:3000/'],
  ['userinfo hilesi', 'http://localhost@evil.example/'],
  ['URL içinde kimlik', 'http://user:pass@localhost:3000/'],
  ['file şeması', 'file:///etc/passwd'],
  ['gopher şeması', 'gopher://localhost:6379/_INFO'],
];
for (const [name, url] of mustBlock) {
  const r = await checkUrl(url);
  t('scope', `reddet: ${name}`, !r.ok, r.reason);
}
for (const url of ['http://localhost:3000/', 'http://127.0.0.1:3000/x', 'http://[::1]:3000/', 'http://api.localhost/', 'http://172.18.0.2:5432/']) {
  const r = await checkUrl(url);
  t('scope', `izin ver: ${url}`, r.ok, r.reason);
}

// 1b) Yönlendirme kaçışı ve hız sınırı (yerel sunucu)
const server = http.createServer((req, res) => {
  if (req.url === '/redir-meta') { res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' }); return res.end(); }
  if (req.url === '/redir-ext') { res.writeHead(302, { location: 'https://evil.example/steal' }); return res.end(); }
  if (req.url === '/redir-local') { res.writeHead(302, { location: '/ok' }); return res.end(); }
  res.writeHead(200); res.end('ok');
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;
for (const p of ['/redir-meta', '/redir-ext']) {
  let blocked = false;
  try { await guardedFetch(base + p); } catch (e) { blocked = /K1/.test(e.message); }
  t('scope', `yönlendirme kaçışı engellenir: ${p}`, blocked);
}
const okRes = await guardedFetch(base + '/redir-local');
t('scope', 'yerel yönlendirme izlenir', okRes.status === 200);
const t0 = Date.now();
await Promise.all(Array.from({ length: 21 }, () => guardedFetch(base + '/ok')));
t('scope', 'hız sınırı (21 istek ≥ ~1 sn)', Date.now() - t0 >= 900, `${Date.now() - t0} ms`);
server.close();

// 1c) Üretim adının kapsama eklenmesi engellenir
let initBlocked = false;
try { execFileSync(process.execPath, [path.join(SCRIPTS, 'scope-guard.mjs'), '--init', '--target', 'https://app.mycompany.com', '--confirm'], { stdio: 'pipe' }); } catch { initBlocked = true; }
t('scope', 'canlı adlı hedef --init ile eklenemez', initBlocked);
let noConfirm = false;
try { execFileSync(process.execPath, [path.join(SCRIPTS, 'scope-guard.mjs'), '--init', '--target', 'https://staging.mycompany.com'], { stdio: 'pipe' }); } catch { noConfirm = true; }
t('scope', 'sahiplik onayı olmadan --init reddedilir', noConfirm);

// 2) Sır hijyeni
// Sahte değerler parçalardan birleştirilir; düz metin anahtar repoda durmaz (push protection).
const FAKE = {
  stripe: ['sk', 'live', '51HxVTfakeFAKEfake0000000000'].join('_'),
  aws: 'AKIA' + 'IOSFODNN7EXAMPLE',
  gh: 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
  jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2dC10ZXN0In0.c2lnbmF0dXJlLWZha2U',
};
const leaky = `api_key="${FAKE.stripe}" aws=${FAKE.aws} token: ${FAKE.gh}\nAuthorization: Bearer ${FAKE.jwt}\nSet-Cookie: session=abcdef123456; HttpOnly`;
const masked = maskSecrets(leaky);
for (const [k, v] of Object.entries(FAKE)) t('secrets', `maskSecrets ham ${k} bırakmaz`, !masked.includes(v));
t('secrets', 'cookie değeri maskelenir', !masked.includes('abcdef123456'));
const fnd = (args) => execFileSync(process.execPath, [path.join(SCRIPTS, 'findings.mjs'), ...args], { stdio: 'pipe', env: process.env }).toString();
fnd(['add', '--title', `Kodda Stripe anahtarı ${FAKE.stripe}`, '--class', 'secrets', '--location', 'src/pay.ts:3', '--plain', `Anahtar: ${FAKE.stripe}`]);
const fjson = fs.readFileSync(path.join(process.env.VT_DIR, 'findings.json'), 'utf8');
t('secrets', 'findings.json ham anahtar içermez', !fjson.includes(FAKE.stripe));
const rep = path.join(TMP, 'report.md');
fnd(['report', '--template', path.join(HERE, '..', 'references', 'report-template.md'), '--out', rep]);
t('secrets', 'report.md ham anahtar içermez', !fs.readFileSync(rep, 'utf8').includes(FAKE.stripe));
t('secrets', 'findings list çıktısı ham anahtar içermez', !fnd(['list']).includes(FAKE.stripe));

// 3) K3/K4 durum makinesi ve karar
const fails = (args) => { try { fnd(args); return false; } catch { return true; } };
fnd(['add', '--title', 'Admin ucu herkese açık', '--class', 'authz', '--cwe', 'CWE-285', '--severity', 'critical', '--endpoint', 'GET /api/admin/users']);
t('state-machine', 'kanıtsız doğrulandı reddedilir (K3)', fails(['update', 'VT-002', '--status', 'confirmed']));
const ev = path.join(TMP, 'ev.txt'); fs.writeFileSync(ev, 'GET /api/admin/users → 200');
fnd(['update', 'VT-002', '--status', 'confirmed', '--evidence', ev]);
t('state-machine', 'açık Kritik → NO-GO', /NO-GO/.test(fnd(['decision'])));
t('state-machine', 'retest kanıtsız kapatma reddedilir (K4)', fails(['update', 'VT-002', '--status', 'fixed-verified']));
t('state-machine', 'gerekçesiz risk kabulü reddedilir', fails(['update', 'VT-002', '--status', 'risk-accepted']));
fnd(['update', 'VT-002', '--status', 'risk-accepted', '--reason', 'test']);
t('state-machine', 'riski kabul edilmiş Kritik yine NO-GO', /NO-GO/.test(fnd(['decision'])));
fnd(['update', 'VT-002', '--status', 'fixed-verified', '--retest', ev]);
t('state-machine', 'kapatılınca NO-GO kalkar', !/NO-GO/.test(fnd(['decision'])));
t('state-machine', 'şüpheli geçersiz geçiş reddedilir', fails(['update', 'VT-001', '--status', 'fixed-verified', '--retest', ev]));

// 4) Yıkıcı buton filtresi (inventory.mjs içindeki desen)
const inv = fs.readFileSync(path.join(SCRIPTS, 'inventory.mjs'), 'utf8');
const DESTRUCTIVE = new RegExp(inv.match(/const DESTRUCTIVE = \/(.+)\/i;/)[1], 'i');
for (const label of ['Tüm kullanıcıları sil', 'Delete all users', 'Ödeme yap', 'Siparişi onayla', 'Çıkış', 'Reset database', 'E-posta gönder', 'Hesabı kapat'])
  t('destructive', `tıklanmaz: "${label}"`, DESTRUCTIVE.test(label));
for (const label of ['Menü', 'Profil', 'Sonraki sayfa', 'Filtrele', 'Detaylar'])
  t('destructive', `tıklanabilir: "${label}"`, !DESTRUCTIVE.test(label));

// 5) Kesinti/devam: state + hash
const f1 = path.join(TMP, 'a.js'); const f2 = path.join(TMP, 'b.js');
fs.writeFileSync(f1, 'x'); fs.writeFileSync(f2, 'y');
fnd(['state', 'set', 'mode', 'standard']);
fnd(['state', 'step-done', '0']); fnd(['state', 'step-done', '1']);
fnd(['state', 'hash', f1, f2]);
fs.writeFileSync(f2, 'y2');
const changed = fnd(['state', 'changed', f1, f2]).split('\n').filter((l) => l && !l.startsWith('[vt]'));
t('resume', 'yalnızca değişen dosya yeniden taranır', changed.length === 1 && changed[0] === f2, changed.join(','));
const st = JSON.parse(fs.readFileSync(path.join(process.env.VT_DIR, 'state.json'), 'utf8'));
t('resume', 'tamamlanan adımlar korunur', JSON.stringify(st.steps_done) === '[0,1]' && st.mode === 'standard');

// Rapor
const groups = {};
for (const r of results) (groups[r.group] ||= { pass: 0, fail: 0 })[r.ok ? 'pass' : 'fail']++;
for (const r of results.filter((x) => !x.ok)) console.log(`KALDI  [${r.group}] ${r.name} ${r.detail ? '— ' + r.detail : ''}`);
console.log('| Grup | Geçti | Kaldı |\n|---|---|---|');
for (const [g, c] of Object.entries(groups)) console.log(`| ${g} | ${c.pass} | ${c.fail} |`);
const failed = results.filter((r) => !r.ok).length;
console.log(`Toplam: ${results.length - failed}/${results.length} geçti`);
fs.rmSync(TMP, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
