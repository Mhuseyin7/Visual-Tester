#!/usr/bin/env node
// Kapsam matrisi: yüzey × saldırı sınıfı → test edildi / uygulanamaz / engellendi / test edilmedi.
import fs from 'node:fs';
import { vtPath, readJson, writeJson, parseArgs, isMain, die, info, nowIso } from './lib/common.mjs';

const HELP = `coverage.mjs — kapsam matrisi

Kullanım:
  node coverage.mjs init [--surfaces public,user,admin,api] [--from-inventory]
  node coverage.mjs set <yüzey> <sınıf> <durum> [--note "..."]
  node coverage.mjs render [--out .visual-tester/coverage.md]
  node coverage.mjs summary

Sınıflar: ${'authn,authz,injection,request-forgery,file,business-logic,api,infra,ui,supply-chain'}
Durumlar: tested | na | blocked | untested   (Türkçe: test-edildi | uygulanamaz | engellendi | test-edilmedi)
Veri: .visual-tester/coverage.json`;

export const CLASSES = ['authn', 'authz', 'injection', 'request-forgery', 'file', 'business-logic', 'api', 'infra', 'ui', 'supply-chain'];
export const CLASS_TR = {
  authn: 'Kimlik/oturum', authz: 'Yetkilendirme', injection: 'Enjeksiyon', 'request-forgery': 'İstek sahteciliği',
  file: 'Dosya', 'business-logic': 'İş mantığı', api: 'API', infra: 'Altyapı', ui: 'Arayüz', 'supply-chain': 'Tedarik zinciri',
};
const STATUS_ALIAS = { 'test-edildi': 'tested', uygulanamaz: 'na', engellendi: 'blocked', 'test-edilmedi': 'untested' };
const SYMBOL = { tested: '✅', na: '➖', blocked: '⛔', untested: '❓' };
const FILE = vtPath('coverage.json');

export function loadCoverage() {
  return readJson(FILE, { surfaces: [], cells: {} });
}

export function renderCoverage(cov = loadCoverage()) {
  if (!cov.surfaces.length) return '_Kapsam matrisi boş (coverage.mjs init çalıştırılmadı)._';
  const head = `| Yüzey | ${CLASSES.map((c) => CLASS_TR[c]).join(' | ')} |`;
  const sep = `|---|${CLASSES.map(() => ':-:').join('|')}|`;
  const rows = cov.surfaces.map((s) => `| ${s} | ${CLASSES.map((c) => SYMBOL[(cov.cells[`${s}|${c}`] || {}).status || 'untested']).join(' | ')} |`);
  const notes = Object.entries(cov.cells).filter(([, v]) => v.note && v.status !== 'tested')
    .map(([k, v]) => `- ${k.replace('|', ' / ')}: ${SYMBOL[v.status]} ${v.note}`);
  return [head, sep, ...rows, ...(notes.length ? ['', '**Notlar:**', ...notes] : [])].join('\n');
}

export function coverageSummary(cov = loadCoverage()) {
  const counts = { tested: 0, na: 0, blocked: 0, untested: 0 };
  const gaps = [];
  for (const s of cov.surfaces) for (const c of CLASSES) {
    const st = (cov.cells[`${s}|${c}`] || {}).status || 'untested';
    counts[st]++;
    if (st === 'untested' || st === 'blocked') gaps.push({ surface: s, class: c, status: st, note: (cov.cells[`${s}|${c}`] || {}).note || '' });
  }
  return { counts, gaps };
}

function main() {
  const args = parseArgs(process.argv.slice(2), { flags: ['fromInventory', 'help'] });
  const [cmd, ...rest] = args._;
  if (args.help || !cmd) { console.log(HELP); return; }
  const cov = loadCoverage();

  if (cmd === 'init') {
    let surfaces = args.surfaces ? String(args.surfaces).split(',').map((s) => s.trim()).filter(Boolean) : ['public', 'user', 'admin', 'api'];
    if (args.fromInventory) {
      const inv = readJson(vtPath('inventory.json'));
      surfaces = Array.from(new Set([...Object.keys(inv.roles || {}), 'api']));
    }
    cov.surfaces = Array.from(new Set([...cov.surfaces, ...surfaces]));
    cov.updated_at = nowIso();
    writeJson(FILE, cov);
    info(`Yüzeyler: ${cov.surfaces.join(', ')}`);
    return;
  }
  if (cmd === 'set') {
    const [surface, cls, statusRaw] = rest;
    const status = STATUS_ALIAS[statusRaw] || statusRaw;
    if (!surface || !cls || !status) die('Kullanım: set <yüzey> <sınıf> <durum>');
    if (!CLASSES.includes(cls)) die(`Bilinmeyen sınıf: ${cls}. Geçerli: ${CLASSES.join(', ')}`);
    if (!SYMBOL[status]) die(`Bilinmeyen durum: ${statusRaw}. Geçerli: tested, na, blocked, untested`);
    if (!cov.surfaces.includes(surface)) cov.surfaces.push(surface);
    cov.cells[`${surface}|${cls}`] = { status, note: args.note || '', at: nowIso() };
    cov.updated_at = nowIso();
    writeJson(FILE, cov);
    info(`${surface} / ${cls} → ${status}`);
    return;
  }
  if (cmd === 'render') {
    const md = renderCoverage(cov);
    const out = String(args.out || vtPath('coverage.md'));
    fs.writeFileSync(out, md + '\n');
    const { counts } = coverageSummary(cov);
    info(`✅ ${counts.tested} · ➖ ${counts.na} · ⛔ ${counts.blocked} · ❓ ${counts.untested} → ${out}`);
    return;
  }
  if (cmd === 'summary') {
    const { counts, gaps } = coverageSummary(cov);
    info(`✅ ${counts.tested} · ➖ ${counts.na} · ⛔ ${counts.blocked} · ❓ ${counts.untested}`);
    for (const g of gaps.slice(0, 15)) info(`  ${SYMBOL[g.status]} ${g.surface} / ${g.class}${g.note ? ` — ${g.note}` : ''}`);
    if (gaps.length > 15) info(`  ... ve ${gaps.length - 15} boşluk daha`);
    return;
  }
  die(`Bilinmeyen komut: ${cmd}\n${HELP}`);
}

if (isMain(import.meta.url)) {
  try { main(); } catch (e) { die(e.message); }
}
