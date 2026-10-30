#!/usr/bin/env node
// findings.json CRUD, tekilleştirme, durum makinesi (K3/K4), araç çıktısı içe aktarma, rapor/karar ve state.json.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { vtPath, readJson, writeJson, parseArgs, isMain, die, info, maskDeep, normalizePath, nowIso } from './lib/common.mjs';
import { renderCoverage, coverageSummary } from './coverage.mjs';

const HELP = `findings.mjs — bulgu yönetimi, rapor ve durum

Bulgular (.visual-tester/findings.json):
  add --title T --class C [--cwe CWE-89] [--owasp A03] [--severity high] [--confidence medium]
      [--surface admin] [--endpoint "GET /api/x/1"] [--location src/a.ts:42] [--evidence p1,p2]
      [--plain "sade anlatım"] [--root-cause "..."] [--score "E3×S3×A2=18"] [--json dosya]
  update <ID> --status <durum> [--evidence p] [--retest p] [--reason "..."] [--note "..."] [--severity s] [--fix "..."] [--commit sha]
  list [--status s] [--severity s]      show <ID>      dedupe
  import --tool semgrep|sarif|gitleaks|zap|nuclei|headers|npm-audit|authz --file <dosya>

Rapor:
  render [--out .visual-tester/findings.md]
  decision                               GO / KOŞULLU GO / NO-GO ve gerekçeler
  report --template <report-template.md> [--out .visual-tester/report.md] [--mode standard]

Durum (.visual-tester/state.json):
  state get | state set <anahtar> <değer> | state step-done <n> | state tool-missing <ad>
  state hash <dosya...> | state changed <dosya...>

Durumlar: suspected(şüpheli) → confirmed(doğrulandı) → fixed-verified(düzeltildi-doğrulandı) | risk-accepted(riski-kabul) | false-positive(yanlış-pozitif)
Önem: critical|high|medium|low|info (kritik|yüksek|orta|düşük|bilgi). Güven: high|medium|low.
Tüm alanlar kaydedilmeden önce maskelenir (K8).`;

const FILE = vtPath('findings.json');
const STATE = vtPath('state.json');
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_TR = { critical: 'Kritik', high: 'Yüksek', medium: 'Orta', low: 'Düşük', info: 'Bilgi' };
const SEV_ALIAS = { kritik: 'critical', yüksek: 'high', yuksek: 'high', orta: 'medium', düşük: 'low', dusuk: 'low', bilgi: 'info', moderate: 'medium', error: 'high', warning: 'medium', note: 'low' };
const CONF_ALIAS = { yüksek: 'high', yuksek: 'high', orta: 'medium', düşük: 'low', dusuk: 'low' };
const CONF_TR = { high: 'Yüksek', medium: 'Orta', low: 'Düşük' };
const ST_TR = { suspected: 'şüpheli', confirmed: 'doğrulandı', 'fixed-verified': 'düzeltildi-doğrulandı', 'risk-accepted': 'riski-kabul', 'false-positive': 'yanlış-pozitif' };
const ST_ALIAS = Object.fromEntries(Object.entries(ST_TR).map(([k, v]) => [v, k]));
const TRANSITIONS = {
  suspected: ['confirmed', 'false-positive'],
  confirmed: ['fixed-verified', 'risk-accepted', 'false-positive'],
  'risk-accepted': ['confirmed', 'fixed-verified'],
  'fixed-verified': ['confirmed'],
  'false-positive': ['suspected'],
};

const sev = (s) => { const v = SEV_ALIAS[String(s || '').toLowerCase()] || String(s || 'medium').toLowerCase(); if (!SEV.includes(v)) die(`Geçersiz önem: ${s}`); return v; };
const conf = (c) => { const v = CONF_ALIAS[String(c || '').toLowerCase()] || String(c || 'low').toLowerCase(); if (!CONF_TR[v]) die(`Geçersiz güven: ${c}`); return v; };
const status = (s) => { const v = ST_ALIAS[s] || s; if (!ST_TR[v]) die(`Geçersiz durum: ${s}. Geçerli: ${Object.keys(ST_TR).join(', ')}`); return v; };
const list = (v) => (v ? String(v).split(',').map((x) => x.trim()).filter(Boolean) : []);

function load() { return readJson(FILE, { version: 1, next: 1, findings: [] }); }
function save(db) { db.updated_at = nowIso(); writeJson(FILE, maskDeep(db)); }

function dedupeKey(f) {
  const where = f.location || (f.endpoint ? normalizePath(f.endpoint.replace(/^[A-Z]+\s+/, '')) : '');
  return [f.class, f.cwe || '', where, where ? (f.rule || '') : f.title].join('|').toLowerCase();
}

function addFinding(db, input, { quiet = false } = {}) {
  if (!input.title || !input.class) die('add: --title ve --class zorunlu.');
  const f = {
    title: String(input.title).slice(0, 200), class: String(input.class), rule: input.rule || null,
    cwe: input.cwe || null, owasp: input.owasp || null, severity: sev(input.severity), confidence: conf(input.confidence),
    status: 'suspected', surface: input.surface || null, endpoint: input.endpoint || null, location: input.location || null,
    evidence: list(input.evidence), plain: input.plain || null, root_cause: input.rootCause || input.root_cause || null,
    score: input.score || null, source: input.source || 'manual', related: list(input.related),
  };
  const key = dedupeKey(f);
  const dup = db.findings.find((x) => x.key === key && x.status !== 'false-positive');
  if (dup) {
    dup.evidence = Array.from(new Set([...dup.evidence, ...f.evidence]));
    dup.sources = Array.from(new Set([...(dup.sources || [dup.source]), f.source]));
    if (SEV.indexOf(f.severity) < SEV.indexOf(dup.severity) && dup.status === 'suspected') dup.severity = f.severity;
    dup.occurrences = (dup.occurrences || 1) + 1;
    if (!quiet) info(`Tekrar: ${dup.id} ile birleştirildi.`);
    return { finding: dup, duplicate: true };
  }
  const id = `VT-${String(db.next++).padStart(3, '0')}`;
  const rec = { id, key, ...f, occurrences: 1, created_at: nowIso(), history: [{ at: nowIso(), status: 'suspected', note: `kaynak: ${f.source}` }] };
  db.findings.push(rec);
  if (!quiet) info(`${id} eklendi (${SEV_TR[rec.severity]}, şüpheli).`);
  return { finding: rec, duplicate: false };
}

function existing(paths) { return paths.filter((p) => fs.existsSync(p)); }

function updateFinding(db, id, a) {
  const f = db.findings.find((x) => x.id === id);
  if (!f) die(`Bulgu yok: ${id}`);
  const ev = list(a.evidence);
  if (ev.length) f.evidence = Array.from(new Set([...f.evidence, ...ev]));
  if (a.severity) f.severity = sev(a.severity);
  if (a.confidence) f.confidence = conf(a.confidence);
  for (const k of ['plain', 'fix', 'commit', 'location', 'score', 'cwe', 'owasp']) if (a[k]) f[k] = a[k];
  if (a.rootCause) f.root_cause = a.rootCause;
  if (a.status) {
    const to = status(a.status);
    if (to !== f.status) {
      if (!TRANSITIONS[f.status].includes(to)) die(`Geçersiz geçiş: ${ST_TR[f.status]} → ${ST_TR[to]}. İzinli: ${TRANSITIONS[f.status].map((s) => ST_TR[s]).join(', ')}`);
      if (to === 'confirmed' && !existing(f.evidence).length) die('K3: "doğrulandı" için diskte var olan en az bir kanıt dosyası gerekli (--evidence).');
      if (to === 'fixed-verified') {
        if (!a.retest || !existing([a.retest]).length) die('K4: "düzeltildi-doğrulandı" için aynı saldırının tekrar sonucu gerekli (--retest <var olan dosya>).');
        f.retest = a.retest;
      }
      if ((to === 'risk-accepted' || to === 'false-positive') && !a.reason) die(`"${ST_TR[to]}" için --reason (gerekçe) zorunlu.`);
      if (a.reason) f.reason = a.reason;
      f.status = to;
    }
  }
  f.history.push({ at: nowIso(), status: f.status, note: a.note || a.reason || null });
  f.updated_at = nowIso();
  info(`${f.id} → ${ST_TR[f.status]} (${SEV_TR[f.severity]})`);
}

// ---- içe aktarma -------------------------------------------------------------
function importTool(db, tool, file) {
  const raw = fs.readFileSync(file, 'utf8');
  const items = [];
  const t = tool.toLowerCase();
  if (t === 'semgrep' || t === 'sarif') {
    const sarif = JSON.parse(raw);
    for (const run of sarif.runs || []) {
      const rules = Object.fromEntries((run.tool?.driver?.rules || []).map((r) => [r.id, r]));
      for (const r of run.results || []) {
        const loc = r.locations?.[0]?.physicalLocation;
        const tags = (rules[r.ruleId]?.properties?.tags || []).join(' ');
        const cwe = (tags.match(/CWE-\d+/) || [null])[0];
        const owasp = (tags.match(/A\d{2}:20\d\d/) || [null])[0];
        items.push({
          title: (r.message?.text || r.ruleId).split('\n')[0], class: 'static', rule: r.ruleId, cwe, owasp,
          severity: SEV_ALIAS[r.level] || 'medium', confidence: 'low',
          location: loc ? `${loc.artifactLocation?.uri}:${loc.region?.startLine || 0}` : null, source: t, evidence: file,
        });
      }
    }
  } else if (t === 'gitleaks') {
    for (const g of JSON.parse(raw || '[]')) {
      items.push({ title: `Kodda/geçmişte sır: ${g.Description || g.RuleID}`, class: 'secrets', rule: g.RuleID, cwe: 'CWE-798', owasp: 'A07',
        severity: 'high', confidence: 'medium', location: `${g.File}:${g.StartLine}${g.Commit ? `@${String(g.Commit).slice(0, 8)}` : ''}`, source: 'gitleaks', evidence: file });
    }
  } else if (t === 'zap') {
    const z = JSON.parse(raw);
    const map = { 3: 'high', 2: 'medium', 1: 'low', 0: 'info' };
    for (const site of z.site || []) for (const a of site.alerts || []) {
      const inst = a.instances?.[0] || {};
      items.push({ title: a.alert || a.name, class: 'dynamic', rule: `zap-${a.pluginid}`, cwe: a.cweid && a.cweid !== '-1' ? `CWE-${a.cweid}` : null,
        severity: map[a.riskcode] || 'low', confidence: 'low', endpoint: inst.uri ? `${inst.method || 'GET'} ${new URL(inst.uri).pathname}` : null, source: 'zap', evidence: file });
    }
  } else if (t === 'nuclei') {
    for (const line of raw.split('\n').filter(Boolean)) {
      let n;
      try { n = JSON.parse(line); } catch { continue; }
      const cwe = n.info?.classification?.['cwe-id']?.[0];
      let ep = null;
      try { ep = `GET ${new URL(n['matched-at']).pathname}`; } catch { ep = n['matched-at'] || null; }
      items.push({ title: n.info?.name || n['template-id'], class: 'dynamic', rule: n['template-id'], cwe: cwe ? cwe.toUpperCase() : null,
        severity: n.info?.severity || 'info', confidence: 'low', endpoint: ep, source: 'nuclei', evidence: file });
    }
  } else if (t === 'headers') {
    const h = JSON.parse(raw);
    for (const r of h.results || []) {
      if (r.level !== 'FAIL' && r.level !== 'WARN') continue;
      items.push({ title: r.message, class: 'infra', rule: `hdr-${r.id}`, cwe: r.cwe || 'CWE-693', owasp: 'A05',
        severity: r.level === 'FAIL' ? 'medium' : 'low', confidence: 'high', endpoint: `GET ${new URL(h.url).pathname}`, source: 'headers-check', evidence: file });
    }
  } else if (t === 'npm-audit') {
    const a = JSON.parse(raw);
    for (const [name, v] of Object.entries(a.vulnerabilities || {})) {
      if (!v.isDirect && v.severity !== 'critical') continue;
      const via = (v.via || []).find((x) => typeof x === 'object') || {};
      items.push({ title: `Bağımlılık açığı: ${name} ${v.range || ''} ${via.title ? '— ' + via.title : ''}`.trim(), class: 'supply-chain', rule: `npm-${name}`,
        cwe: (via.cwe || [])[0] || 'CWE-1395', owasp: 'A06', severity: v.severity, confidence: 'medium', location: `package.json (${name})`, source: 'npm-audit', evidence: file });
    }
  } else if (t === 'authz') {
    const m = JSON.parse(raw);
    for (const row of m.rows || []) for (const [role, r] of Object.entries(row.results || {})) {
      if (r.verdict !== 'UNEXPECTED_ALLOW') continue;
      const admin = /admin|manage|internal/i.test(row.path);
      items.push({ title: `${role} rolü ${row.method} ${row.path} ucuna beklenmedik şekilde erişebiliyor${r.body_same_as_owner ? ' (sahibiyle aynı veri)' : ''}`,
        class: 'authz', rule: `authz-${role}`, cwe: admin ? 'CWE-285' : 'CWE-639', owasp: 'A01', severity: admin || r.body_same_as_owner ? 'high' : 'medium',
        confidence: r.body_same_as_owner ? 'medium' : 'low', endpoint: `${row.method} ${row.example}`, source: 'authz-matrix', evidence: [file, r.evidence].filter(Boolean).join(',') });
    }
  } else {
    die(`Bilinmeyen araç: ${tool}`);
  }
  let added = 0;
  let dup = 0;
  for (const it of items) (addFinding(db, it, { quiet: true }).duplicate ? dup++ : added++);
  info(`${tool}: ${items.length} kayıt → ${added} yeni şüpheli, ${dup} tekrar birleştirildi.`);
}

// ---- rapor ve karar -------------------------------------------------------------
const bySev = (a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.id.localeCompare(b.id);

function table(rows) {
  if (!rows.length) return '_Yok._';
  return ['| ID | Önem | Durum | Güven | Sınıf | Kısa açıklama | Konum |', '|---|---|---|---|---|---|---|',
    ...rows.sort(bySev).map((f) => `| ${f.id} | ${SEV_TR[f.severity]} | ${ST_TR[f.status]} | ${CONF_TR[f.confidence]} | ${f.class}${f.cwe ? ` (${f.cwe})` : ''} | ${(f.plain || f.title).replace(/\|/g, '\\|')} | ${f.location || f.endpoint || '—'} |`)].join('\n');
}

export function decide(db = load()) {
  const counted = db.findings.filter((f) => ['confirmed', 'risk-accepted'].includes(f.status));
  const reasons = [];
  const blockers = counted.filter((f) => f.severity === 'critical' || f.severity === 'high');
  const checklist = readJson(vtPath('checklist.json'), null);
  const clFail = checklist ? (checklist.items || []).filter((i) => i.status === 'fail') : null;
  const unverifiedHigh = db.findings.filter((f) => f.status === 'suspected' && (f.severity === 'critical' || f.severity === 'high'));
  if (blockers.length) {
    reasons.push(`Açık veya riski kabul edilmiş Kritik/Yüksek bulgu: ${blockers.map((f) => f.id).join(', ')}`);
    return { decision: 'NO-GO', reasons };
  }
  const openMed = counted.filter((f) => f.status === 'confirmed');
  const accepted = counted.filter((f) => f.status === 'risk-accepted');
  if (openMed.length) reasons.push(`Kapatılmamış Orta/Düşük bulgu (kapatın veya riski kabul edin): ${openMed.map((f) => f.id).join(', ')}`);
  if (accepted.length) reasons.push(`Riski kabul edilmiş Orta/Düşük bulgu: ${accepted.map((f) => f.id).join(', ')}`);
  if (!checklist) reasons.push('Yayın öncesi kontrol listesi tamamlanmadı (.visual-tester/checklist.json yok).');
  else if (clFail.length) reasons.push(`Kontrol listesinde kalan madde: ${clFail.map((i) => i.id).join(', ')}`);
  if (unverifiedHigh.length) reasons.push(`Doğrulanmamış Kritik/Yüksek şüphe (puana sayılmaz, incelenmeli): ${unverifiedHigh.map((f) => f.id).join(', ')}`);
  if (reasons.length) return { decision: 'KOŞULLU GO', reasons };
  return { decision: 'GO', reasons: ['Doğrulanmış tüm bulgular kapatıldı ve yeniden test edildi; kontrol listesi geçti. Kalan risk bölümüne bakın.'] };
}

function render(db = load()) {
  return ['# Bulgular', '', table(db.findings.filter((f) => f.status !== 'false-positive')), '',
    `Yanlış-pozitif: ${db.findings.filter((f) => f.status === 'false-positive').map((f) => f.id).join(', ') || 'yok'}`].join('\n');
}

function report(templateFile, a) {
  const db = load();
  const st = readJson(STATE, {});
  const scope = readJson(vtPath('scope.json'), {});
  const tpl = fs.readFileSync(templateFile, 'utf8');
  const { decision, reasons } = decide(db);
  const pkg = readJson(path.join(process.cwd(), 'package.json'), {});
  const counted = db.findings.filter((f) => ['confirmed', 'fixed-verified', 'risk-accepted'].includes(f.status));
  const fixed = db.findings.filter((f) => f.status === 'fixed-verified').sort(bySev)
    .map((f) => `- **${f.id}** (${SEV_TR[f.severity]}) ${f.plain || f.title}\n  - Kök neden: ${f.root_cause || '—'} · Düzeltme: ${f.fix || '—'}${f.commit ? ` · commit ${f.commit}` : ''}\n  - Kanıt: ${f.evidence.join(', ') || '—'} · Yeniden test: ${f.retest}`);
  const open = db.findings.filter((f) => ['confirmed', 'risk-accepted'].includes(f.status)).sort(bySev)
    .map((f) => `- **${f.id}** (${SEV_TR[f.severity]}, ${ST_TR[f.status]}) ${f.plain || f.title} — ${f.reason ? `gerekçe: ${f.reason}` : 'neden: kullanıcı kararı bekleniyor'}`);
  const unv = db.findings.filter((f) => f.status === 'suspected').sort(bySev)
    .map((f) => `- ${f.id} (${SEV_TR[f.severity]}, güven ${CONF_TR[f.confidence]}) ${f.title} — ${f.location || f.endpoint || ''} [${f.source}]`);
  const cl = readJson(vtPath('checklist.json'), null);
  const clMd = cl ? ['| ID | Madde | Sonuç | Kanıt |', '|---|---|---|---|', ...(cl.items || []).map((i) => `| ${i.id} | ${i.title || ''} | ${{ pass: 'geçti', fail: 'kaldı', na: 'uygulanamaz' }[i.status] || i.status} | ${i.evidence || '—'} |`)].join('\n') : '_Kontrol listesi doldurulmadı._';
  const { gaps } = coverageSummary();
  const untested = [
    ...gaps.map((g) => `- ${g.surface} / ${g.class}: ${g.status === 'blocked' ? 'engellendi' : 'test edilmedi'}${g.note ? ` — ${g.note}` : ''}`),
    ...(st.tools_missing || []).map((t) => `- Araç yok: ${t}`),
  ];
  const vals = {
    PROJECT: pkg.name || path.basename(process.cwd()), DATE: new Date().toISOString().slice(0, 10),
    MODE: a.mode || st.mode || 'standard', ENVIRONMENT: scope.environment || 'localhost',
    DECISION: decision, DECISION_REASONS: reasons.map((r) => `- ${r}`).join('\n'),
    FINDINGS_TABLE: table(counted), FIXED: fixed.join('\n') || '_Yok._', OPEN: open.join('\n') || '_Yok._',
    UNVERIFIED: unv.join('\n') || '_Yok._', COVERAGE: renderCoverage(), CHECKLIST: clMd,
    UNTESTED: untested.join('\n') || '_Kapsam matrisinde boşluk yok; yine de otomatik testlerin sınırları geçerlidir._',
    SCOPE: ['localhost/Docker', ...(scope.targets || [])].join(', '),
  };
  const out = tpl.replace(/\{\{(\w+)\}\}/g, (m, k) => (k in vals ? vals[k] : m));
  const outFile = String(a.out || vtPath('report.md'));
  fs.writeFileSync(outFile, out);
  info(`Rapor iskeleti: ${outFile} · Karar: ${decision} · <!-- LLM: --> bölümlerini doldurun.`);
}

// ---- state.json -------------------------------------------------------------------
function sha(file) {
  try { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').slice(0, 20); } catch { return null; }
}
function stateCmd(sub, rest) {
  const st = readJson(STATE, { steps_done: [], surfaces: {}, hashes: {}, tools_missing: [] });
  const persist = () => { st.updated_at = nowIso(); writeJson(STATE, st); };
  if (sub === 'get' || !sub) { console.log(JSON.stringify({ ...st, hashes: `${Object.keys(st.hashes).length} dosya` }, null, 2)); return; }
  if (sub === 'set') { if (rest.length < 2) die('state set <anahtar> <değer>'); st[rest[0]] = rest.slice(1).join(' '); persist(); info(`${rest[0]} = ${st[rest[0]]}`); return; }
  if (sub === 'step-done') { const n = Number(rest[0]); if (Number.isNaN(n)) die('state step-done <n>'); if (!st.steps_done.includes(n)) st.steps_done.push(n); st.steps_done.sort((x, y) => x - y); persist(); info(`Tamamlanan adımlar: ${st.steps_done.join(', ')}`); return; }
  if (sub === 'tool-missing') { for (const t of rest) if (!st.tools_missing.includes(t)) st.tools_missing.push(t); persist(); return; }
  if (sub === 'surface') { st.surfaces[rest[0]] = rest[1] || 'done'; persist(); return; }
  if (sub === 'hash') { for (const f of rest) st.hashes[f] = sha(f); persist(); info(`${rest.length} dosya hash'lendi.`); return; }
  if (sub === 'changed') {
    const changed = rest.filter((f) => st.hashes[f] !== sha(f));
    console.log(changed.join('\n'));
    info(`${changed.length}/${rest.length} dosya değişmiş veya yeni.`);
    return;
  }
  die(`Bilinmeyen state komutu: ${sub}`);
}

function main() {
  const args = parseArgs(process.argv.slice(2), { flags: ['help'] });
  const [cmd, ...rest] = args._;
  if (args.help || !cmd) { console.log(HELP); return; }
  if (cmd === 'state') return stateCmd(rest[0], rest.slice(1));
  const db = load();
  switch (cmd) {
    case 'add': {
      const input = args.json ? readJson(String(args.json)) : args;
      const arr = Array.isArray(input) ? input : [input];
      for (const it of arr) addFinding(db, it);
      save(db);
      break;
    }
    case 'update':
      if (!rest[0]) die('update <ID> ...');
      updateFinding(db, rest[0], args);
      save(db);
      break;
    case 'import':
      if (!args.tool || !args.file) die('import --tool <ad> --file <dosya>');
      importTool(db, String(args.tool), String(args.file));
      save(db);
      break;
    case 'dedupe': {
      const before = db.findings.length;
      const fresh = { ...db, next: db.next, findings: [] };
      for (const f of db.findings) {
        f.key = dedupeKey(f);
        const d = fresh.findings.find((x) => x.key === f.key && x.status === f.status);
        if (d) { d.evidence = Array.from(new Set([...d.evidence, ...f.evidence])); d.occurrences += f.occurrences || 1; } else fresh.findings.push(f);
      }
      save(fresh);
      info(`${before} → ${fresh.findings.length} bulgu.`);
      break;
    }
    case 'list': {
      let rows = db.findings;
      if (args.status) rows = rows.filter((f) => f.status === status(String(args.status)));
      if (args.severity) rows = rows.filter((f) => f.severity === sev(String(args.severity)));
      for (const f of rows.sort(bySev)) console.log(`${f.id}  ${SEV_TR[f.severity].padEnd(6)} ${ST_TR[f.status].padEnd(22)} ${f.class.padEnd(14)} ${f.title.slice(0, 70)}`);
      info(`${rows.length} bulgu.`);
      break;
    }
    case 'show': {
      const f = db.findings.find((x) => x.id === rest[0]);
      if (!f) die(`Bulgu yok: ${rest[0]}`);
      console.log(JSON.stringify(f, null, 2));
      break;
    }
    case 'render': {
      const out = String(args.out || vtPath('findings.md'));
      fs.writeFileSync(out, render(db) + '\n');
      info(`Yazıldı: ${out}`);
      break;
    }
    case 'decision': {
      const d = decide(db);
      console.log(`KARAR: ${d.decision}`);
      for (const r of d.reasons) console.log(`- ${r}`);
      break;
    }
    case 'report':
      if (!args.template) die('report --template <report-template.md>');
      report(String(args.template), args);
      break;
    default:
      die(`Bilinmeyen komut: ${cmd}\n${HELP}`);
  }
}

if (isMain(import.meta.url)) {
  try { main(); } catch (e) { die(e.message); }
}
