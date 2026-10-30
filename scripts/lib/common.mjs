// Visual Tester ortak yardımcıları: yollar, argüman ayrıştırma, JSON, sır maskeleme (K8).
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const SCRIPTS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const SKILL_DIR = path.resolve(SCRIPTS_DIR, '..');
export const VT_DIR = path.resolve(process.env.VT_DIR || path.join(process.cwd(), '.visual-tester'));

export function vtPath(...parts) {
  return path.join(VT_DIR, ...parts);
}

export function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT' && fallback !== undefined) return fallback;
    if (e.code === 'ENOENT') throw new Error(`Dosya bulunamadı: ${file}`);
    throw new Error(`${file} okunamadı/ayrıştırılamadı: ${e.message}`);
  }
}

export function writeJson(file, data) {
  ensureDir(path.dirname(file));
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n');
  fs.renameSync(tmp, file);
}

// --anahtar değer, --anahtar=değer, --bayrak; geri kalanlar _ dizisine.
export function parseArgs(argv, { flags = [] } = {}) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h') { out.help = true; continue; }
    if (!a.startsWith('--')) { out._.push(a); continue; }
    const eq = a.indexOf('=');
    const key = (eq > -1 ? a.slice(2, eq) : a.slice(2)).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    if (eq > -1) { out[key] = a.slice(eq + 1); continue; }
    if (flags.includes(key) || i + 1 >= argv.length || argv[i + 1].startsWith('--')) { out[key] = true; continue; }
    out[key] = argv[++i];
  }
  return out;
}

export function isMain(metaUrl) {
  if (!process.argv[1]) return false;
  try {
    return metaUrl === pathToFileURL(fs.realpathSync(process.argv[1])).href;
  } catch {
    return metaUrl === pathToFileURL(path.resolve(process.argv[1])).href;
  }
}

export function die(msg, code = 1) {
  process.stderr.write(`[vt] HATA: ${msg}\n`);
  process.exit(code);
}

export function info(msg) {
  process.stdout.write(`[vt] ${msg}\n`);
}

// ---- K8: sır maskeleme -------------------------------------------------------
export function maskValue(v) {
  const s = String(v);
  return s.length <= 4 ? '***' : `${s.slice(0, 4)}***`;
}

const TOKEN_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g,
  /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
];
const AUTH_SCHEME = /\b(Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{8,})/gi;
const KEY_VALUE = /((?:pass(?:word)?|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|session(?:id)?|sid|jwt|auth)["']?\s*[:=]\s*["']?)([^\s"'&,;<>]{4,})/gi;
const COOKIE_HDR = /^((?:set-)?cookie\s*:\s*)(.*)$/gim;

export function maskSecrets(text) {
  if (text == null) return text;
  let s = String(text);
  for (const re of TOKEN_PATTERNS) s = s.replace(re, (m) => (m.includes('***') ? m : maskValue(m)));
  s = s.replace(AUTH_SCHEME, (m, scheme, val) => (val.includes('***') ? m : `${scheme} ${maskValue(val)}`));
  s = s.replace(COOKIE_HDR, (m, head, rest) =>
    head + rest.replace(/([^=;,\s]+)=([^;,\s]+)/g, (mm, k, v) => (/^(path|domain|expires|max-age|samesite)$/i.test(k) ? mm : `${k}=${maskValue(v)}`)));
  s = s.replace(KEY_VALUE, (m, head, val) => (val.includes('***') ? m : head + maskValue(val)));
  return s;
}

export function maskDeep(value) {
  if (typeof value === 'string') return maskSecrets(value);
  if (Array.isArray(value)) return value.map(maskDeep);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = maskDeep(v);
    return out;
  }
  return value;
}

// ---- yol normalizasyonu: /users/42 → /users/:id ----------------------------
export function normalizePath(p) {
  let s = String(p || '/').split('?')[0].split('#')[0];
  s = s.replace(/\[\.\.\.(\w+)\]|\[(\w+)\]|\{(\w+)\}|<(?:\w+:)?(\w+)>/g, ':id'); // [id] {id} <int:id>
  s = s.split('/').map((seg) => {
    if (!seg) return seg;
    if (seg.startsWith(':')) return ':id';
    if (/^\d+$/.test(seg)) return ':id';
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return ':id';
    if (/^[0-9a-f]{16,}$/i.test(seg)) return ':id';
    if (/^[A-Za-z0-9_-]{20,}$/.test(seg) && /\d/.test(seg)) return ':id';
    return seg;
  }).join('/');
  if (s.length > 1) s = s.replace(/\/+$/, '');
  return s || '/';
}

// Playwright'ı önce projenin, sonra skill'in node_modules'undan yükle.
export function loadPlaywright() {
  const bases = [process.cwd(), SKILL_DIR];
  for (const base of bases) {
    for (const name of ['playwright', 'playwright-core', '@playwright/test']) {
      try {
        const req = createRequire(path.join(base, '__vt__.cjs'));
        const mod = req(name);
        if (mod.chromium) return mod;
      } catch { /* sıradakini dene */ }
    }
  }
  die('Playwright bulunamadı. Proje kökünde kur: `npm i -D playwright && npx playwright install chromium` (onay gerekir, K2).');
}

export function nowIso() {
  return new Date().toISOString();
}
