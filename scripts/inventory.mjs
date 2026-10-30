#!/usr/bin/env node
// Rol bazlı tarayıcı envanteri: sayfa, link, buton, form, input, XHR/fetch/WebSocket uçları → JSON.
// Her istek scope-guard'dan geçer (K1); yıkıcı görünen butonlara tıklanmaz (K7).
import fs from 'node:fs';
import path from 'node:path';
import { checkUrl } from './scope-guard.mjs';
import { vtPath, readJson, writeJson, ensureDir, parseArgs, isMain, die, info, normalizePath, loadPlaywright, maskSecrets, nowIso } from './lib/common.mjs';

const HELP = `inventory.mjs — rol bazlı Playwright envanteri

Kullanım:
  node inventory.mjs --base <url> [--roles .visual-tester/roles.json] [seçenekler]

Seçenekler:
  --roles <dosya>          Roller ve giriş adımları (yoksa yalnızca "anon")
  --only <rol,rol>         Yalnızca bu rolleri gez
  --max-pages <n>          Rol başına en fazla sayfa (varsayılan 150)
  --max-clicks <n>         Sayfa başına en fazla güvenli buton tıklaması (varsayılan 12)
  --no-click               Butonlara hiç tıklama
  --seed <dosya>           Ek başlangıç yolları (JSON dizi: ["/admin", ...])
  --compare-routes <dosya> Kod route listesi (code-routes.json) ile karşılaştır
  --allow-third-party-static  Üçüncü taraf CSS/font/görsel/script GET'lerine izin ver (yalnızca kayıt; saldırı yok)
  --headed                 Tarayıcıyı görünür aç
  --ignore-https-errors    Self-signed staging sertifikası için
  --out <dosya>            Çıktı (varsayılan .visual-tester/inventory.json)

roles.json örneği (şifreler env: önekiyle, dosyada düz şifre tutulmaz — K8):
  {"roles":[
    {"name":"anon"},
    {"name":"userA","login":{"url":"/login","fields":{"#email":"a@test.local","#password":"env:VT_USER_A_PASS"},"submit":"button[type=submit]"}},
    {"name":"admin","storageState":".visual-tester/auth/admin.json"}]}
Giriş sonrası oturum .visual-tester/auth/<rol>.json'a kaydedilir (authz-matrix.mjs kullanır).`;

const DESTRUCTIVE = /(sil|kaldır|delete|remove|destroy|drop|purge|truncate|öde|ödeme|pay|checkout|satın|buy|order|sipariş|gönder|send|submit|kaydet|save|onayla|confirm|approve|reject|reddet|iptal|cancel|refund|iade|transfer|reset|sıfırla|ban|block|engelle|deactivate|disable|archive|arşiv|publish|yayınla|invite|davet|import|upload|yükle|logout|log out|sign out|signout|çıkış|oturumu kapat|hesab[ıi] (kapat|dondur)|close account|wipe|temizle|clear all)/i;
const LOGOUT_LINK = /(logout|log-out|signout|sign-out|cikis|çıkış|oturumu-kapat)/i;

function resolveSecret(v) {
  if (typeof v === 'string' && v.startsWith('env:')) {
    const name = v.slice(4);
    if (process.env[name] === undefined) die(`Ortam değişkeni tanımlı değil: ${name}`);
    return process.env[name];
  }
  return v;
}

async function login(page, base, role) {
  const l = role.login;
  await page.goto(new URL(l.url, base).href, { waitUntil: 'domcontentloaded', timeout: 30000 });
  for (const [sel, val] of Object.entries(l.fields || {})) await page.fill(sel, String(resolveSecret(val)));
  await Promise.all([
    page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {}),
    page.click(l.submit || 'button[type=submit]'),
  ]);
  await page.waitForTimeout(800);
  if (l.successSelector) await page.waitForSelector(l.successSelector, { timeout: 10000 });
}

async function extract(page) {
  return page.evaluate(() => {
    const vis = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
    const txt = (el) => (el.innerText || el.value || el.getAttribute('aria-label') || el.title || '').trim().slice(0, 80);
    const cssPath = (el) => {
      if (el.id) return `#${CSS.escape(el.id)}`;
      const parts = [];
      let n = el;
      while (n && n.nodeType === 1 && parts.length < 4) {
        let p = n.tagName.toLowerCase();
        if (n.getAttribute('name')) p += `[name="${n.getAttribute('name')}"]`;
        else if (n.parentElement) {
          const sib = Array.from(n.parentElement.children).filter((c) => c.tagName === n.tagName);
          if (sib.length > 1) p += `:nth-of-type(${sib.indexOf(n) + 1})`;
        }
        parts.unshift(p);
        n = n.parentElement;
      }
      return parts.join(' > ');
    };
    const inputs = (root) => Array.from(root.querySelectorAll('input,select,textarea')).map((i) => ({
      name: i.name || i.id || '', type: (i.type || i.tagName).toLowerCase(), required: i.required,
      maxlength: i.maxLength > 0 ? i.maxLength : null, pattern: i.pattern || null, min: i.min || null, max: i.max || null,
      autocomplete: i.getAttribute('autocomplete'),
    }));
    return {
      title: document.title,
      links: Array.from(document.querySelectorAll('a[href]')).map((a) => ({ href: a.href, text: txt(a), visible: vis(a) })),
      buttons: Array.from(document.querySelectorAll('button,[role=button],input[type=button],input[type=submit]')).map((b) => ({
        text: txt(b), selector: cssPath(b), type: b.type || null, inForm: !!b.closest('form'), visible: vis(b), disabled: !!b.disabled,
      })),
      forms: Array.from(document.forms).map((f) => ({
        action: f.action, method: (f.getAttribute('method') || 'GET').toUpperCase(), selector: cssPath(f),
        hasCsrfField: !!f.querySelector('input[type=hidden][name*=csrf i],input[type=hidden][name*=token i],input[name=_token]'),
        inputs: inputs(f),
      })),
      looseInputs: inputs(document).filter((_, idx) => !document.querySelectorAll('input,select,textarea')[idx].form),
      scripts: Array.from(document.scripts).filter((s) => s.src).map((s) => ({ src: s.src, integrity: !!s.integrity })),
      iframes: Array.from(document.querySelectorAll('iframe')).map((f) => f.src),
      mixedContent: location.protocol === 'https:'
        ? Array.from(document.querySelectorAll('[src^="http:"],[href^="http:"]')).map((e) => e.getAttribute('src') || e.getAttribute('href'))
        : [],
    };
  });
}

async function crawlRole(browser, base, role, opts) {
  const origin = new URL(base).origin;
  const authDir = ensureDir(vtPath('auth'));
  const statePath = role.storageState && fs.existsSync(role.storageState) ? role.storageState : null;
  const context = await browser.newContext({ ignoreHTTPSErrors: !!opts.ignoreHttpsErrors, ...(statePath ? { storageState: statePath } : {}) });
  const r = {
    role: role.name, pages: [], endpoints: {}, blocked: [], thirdParty: [], consoleErrors: [],
    brokenLinks: [], skippedDestructive: [], websockets: [], scriptsWithoutSri: new Set(),
  };
  const scopeCache = new Map();
  const inScope = async (u) => {
    const key = new URL(u).origin;
    if (!scopeCache.has(key)) scopeCache.set(key, (await checkUrl(u)).ok);
    return scopeCache.get(key);
  };

  await context.route('**/*', async (route) => {
    const req = route.request();
    const u = req.url();
    if (/^(data|blob|about):/.test(u)) return route.continue();
    if (await inScope(u)) return route.continue();
    const staticType = ['stylesheet', 'font', 'image', 'script', 'media'].includes(req.resourceType());
    if (opts.allowThirdPartyStatic && req.method() === 'GET' && staticType) {
      r.thirdParty.push(`${req.resourceType()} ${new URL(u).origin}`);
      return route.continue();
    }
    r.blocked.push(`${req.method()} ${new URL(u).origin}${new URL(u).pathname}`);
    return route.abort('blockedbyclient');
  });

  const page = await context.newPage();
  let currentPage = '';
  page.on('console', (m) => { if (m.type() === 'error') r.consoleErrors.push({ page: currentPage, text: maskSecrets(m.text()).slice(0, 300) }); });
  page.on('pageerror', (e) => r.consoleErrors.push({ page: currentPage, text: maskSecrets(String(e.message)).slice(0, 300) }));
  page.on('websocket', (ws) => r.websockets.push({ url: ws.url(), page: currentPage }));
  page.on('response', (res) => {
    const req = res.request();
    const type = req.resourceType();
    let u;
    try { u = new URL(res.url()); } catch { return; }
    if (u.origin !== origin) return;
    if (type === 'xhr' || type === 'fetch' || type === 'document' || type === 'eventsource') {
      const key = `${req.method()} ${normalizePath(u.pathname)}`;
      const e = r.endpoints[key] || (r.endpoints[key] = { method: req.method(), path: normalizePath(u.pathname), examples: [], statuses: [], type, seenOn: [] });
      if (e.examples.length < 3 && !e.examples.includes(u.pathname + u.search)) e.examples.push(u.pathname + u.search);
      if (!e.statuses.includes(res.status())) e.statuses.push(res.status());
      if (e.seenOn.length < 3 && !e.seenOn.includes(currentPage)) e.seenOn.push(currentPage);
    }
    if (type === 'document' && res.status() >= 400) r.brokenLinks.push({ url: u.pathname + u.search, status: res.status(), from: currentPage });
  });

  if (role.login) {
    try {
      await login(page, base, role);
      await context.storageState({ path: path.join(authDir, `${role.name}.json`) });
      info(`[${role.name}] giriş yapıldı, oturum kaydedildi.`);
    } catch (e) {
      r.loginError = e.message.split('\n')[0];
      info(`[${role.name}] giriş başarısız: ${r.loginError}`);
    }
  } else if (statePath) {
    fs.copyFileSync(statePath, path.join(authDir, `${role.name}.json`));
  }

  const seen = new Set();
  const queue = [{ url: base, source: 'base' }, ...opts.seeds.map((s) => ({ url: new URL(s, base).href, source: 'seed' }))];
  while (queue.length && r.pages.length < opts.maxPages) {
    const { url, source } = queue.shift();
    const u = new URL(url);
    u.hash = '';
    const key = normalizePath(u.pathname) + (u.search ? '?' : '');
    if (seen.has(key)) continue;
    seen.add(key);
    if (!(await checkUrl(u.href)).ok) { r.blocked.push(`NAV ${u.href}`); continue; }
    currentPage = u.pathname + u.search;
    let status = null;
    try {
      const resp = await page.goto(u.href, { waitUntil: 'networkidle', timeout: 20000 });
      status = resp ? resp.status() : null;
    } catch (e) {
      r.pages.push({ url: currentPage, source, error: e.message.split('\n')[0] });
      continue;
    }
    const finalUrl = new URL(page.url());
    const data = await extract(page).catch(() => null);
    if (!data) continue;
    for (const s of data.scripts) if (!s.integrity && new URL(s.src).origin !== origin) r.scriptsWithoutSri.add(s.src);
    const pg = {
      url: currentPage, finalUrl: finalUrl.origin === origin ? finalUrl.pathname + finalUrl.search : finalUrl.href,
      status, source, title: data.title,
      links: data.links.filter((l) => l.visible).map((l) => l.href).slice(0, 200),
      buttons: data.buttons.filter((b) => b.visible), forms: data.forms, looseInputs: data.looseInputs,
      iframes: data.iframes, mixedContent: data.mixedContent, clicked: [],
    };
    r.pages.push(pg);

    for (const l of data.links) {
      let lu;
      try { lu = new URL(l.href); } catch { continue; }
      if (lu.origin !== origin || LOGOUT_LINK.test(lu.pathname)) continue;
      if (/\.(pdf|zip|png|jpe?g|gif|svg|webp|ico|mp4|mp3|woff2?|css|js)$/i.test(lu.pathname)) continue;
      queue.push({ url: lu.href, source: 'link' });
    }

    if (!opts.noClick) {
      let clicks = 0;
      for (const b of pg.buttons) {
        if (clicks >= opts.maxClicks) break;
        if (b.disabled) continue;
        if (!b.text || DESTRUCTIVE.test(b.text) || (b.inForm && b.type !== 'button')) {
          r.skippedDestructive.push({ page: currentPage, text: b.text, selector: b.selector });
          continue;
        }
        try {
          await page.click(b.selector, { timeout: 3000 });
          await page.waitForTimeout(600);
          pg.clicked.push(b.text || b.selector);
          clicks++;
          if (new URL(page.url()).pathname !== finalUrl.pathname) {
            queue.push({ url: page.url(), source: 'click' });
            await page.goto(finalUrl.href, { waitUntil: 'networkidle', timeout: 20000 }).catch(() => {});
          }
        } catch { /* görünmez/kaybolan buton */ }
      }
    }
  }
  await context.close();
  return {
    ...r,
    endpoints: Object.values(r.endpoints),
    blocked: Array.from(new Set(r.blocked)),
    thirdParty: Array.from(new Set(r.thirdParty)),
    scriptsWithoutSri: Array.from(r.scriptsWithoutSri),
  };
}

function compareRoutes(result, routesFile) {
  const code = readJson(routesFile);
  const ui = new Set();
  for (const rr of Object.values(result.roles)) {
    for (const p of rr.pages) ui.add(`GET ${normalizePath(p.url)}`);
    for (const e of rr.endpoints) ui.add(`${e.method} ${e.path}`);
  }
  const codeSet = new Set(code.map((c) => `${(c.method || 'GET').toUpperCase()} ${normalizePath(c.path)}`));
  return {
    code_only: code.filter((c) => !ui.has(`${(c.method || 'GET').toUpperCase()} ${normalizePath(c.path)}`) && !(c.method || '').match(/^ALL$/i))
      .map((c) => ({ method: (c.method || 'GET').toUpperCase(), path: normalizePath(c.path), file: c.file || null })),
    ui_only: Array.from(ui).filter((k) => !codeSet.has(k)),
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { flags: ['noClick', 'headed', 'ignoreHttpsErrors', 'allowThirdPartyStatic', 'help'] });
  if (args.help || !args.base) { console.log(HELP); if (!args.help) process.exit(1); return; }
  const base = new URL(String(args.base)).href;
  const scope = await checkUrl(base);
  if (!scope.ok) die(`K1: ${scope.reason}`, 2);

  const rolesFile = args.roles || vtPath('roles.json');
  let roles = fs.existsSync(rolesFile) ? readJson(rolesFile).roles : [{ name: 'anon' }];
  if (!Array.isArray(roles) || !roles.length) die(`${rolesFile} içinde "roles" dizisi yok.`);
  if (args.only) { const only = String(args.only).split(','); roles = roles.filter((r) => only.includes(r.name)); }
  const seeds = args.seed ? readJson(String(args.seed)) : [];

  const pw = loadPlaywright();
  let browser;
  try {
    browser = await pw.chromium.launch({ headless: !args.headed });
  } catch (e) {
    die(`Chromium başlatılamadı: ${e.message.split('\n')[0]}\nKur: npx playwright install chromium`);
  }
  const opts = {
    maxPages: Number(args.maxPages || 150), maxClicks: Number(args.maxClicks || 12), noClick: !!args.noClick,
    allowThirdPartyStatic: !!args.allowThirdPartyStatic, ignoreHttpsErrors: !!args.ignoreHttpsErrors, seeds,
  };
  const result = { generated_at: nowIso(), base, roles: {} };
  try {
    for (const role of roles) {
      info(`[${role.name}] geziliyor...`);
      result.roles[role.name] = await crawlRole(browser, base, role, opts);
    }
  } finally {
    await browser.close();
  }
  if (args.compareRoutes) result.route_diff = compareRoutes(result, String(args.compareRoutes));

  const out = String(args.out || vtPath('inventory.json'));
  writeJson(out, result);
  for (const [name, rr] of Object.entries(result.roles)) {
    const forms = rr.pages.reduce((n, p) => n + (p.forms ? p.forms.length : 0), 0);
    info(`${name}: ${rr.pages.length} sayfa, ${rr.endpoints.length} uç, ${forms} form, ${rr.brokenLinks.length} kırık link, ${rr.consoleErrors.length} konsol hatası, ${rr.skippedDestructive.length} yıkıcı buton atlandı, ${rr.blocked.length} scope dışı istek engellendi${rr.loginError ? ', GİRİŞ BAŞARISIZ' : ''}`);
  }
  if (result.route_diff) info(`Kodda olup UI'da görünmeyen: ${result.route_diff.code_only.length} · UI'da olup kod listesinde olmayan: ${result.route_diff.ui_only.length}`);
  info(`Çıktı: ${out}`);
}

if (isMain(import.meta.url)) main().catch((e) => die(e.stack || e.message));
