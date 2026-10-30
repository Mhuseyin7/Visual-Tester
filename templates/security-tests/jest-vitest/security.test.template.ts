// Visual Tester güvenlik regresyon testi şablonu — Jest ve Vitest.
// Vitest: aşağıdaki import satırını açın. Jest: globals yeterli (ts-jest/babel-jest).
// import { describe, it, expect, beforeAll } from 'vitest';
//
// İki yol: (A) uygulama nesnesi + supertest (sunucu gerekmez), (B) çalışan test sunucusuna fetch (VT_BASE_URL).
// Kullanılmayan bloğu silin. {{...}} yer tutucularını doldurun.

const BASE = process.env.VT_BASE_URL ?? 'http://localhost:3000';

async function login(email: string, password: string): Promise<string> {
  // Projenin giriş akışına göre uyarlayın: cookie döndürür.
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
    redirect: 'manual',
  });
  const cookie = res.headers.get('set-cookie') ?? '';
  if (!cookie) throw new Error(`Giriş başarısız (${res.status})`);
  return cookie.split(';')[0];
}

describe('security: {{FINDING_ID}}', () => {
  let userA = '';
  let userB = '';
  let admin = '';

  beforeAll(async () => {
    userA = await login('a@test.local', process.env.VT_USER_A_PASS ?? 'test-password-a');
    userB = await login('b@test.local', process.env.VT_USER_B_PASS ?? 'test-password-b');
    admin = await login('admin@test.local', process.env.VT_ADMIN_PASS ?? 'test-password-admin');
  });

  // IDOR / BOLA: B, A'nın kaydını görememeli.
  it('başka kullanıcının kaydına erişim reddedilir (IDOR)', async () => {
    const res = await fetch(`${BASE}{{ENDPOINT}}/{{OWNER_ID}}`, { headers: { cookie: userB } });
    expect([403, 404]).toContain(res.status);
    const own = await fetch(`${BASE}{{ENDPOINT}}/{{OWNER_ID}}`, { headers: { cookie: userA } });
    expect(own.status).toBe(200); // pozitif kontrol: sahibi erişebilmeli
  });

  // BFLA: normal kullanıcı admin fonksiyonunu çağıramaz; anonim hiç çağıramaz.
  it('admin ucu yalnızca admin içindir (BFLA)', async () => {
    const asUser = await fetch(`${BASE}/api/admin/users`, { headers: { cookie: userA } });
    expect([401, 403, 404]).toContain(asUser.status);
    const anon = await fetch(`${BASE}/api/admin/users`, { redirect: 'manual' });
    expect([301, 302, 401, 403, 404]).toContain(anon.status);
    const asAdmin = await fetch(`${BASE}/api/admin/users`, { headers: { cookie: admin } });
    expect(asAdmin.status).toBe(200);
  });

  // Mass assignment: rol alanı istemciden değiştirilemez.
  it('profil güncellemesi rol alanını yok sayar (mass assignment)', async () => {
    await fetch(`${BASE}/api/me`, {
      method: 'PATCH',
      headers: { cookie: userA, 'content-type': 'application/json' },
      body: JSON.stringify({ displayName: 'VT', role: 'admin', isAdmin: true }),
    });
    const me = await (await fetch(`${BASE}/api/me`, { headers: { cookie: userA } })).json();
    expect(me.role ?? 'user').not.toBe('admin');
    expect(me.isAdmin ?? false).toBe(false);
  });

  // SQL/NoSQL enjeksiyon: canary payload hata ya da fazladan sonuç üretmez.
  it('arama girdisi sorguya enjekte edilemez (SQLi)', async () => {
    const normal = await fetch(`${BASE}/api/search?q=${encodeURIComponent('zzz-vt-none')}`, { headers: { cookie: userA } });
    const inj = await fetch(`${BASE}/api/search?q=${encodeURIComponent("zzz-vt-none' OR '1'='1")}`, { headers: { cookie: userA } });
    expect(inj.status).toBeLessThan(500);
    const [a, b] = [await normal.json(), await inj.json()];
    expect(JSON.stringify(b).length).toBeLessThanOrEqual(JSON.stringify(a).length + 50);
  });

  // Stored/Reflected XSS: payload kaçışlı döner.
  it('kullanıcı girdisi HTML olarak yansımaz (XSS)', async () => {
    const payload = '{{PAYLOAD}}'; // örn. VT7f3a"><vt-x id=VT7f3a>
    const res = await fetch(`${BASE}/search?q=${encodeURIComponent(payload)}`);
    const html = await res.text();
    expect(html).not.toContain('<vt-x id=VT7f3a>');
  });

  // Güvenlik başlıkları (merkezi middleware düzeltmesinin regresyonu).
  it('güvenlik başlıkları mevcut', async () => {
    const res = await fetch(`${BASE}/`);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('content-security-policy') ?? '').toMatch(/frame-ancestors|default-src/);
    expect(res.headers.get('x-powered-by')).toBeNull();
  });

  // Rate limit: giriş ucunda eşik (gerçek hesap kırma değil; test hesabı, düşük sayı).
  it('giriş ucu tekrarlanan hatalı denemeleri sınırlar', async () => {
    let limited = false;
    for (let i = 0; i < 12 && !limited; i++) {
      const r = await fetch(`${BASE}/api/auth/login`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'a@test.local', password: `wrong-${i}` }),
      });
      limited = r.status === 429 || r.status === 423;
    }
    expect(limited).toBe(true);
  });
});

/* (A) supertest ile (sunucu başlatmadan):
import request from 'supertest';
import { app } from '../../src/app';
it('IDOR', async () => {
  const agentB = request.agent(app);
  await agentB.post('/api/auth/login').send({ email: 'b@test.local', password: process.env.VT_USER_B_PASS });
  await agentB.get('/api/orders/{{OWNER_ID}}').expect((r) => expect([403, 404]).toContain(r.status));
});
*/
