// Visual Tester güvenlik regresyon testi şablonu — Playwright Test (arayüz düzeyi).
// Oturumlar: inventory.mjs'in ürettiği .visual-tester/auth/<rol>.json yerine projenin kendi
// global-setup'ı tercih edilir (CI'da .visual-tester bulunmaz).
import { test, expect } from '@playwright/test';

const BASE = process.env.VT_BASE_URL ?? 'http://localhost:3000';

test.describe('security: {{FINDING_ID}}', () => {
  test('stored XSS: başka kullanıcının girdiği payload çalışmaz', async ({ browser }) => {
    const a = await browser.newContext({ storageState: 'tests/security/.auth/userA.json' });
    const pa = await a.newPage();
    await pa.goto(`${BASE}/profile`);
    await pa.fill('[name="bio"]', 'VT7f3a"><img src=x onerror="window.__vt=1"><vt-x id=VT7f3a>');
    await pa.click('button:has-text("Kaydet"), button[type=submit]');

    const b = await browser.newContext({ storageState: 'tests/security/.auth/userB.json' });
    const pb = await b.newPage();
    await pb.goto(`${BASE}/users/{{OWNER_ID}}`);
    expect(await pb.evaluate(() => (window as any).__vt)).toBeUndefined();
    await expect(pb.locator('vt-x#VT7f3a')).toHaveCount(0);
    await a.close();
    await b.close();
  });

  test('UI gizli ama sunucuda kapalı: admin menüsü ve ucu normal kullanıcıya kapalı', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: 'tests/security/.auth/userA.json' });
    const page = await ctx.newPage();
    await page.goto(`${BASE}/`);
    await expect(page.getByRole('link', { name: /admin|yönetim/i })).toHaveCount(0);
    const res = await page.request.get(`${BASE}/api/admin/users`);
    expect([401, 403, 404]).toContain(res.status());
    const direct = await page.goto(`${BASE}/admin`);
    expect(page.url()).not.toMatch(/\/admin\/?$/);
    expect(direct?.status() ?? 403).not.toBe(200);
    await ctx.close();
  });

  test('DOM XSS: URL fragment/query sayfada çalışmaz', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', (m) => errors.push(m.text()));
    await page.goto(`${BASE}/search?q=${encodeURIComponent('<img src=x onerror=console.log("VT7f3a")>')}#<img src=x onerror=console.log("VT7f3a")>`);
    await page.waitForTimeout(500);
    expect(errors.join('\n')).not.toContain('VT7f3a');
  });

  test('açık yönlendirme: next parametresi dış siteye götürmez', async ({ page }) => {
    await page.goto(`${BASE}/login?next=${encodeURIComponent('//vt-canary.localhost/x')}`);
    expect(new URL(page.url()).hostname).not.toBe('vt-canary.localhost');
  });

  test('clickjacking ve CSP başlıkları', async ({ request }) => {
    const res = await request.get(`${BASE}/`);
    const csp = res.headers()['content-security-policy'] ?? '';
    expect(csp.includes('frame-ancestors') || !!res.headers()['x-frame-options']).toBe(true);
    expect(csp).not.toMatch(/script-src[^;]*'unsafe-eval'/);
  });
});
