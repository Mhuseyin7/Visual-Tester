<?php
// Visual Tester güvenlik regresyon testi şablonu — PHPUnit (Laravel feature test).
// tests/Security/{{FINDING_ID}}Test.php olarak kaydedin. Symfony için WebTestCase + loginUser() ile aynı mantık.

namespace Tests\Security;

use App\Models\Order;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class SecurityTemplateTest extends TestCase
{
    use RefreshDatabase;

    /** {{FINDING_ID}}: B, A'nın siparişini göremez (IDOR). */
    public function test_security_idor(): void
    {
        $a = User::factory()->create();
        $b = User::factory()->create();
        $order = Order::factory()->for($a, 'user')->create();

        $this->actingAs($b)->getJson("/api/orders/{$order->id}")->assertStatus(403);
        $this->actingAs($a)->getJson("/api/orders/{$order->id}")->assertOk();
    }

    /** {{FINDING_ID}}: normal kullanıcı admin uçlarına erişemez (BFLA). */
    public function test_security_bfla(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user)->getJson('/api/admin/users')->assertForbidden();
        $this->getJson('/api/admin/users')->assertUnauthorized();
    }

    /** {{FINDING_ID}}: is_admin istemciden atanamaz (mass assignment). */
    public function test_security_mass_assignment(): void
    {
        $user = User::factory()->create(['is_admin' => false]);
        $this->actingAs($user)->patchJson('/api/me', ['name' => 'VT', 'is_admin' => true, 'role' => 'admin']);
        $this->assertFalse((bool) $user->fresh()->is_admin);
    }

    /** {{FINDING_ID}}: Blade çıktısı kaçışlı (XSS). */
    public function test_security_xss_escaped(): void
    {
        $user = User::factory()->create();
        $payload = 'VT7f3a"><vt-x id=VT7f3a>';
        $this->actingAs($user)->post('/comments', ['body' => $payload]);
        $this->actingAs($user)->get('/comments')->assertDontSee('<vt-x id=VT7f3a>', false);
    }

    /** {{FINDING_ID}}: SQL enjeksiyonu 500 üretmez ve sonuç kümesini genişletmez. */
    public function test_security_sqli(): void
    {
        $user = User::factory()->create();
        $normal = $this->actingAs($user)->getJson('/api/search?q=zzz-vt-none')->json();
        $inj = $this->actingAs($user)->getJson('/api/search?q=' . urlencode("zzz-vt-none' OR '1'='1"));
        $this->assertLessThan(500, $inj->status());
        $this->assertSameSize($normal['data'] ?? [], $inj->json('data') ?? []);
    }

    /** {{FINDING_ID}}: yüklenen PHP dosyası kabul edilmez/çalıştırılmaz. */
    public function test_security_upload_rejects_php(): void
    {
        $user = User::factory()->create();
        $file = \Illuminate\Http\UploadedFile::fake()->createWithContent('vt.php.jpg', "VT7f3a <?php echo 'VT'.(6*7); ?>");
        $this->actingAs($user)->post('/upload', ['file' => $file])->assertStatus(422);
    }

    /** {{FINDING_ID}}: güvenlik başlıkları mevcut. */
    public function test_security_headers(): void
    {
        $res = $this->get('/');
        $res->assertHeader('X-Content-Type-Options', 'nosniff');
        $this->assertNotEmpty($res->headers->get('Content-Security-Policy'));
    }
}
