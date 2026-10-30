# Güvenlik regresyon testi şablonları

Her kapatılan açık için en az bir test (SKILL.md adım 6). Testler `tests/security/` altına, projenin mevcut test çatısıyla yazılır.

| Çatı | Şablon | Ne zaman |
|---|---|---|
| Jest / Vitest | `jest-vitest/security.test.template.ts` | Node/TS backend, Next.js route handler'lar |
| Pytest | `pytest/test_security_template.py` | Django, Flask, FastAPI |
| PHPUnit | `phpunit/SecurityTest.template.php` | Laravel, Symfony |
| Playwright | `playwright/security.spec.template.ts` | Arayüz: stored XSS, gizli menü/sunucu yetkisi, CSP |

## Yer tutucular

| Yer tutucu | Anlamı |
|---|---|
| `{{FINDING_ID}}` | VT-007 gibi bulgu kimliği (test adında geçer; rapordan izlenebilir) |
| `{{BASE_URL}}` | Varsayılan `process.env.VT_BASE_URL` / `os.environ["VT_BASE_URL"]` |
| `{{ENDPOINT}}`, `{{METHOD}}` | Saldırının yapıldığı uç |
| `{{OWNER_ID}}`, `{{OTHER_ID}}` | Kullanıcı A ve B'nin seed kayıt kimlikleri |
| `{{PAYLOAD}}` | Saldırıda kullanılan zararsız canary payload |

## Kurallar

1. **Test, açığı yakalamalı:** düzeltme geçici olarak geri alındığında test KIRILMALI (SKILL.md adım 6). Kırılmıyorsa test yanlış şeyi ölçüyor.
2. **Saldırının aynısı:** K4'teki yeniden doğrulama isteği teste dönüştürülür; aynı uç, aynı rol, aynı payload.
3. **Sır yok:** test hesap şifreleri env'den (`VT_USER_A_PASS`), fixture'dan veya framework'ün test yardımcılarından (`actingAs`, `force_login`) gelir.
4. **Yalnızca test veritabanı:** framework'ün test DB'si / transaction rollback.
5. **İsim:** `security: {{FINDING_ID}} <kısa açıklama>`; dosya `tests/security/<sınıf>.test.*`.
6. Uygulama içi test yardımcısı varsa (supertest, Django test client, Laravel HTTP tests) HTTP yerine onu tercih et: hızlı ve sunucu gerektirmez. Şablonlar her iki yolu da gösterir.
