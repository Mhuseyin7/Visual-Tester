# Yayın öncesi kontrol listesi

Her madde: **geçti / kaldı / uygulanamaz** + kanıt (dosya:satır, komut çıktısı yolu veya headers-check satırı). Sonuç `.visual-tester/checklist.json`:
```json
{"items":[{"id":"C01","title":"Sırlar env'de","status":"pass","evidence":"secrets-scan: 0 bulgu (.visual-tester/secrets/summary.md)"}]}
```
`status`: `pass` | `fail` | `na`. `findings.mjs decision` bu dosyayı okur; eksik veya `fail` maddesi varsa karar en fazla KOŞULLU GO olur. Kaldı maddesi gerçek bir açıksa ayrıca `findings.mjs add` ile bulgu aç.

| ID | Madde | Nasıl kontrol edilir |
|---|---|---|
| C01 | Sırlar kodda ve git geçmişinde yok | secrets-scan.sh özeti |
| C02 | Sızmış/sızma şüpheli sırlar rotasyona alındı | Kullanıcı onayı (sen rotasyon yapamazsın) |
| C03 | Production env değişkenleri ayrı; `.env.example` gerçek değer içermiyor | `.env.example` okuma, deploy config |
| C04 | Debug/geliştirici modu production config'inde kapalı | stack-notes.md ilgili bayrak, config dosyası |
| C05 | HTTPS zorunlu, HTTP → HTTPS yönlendirme | headers-check.sh (staging) / proxy config |
| C06 | HSTS (`max-age` ≥ 15552000) | headers-check.sh |
| C07 | CSP tanımlı; `unsafe-inline`/`unsafe-eval` script-src'de yok veya gerekçeli | headers-check.sh |
| C08 | `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors`/XFO | headers-check.sh |
| C09 | Oturum cookie'leri `HttpOnly; Secure; SameSite` | headers-check.sh |
| C10 | CORS allowlist; kimlikli yansıtma yok | headers-check.sh + attack-playbook §4 |
| C11 | Kimlik uçlarında rate limit ve hesap kilitleme/gecikme | attack-playbook §1 eşik testi |
| C12 | Özel hata sayfaları; stack trace/sürüm sızmıyor | attack-playbook §7 verbose hata |
| C13 | Loglama: kimlik olayları ve yetki hataları loglanıyor; şifre/token loga yazılmıyor | Logger çağrıları grep (`password`, `token`, `authorization` loga gidiyor mu) |
| C14 | İzleme/uyarı: hata ve 5xx artışı için uyarı mekanizması var | Config/CI/servis tanımı (yoksa kaldı, öneri) |
| C15 | Yedekleme var ve geri yükleme EN AZ BİR KEZ denendi | db-snapshot.sh + db-restore.sh yerel deneme; production yedek politikası kullanıcıdan |
| C16 | Bağımlılık güncelleme politikası (Dependabot/Renovate) ve açık Yüksek/Kritik CVE yok | deps-audit.sh, `.github/dependabot.yml` |
| C17 | Admin erişimi kısıtlı (MFA ve/veya IP allowlist/VPN), varsayılan admin hesabı yok | Kod/config, seed dosyaları |
| C18 | `robots.txt`/`sitemap.xml` gizli yolları (admin, staging, api) ifşa etmiyor | GET /robots.txt, /sitemap.xml |
| C19 | Source map, `.git`, `.env`, yedek dosyalar yayın artefaktında yok | attack-playbook §8 hassas dosyalar |
| C20 | Container: root değil, gereksiz port yok, DB dışarı kapalı, imaj sürümü sabit | Dockerfile/compose okuma |
| C21 | Dosya yüklemeleri çalıştırılamaz dizinde, boyut limitli | attack-playbook §5 |
| C22 | E-posta/ödeme/SMS anahtarları production'da canlı, test ortamında sandbox (karışmamış) | Config okuma |
| C23 | Olay müdahale notu: sır sızarsa / hesap ele geçirilirse kim, ne yapar (1 sayfa) | `SECURITY.md` veya docs; yoksa şablon öner |
| C24 | Kapatılan her açık için regresyon testi var ve CI'da çalışıyor | `tests/security/` + CI config |

## Olay müdahale notu şablonu (C23 kaldıysa öner)

```
# Güvenlik olayı müdahale notu
İletişim: <kişi/kanal>    Yedek kişi: <...>
1. Tespit: kim fark etti, ne zaman, hangi sistem
2. Sınırlama: etkilenen anahtarları iptal/rotasyon (<sağlayıcı paneli linkleri>), şüpheli oturumları sonlandır (<komut>)
3. İnceleme: loglar <nerede>, saklama süresi <...>
4. Kurtarma: yedekten dönüş <komut/prosedür>
5. Bildirim: kullanıcılar / KVKK-GDPR yükümlülüğü (72 saat) değerlendirmesi
6. Ders: kök neden, regresyon testi, kontrol listesi güncellemesi
```
