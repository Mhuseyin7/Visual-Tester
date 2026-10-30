# Kök neden düzeltme kalıpları

İlke (K4): tek tek örnek yamalama yerine kalıbı merkezileştir. Önce aynı hatanın tüm örneklerini grep ile topla, K2 kartında hepsini birlikte öner. Her kalıpta: kök neden → merkezi çözüm → toplu bulma grep'i → doğrulama.

## İçindekiler
1. Yetkilendirme (IDOR, BFLA, mass assignment)
2. Oturum ve kimlik
3. Enjeksiyon
4. İstek sahteciliği
5. Dosya
6. İş mantığı
7. API
8. Yapılandırma ve başlıklar
9. Tedarik zinciri
10. Sırlar

---

## 1. Yetkilendirme

**Kök neden:** yetki kararı her route'ta elle ve tutarsız; nesne sahipliği kontrol edilmiyor; istemci girdisi doğrudan modele yazılıyor.

**Merkezi çözüm:**
- **Varsayılan reddet:** global auth middleware/guard; açık uçlar açık listeyle işaretlenir (`@Public()`, `AllowAnonymous`, `permitAll` yalnızca listedekiler).
- **Policy katmanı:** `can(user, action, resource)` tek yerde. Sorgu seviyesinde kapsamlama tercih edilir:
  - Express/Prisma: `prisma.order.findFirst({ where: { id, userId: req.user.id } })`
  - Django: `def get_queryset(self): return Order.objects.filter(owner=self.request.user)`
  - Laravel: `$this->authorize('view', $order)` + Policy; ya da `auth()->user()->orders()->findOrFail($id)`
  - Rails: `current_user.orders.find(params[:id])`
  - Spring: `@PreAuthorize("@orderPolicy.canView(#id, authentication)")`
  - ASP.NET: `IAuthorizationService.AuthorizeAsync(User, order, "OrderOwner")`
- **Rol kontrolü merkezde:** admin router'ının tamamına tek middleware (`router.use(requireRole('admin'))`), tek tek route'lara değil.
- **Mass assignment:** giriş DTO/şema allowlist'i (Zod/Joi/class-validator `whitelist+forbidNonWhitelisted`, DRF serializer `fields` açık listesi + `read_only_fields`, Laravel `$fillable`, Rails strong params, ASP.NET ayrı input modeli).

**Toplu bulma:** `findById(req.params`, `findByPk(`, `.get(id=`, `::find($`, `.find(params[:id])`, `findById(id)` + controller'da sahiplik yok; `create(req.body)`, `fields = '__all__'`, `$guarded = []`.
**Doğrulama:** authz-matrix.mjs yeniden; `UNEXPECTED_ALLOW` = 0.

## 2. Oturum ve kimlik

| Sorun | Merkezi çözüm |
|---|---|
| Enumeration | Tüm kimlik uçlarında tek tip mesaj ("E-posta veya şifre hatalı" / "Hesap varsa e-posta gönderildi"), sabit süreli yanıt (kullanıcı yoksa da hash hesapla) |
| Sıfırlama token'ı | `crypto.randomBytes(32)`/`secrets.token_urlsafe(32)`, DB'de hash'li sakla, 15-60 dk süre, tek kullanım, yenisi istenince eskiler iptal |
| Host header | Linkleri config'teki sabit `APP_URL`'den üret; `Host`/`X-Forwarded-Host`'a güvenme; proxy'de `ALLOWED_HOSTS` |
| Fixation | Girişte oturum yenile: `req.session.regenerate`, Django otomatik, Laravel `session()->regenerate()`, Rails `reset_session` |
| Logout | Sunucu tarafı oturum silme; JWT ise kısa ömür + refresh token iptali/denylist |
| JWT | Algoritmayı sabitle (`algorithms: ['RS256']`/`['HS256']`), ≥32 bayt rastgele sır env'de, `exp` ≤ 15 dk, `aud/iss` doğrula, `verify` kullan `decode` değil |
| Cookie | `HttpOnly; Secure; SameSite=Lax` (cross-site gerekirse `None; Secure` + CSRF token), `__Host-` öneki |
| Rate limit | Kimlik uçlarına merkezi limiter (IP + hesap anahtarlı): `express-rate-limit`, `django-ratelimit`, Laravel `throttle:`, ASP.NET `AddRateLimiter`, Spring Bucket4j, Rails `rack-attack`; artan gecikme/kilit |
| MFA | MFA tamamlanmadan oturum "kısmi" durumda; korumalı middleware kısmi oturumu reddeder; kodlar tek kullanım |

## 3. Enjeksiyon

| Sınıf | Merkezi çözüm |
|---|---|
| SQLi | Parametreli sorgu / ORM sorgu oluşturucu; ham sorgu yalnızca bağlı parametreyle (`$1`, `?`, `:name`). Sıralama/kolon adları allowlist. Toplu bul: şablon string/concat içeren `query(`, `raw(`, `execute(`. |
| NoSQLi | Şema doğrulama ile tipleri zorla (string bekleniyorsa nesne reddedilir); `mongo-sanitize` / `$`-anahtar reddi; `$where` yasak |
| XSS | Framework'ün otomatik kaçışına güven; `innerHTML/dangerouslySetInnerHTML/v-html/|safe/{!! !!}/Html.Raw/html_safe` yerine metin; zorunluysa DOMPurify/bleach ile tek merkezi `sanitizeHtml()`. Katman 2: sıkı CSP (nonce tabanlı) |
| SSTI | Kullanıcı girdisini şablon olarak değil, değişken olarak ver (`render_template('x.html', v=girdi)`) |
| Komut | Shell'siz çağrı: `execFile(cmd, [args])`, `subprocess.run([...], shell=False)`; argümanlar allowlist; mümkünse kütüphane API'si |
| Path traversal | `path.resolve(base, name)` sonrası `startsWith(base + sep)` kontrolü; dosyaya ID ile eriş, adla değil |
| XXE | Parser'da DTD/dış entity kapalı (`defusedxml`, `XMLInputFactory.SUPPORT_DTD=false`, `libxml_disable_entity_loader`/LIBXML_NONET) |
| CRLF | Başlık değerlerinde `\r\n` reddi; yönlendirme URL'leri allowlist |
| Log | Yapısal loglama (JSON), kullanıcı girdisini alan olarak; satır sonlarını kaçır |

**Merkezi giriş doğrulama:** her uçta şema (Zod/Joi/class-validator/Pydantic/DRF serializer/FormRequest/Bean Validation/strong params). Middleware ile şemasız uç bırakmamak hedeflenir.

## 4. İstek sahteciliği

- **CSRF:** framework CSRF korumasını aç (Django/Laravel/Rails varsayılan; Express `csrf-csrf`/double-submit; Spring varsayılan). SameSite=Lax + GET ile durum değiştirmeme. API sadece `Authorization` başlığı ile kimlik alıyorsa CSRF riski düşük.
- **SSRF:** dışa istek atan tek bir istemci modülü: şema allowlist (https), host allowlist; DNS çözümleyip özel/loopback/link-local IP reddi (yeniden çözümleme saldırısına karşı çözülen IP'ye bağlan); yönlendirmeleri kapat veya her adımda tekrar kontrol; metadata IP'leri engelle. Mümkünse ağ katmanında egress kısıtı.
- **Açık yönlendirme:** yalnızca göreli yol (`/` ile başlayan, `//` ve `/\` ile başlamayan) veya allowlist.
- **CORS:** sabit origin allowlist; `credentials: true` ise asla yansıtma/`*`; `null` origin reddi.
- **Clickjacking:** `Content-Security-Policy: frame-ancestors 'self'` (+ eski tarayıcılar için `X-Frame-Options: DENY`).
- **WebSocket:** handshake'te `Origin` allowlist kontrolü + token tabanlı kimlik.

## 5. Dosya

- Uzantı ve içerik (magic bytes) allowlist'i birlikte; dosya adını sunucuda üret (UUID), orijinal adı yalnızca meta olarak sakla.
- Yükleme dizini web kökü dışında veya çalıştırma kapalı (nginx `location /uploads { types {} default_type application/octet-stream; }`, PHP için `php_admin_flag engine off`).
- Kullanıcı dosyalarını ayrı origin/alt alan adından veya `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff` ile sun; SVG'yi `image/svg+xml` olarak aynı origin'den sunma.
- Boyut limiti hem proxy (`client_max_body_size`) hem uygulama (multer `limits`).
- İndirme: ID → sahiplik kontrolü → dosya yolu (path traversal + IDOR aynı yerde çözülür).

## 6. İş mantığı

- Fiyat/toplam sunucuda hesaplanır; istemciden gelen fiyat yok sayılır.
- Şema ile `quantity` pozitif tamsayı, üst sınır.
- Durum makinesi tek modülde: izinli geçişler tablosu; istemci `status` gönderemez.
- Tek kullanımlık işlemler: DB kısıtı (unique), satır kilidi (`SELECT ... FOR UPDATE`), atomik güncelleme (`UPDATE ... WHERE used = false`), idempotency anahtarı.
- Webhook: imza doğrulama (sağlayıcı SDK), timestamp toleransı, olay ID'si ile tekrar reddi.

## 7. API

- Global hata handler: production'da genel mesaj + korelasyon ID; ayrıntı yalnızca loga.
- Yanıt DTO'su/serializer allowlist'i (aşırı veri dönüşünün kök çözümü); entity'yi doğrudan döndürme.
- GraphQL: production'da introspection kapalı, derinlik/karmaşıklık limiti, alan seviyesinde yetki (resolver değil, merkezi directive/middleware).
- Merkezi rate limiter + `RateLimit-*` başlıkları.
- Eski sürümleri kaldır veya aynı auth/policy zincirine bağla; dokümantasyon uçlarını production'da kapat.
- İçerik tipi: JSON uçlarında `Content-Type: application/json` zorunlu.

## 8. Yapılandırma ve başlıklar

Tek merkezi güvenlik başlığı katmanı (helmet, `django-csp` + `SecurityMiddleware`, Laravel middleware, ASP.NET `NWebsec`/özel middleware, Spring `headers()`, Rails `content_security_policy` initializer) veya reverse proxy:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{N}'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```
- Bilgi sızdıran başlıkları kaldır (`app.disable('x-powered-by')`, `server_tokens off`, `expose_php = Off`).
- Debug yalnızca env ile ve varsayılan KAPALI (`DEBUG = env.bool('DEBUG', default=False)`).
- Statik sunucuda dizin listeleme kapalı; `.git`, `.env`, yedekler deploy artefaktına girmez (`.dockerignore`, build çıktısı).
- Docker: `USER` ile root olmayan kullanıcı, `read_only: true`, gereksiz port yok, DB yalnızca iç ağ, sabit imaj sürümü.

## 9. Tedarik zinciri

- Yükseltme: önce yama/minor sürüm; major ise changelog'u özetle ve ayrı kart. Kilit dosyasını güncelle, testleri çalıştır.
- Kullanılmayan paketleri kaldır (ayrı kart).
- CDN script'lerine `integrity` + `crossorigin="anonymous"` veya self-host.
- CI: action'ları commit SHA ile sabitle; `pull_request_target` içinde PR kodunu checkout etme.

## 10. Sırlar

- Sırrı koddan env/secret manager'a taşı; `.env.example`'da yer tutucu bırak.
- **Rotasyon şart:** git geçmişine girmiş sır, silinse de sızmış sayılır. Kullanıcıya sağlayıcı panelinden rotasyon adımını söyle (sen yapma, K8). Geçmiş temizliği (`git filter-repo`) yalnızca ayrı onayla ve uyarıyla (geçmişi yeniden yazar).
- Pre-commit: gitleaks hook önerisi.
