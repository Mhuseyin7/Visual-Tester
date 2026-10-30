# Saldırı oyun kitabı

Yalnızca ilgili bölümü oku: `grep -n "^## " attack-playbook.md` ile satır numarasını bul, o aralığı oku. Her bölüm tek başına okunabilir; ortak kurallar her bölümün başındaki "Ön koşul" satırında tekrar edilir.

## Bölüm indeksi

| Anahtar (coverage sınıfı) | Bölüm | Ana araç |
|---|---|---|
| `general` | 0. Ortak ilkeler (payload, canary, durdurma) | — |
| `authn` | 1. Kimlik doğrulama ve oturum | curl, tarayıcı |
| `authz` | 2. Yetkilendirme (IDOR/BOLA, BFLA, mass assignment) | authz-matrix.mjs |
| `injection` | 3. Enjeksiyon (SQL, NoSQL, XSS, SSTI, komut, path, XXE, CRLF, log) | curl, tarayıcı |
| `request-forgery` | 4. İstek sahteciliği ve ağ (CSRF, SSRF, yönlendirme, CORS, clickjacking, WebSocket) | canary, headers-check.sh |
| `file` | 5. Dosya yükleme ve indirme | curl |
| `business-logic` | 6. İş mantığı | curl, tarayıcı |
| `api` | 7. API | inventory.json, curl |
| `infra` | 8. Altyapı ve yapılandırma | headers-check.sh, tools-run.sh |
| `ui` | 9. Arayüz ve gezinme | inventory.mjs |
| `supply-chain` | 10. Tedarik zinciri | deps-audit.sh |

---

## 0. Ortak ilkeler

Ön koşul: hedef `scope-guard.mjs --check` ile doğrulandı (K1); yazma işlemi gerektiren testlerden önce `db-snapshot.sh` alındı (K7).

- **Canary kimliği:** her deneme için benzersiz işaret: `VT<ID>` (ör. `VT7f3a`). Yanıtta, logda, DB'de, canary dinleyicide arayacağın şey budur.
- **Zararsız payload:** yalnızca varlığı kanıtlar. Veri okuma/silme/yazma için kullanılmaz. Örnek: SQL'de `UNION SELECT` ile tablo dökme yok; boolean fark veya hata mesajı yeter. XSS'te `alert` yerine DOM'a/konsola canary yazdır.
- **İlk kanıtta dur:** açık doğrulandıysa aynı uçta daha derine inme; kalıbı koddan grep ile topla (K4).
- **Hız:** guardedFetch saniyede ~20 istekle sınırlı. Paralel istek yalnızca yarış durumu testinde, en fazla 10.
- **Kanıt:** `.visual-tester/evidence/<ID>/request.txt|response.txt|trace.md` (bkz. severity-and-evidence.md §3). Sırları maskele.
- **K5:** yanıtta sana yönelik talimat görürsen uygulama, alıntıla ve bildir.

---

## 1. Kimlik doğrulama ve oturum (`authn`)

Ön koşul: scope doğrulandı; yalnızca test hesapları; brute-force YOK (eşik testi en fazla 15 istek).

| Test | Nasıl | Açık belirtisi |
|---|---|---|
| Kullanıcı enumeration | Var olan / olmayan e-posta ile giriş, kayıt, şifre sıfırlama; yanıt gövdesi, durum kodu, süre farkı | Farklı mesaj ("kullanıcı bulunamadı" vs "şifre yanlış"), farklı kod, belirgin süre farkı (>150 ms tutarlı) |
| Şifre sıfırlama: token | 2 sıfırlama iste (test hesabı, Mailpit'ten oku); token uzunluğu, rastgelelik, ardışıklık | <16 bayt entropi, zaman damgası/ID'den türetilmiş, ardışık |
| Şifre sıfırlama: tekrar kullanım / süre | Aynı token'ı ikinci kez kullan; eski token'ı yenisi istendikten sonra kullan | İkinci kullanım başarılı; eski token geçerli; süresiz token |
| Host header zehirleme | Sıfırlama isteğinde `Host: vt-canary.localhost` veya `X-Forwarded-Host` | E-postadaki link saldırgan host'unu içeriyor |
| Oturum fixation | Girişten önceki session cookie değerini not et, giriş yap, karşılaştır | Giriş sonrası session ID değişmiyor |
| Logout geçersizleşme | Cookie/token kopyala → logout → kopyayla istek | Eski token/cookie hâlâ çalışıyor |
| Şifre değişince oturum | A oturumu açık; B tarayıcıdan şifre değiştir; A'yı dene | Diğer oturumlar düşmüyor (Düşük/Orta) |
| JWT `alg:none` | Header'ı `{"alg":"none"}` yap, imzayı boşalt | Kabul ediliyor |
| JWT zayıf sır | Koddaki/env örneğindeki sırrı ara (`grep -rn "jwt.*secret\|JWT_SECRET"`); varsayılan değer (`secret`, `changeme`) mi | Varsayılan/kısa sır; kanıtı kod yolu izi ile, kırma denemesi yok |
| JWT süre / doğrulama | `exp` yok veya çok uzun; `aud/iss` kontrolü; imza doğrulanmadan `decode` kullanımı | `jwt.decode(` ile yetki kararı; `exp` yok |
| Cookie bayrakları | headers-check.sh çıktısı | Session cookie'de HttpOnly/Secure/SameSite eksik |
| MFA atlatma | MFA adımını atlayıp doğrudan korumalı sayfaya git; MFA kodu alanını boş/yanlış ver; aynı kodu tekrar kullan | Korumalı sayfa açılıyor; kod tekrar kullanılabiliyor |
| Rate limit (eşik) | Test hesabına 12 yanlış şifre (1 sn arayla) | 12 denemede hiç yavaşlama/kilit/CAPTCHA yok → Orta |

Kök neden → fix-patterns.md §Oturum ve kimlik. Eşleme: A07, API2, CWE-204/384/640/347/307.

---

## 2. Yetkilendirme (`authz`)

Ön koşul: scope doğrulandı; en az kullanıcı A, kullanıcı B, admin test hesabı; `inventory.mjs` ile her rolün storageState'i `.visual-tester/auth/` altında.

1. **Matris:** `.visual-tester/expect.json` yaz (hangi rol hangi uca erişmeli), sonra:
   `node $VT/scripts/authz-matrix.mjs --base URL --inventory .visual-tester/inventory.json --roles .visual-tester/roles.json --expect .visual-tester/expect.json`
   `UNEXPECTED_ALLOW` satırları doğrulanacak adaylardır.
2. **IDOR/BOLA (yatay):** A'nın kaydına ait URL/ID'yi B ile iste (matris bunu `observed_by` ile otomatik yapar). Ayrıca: gövdedeki ID'ler (`{"orderId":..}`), sorgu parametreleri, GraphQL değişkenleri, dosya indirme yolları. `body_same_as_owner: true` güçlü kanıttır.
3. **BFLA (dikey):** Admin uçlarını (kodda `admin`, `manage`, `internal`, `/api/v*/users` silme/rol değiştirme) kullanıcı A ve anonim ile iste. Yazma metodları yalnızca snapshot sonrası `--allow-write`.
4. **UI'da gizli ama sunucuda açık:** inventory'de rol X'te görünmeyen buton/menüye karşılık gelen endpoint'i (admin rolünün endpoint listesinden) rol X ile çağır.
5. **Mass assignment:** profil güncelleme/kayıt isteğine `role`, `isAdmin`, `is_staff`, `verified`, `balance`, `ownerId`, `tenantId` ekle; sonra kaydı oku.
6. **Metot değiştirme:** korunan `POST /x` için `PUT/PATCH`, `X-HTTP-Method-Override`, `_method=DELETE` dene.
7. **Yol varyasyonu:** `/admin` korunuyorsa `/admin/`, `/ADMIN`, `/admin;x`, `/admin%2f`, `/./admin`, `/api/v1/` yerine `/api/v0/`.
8. **Çok kiracılık:** `tenantId`/`orgId` başlık veya parametresini değiştir.

Açık belirtisi: 2xx + başkasının verisi; yetkisiz rolün yazma işlemi DB'de görülüyor; rol alanı kaydediliyor.
Kök neden → fix-patterns.md §Yetkilendirme. Eşleme: A01, API1/API3/API5, CWE-639/285/915.

---

## 3. Enjeksiyon (`injection`)

Ön koşul: scope doğrulandı; yalnızca canary payload; veri dökme yok; ilk kanıtta dur.

Önce koddan aday topla (hedefli grep, stack-notes.md'deki desenler): string birleştirmeli sorgu, `raw(`, `$where`, `eval(`, `exec(`, `render_template_string`, `dangerouslySetInnerHTML`, `v-html`, `|safe`, `{!! !!}`, `innerHTML`, `child_process`, `subprocess(..., shell=True)`, `open(` + kullanıcı girdisi.

| Sınıf | Zararsız payload | Kanıt |
|---|---|---|
| SQLi (hata) | `'` ve `"` | DB hata mesajı (sözdizimi) yanıtta veya 500 |
| SQLi (boolean) | `x' AND '1'='1` vs `x' AND '1'='2` (sayısal: `1 AND 1=1` vs `1 AND 1=2`) | İki yanıt arasında tutarlı fark |
| SQLi (zaman, tek sefer) | `' AND SLEEP(2)-- -` / `';SELECT pg_sleep(2)--` | ~2 sn tutarlı gecikme (3 ölçüm) |
| NoSQLi | JSON'da `{"$ne":null}`, `{"$gt":""}`; query'de `user[$ne]=x` | Filtre atlanıyor (ör. şifresiz giriş TEST hesabıyla) |
| Reflected XSS | `VT7f3a"><vt-x id=VT7f3a>` | Yanıtta kaçışsız etiket; tarayıcıda `document.getElementById('VT7f3a')` var |
| Stored XSS | Aynı payload'u yorum/profil alanına; başka rolle görüntüle | Diğer rolün sayfasında DOM'da eleman |
| DOM XSS | URL fragment/query → `#<img src=x onerror=console.log('VT7f3a')>` | Konsolda canary |
| SSTI | `{{7*7}}VT`, `${7*7}VT`, `<%= 7*7 %>VT`, `#{7*7}VT` | Yanıtta `49VT` |
| Komut enjeksiyonu | `;echo VT$((6*7))`, `| echo VT42`, `` `echo VT42` `` (Windows: `& echo VT42`) | Yanıtta veya logda `VT42` |
| Path traversal | `../../package.json`, `..%2f..%2fpackage.json`, `....//....//package.json` | Projenin kendi dosyası dönüyor (bilinen içerik) |
| XXE | `<!DOCTYPE x [<!ENTITY e SYSTEM "http://127.0.0.1:<canary>/vt-canary/VT7f3a">]><x>&e;</x>` | Canary'ye istek düştü |
| LDAP | `*)(uid=*` | Filtre davranışı değişiyor |
| CRLF / header | `%0d%0aX-VT: VT7f3a` (yönlendirme parametrelerinde) | Yanıtta `X-VT` başlığı |
| Log enjeksiyonu | `VT7f3a%0a[ADMIN] fake entry` | Log dosyasında sahte satır (log okunabiliyorsa) |

Kök neden → fix-patterns.md §Enjeksiyon. Eşleme: A03, CWE-89/943/79/1336/78/22/611/113/117.

---

## 4. İstek sahteciliği ve ağ (`request-forgery`)

Ön koşul: scope doğrulandı; SSRF için canary çalışıyor: `node $VT/scripts/scope-guard.mjs --canary --port 8089` (uygulama Docker içindeyse URL'de `host.docker.internal`).

- **CSRF:** cookie tabanlı oturumda durum değiştiren bir isteği (test hesabı, zararsız alan, ör. görünen ad) `Origin`/`Referer` olmadan ve CSRF token'sız tekrarla. Başarılıysa ve cookie `SameSite=None`/yoksa → açık. SameSite=Lax tek başına GET ile durum değiştiren uçları korumaz: GET ile yazma var mı bak.
- **SSRF:** URL alan her parametre (webhook, avatar URL, import, PDF oluşturucu, önizleme): `http://127.0.0.1:8089/vt-canary/VT7f3a`. Canary logunda istek → doğrulandı. Metadata adreslerini (169.254.169.254) ASLA deneme; kodda engelleme olup olmadığını kod yolu iziyle göster.
- **Açık yönlendirme:** `next`, `redirect`, `returnUrl`, `continue` parametrelerine `//vt-canary.localhost`, `https:%2f%2fvt-canary.localhost`, `/\vt-canary.localhost`. Yönlendirme takip etme (`curl` -L YOK), yalnızca `Location` başlığını oku.
- **CORS:** `headers-check.sh` CORS bölümü; ayrıca kimlikli API uçlarına `Origin: https://vt-evil.example` ve `Origin: null`. Yansıtma + `Access-Control-Allow-Credentials: true` → Yüksek.
- **Clickjacking:** `frame-ancestors` veya `X-Frame-Options` yok ve sayfada durum değiştiren eylem varsa → Orta.
- **WebSocket origin:** inventory'deki ws uçlarına `Origin: https://vt-evil.example` ile bağlan (Node: `new WebSocket(url, {headers})` yoksa `curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGVzdA==" -H "Origin: https://vt-evil.example"`). 101 dönüyor ve cookie ile kimlik alıyorsa → açık (CSWSH).

Kök neden → fix-patterns.md §İstek sahteciliği. Eşleme: A01/A05/A10, API7, CWE-352/918/601/942/1021/1385.

---

## 5. Dosya yükleme ve indirme (`file`)

Ön koşul: scope doğrulandı; yüklenen marker dosyaları test sonunda silinir veya snapshot'tan dönülür.

Marker dosyaları (zararsız): `vt.txt` (`VT7f3a`), `vt.svg` (`<svg xmlns="http://www.w3.org/2000/svg"><script>console.log('VT7f3a')</script></svg>`), `vt.html` (`<p id=VT7f3a>`), `vt.php.jpg` / `vt.jpg.php` (içerik: `VT7f3a <?php echo 'VT'.(6*7); ?>`), sunucu dili için marker (`vt.jsp`, `vt.aspx` aynı mantık).

| Test | Açık belirtisi |
|---|---|
| Uzantı bypass (çift uzantı, büyük/küçük harf, `.pHp`, `.php5`, sonda nokta/boşluk) | Yasaklı uzantı kabul ediliyor |
| MIME bypass (`Content-Type: image/png` + farklı içerik) | Yalnızca istemci başlığına güveniliyor |
| Çalıştırılabilirlik | Yüklenen marker'ın URL'i istendiğinde `VT42` dönüyor (kod çalıştı) → Kritik |
| SVG/HTML içinde script | Dosya uygulama origin'inden `text/html`/`image/svg+xml` olarak ve `Content-Disposition: attachment` olmadan sunuluyor → stored XSS |
| Boyut limiti | 25 MB üstü sahte dosya (tek istek) kabul ediliyor; limit yok → Düşük/Orta (DoS denemesi YAPMA, tek istek) |
| Yol manipülasyonu | Dosya adı `../../vt.txt` → upload dizini dışına yazıldı mı (kodda `path.join(dir, originalname)`) |
| İndirme | `download?file=../../package.json`, ID değiştirerek başkasının dosyası (IDOR) |

Kök neden → fix-patterns.md §Dosya. Eşleme: A04/A01, CWE-434/22/79.

---

## 6. İş mantığı (`business-logic`)

Ön koşul: scope doğrulandı; db-snapshot alındı; ödeme sağlayıcısı test/sandbox modunda (yoksa "test edilmedi: yıkıcı risk").

- **Fiyat/miktar:** sepete ekleme/ödeme isteğinde `price`, `amount`, `total`, `discount` alanlarını değiştir; `quantity: -1`, `0`, `0.01`, `1e9`, `"1"` (tip karışıklığı).
- **Adım atlama:** çok adımlı akışta (sepet → adres → ödeme → onay) son adımı doğrudan çağır; ödeme onay callback'ini sahte parametreyle tetikle.
- **Kupon/indirim:** aynı kuponu iki kez; iki kupon birlikte; başka kullanıcıya özel kupon; süresi geçmiş kupon.
- **İade/iptal:** tamamlanmamış siparişi iade; iade tutarını değiştir; iptal sonrası ürün/kredi hâlâ kullanılabiliyor mu.
- **Yarış durumu (sınırlı):** tek kullanımlık işlemde (kupon, bakiye çekme, oy) aynı isteği 10 paralel gönder (`Promise.all`, guardedFetch). Birden fazla başarı → açık.
- **Tekrar oynatma:** webhook/ödeme bildirimi isteğini aynen tekrar gönder (imza + idempotency kontrolü var mı); nonce/timestamp yok mu.
- **Durum makinesi:** `status` alanını istemciden `paid`/`shipped`/`approved` yap.

Kök neden → fix-patterns.md §İş mantığı. Eşleme: A04, API6, CWE-840/362/841.

---

## 7. API (`api`)

Ön koşul: scope doğrulandı; uç listesi `inventory.json` + `code-routes.json`.

- **Rate limit:** kimlik doğrulama dışı bir okuma ucuna 30 istek / 10 sn (guardedFetch sınırı içinde). `429` veya `RateLimit-*` başlığı yok → Düşük/Orta (pahalı uçlarda Orta).
- **Verbose hata:** geçersiz JSON, yanlış tip, çok uzun değer, beklenmeyen metot gönder; stack trace, SQL, iç yol, framework sürümü sızıyor mu.
- **GraphQL:** introspection (`{__schema{types{name}}}`) production ayarlarında açık mı; derinlik/karmaşıklık sınırı (5 seviyeli iç içe sorgu, tek istek); batching ile rate limit atlatma; alan seviyesinde yetki (authz bölümü).
- **Gereksiz açık uç:** `/swagger`, `/api-docs`, `/openapi.json`, `/graphql` playground, `/actuator`, `/health` detayları, `/metrics`, `/debug`, `/_profiler`, `/telescope`, `/horizon`, `/__debug__`.
- **Aşırı veri dönüşü:** liste/detay yanıtlarında `password`, `hash`, `token`, `email` (başkasının), `internal`, `isAdmin` alanları; UI'ın kullanmadığı alanlar.
- **Sürüm kalıntıları:** `/api/v1` varken `/api/v0`, `/api/beta`, `/api/old`, `/api/internal` (kod route listesinden).
- **İçerik tipi:** JSON ucu `application/x-www-form-urlencoded` veya `text/plain` kabul ediyor mu (CSRF'e kapı açar).

Kök neden → fix-patterns.md §API. Eşleme: API2/3/4/8/9, CWE-209/213/770/1059.

---

## 8. Altyapı ve yapılandırma (`infra`)

Ön koşul: scope doğrulandı; yalnızca okuma istekleri.

- **Hassas dosyalar (GET, tek istek):** `/.git/HEAD`, `/.git/config`, `/.env`, `/.env.local`, `/.env.production`, `/config.json`, `/backup.zip`, `/db.sqlite`, `/dump.sql`, `/.DS_Store`, `/web.config`, `/phpinfo.php`, `/server-status`, `/.npmrc`, `/docker-compose.yml`, `/*.map` (source map production'da).
- **Dizin listeleme:** `/uploads/`, `/static/`, `/assets/`, `/public/` → "Index of".
- **Debug modu:** hatalı istekle framework debug sayfası (Django yellow page, Laravel Ignition/Whoops, Werkzeug debugger, Next.js dev overlay, ASP.NET Developer Exception Page, Spring Whitelabel ayrıntılı).
- **Varsayılan şifreler:** YALNIZCA kodda/seed'de/README'de görünen varsayılan admin hesabı (`admin/admin`, `admin@example.com/password`) ile tek deneme. Tahmin listesi YOK.
- **Açık yönetim portları:** compose/Dockerfile'da dışarı açılan DB (5432, 3306, 27017, 6379), adminer/phpmyadmin, debug portu (9229, 5005). `ports:` vs `expose:`.
- **Docker/compose:** `USER` yok (root), `privileged: true`, `network_mode: host`, Docker socket mount, `:latest` imaj, `.env` imaja kopyalanmış (`COPY . .` + `.dockerignore` yok).
- **Reverse proxy:** `X-Forwarded-For` güveni (IP tabanlı kısıtlarda başlıkla atlatma), `proxy_pass` ile iç servis açığa çıkması.
- **Başlıklar ve hata sayfaları:** `headers-check.sh` çıktısı; 404/500 sayfasında sürüm/yol.
- **TLS (staging):** headers-check.sh TLS bölümü.

Kök neden → fix-patterns.md §Yapılandırma. Eşleme: A05, API8, CWE-489/548/538/1188/250.

---

## 9. Arayüz ve gezinme (`ui`)

Ön koşul: scope doğrulandı; `inventory.mjs` her rol için çalıştı (yıkıcı buton koruması açık).

- **Her link/buton/menü:** inventory'de `clicked`, `skipped_destructive`, `broken_links`. Atlanan yıkıcı butonlar snapshot sonrası elle denenir veya "test edilmedi: yıkıcı risk".
- **Konsol hataları:** `console_errors`; güvenlikle ilgili olanlar (CSP ihlali, mixed content, CORS) bulgu, diğerleri rapora bilgi notu.
- **Mixed content:** HTTPS sayfada `http://` kaynak.
- **İstemci doğrulaması sunucuda da var mı:** her formda `required`, `maxlength`, `pattern`, `type=email`, `min/max` olan alanları doğrudan API'ye kuralı çiğneyerek gönder (boş, çok uzun, negatif, yanlış tip). Sunucu kabul ediyorsa → Düşük/Orta (bağlama göre).
- **CSP ihlalleri:** konsolda `Refused to` mesajları; CSP report-only ise rapor adresi.
- **Hassas veri ön bellekte:** hesap sayfalarında `Cache-Control: no-store` yoksa (headers-check ile o sayfa için).
- **Otomatik tamamlama:** şifre/kart alanlarında `autocomplete` uygun mu (Bilgi).

Eşleme: A04/A05, CWE-602/319/693.

---

## 10. Tedarik zinciri (`supply-chain`)

Ön koşul: yalnızca yerel analiz; paket kurma/güncelleme K2 onayıyla.

- **Bağımlılık CVE:** `deps-audit.sh` özeti. Doğrudan bağımlılıkta Yüksek/Kritik + kodda zafiyetli fonksiyon kullanılıyorsa → Yüksek; yalnızca dev bağımlılıkta → Düşük.
- **Kilit dosyası:** yok veya package.json ile tutarsız (`npm ci` başarısız) → Orta.
- **Kullanılmayan paketler:** `npx --no-install depcheck` varsa; yoksa import grep ile kaba kontrol (Bilgi).
- **SRI:** inventory'de `scripts_without_sri` (üçüncü taraf CDN'den `integrity` olmadan yüklenen script) → Düşük/Orta.
- **Install script'leri:** yeni eklenen paketlerde `postinstall` (Bilgi).
- **CI:** `pull_request_target` + checkout, sırların fork PR'lara açılması, sabitlenmemiş action sürümleri (`@main`) → Orta.

Kök neden → fix-patterns.md §Tedarik zinciri. Eşleme: A06/A08, CWE-1395/353/1357.
