# Önem puanlama, kanıt standardı ve güven düzeyi

## İçindekiler
1. Önem puanlama
2. Önem düşürme/yükseltme kuralları
3. Kanıt standardı (K3)
4. Güven düzeyi
5. Durum geçişleri
6. Sade anlatım kalıpları
7. CWE / OWASP eşleme tablosu

## 1. Önem puanlama

Puan = **Etki (1-4) × Sömürülebilirlik (1-3) × Erişim koşulu (1-3)** → 1-36.

| Etki | Anlam |
|---|---|
| 4 | Tam hesap/sistem ele geçirme, admin yetkisi, uzaktan kod çalıştırma, tüm veritabanı okuma/yazma |
| 3 | Başka kullanıcıların verisini okuma/değiştirme, ödeme/sipariş manipülasyonu, oturum çalma |
| 2 | Sınırlı veri sızıntısı (e-posta varlığı, iç yol, sürüm), tek kullanıcıyı etkileyen XSS |
| 1 | Sertleştirme eksiği, doğrudan sömürü yolu yok (eksik başlık, bilgi sızdıran başlık) |

| Sömürülebilirlik | Anlam |
|---|---|
| 3 | Tek istek / hazır araçla, özel bilgi gerekmez |
| 2 | Birkaç adım veya tahmin edilebilir bir değer gerekir |
| 1 | Yarış durumu, nadir koşul, kullanıcı etkileşimi (ör. phishing ile tıklatma) gerekir |

| Erişim koşulu | Anlam |
|---|---|
| 3 | Anonim (giriş gerekmez) |
| 2 | Herhangi bir kayıtlı kullanıcı (kayıt açık) |
| 1 | Admin, davetli kullanıcı veya iç ağ |

| Puan | Önem |
|---|---|
| 24-36 | **Kritik** |
| 12-23 | **Yüksek** |
| 6-11 | **Orta** |
| 1-5 | **Düşük** |

Hesaplamayı bulgu kaydına yaz: `--score "E3×S3×A2=18"`.

## 2. Düşürme/yükseltme kuralları

- Kimlik doğrulama gerekiyor VE yalnızca saldırganın kendi verisini etkiliyorsa: bir kademe düşür (self-XSS, kendi profilinde mass assignment ile zararsız alan).
- Sömürü başka bir bulguyla zincirleniyorsa (ör. açık yönlendirme + OAuth token sızıntısı): zincirin toplam etkisine göre puanla, zincir bulgularını `related` alanında bağla.
- Sırrın gerçek olduğu doğrulanamıyorsa (gitleaks eşleşmesi, test anahtarı olabilir): güven düzeyini Orta yap; canlı anahtar biçimi (`sk_live_`, `AKIA`) ise Yüksek bırak. Sırrı ASLA denemek için kullanma (K8).
- Production'da kapalı olduğu kanıtlanan debug özelliği (env bayrağı koddan izlenebiliyorsa): Düşük + not.
- Admin paneli yalnızca VPN/IP allowlist arkasındaysa: erişim koşulu 1.

## 3. Kanıt standardı (K3)

"Doğrulandı" için şunlardan EN AZ biri, `.visual-tester/evidence/<ID>/` altında:

| Tür | Dosya | İçerik |
|---|---|---|
| İstek/yanıt | `request.txt`, `response.txt` | Yöntem, yol, ilgili başlıklar (sırlar maskeli), gövdenin ilgili ≤40 satırı |
| Ekran görüntüsü | `screenshot.png` | Canary'nin çalıştığı ya da yetkisiz verinin göründüğü an |
| Kod yolu izi | `trace.md` | `girdi (dosya:satır) → işlem (dosya:satır) → tehlikeli çağrı (dosya:satır)`, her adım 1 satır |
| Araç çıktısı + manuel teyit | `tool.json` + `manual.md` | Araç bulgusu tek başına yetmez; manuel teyit şart |

Minimal PoC ilkesi: zararı göstermek için gereken en küçük adım. Veri silme, toplu okuma, kalıcı değişiklik yerine: canary değer, tek kayıt, kendi test hesabın. Gerçek kullanıcı verisi kanıta girmez.

Retest kanıtı (K4): aynı istek, düzeltme sonrası yanıtı `retest.txt`. "Düzeltildi-doğrulandı" bunu gerektirir.

## 4. Güven düzeyi

| Düzey | Ne zaman |
|---|---|
| Yüksek | Dinamik PoC başarılı VE kök neden kodda bulundu |
| Orta | Dinamik PoC başarılı ama kök neden bulunamadı, ya da kod yolu kesin ama dinamik deneme yapılamadı (yıkıcı risk, ortam yok) |
| Düşük | Yalnızca araç/desen eşleşmesi; bağlam belirsiz. Bu düzeyde bulgu "şüpheli"den öteye geçmez |

## 5. Durum geçişleri

```
şüpheli ──(kanıt)──> doğrulandı ──(retest kanıtı)──> düzeltildi-doğrulandı
   │                    │  └──(gerekçe)──> riski-kabul
   └──(gerekçe)──> yanlış-pozitif <──(gerekçe)──┘
düzeltildi-doğrulandı ──(regresyon)──> doğrulandı   (yeniden açılır)
```

`findings.mjs` bu geçişleri zorlar; eksik kanıt/gerekçe ile geçiş reddedilir.

## 6. Sade anlatım kalıpları ("Bu ne demek?")

Teknik terim yok, sonuç odaklı, 1-2 cümle. Örnekler:
- IDOR: "Giriş yapmış herhangi biri, adres çubuğundaki numarayı değiştirerek başka müşterilerin siparişlerini görebiliyor."
- Stored XSS: "Bir kullanıcının yazdığı yoruma gizlenmiş kod, o yorumu açan herkesin tarayıcısında çalışıyor; oturumları ele geçirilebilir."
- SQLi: "Arama kutusuna yazılan özel karakterler veritabanına doğrudan komut olarak gidiyor; saldırgan tüm kayıtları okuyabilir."
- Eksik CSP: "Sitede bir açık bulunursa, tarayıcının zararlı kodu engellemesini sağlayan ek kilit takılı değil."
- Sır sızıntısı: "Ödeme servisinin gizli anahtarı kodun içinde duruyor; kodu gören herkes sizin adınıza işlem yapabilir."

## 7. CWE / OWASP eşleme tablosu

| Sınıf | CWE | OWASP 2021 | API 2023 |
|---|---|---|---|
| IDOR/BOLA | CWE-639 | A01 | API1 |
| BFLA / dikey yetki | CWE-285 | A01 | API5 |
| Mass assignment | CWE-915 | A04 | API3 |
| Aşırı veri dönüşü | CWE-213 | A01 | API3 |
| SQLi | CWE-89 | A03 | API8 |
| NoSQLi | CWE-943 | A03 | API8 |
| XSS | CWE-79 | A03 | — |
| SSTI | CWE-1336 | A03 | — |
| Komut enjeksiyonu | CWE-78 | A03 | — |
| Path traversal | CWE-22 | A01 | — |
| XXE | CWE-611 | A05 | — |
| CRLF/header | CWE-113 | A03 | — |
| Log enjeksiyonu | CWE-117 | A09 | — |
| CSRF | CWE-352 | A01 | — |
| SSRF | CWE-918 | A10 | API7 |
| Açık yönlendirme | CWE-601 | A01 | — |
| CORS hatası | CWE-942 | A05 | API8 |
| Clickjacking | CWE-1021 | A05 | — |
| Kullanıcı enumeration | CWE-204 | A07 | API2 |
| Zayıf şifre sıfırlama | CWE-640 | A07 | API2 |
| Oturum fixation | CWE-384 | A07 | API2 |
| JWT zayıflığı | CWE-347 / CWE-345 | A02/A07 | API2 |
| Rate limit yok | CWE-307 / CWE-770 | A07 | API4 |
| Dosya yükleme | CWE-434 | A04 | — |
| İş mantığı | CWE-840 | A04 | API6 |
| Yarış durumu | CWE-362 | A04 | API6 |
| Verbose hata | CWE-209 | A05 | API8 |
| Debug açık | CWE-489 | A05 | API8 |
| Sır kodda | CWE-798 | A07 | — |
| Eksik başlık / cookie bayrağı | CWE-693 / CWE-614 / CWE-1004 | A05 | API8 |
| Bağımlılık CVE | CWE-1395 | A06 | — |
| SRI yok | CWE-353 | A08 | — |
| Eski API sürümü | CWE-1059 | A05 | API9 |
| Güvensiz dış API tüketimi | CWE-20 | A08 | API10 |
