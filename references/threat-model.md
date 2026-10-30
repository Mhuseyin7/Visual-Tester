# Tehdit modeli şablonu

Amaç: saldırı önceliğini sezgiyle değil, "neyi kaybedersek en çok canımız yanar" sorusuyla sıralamak. Çıktı `.visual-tester/threat-model.md`, en fazla 15 satır. Konuşmaya yalnızca ilk 3 öncelik yazılır.

## 1. Kaynaklar (yalnızca hedefli okuma)

| Bilgi | Nereden |
|---|---|
| Varlıklar | DB şeması/modeller (`grep -rn "model\|Schema\|CREATE TABLE\|class .*Model"`), dosya depolama ayarları, ödeme SDK importları |
| Roller | `role`, `isAdmin`, `permission`, `policy`, `can(`, `@PreAuthorize`, `Gate::`, `@permission_classes` aramaları |
| Güven sınırları | middleware/guard tanımları, reverse proxy config, CORS ayarı, webhook route'ları, dış API istemcileri |
| Yüzeyler | `.visual-tester/inventory.json` + `.visual-tester/code-routes.json` |

## 2. Doldurulacak şablon (15 satır)

```
# Tehdit modeli — <proje> (<tarih>)
Stack: <framework, DB, auth yöntemi, barındırma>
Varlıklar: <kullanıcı PII> | <ödeme/sipariş> | <admin yetkisi> | <yüklenen dosyalar> | <sırlar/API anahtarları>
Roller: anonim → kullanıcı → (sahip) → admin [+ servis hesabı/webhook]
Güven sınırları: tarayıcı→API (<auth tipi>), API→DB, API→dış servis (<liste>), webhook→API (<imza var mı>), admin paneli (<ayrı mı>)
Giriş noktaları: <N> sayfa, <N> form, <N> API ucu, <N> dosya yükleme, <N> gizli route (kodda var, UI'da yok)
Öncelik 1: <varlık> ← <yüzey> (<neden: yüksek etki + kolay erişim>)
Öncelik 2: ...
Öncelik 3: ...
Öncelik 4-6: ...
Kapsam dışı / test edilemeyen: <yıkıcı yüzeyler, dış servisler>
Varsayımlar: <ör. TLS reverse proxy'de sonlanıyor>
```

## 3. Önceliklendirme kuralı

Puan = **etki** (varlığın değeri: admin yetkisi, ödeme, toplu PII = 3; tekil kullanıcı verisi = 2; görünüm/içerik = 1) × **erişim** (anonim = 3, herhangi bir kullanıcı = 2, admin/özel koşul = 1). Eşitlikte: kodda olup UI'da görünmeyen route'lar ve yazma işlemi yapan uçlar öne alınır.

Tipik sıra (proje aksini göstermedikçe):
1. Admin/yönetim uçlarının yetkisiz erişimi (BFLA)
2. Nesne seviyesinde yetki (IDOR/BOLA): başka kullanıcının kaydı
3. Kimlik doğrulama akışları: giriş, şifre sıfırlama, oturum
4. Enjeksiyon (SQL/NoSQL/komut/SSTI) kullanıcı girdisi alan uçlarda
5. Dosya yükleme ve dosya sunma
6. İş mantığı: fiyat, miktar, kupon, durum geçişleri
7. Yapılandırma ve başlıklar, tedarik zinciri

## 4. Güven sınırı soruları (her sınır için tek satır cevap)

- Bu sınırı geçen istekte kimlik nerede doğrulanıyor? Merkezi mi (middleware), tek tek mi (route içinde)?
- Yetki kontrolü nesneye göre mi (sahiplik), yalnızca role göre mi?
- Girdi şeması sunucuda doğrulanıyor mu, yoksa yalnızca formda mı?
- Bu sınırdan dışarıya (dış servis, dosya sistemi, shell) giden bir çağrı kullanıcı girdisi taşıyor mu?
- Hata olursa ne sızar (stack trace, SQL, iç yol)?
