# Değişiklik günlüğü

Biçim: [Keep a Changelog](https://keepachangelog.com/tr/1.1.0/) · Sürümleme: [SemVer](https://semver.org/lang/tr/)

## [1.0.0] — 2026-10-30

### Eklendi
- SKILL.md: değişmez kurallar K1-K9, dört mod (quick/standard/deep/retest), 0-8 adımlı iş akışı, token/zaman optimizasyonu, Claude Code ve Codex uyumluluğu.
- `references/`: tehdit modeli, saldırı oyun kitabı (10 sınıf, bölüm indeksli), 8 stack notu, önem/kanıt standardı, kök neden düzeltme kalıpları, 24 maddelik yayın kontrol listesi, rapor şablonu.
- `scripts/`: `scope-guard.mjs` (kodla zorlanan kapsam, metadata/DNS rebinding reddi, hız sınırı, canary dinleyici), `inventory.mjs` (rol bazlı Playwright envanteri, yıkıcı buton koruması), `authz-matrix.mjs` (rol × endpoint, IDOR sinyali), `findings.mjs` (durum makinesi, içe aktarma, karar, rapor, state.json), `coverage.mjs`, `preflight.sh`, `tools-run.sh`, `headers-check.sh`, `secrets-scan.sh`, `deps-audit.sh`, `db-snapshot.sh`, `db-restore.sh`.
- `templates/`: Jest/Vitest, Pytest, PHPUnit, Playwright regresyon test şablonları; Codex için `AGENTS.snippet.md`.
- `evals/cases.json`: Faz 2 için 6 zafiyetli hedef + 4 güvenlik/süreç vakası.
- `evals/selftest.mjs`: skill'in kendisine yönelik 58 deterministik güvenlik testi (scope kaçışı, yönlendirme kaçışı, sır maskeleme, durum makinesi, yıkıcı buton filtresi, kesinti sonrası devam).
- Animasyonlu README (`assets/banner.svg`, `assets/flow.svg`).

### Değişti
- `inventory.mjs`: yıkıcı buton filtresine hesap kapatma/dondurma, wipe, temizle, clear all eklendi.

### Bilinen sınırlar
- Hedef uygulamalar üzerinde uçtan uca ölçüm (recall/precision, token A/B) henüz yapılmadı; doğrulama `selftest.mjs` (58/58), sözdizimi kontrolleri ve `--help` düzeyindedir.
