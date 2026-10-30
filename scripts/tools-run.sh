#!/usr/bin/env bash
# Kurulu güvenlik araçlarını çalıştırır (semgrep, gitleaks, ZAP baseline, nuclei) ve kısa özet üretir.
set -u
. "$(dirname "$0")/lib/common.sh"

usage() {
  cat <<'EOF'
tools-run.sh — kurulu olan statik/dinamik araçları çalıştırır, SARIF/JSON + özet üretir

Kullanım: bash tools-run.sh [--src .] [--target URL] [--out DIR] [--only semgrep,gitleaks,zap,nuclei] [--zap-active]

  --src DIR      Kaynak kod kökü (varsayılan: .)
  --target URL   Dinamik araçlar (ZAP, nuclei) için hedef; scope-guard ile kontrol edilir (K1)
  --out DIR      Çıktı dizini (varsayılan: .visual-tester/tools)
  --only LIST    Yalnızca bu araçlar
  --zap-active   ZAP aktif tarama (yalnızca deep modda, yalnızca scope içi; snapshot önerilir)

Çıktılar: semgrep.sarif, gitleaks-tree.json, zap.json, nuclei.jsonl, summary.md (≤20 satır özet stdout'a)
Kurulu olmayan araç atlanır ve özete "araç yok" yazılır. Semgrep kuralları registry'den indirilir (SEMGREP_CONFIG ile değiştirilebilir).
nuclei: dos, fuzz, intrusive, bruteforce etiketleri hariç; hız 10 istek/sn.
EOF
}

SRC="."; TARGET=""; OUT="$VT_DIR/tools"; ONLY="semgrep,gitleaks,zap,nuclei"; ZAP_ACTIVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --src) vt_require_arg "$1" "${2:-}"; SRC="$2"; shift 2 ;;
    --target) vt_require_arg "$1" "${2:-}"; TARGET="$2"; shift 2 ;;
    --out) vt_require_arg "$1" "${2:-}"; OUT="$2"; shift 2 ;;
    --only) vt_require_arg "$1" "${2:-}"; ONLY="$2"; shift 2 ;;
    --zap-active) ZAP_ACTIVE=1; shift ;;
    *) vt_die "Bilinmeyen argüman: $1 (--help)" ;;
  esac
done
[ -d "$SRC" ] || vt_die "Kaynak dizini yok: $SRC"
mkdir -p "$OUT"
want() { case ",$ONLY," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
NOTES=()

if [ -n "$TARGET" ]; then vt_scope_check "$TARGET"; fi

# --- semgrep -------------------------------------------------------------
if want semgrep; then
  if vt_have semgrep; then
    vt_info "semgrep çalışıyor..."
    CFG=()
    for c in ${SEMGREP_CONFIG:-p/default p/owasp-top-ten}; do CFG+=(--config "$c"); done
    EXC=()
    for d in $VT_EXCLUDE_DIRS; do EXC+=(--exclude "$d"); done
    semgrep scan "${CFG[@]}" "${EXC[@]}" --metrics=off --sarif --output "$OUT/semgrep.sarif" --quiet "$SRC" >"$OUT/semgrep.log" 2>&1 \
      || NOTES+=("semgrep hata/uyarı ile bitti: $OUT/semgrep.log")
  else
    NOTES+=("semgrep: araç yok")
  fi
fi

# --- gitleaks (çalışma ağacı; geçmiş için secrets-scan.sh) ----------------
if want gitleaks; then
  if vt_have gitleaks; then
    vt_info "gitleaks (çalışma ağacı) çalışıyor..."
    gitleaks detect --source "$SRC" --no-git --redact --no-banner --report-format json --report-path "$OUT/gitleaks-tree.json" >"$OUT/gitleaks.log" 2>&1
    [ $? -gt 1 ] && NOTES+=("gitleaks hata: $OUT/gitleaks.log")
  else
    NOTES+=("gitleaks: araç yok")
  fi
fi

# --- ZAP -----------------------------------------------------------------
if want zap; then
  if [ -z "$TARGET" ]; then
    NOTES+=("zap: --target verilmedi, atlandı")
  else
    SCRIPT="zap-baseline.py"; [ "$ZAP_ACTIVE" = 1 ] && SCRIPT="zap-full-scan.py"
    if vt_have docker && docker info >/dev/null 2>&1; then
      DT="$(printf '%s' "$TARGET" | sed -E 's#://(localhost|127\.0\.0\.1|\[::1\])#://host.docker.internal#')"
      vt_info "ZAP ($SCRIPT) Docker ile çalışıyor → $DT"
      MSYS_NO_PATHCONV=1 docker run --rm --add-host=host.docker.internal:host-gateway \
        -v "$(vt_native_path "$(cd "$OUT" && pwd)")":/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
        "$SCRIPT" -t "$DT" -J zap.json -m 5 -I >"$OUT/zap.log" 2>&1 || NOTES+=("zap hata: $OUT/zap.log")
    elif vt_have zap-baseline.py; then
      "$SCRIPT" -t "$TARGET" -J "$OUT/zap.json" -m 5 -I >"$OUT/zap.log" 2>&1 || NOTES+=("zap hata: $OUT/zap.log")
    else
      NOTES+=("zap: araç yok (Docker veya zap-baseline.py gerekli)")
    fi
  fi
fi

# --- nuclei ---------------------------------------------------------------
if want nuclei; then
  if [ -z "$TARGET" ]; then
    NOTES+=("nuclei: --target verilmedi, atlandı")
  elif vt_have nuclei; then
    vt_info "nuclei çalışıyor (yıkıcı/brute-force şablonları hariç)..."
    nuclei -u "$TARGET" -jsonl -o "$OUT/nuclei.jsonl" -rl 10 -c 5 -duc -silent -nc \
      -etags dos,fuzz,intrusive,bruteforce,brute-force -severity info,low,medium,high,critical >"$OUT/nuclei.log" 2>&1 \
      || NOTES+=("nuclei hata: $OUT/nuclei.log")
  else
    NOTES+=("nuclei: araç yok")
  fi
fi

# --- özet ------------------------------------------------------------------
node - "$(vt_native_path "$OUT")" "${NOTES[@]+"${NOTES[@]}"}" <<'JS' | tee "$OUT/summary.md" | head -20
const fs = require('fs'); const p = require('path');
const [out, ...notes] = process.argv.slice(2);
const read = (f) => { try { return fs.readFileSync(p.join(out, f), 'utf8'); } catch { return null; } };
const lines = ['# Araç taraması özeti', ''];
const s = read('semgrep.sarif');
if (s) { try { const c = {}; for (const r of JSON.parse(s).runs || []) for (const x of r.results || []) c[x.level || 'warning'] = (c[x.level || 'warning'] || 0) + 1;
  lines.push(`- semgrep: ${Object.entries(c).map(([k, v]) => `${k} ${v}`).join(', ') || '0 bulgu'} → semgrep.sarif`); } catch { lines.push('- semgrep: SARIF okunamadı'); } }
const g = read('gitleaks-tree.json');
if (g !== null) { try { lines.push(`- gitleaks (ağaç): ${JSON.parse(g || '[]').length} olası sır → gitleaks-tree.json`); } catch { lines.push('- gitleaks: JSON okunamadı'); } }
const z = read('zap.json');
if (z) { try { const c = { 3: 0, 2: 0, 1: 0, 0: 0 }; for (const st of JSON.parse(z).site || []) for (const a of st.alerts || []) c[a.riskcode]++;
  lines.push(`- ZAP: yüksek ${c[3]}, orta ${c[2]}, düşük ${c[1]}, bilgi ${c[0]} → zap.json`); } catch { lines.push('- ZAP: JSON okunamadı'); } }
const n = read('nuclei.jsonl');
if (n !== null) { const c = {}; for (const l of n.split('\n').filter(Boolean)) { try { const sv = JSON.parse(l).info.severity; c[sv] = (c[sv] || 0) + 1; } catch {} }
  lines.push(`- nuclei: ${Object.entries(c).map(([k, v]) => `${k} ${v}`).join(', ') || '0 bulgu'} → nuclei.jsonl`); }
for (const x of notes) lines.push(`- NOT: ${x}`);
lines.push('', 'İçe aktar: node findings.mjs import --tool semgrep|gitleaks|zap|nuclei --file <dosya>');
console.log(lines.join('\n'));
JS
