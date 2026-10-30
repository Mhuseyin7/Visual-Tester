#!/usr/bin/env bash
# Çalışma ağacı + git geçmişinde sır taraması. Sonuçlar HER ZAMAN maskeli (K8).
set -u
. "$(dirname "$0")/lib/common.sh"

usage() {
  cat <<'EOF'
secrets-scan.sh — sır taraması (çalışma ağacı + git geçmişi), maskeli çıktı

Kullanım: bash secrets-scan.sh [--src .] [--out DIR] [--no-history] [--max-commits N]

gitleaks kuruluysa onu kullanır (--redact). Yoksa yerleşik desenlerle grep tabanlı tarama yapar
(AWS, GitHub, Stripe, Slack, Google, OpenAI/Anthropic biçimli anahtarlar, özel anahtarlar, JWT,
password/secret/token atamaları) ve git'e eklenmiş .env dosyalarını listeler.
Değerler "ilk 4 karakter + ***" olarak yazılır. Bulunan sır hiçbir sisteme karşı denenmez.
Çıktı: DIR/secrets-tree.json|txt, secrets-history.json|txt, summary.md (varsayılan DIR: .visual-tester/secrets)
EOF
}

SRC="."; OUT="$VT_DIR/secrets"; HISTORY=1; MAXC=5000
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --src) vt_require_arg "$1" "${2:-}"; SRC="$2"; shift 2 ;;
    --out) vt_require_arg "$1" "${2:-}"; OUT="$2"; shift 2 ;;
    --no-history) HISTORY=0; shift ;;
    --max-commits) vt_require_arg "$1" "${2:-}"; MAXC="$2"; shift 2 ;;
    *) vt_die "Bilinmeyen argüman: $1 (--help)" ;;
  esac
done
[ -d "$SRC" ] || vt_die "Kaynak dizini yok: $SRC"
mkdir -p "$OUT"
SUM=("# Sır taraması özeti" "")
IS_GIT=0; git -C "$SRC" rev-parse --is-inside-work-tree >/dev/null 2>&1 && IS_GIT=1

PAT='(AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|[sr]k_live_[A-Za-z0-9]{16,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|sk-(ant-|proj-)?[A-Za-z0-9_-]{32,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|(password|passwd|secret|api_?key|access_?key|auth_?token|client_?secret)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"'[:space:]]{8,}["'"'"']'
PLACEHOLDER='(example|changeme|your[_-]|xxx|dummy|placeholder|<|\$\{|process\.env|os\.environ|getenv|env\()'

mask_line() { # dosya:satır:eşleşme → maskeli
  local loc="$1" m="$2"
  printf '%s  %s\n' "$loc" "$(vt_mask "$m")"
}

if vt_have gitleaks; then
  vt_info "gitleaks: çalışma ağacı"
  gitleaks detect --source "$SRC" --no-git --redact --no-banner --report-format json --report-path "$OUT/secrets-tree.json" >/dev/null 2>&1
  N="$(node -e "try{console.log(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')||'[]').length)}catch(e){console.log('?')}" "$(vt_native_path "$OUT/secrets-tree.json")")"
  SUM+=("- Çalışma ağacı (gitleaks): $N olası sır → secrets-tree.json")
  if [ "$HISTORY" = 1 ] && [ "$IS_GIT" = 1 ]; then
    vt_info "gitleaks: git geçmişi"
    gitleaks detect --source "$SRC" --redact --no-banner --log-opts="--all -n $MAXC" --report-format json --report-path "$OUT/secrets-history.json" >/dev/null 2>&1
    N="$(node -e "try{console.log(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')||'[]').length)}catch(e){console.log('?')}" "$(vt_native_path "$OUT/secrets-history.json")")"
    SUM+=("- Git geçmişi (gitleaks): $N olası sır → secrets-history.json (silinmiş olsa da sızmış sayılır: rotasyon)")
  fi
else
  vt_warn "gitleaks yok; yerleşik desenlerle tarama (daha az kapsamlı)."
  # shellcheck disable=SC2046
  grep -rnoIE $(vt_grep_excludes) "$PAT" "$SRC" 2>/dev/null | grep -viE "$PLACEHOLDER" | head -500 | while IFS= read -r l; do
    f="${l%%:*}"; rest="${l#*:}"; ln="${rest%%:*}"; m="${rest#*:}"
    mask_line "$f:$ln" "$m"
  done > "$OUT/secrets-tree.txt"
  SUM+=("- Çalışma ağacı (yerleşik): $(wc -l < "$OUT/secrets-tree.txt" | tr -d ' ') olası sır → secrets-tree.txt")
  if [ "$HISTORY" = 1 ] && [ "$IS_GIT" = 1 ]; then
    git -C "$SRC" log --all -n "$MAXC" -p --no-color --format='commit %h' 2>/dev/null \
      | awk '/^commit /{c=$2} /^\+\+\+ b\//{f=substr($0,7)} /^\+[^+]/{print c "\t" f "\t" substr($0,2)}' \
      | grep -E "$PAT" | grep -viE "$PLACEHOLDER" | head -300 | while IFS=$'\t' read -r c f line; do
        m="$(printf '%s' "$line" | grep -oE "$PAT" | head -1)"
        printf '%s %s  %s\n' "$c" "$f" "$(vt_mask "$m")"
      done > "$OUT/secrets-history.txt"
    SUM+=("- Git geçmişi (yerleşik): $(wc -l < "$OUT/secrets-history.txt" | tr -d ' ') olası sır → secrets-history.txt")
  fi
fi

# Git'e eklenmiş .env dosyaları
if [ "$IS_GIT" = 1 ]; then
  ENVS="$(git -C "$SRC" ls-files | grep -E '(^|/)\.env(\.|$)' | grep -vE '\.(example|sample|template|dist)$' || true)"
  if [ -n "$ENVS" ]; then SUM+=("- UYARI: git'te izlenen .env dosyaları: $(printf '%s' "$ENVS" | tr '\n' ' ')"); fi
  if ! git -C "$SRC" check-ignore -q .visual-tester/x 2>/dev/null; then SUM+=("- NOT: .visual-tester/ henüz .gitignore'da değil (K8)."); fi
fi
[ "$IS_GIT" = 0 ] && [ "$HISTORY" = 1 ] && SUM+=("- Git deposu değil; geçmiş taranmadı.")

printf '%s\n' "${SUM[@]}" | tee "$OUT/summary.md"
