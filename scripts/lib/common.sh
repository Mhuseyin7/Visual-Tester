# shellcheck shell=bash
# Visual Tester bash ortakları. Kaynak: . "$(dirname "$0")/lib/common.sh"

VT_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VT_DIR="${VT_DIR:-$PWD/.visual-tester}"
export VT_DIR

vt_info() { printf '[vt] %s\n' "$*"; }
vt_warn() { printf '[vt] UYARI: %s\n' "$*" >&2; }
vt_die()  { printf '[vt] HATA: %s\n' "$1" >&2; exit "${2:-1}"; }
vt_have() { command -v "$1" >/dev/null 2>&1; }
vt_ts()   { date +%Y%m%d-%H%M%S; }

# K8: ilk 4 karakter + ***
vt_mask() {
  local s="$1"
  if [ "${#s}" -le 4 ]; then printf '***'; else printf '%s***' "${s:0:4}"; fi
}

# K1: hedef scope-guard'dan geçmeden hiçbir istek atılmaz.
vt_scope_check() {
  vt_have node || vt_die "node bulunamadı; kapsam kontrolü yapılamıyor, duruyorum (K1)."
  if ! node "$(vt_native_path "$VT_SCRIPTS_DIR")/scope-guard.mjs" --check "$1" >&2; then
    vt_die "Hedef kapsam dışı: $1 (K1)" 2
  fi
}

# Tarama dışı dizinler (deps-audit hariç her yerde)
VT_EXCLUDE_DIRS="node_modules .git dist build out .next .nuxt vendor coverage .venv venv __pycache__ target bin obj .visual-tester .cache"

vt_grep_excludes() {
  local d out=""
  for d in $VT_EXCLUDE_DIRS; do out="$out --exclude-dir=$d"; done
  printf '%s' "$out --exclude=*.lock --exclude=package-lock.json --exclude=pnpm-lock.yaml --exclude=*.min.js --exclude=*.map"
}

# Windows (Git Bash/MSYS/Cygwin) yolunu node/docker'ın anlayacağı biçime çevirir.
vt_native_path() {
  if vt_have cygpath; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

vt_join() { local IFS=','; printf '%s' "$*" | sed 's/,/, /g'; }

vt_require_arg() { [ -n "$2" ] || vt_die "$1 için değer gerekli."; }
