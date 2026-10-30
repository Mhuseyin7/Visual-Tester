#!/usr/bin/env bash
# Ortam ön kontrolü: araçları kontrol eder, eksikleri TEK listede verir. Hiçbir şey kurmaz.
set -u
. "$(dirname "$0")/lib/common.sh"

usage() {
  cat <<'EOF'
preflight.sh — Visual Tester ortam ön kontrolü (hiçbir şey kurmaz, hedefe istek atmaz)

Kullanım: bash preflight.sh [--json]

Kontrol: node (>=18, zorunlu), curl (zorunlu), git, docker (+daemon), Playwright + Chromium,
         semgrep, gitleaks, OWASP ZAP (yerel veya Docker imajı), nuclei, openssl,
         denetim araçları (npm/pnpm/yarn, pip-audit, composer, govulncheck).
Çıkış: 0 = zorunlular tamam, 1 = zorunlu eksik.
EOF
}
JSON=0
for a in "$@"; do
  case "$a" in
    -h|--help) usage; exit 0 ;;
    --json) JSON=1 ;;
    *) vt_die "Bilinmeyen argüman: $a (--help)" ;;
  esac
done

MISSING=()
REQUIRED_MISSING=0
ROWS=()

row() { ROWS+=("$1|$2|$3"); }  # durum|ad|ayrıntı

hint() {
  case "$1" in
    node) echo "https://nodejs.org (LTS) veya nvm" ;;
    curl) echo "paket yöneticisi: apt/brew/winget install curl" ;;
    git) echo "https://git-scm.com" ;;
    docker) echo "Docker Desktop / docker engine" ;;
    playwright) echo "npm i -D playwright" ;;
    chromium) echo "npx playwright install chromium" ;;
    semgrep) echo "pipx install semgrep (Windows: WSL veya docker run semgrep/semgrep)" ;;
    gitleaks) echo "brew install gitleaks / winget install gitleaks / GitHub releases" ;;
    zap) echo "docker pull ghcr.io/zaproxy/zaproxy:stable" ;;
    nuclei) echo "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest veya GitHub releases" ;;
    openssl) echo "Git for Windows/brew/apt ile gelir" ;;
    pip-audit) echo "pipx install pip-audit" ;;
    govulncheck) echo "go install golang.org/x/vuln/cmd/govulncheck@latest" ;;
    *) echo "-" ;;
  esac
}

check_cmd() { # ad komut zorunlu(0/1)
  local name="$1" cmd="$2" req="$3" ver
  if vt_have "$cmd"; then
    ver="$("$cmd" --version 2>/dev/null | head -1 | cut -c1-60)"
    row "ok" "$name" "${ver:-kurulu}"
  else
    row "eksik" "$name" "$(hint "$name")"
    MISSING+=("$name")
    [ "$req" = 1 ] && REQUIRED_MISSING=1
  fi
}

# node + sürüm
if vt_have node; then
  NV="$(node -p 'process.versions.node' 2>/dev/null)"
  if [ "${NV%%.*}" -ge 18 ] 2>/dev/null; then row "ok" "node" "v$NV"; else row "eksik" "node" "v$NV (>=18 gerekli)"; MISSING+=("node>=18"); REQUIRED_MISSING=1; fi
else
  row "eksik" "node" "$(hint node)"; MISSING+=("node"); REQUIRED_MISSING=1
fi
check_cmd curl curl 1
check_cmd git git 0

# docker + daemon
if vt_have docker; then
  if docker info >/dev/null 2>&1; then row "ok" "docker" "$(docker --version | cut -c1-60)"; else row "uyarı" "docker" "kurulu ama daemon çalışmıyor"; MISSING+=("docker-daemon"); fi
else
  row "eksik" "docker" "$(hint docker)"; MISSING+=("docker")
fi

# Playwright (proje veya skill node_modules) + Chromium
if vt_have node; then
  PW="$(node -e "
    const {createRequire}=require('module');const p=require('path');
    for (const b of [process.cwd(), p.resolve('$(vt_native_path "$VT_SCRIPTS_DIR")/..')]) for (const n of ['playwright','playwright-core','@playwright/test']) {
      try { const r=createRequire(p.join(b,'x.js')); r.resolve(n); console.log(n+'@'+b); process.exit(0);} catch(e){}
    }" 2>/dev/null)"
  if [ -n "$PW" ]; then row "ok" "playwright" "$PW"; else row "eksik" "playwright" "$(hint playwright)"; MISSING+=("playwright"); fi
  BROWSERS="${PLAYWRIGHT_BROWSERS_PATH:-}"
  if [ -z "$BROWSERS" ]; then
    for d in "${LOCALAPPDATA:-}/ms-playwright" "$HOME/AppData/Local/ms-playwright" "$HOME/Library/Caches/ms-playwright" "$HOME/.cache/ms-playwright"; do
      [ -d "$d" ] && BROWSERS="$d" && break
    done
  fi
  if [ -n "$BROWSERS" ] && ls -d "$BROWSERS"/chromium* >/dev/null 2>&1; then row "ok" "chromium" "$BROWSERS"; else row "eksik" "chromium" "$(hint chromium)"; MISSING+=("chromium"); fi
fi

check_cmd semgrep semgrep 0
check_cmd gitleaks gitleaks 0

# ZAP: yerel veya Docker imajı
if vt_have zap.sh || vt_have zap || vt_have zaproxy; then
  row "ok" "zap" "yerel kurulum"
elif vt_have docker && docker image inspect ghcr.io/zaproxy/zaproxy:stable >/dev/null 2>&1; then
  row "ok" "zap" "docker: ghcr.io/zaproxy/zaproxy:stable"
else
  row "eksik" "zap" "$(hint zap)"; MISSING+=("zap")
fi

check_cmd nuclei nuclei 0
check_cmd openssl openssl 0

# Denetim araçları: yalnızca projede ilgili dosya varsa önemlidir
[ -f package.json ] && { check_cmd npm npm 0; [ -f pnpm-lock.yaml ] && check_cmd pnpm pnpm 0; [ -f yarn.lock ] && check_cmd yarn yarn 0; }
{ [ -f requirements.txt ] || [ -f pyproject.toml ] || [ -f Pipfile.lock ] || [ -f poetry.lock ]; } && check_cmd pip-audit pip-audit 0
[ -f composer.json ] && check_cmd composer composer 0
[ -f go.mod ] && check_cmd govulncheck govulncheck 0

OS="$(uname -s 2>/dev/null || echo unknown)"
case "$OS" in MINGW*|MSYS*|CYGWIN*) OSN="windows-gitbash" ;; Linux*) grep -qi microsoft /proc/version 2>/dev/null && OSN="wsl" || OSN="linux" ;; Darwin*) OSN="macos" ;; *) OSN="$OS" ;; esac

if [ "$JSON" = 1 ]; then
  printf '{"os":"%s","required_ok":%s,"missing":[' "$OSN" "$([ $REQUIRED_MISSING = 0 ] && echo true || echo false)"
  first=1; for m in "${MISSING[@]+"${MISSING[@]}"}"; do [ $first = 1 ] || printf ','; printf '"%s"' "$m"; first=0; done
  printf '],"tools":['
  first=1; for r in "${ROWS[@]}"; do IFS='|' read -r s n d <<<"$r"; [ $first = 1 ] || printf ','; d="${d//\\/\\\\}"; printf '{"name":"%s","status":"%s","detail":"%s"}' "$n" "$s" "${d//\"/\'}"; first=0; done
  printf ']}\n'
else
  vt_info "Platform: $OSN"
  for r in "${ROWS[@]}"; do
    IFS='|' read -r s n d <<<"$r"
    case "$s" in ok) mark="✔" ;; uyarı) mark="!" ;; *) mark="✖" ;; esac
    printf '  %s %-12s %s\n' "$mark" "$n" "$d"
  done
  if [ "${#MISSING[@]}" -gt 0 ]; then
    printf 'EKSİK: %s\n' "$(vt_join "${MISSING[@]}")"
    echo "Not: eksik araçlar kurulmadan da devam edilir; ilgili adım rapora 'araç yok' olarak yazılır (K9)."
  else
    echo "EKSİK: yok"
  fi
fi
exit "$REQUIRED_MISSING"
