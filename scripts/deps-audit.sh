#!/usr/bin/env bash
# Bağımlılık denetimi: projede hangi ekosistem varsa onun yerleşik/standart denetim aracını çalıştırır.
set -u
. "$(dirname "$0")/lib/common.sh"

usage() {
  cat <<'EOF'
deps-audit.sh — bağımlılık açıkları denetimi (hiçbir paketi kurmaz/güncellemez)

Kullanım: bash deps-audit.sh [--src .] [--out DIR]

Algılanan ekosistemler ve araçlar:
  package-lock.json → npm audit · pnpm-lock.yaml → pnpm audit · yarn.lock → yarn audit / yarn npm audit
  requirements*.txt, pyproject.toml, poetry.lock, Pipfile.lock → pip-audit
  composer.lock → composer audit · go.mod → govulncheck · Gemfile.lock → bundle-audit
  *.csproj/*.sln → dotnet list package --vulnerable
Kurulu olmayan araç atlanır ve özete yazılır. Denetim araçları kendi açık veritabanlarına (registry) bağlanır.
Çıktı: DIR/<araç>.json + summary.md (varsayılan DIR: .visual-tester/deps)
EOF
}

SRC="."; OUT="$VT_DIR/deps"
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --src) vt_require_arg "$1" "${2:-}"; SRC="$2"; shift 2 ;;
    --out) vt_require_arg "$1" "${2:-}"; OUT="$2"; shift 2 ;;
    *) vt_die "Bilinmeyen argüman: $1 (--help)" ;;
  esac
done
[ -d "$SRC" ] || vt_die "Kaynak dizini yok: $SRC"
mkdir -p "$OUT"
OUT_ABS="$(cd "$OUT" && pwd)"
cd "$SRC" || exit 1
SUM=("# Bağımlılık denetimi özeti" "")
FOUND=0

count_npm() { # npm/pnpm audit json → "kritik X, yüksek Y, ..."
  node -e '
    const t=require("fs").readFileSync(process.argv[1],"utf8"); let v={};
    try { const j=JSON.parse(t); v=(j.metadata&&j.metadata.vulnerabilities)||{}; }
    catch { for (const l of t.split("\n")) { try { const o=JSON.parse(l); if(o.type==="auditSummary") v=o.data.vulnerabilities; } catch {} } }
    console.log(`kritik ${v.critical||0}, yüksek ${v.high||0}, orta ${v.moderate||0}, düşük ${v.low||0}`);' "$(vt_native_path "$1")" 2>/dev/null || echo "özet okunamadı"
}

run() { # ad komut... → OUT/ad.json
  local name="$1"; shift
  if ! vt_have "$1"; then SUM+=("- $name: araç yok ($1)"); return 1; fi
  "$@" > "$OUT_ABS/$name.json" 2> "$OUT_ABS/$name.err"
  return 0
}

if [ -f package-lock.json ]; then FOUND=1
  run npm-audit npm audit --json && SUM+=("- npm audit: $(count_npm "$OUT_ABS/npm-audit.json") → npm-audit.json (içe aktar: --tool npm-audit)")
fi
if [ -f pnpm-lock.yaml ]; then FOUND=1
  run pnpm-audit pnpm audit --json && SUM+=("- pnpm audit: $(count_npm "$OUT_ABS/pnpm-audit.json") → pnpm-audit.json")
fi
if [ -f yarn.lock ]; then FOUND=1
  if vt_have yarn && yarn --version 2>/dev/null | grep -q '^1\.'; then
    run yarn-audit yarn audit --json && SUM+=("- yarn audit: $(count_npm "$OUT_ABS/yarn-audit.json") → yarn-audit.json")
  else
    run yarn-audit yarn npm audit --all --recursive --json && SUM+=("- yarn npm audit → yarn-audit.json")
  fi
fi
[ -f package.json ] && [ ! -f package-lock.json ] && [ ! -f pnpm-lock.yaml ] && [ ! -f yarn.lock ] && SUM+=("- UYARI: package.json var ama kilit dosyası yok (tedarik zinciri riski)")

PYREQ=""
for f in requirements.txt requirements-prod.txt requirements/base.txt requirements/prod.txt; do [ -f "$f" ] && PYREQ="$PYREQ -r $f"; done
if [ -n "$PYREQ" ] || [ -f pyproject.toml ] || [ -f poetry.lock ] || [ -f Pipfile.lock ]; then FOUND=1
  if [ -n "$PYREQ" ]; then
    # shellcheck disable=SC2086
    run pip-audit pip-audit $PYREQ -f json --progress-spinner off
  else
    run pip-audit pip-audit -f json --progress-spinner off
  fi && SUM+=("- pip-audit: $(node -e 'try{const j=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const d=j.dependencies||j;console.log(d.reduce((n,x)=>n+((x.vulns||[]).length),0)+" açık")}catch(e){console.log("özet okunamadı")}' "$(vt_native_path "$OUT_ABS/pip-audit.json")") → pip-audit.json")
fi

if [ -f composer.lock ]; then FOUND=1
  run composer-audit composer audit --format=json --locked && SUM+=("- composer audit: $(node -e 'try{const j=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const a=j.advisories||{};console.log(Object.values(a).reduce((n,x)=>n+(Array.isArray(x)?x.length:Object.keys(x).length),0)+" danışma")}catch(e){console.log("özet okunamadı")}' "$(vt_native_path "$OUT_ABS/composer-audit.json")") → composer-audit.json")
fi

if [ -f go.mod ]; then FOUND=1
  run govulncheck govulncheck -json ./... && SUM+=("- govulncheck: $(grep -c '"finding"' "$OUT_ABS/govulncheck.json" 2>/dev/null || echo 0) bulgu kaydı → govulncheck.json")
fi

if [ -f Gemfile.lock ]; then FOUND=1
  run bundle-audit bundle-audit check --format json && SUM+=("- bundle-audit → bundle-audit.json")
fi

if ls ./*.csproj ./*.sln >/dev/null 2>&1; then FOUND=1
  if vt_have dotnet; then
    dotnet list package --vulnerable --include-transitive > "$OUT_ABS/dotnet-vulnerable.txt" 2>&1
    SUM+=("- dotnet: $(grep -cE '(Critical|High|Moderate|Low)' "$OUT_ABS/dotnet-vulnerable.txt" || echo 0) satır → dotnet-vulnerable.txt")
  else
    SUM+=("- dotnet: araç yok")
  fi
fi

[ -f pom.xml ] || [ -f build.gradle ] || [ -f build.gradle.kts ] && { FOUND=1; SUM+=("- Java (Maven/Gradle): yerleşik denetim yok; OWASP Dependency-Check veya 'mvn org.owasp:dependency-check-maven:check' önerilir (onayla)"); }
[ "$FOUND" = 0 ] && SUM+=("- Tanınan bağımlılık dosyası bulunamadı.")

printf '%s\n' "${SUM[@]}" | tee "$OUT_ABS/summary.md"
