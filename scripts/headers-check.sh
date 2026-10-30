#!/usr/bin/env bash
# Güvenlik başlıkları, CSP kalitesi, cookie bayrakları, CORS, TLS ve bilgi sızdıran başlıklar.
set -u
. "$(dirname "$0")/lib/common.sh"

usage() {
  cat <<'EOF'
headers-check.sh — HTTP güvenlik başlıkları denetimi (yalnızca GET/HEAD; scope-guard zorunlu)

Kullanım: bash headers-check.sh <URL> [--out DOSYA.json] [--insecure] [--cookie "ad=değer"]

Kontroller: HSTS, CSP (varlık + unsafe-inline/eval, joker, object-src, base-uri, frame-ancestors),
X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy, Permissions-Policy,
Set-Cookie (Secure/HttpOnly/SameSite), CORS (Origin yansıtma + credentials, null origin),
bilgi sızdıran başlıklar (Server sürümü, X-Powered-By, X-AspNet-Version, X-Debug-Token...),
HTTP→HTTPS yönlendirme, TLS 1.0/1.1 ve sertifika süresi (openssl varsa).
CORS testinde Origin başlığı "https://vt-evil.example" olarak gönderilir; o adrese istek ATILMAZ.
Yönlendirme izlenmez; 3xx dönerse Location gösterilir.
Çıktı: PASS/WARN/FAIL/INFO satırları + JSON (varsayılan .visual-tester/headers-<host>.json)
EOF
}

URL=""; OUTF=""; INSECURE=(); COOKIE=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --out) vt_require_arg "$1" "${2:-}"; OUTF="$2"; shift 2 ;;
    --insecure) INSECURE=(-k); shift ;;
    --cookie) vt_require_arg "$1" "${2:-}"; COOKIE=(-H "Cookie: $2"); shift 2 ;;
    -*) vt_die "Bilinmeyen argüman: $1 (--help)" ;;
    *) URL="$1"; shift ;;
  esac
done
[ -n "$URL" ] || { usage; exit 1; }
vt_have curl || vt_die "curl bulunamadı."
vt_scope_check "$URL"

HOST="$(printf '%s' "$URL" | sed -E 's#^[a-z]+://(\[[^]]+\]|[^/:]+).*#\1#')"
SCHEME="${URL%%://*}"
mkdir -p "$VT_DIR"
[ -n "$OUTF" ] || OUTF="$VT_DIR/headers-$(printf '%s' "$HOST" | tr -c 'A-Za-z0-9.-' '_').json"

fetch() { curl -sS "${INSECURE[@]+"${INSECURE[@]}"}" "${COOKIE[@]+"${COOKIE[@]}"}" -o /dev/null -D - --max-time 15 -A "visual-tester/1.0" "$@" 2>/dev/null | tr -d '\r'; }
HDRS="$(fetch "$URL")" || true
[ -n "$HDRS" ] || vt_die "Yanıt alınamadı: $URL"
hdr() { printf '%s\n' "$HDRS" | grep -i "^$1:" | tail -1 | cut -d: -f2- | sed 's/^ *//'; }

RESULTS=()
CNT_FAIL=0; CNT_WARN=0
res() { # seviye id cwe mesaj
  RESULTS+=("$1|$2|$3|$4")
  printf '%-4s %-22s %s\n' "$1" "$2" "$4"
  [ "$1" = FAIL ] && CNT_FAIL=$((CNT_FAIL+1)); [ "$1" = WARN ] && CNT_WARN=$((CNT_WARN+1)); return 0
}

STATUS="$(printf '%s\n' "$HDRS" | head -1 | awk '{print $2}')"
res INFO status - "HTTP $STATUS"
case "$STATUS" in 3*) res INFO redirect - "Yönlendirme → $(hdr location) (izlenmedi; hedef sayfayı ayrıca verin)";; esac

# HSTS
if [ "$SCHEME" = https ]; then
  HSTS="$(hdr strict-transport-security)"
  if [ -z "$HSTS" ]; then res FAIL hsts CWE-319 "Strict-Transport-Security yok"
  else
    MA="$(printf '%s' "$HSTS" | grep -oiE 'max-age=[0-9]+' | cut -d= -f2)"
    if [ "${MA:-0}" -lt 15552000 ]; then res WARN hsts CWE-319 "HSTS max-age kısa ($MA)"; else res PASS hsts - "HSTS: $HSTS"; fi
  fi
  HTTP_URL="http://${URL#https://}"
  if node "$(vt_native_path "$VT_SCRIPTS_DIR")/scope-guard.mjs" --check "$HTTP_URL" >/dev/null 2>&1; then
    HH="$(curl -sS -o /dev/null -D - --max-time 8 "$HTTP_URL" 2>/dev/null | tr -d '\r')"
    if [ -n "$HH" ]; then
      if printf '%s\n' "$HH" | head -1 | grep -qE ' 30[1278] ' && printf '%s\n' "$HH" | grep -qi '^location: *https://'; then res PASS http-redirect - "HTTP → HTTPS yönlendiriyor"
      else res WARN http-redirect CWE-319 "HTTP isteği HTTPS'e yönlendirilmiyor"; fi
    fi
  fi
else
  res INFO hsts - "HTTP hedef (yerel); HSTS/TLS kontrolleri staging HTTPS'te yapılmalı"
fi

# CSP
CSP="$(hdr content-security-policy)"
CSPRO="$(hdr content-security-policy-report-only)"
if [ -z "$CSP" ]; then
  if [ -n "$CSPRO" ]; then res WARN csp CWE-693 "CSP yalnızca Report-Only modunda"; else res FAIL csp CWE-693 "Content-Security-Policy yok"; fi
else
  csp_dir() { printf '%s' "$CSP" | tr ';' '\n' | sed 's/^ *//' | grep -i "^$1 " | head -1; }
  SCRIPT_SRC="$(csp_dir script-src)"; [ -n "$SCRIPT_SRC" ] || SCRIPT_SRC="$(csp_dir default-src)"
  ISSUES=0
  printf '%s' "$SCRIPT_SRC" | grep -qi "'unsafe-inline'" && ! printf '%s' "$SCRIPT_SRC" | grep -qiE "'nonce-|'sha(256|384|512)-|'strict-dynamic'" && { res WARN csp-inline CWE-693 "script-src 'unsafe-inline' içeriyor (nonce/hash yok)"; ISSUES=1; }
  printf '%s' "$SCRIPT_SRC" | grep -qi "'unsafe-eval'" && { res WARN csp-eval CWE-693 "script-src 'unsafe-eval' içeriyor"; ISSUES=1; }
  printf '%s' "$SCRIPT_SRC" | grep -qE "(^| )(\*|https?:|data:)( |$)" && { res WARN csp-wildcard CWE-693 "script-src joker/şema kaynağı içeriyor (*, https:, data:)"; ISSUES=1; }
  [ -z "$SCRIPT_SRC" ] && { res WARN csp-noscript CWE-693 "CSP'de script-src/default-src yok"; ISSUES=1; }
  { [ -n "$(csp_dir object-src)" ] || csp_dir default-src | grep -qi "'none'"; } || { res WARN csp-object CWE-693 "object-src 'none' yok"; ISSUES=1; }
  [ -n "$(csp_dir base-uri)" ] || { res WARN csp-base CWE-693 "base-uri yok"; ISSUES=1; }
  [ "$ISSUES" = 0 ] && res PASS csp - "CSP tanımlı ve temel kontrolleri geçti"
fi

# Clickjacking
XFO="$(hdr x-frame-options)"
if printf '%s' "$CSP" | grep -qi 'frame-ancestors' || [ -n "$XFO" ]; then res PASS clickjacking - "frame-ancestors/X-Frame-Options var"
else res FAIL clickjacking CWE-1021 "frame-ancestors veya X-Frame-Options yok (clickjacking)"; fi

# Diğer başlıklar
[ "$(hdr x-content-type-options | tr 'A-Z' 'a-z')" = nosniff ] && res PASS nosniff - "X-Content-Type-Options: nosniff" || res WARN nosniff CWE-693 "X-Content-Type-Options: nosniff yok"
[ -n "$(hdr referrer-policy)" ] && res PASS referrer - "Referrer-Policy: $(hdr referrer-policy)" || res WARN referrer CWE-200 "Referrer-Policy yok"
[ -n "$(hdr permissions-policy)" ] && res PASS permissions - "Permissions-Policy var" || res INFO permissions - "Permissions-Policy yok (öneri)"

# Bilgi sızdıran başlıklar
SRV="$(hdr server)"; [ -n "$SRV" ] && printf '%s' "$SRV" | grep -qE '[0-9]' && res WARN server-version CWE-200 "Server sürüm sızdırıyor: $SRV"
[ -n "$(hdr x-powered-by)" ] && res WARN x-powered-by CWE-200 "X-Powered-By: $(hdr x-powered-by)"
for h in x-aspnet-version x-aspnetmvc-version x-generator; do [ -n "$(hdr $h)" ] && res WARN "$h" CWE-200 "$h: $(hdr $h)"; done
for h in x-debug-token x-debug-token-link x-debug; do [ -n "$(hdr $h)" ] && res FAIL "$h" CWE-489 "Debug başlığı açık: $h (profiler/debug modu)"; done

# Cookie bayrakları
printf '%s\n' "$HDRS" | grep -i '^set-cookie:' | while IFS= read -r line; do
  NAME="$(printf '%s' "$line" | cut -d: -f2- | sed 's/^ *//' | cut -d= -f1)"
  LOW="$(printf '%s' "$line" | tr 'A-Z' 'a-z')"
  SENS=0; printf '%s' "$NAME" | grep -qiE 'sess|sid|token|auth|jwt|remember|csrf|xsrf' && SENS=1
  [ "$SCHEME" = https ] && ! printf '%s' "$LOW" | grep -q '; *secure' && echo "COOKIE|WARN|cookie-secure|CWE-614|Cookie '$NAME' Secure bayrağı yok"
  [ "$SENS" = 1 ] && ! printf '%s' "$NAME" | grep -qiE 'csrf|xsrf' && ! printf '%s' "$LOW" | grep -q '; *httponly' && echo "COOKIE|FAIL|cookie-httponly|CWE-1004|Oturum cookie '$NAME' HttpOnly değil"
  ! printf '%s' "$LOW" | grep -q 'samesite' && echo "COOKIE|WARN|cookie-samesite|CWE-1275|Cookie '$NAME' SameSite belirtilmemiş"
  printf '%s' "$LOW" | grep -q 'samesite=none' && ! printf '%s' "$LOW" | grep -q '; *secure' && echo "COOKIE|FAIL|cookie-samesite|CWE-1275|Cookie '$NAME' SameSite=None ama Secure değil"
done > "$VT_DIR/.cookies.tmp"
while IFS='|' read -r _ lvl id cwe msg; do [ -n "$lvl" ] && res "$lvl" "$id" "$cwe" "$msg"; done < "$VT_DIR/.cookies.tmp"
rm -f "$VT_DIR/.cookies.tmp"

# CORS
EVIL="https://vt-evil.example"
CH="$(fetch -H "Origin: $EVIL" "$URL")"
ACAO="$(printf '%s\n' "$CH" | grep -i '^access-control-allow-origin:' | tail -1 | cut -d: -f2- | sed 's/^ *//')"
ACAC="$(printf '%s\n' "$CH" | grep -i '^access-control-allow-credentials:' | tail -1 | cut -d: -f2- | sed 's/^ *//' | tr 'A-Z' 'a-z')"
if [ "$ACAO" = "$EVIL" ]; then
  [ "$ACAC" = true ] && res FAIL cors-reflect CWE-942 "CORS rastgele Origin'i yansıtıyor + credentials=true" || res WARN cors-reflect CWE-942 "CORS rastgele Origin'i yansıtıyor"
elif [ "$ACAO" = "*" ]; then
  [ "$ACAC" = true ] && res FAIL cors-wildcard CWE-942 "ACAO=* ile credentials=true" || res INFO cors-wildcard - "ACAO=* (kimliksiz kaynaklar için kabul edilebilir)"
else
  res PASS cors - "Yabancı Origin yansıtılmıyor"
fi
NH="$(fetch -H "Origin: null" "$URL")"
printf '%s\n' "$NH" | grep -qi '^access-control-allow-origin: *null' && res FAIL cors-null CWE-942 "CORS 'null' origin'e izin veriyor"

# TLS
if [ "$SCHEME" = https ] && vt_have openssl; then
  PORT="$(printf '%s' "$URL" | sed -nE 's#^https://[^/:]+:([0-9]+).*#\1#p')"; PORT="${PORT:-443}"
  TO=""; vt_have timeout && TO="timeout 10"
  for p in tls1 tls1_1; do
    if echo | $TO openssl s_client -connect "$HOST:$PORT" -servername "$HOST" "-$p" >/dev/null 2>&1; then res FAIL "tls-$p" CWE-326 "Eski protokol kabul ediliyor: $p"; fi
  done
  END="$(echo | $TO openssl s_client -connect "$HOST:$PORT" -servername "$HOST" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
  [ -n "$END" ] && res INFO tls-cert - "Sertifika bitiş: $END"
elif [ "$SCHEME" = https ]; then
  res INFO tls - "openssl yok; TLS kontrolü atlandı"
fi

# JSON çıktı
{
  printf '{"url":"%s","checked_at":"%s","fail":%d,"warn":%d,"results":[' "$URL" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CNT_FAIL" "$CNT_WARN"
  first=1
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r lvl id cwe msg <<<"$r"
    msg="${msg//\\/\\\\}"; msg="${msg//\"/\\\"}"
    [ $first = 1 ] || printf ','
    printf '{"level":"%s","id":"%s","cwe":%s,"message":"%s"}' "$lvl" "$id" "$([ "$cwe" = - ] && echo null || echo "\"$cwe\"")" "$msg"
    first=0
  done
  printf ']}\n'
} > "$OUTF"
vt_info "FAIL $CNT_FAIL · WARN $CNT_WARN → $OUTF (içe aktar: findings.mjs import --tool headers --file $OUTF)"
