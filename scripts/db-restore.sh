#!/usr/bin/env bash
# K7: test sonrası veritabanını snapshot'a geri döndürür. --confirm olmadan hiçbir şey yapmaz.
set -u
. "$(dirname "$0")/lib/common.sh"

usage() {
  cat <<'EOF'
db-restore.sh — snapshot'tan geri yükleme (K7)

Kullanım: bash db-restore.sh --confirm [--snapshot .visual-tester/db/<dosya>] [--url URL]

  --snapshot   Varsayılan: .visual-tester/db/latest'in gösterdiği dosya
  --url        Postgres/MySQL (konteynersiz) için bağlantı; verilmezse DATABASE_URL.
               Şifre .meta'da tutulmaz; URL'den veya PGPASSWORD/MYSQL_PWD'den alınır.
  --confirm    Zorunlu: mevcut test veritabanının üzerine yazılır.

Hedef, snapshot'ın .meta dosyasındaki kaynakla aynı olmalıdır (farklı host/DB reddedilir).
EOF
}

SNAP=""; URL="${DATABASE_URL:-}"; CONFIRM=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --snapshot) vt_require_arg "$1" "${2:-}"; SNAP="$2"; shift 2 ;;
    --url) vt_require_arg "$1" "${2:-}"; URL="$2"; shift 2 ;;
    --confirm) CONFIRM=1; shift ;;
    *) vt_die "Bilinmeyen argüman: $1 (--help)" ;;
  esac
done
[ -n "$SNAP" ] || SNAP="$(cat "$VT_DIR/db/latest" 2>/dev/null)"
[ -n "$SNAP" ] && [ -f "$SNAP" ] || vt_die "Snapshot bulunamadı (${SNAP:-latest yok}). Önce db-snapshot.sh."
[ -f "$SNAP.meta" ] || vt_die "Meta dosyası yok: $SNAP.meta"
meta() { grep "^$1=" "$SNAP.meta" | head -1 | cut -d= -f2-; }
TYPE="$(meta type)"
[ "$CONFIRM" = 1 ] || { vt_info "Kuru çalıştırma: $TYPE snapshot'ı ($SNAP) geri yüklenecek. Uygulamak için --confirm ekleyin."; exit 0; }

case "$TYPE" in
  sqlite)
    DEST="$(meta file)"
    cp "$SNAP" "$DEST" || vt_die "Kopyalama başarısız: $DEST"
    for ext in -wal -shm; do if [ -f "$SNAP$ext" ]; then cp "$SNAP$ext" "$DEST$ext"; else rm -f "$DEST$ext"; fi; done
    ;;
  postgres|mysql)
    C="$(meta container)"
    if [ -n "$C" ]; then
      if [ "$TYPE" = postgres ]; then
        MSYS_NO_PATHCONV=1 docker exec -i -e PGPASSWORD="${PGPASSWORD:-}" "$C" psql -q -v ON_ERROR_STOP=1 -U "$(meta db_user)" -d "$(meta db_name)" < "$SNAP" >/dev/null || vt_die "psql (konteyner) başarısız"
      else
        MSYS_NO_PATHCONV=1 docker exec -i -e MYSQL_PWD="${MYSQL_PWD:-}" "$C" mysql -u "$(meta db_user)" "$(meta db_name)" < "$SNAP" || vt_die "mysql (konteyner) başarısız"
      fi
    else
      [ -n "$URL" ] || vt_die "--url veya DATABASE_URL gerekli."
      IFS=$'\t' read -r H P U PW D <<<"$(node -e 'const u=new URL(process.argv[1]);console.log([u.hostname.replace(/^\[|\]$/g,""),u.port,decodeURIComponent(u.username),decodeURIComponent(u.password),u.pathname.replace(/^\//,"")].join("\t"))' "$URL")"
      [ "$H" = "$(meta host)" ] && [ "$D" = "$(meta db_name)" ] || vt_die "Hedef ($H/$D) snapshot kaynağıyla ($(meta host)/$(meta db_name)) eşleşmiyor; reddedildi."
      if [ "$TYPE" = postgres ]; then
        PGPASSWORD="$PW" psql -q -v ON_ERROR_STOP=1 -h "$H" -p "${P:-5432}" -U "$U" -d "$D" -f "$SNAP" >/dev/null || vt_die "psql başarısız"
      else
        MYSQL_PWD="$PW" mysql -h "$H" -P "${P:-3306}" -u "$U" "$D" < "$SNAP" || vt_die "mysql başarısız"
      fi
    fi
    ;;
  *) vt_die "Bilinmeyen snapshot türü: $TYPE" ;;
esac
vt_info "Geri yüklendi: $SNAP → $TYPE"
