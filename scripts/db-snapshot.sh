#!/usr/bin/env bash
# K7: yıkıcı testlerden önce veritabanı anlık görüntüsü. Yalnızca yerel/Docker veritabanları.
set -u
. "$(dirname "$0")/lib/common.sh"

usage() {
  cat <<'EOF'
db-snapshot.sh — test öncesi veritabanı yedeği (K7)

Kullanım:
  bash db-snapshot.sh --type sqlite --file ./data/app.db
  bash db-snapshot.sh --type postgres --url postgres://user:pass@localhost:5432/app
  bash db-snapshot.sh --type mysql    --url mysql://user:pass@127.0.0.1:3306/app
  bash db-snapshot.sh --type postgres --container app-db --db-name app [--db-user postgres]
  bash db-snapshot.sh --type mysql    --container app-db --db-name app [--db-user root]

  --url            Verilmezse DATABASE_URL ortam değişkeni kullanılır. Tür URL şemasından da çıkarılır.
  --container      DB Docker konteynerdeyse pg_dump/mysqldump konteyner İÇİNDE çalışır (yerel istemci gerekmez).
                   Şifre: PGPASSWORD / MYSQL_PWD ortam değişkeni (komut satırına yazılmaz, K8).
  --label          Snapshot adına ek (ör. before-authz)

Güvenlik: host yalnızca localhost/127.x/::1/host.docker.internal/tek etiketli compose servis adı olabilir (K1).
Çıktı: .visual-tester/db/<zaman>[-etiket].{sqlite,sql} + .meta; .visual-tester/db/latest en sonuncuyu gösterir.
Geri yükleme: bash db-restore.sh --confirm
EOF
}

TYPE=""; FILE=""; URL="${DATABASE_URL:-}"; CONTAINER=""; DBNAME=""; DBUSER=""; LABEL=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --type) vt_require_arg "$1" "${2:-}"; TYPE="$2"; shift 2 ;;
    --file) vt_require_arg "$1" "${2:-}"; FILE="$2"; shift 2 ;;
    --url) vt_require_arg "$1" "${2:-}"; URL="$2"; shift 2 ;;
    --container) vt_require_arg "$1" "${2:-}"; CONTAINER="$2"; shift 2 ;;
    --db-name) vt_require_arg "$1" "${2:-}"; DBNAME="$2"; shift 2 ;;
    --db-user) vt_require_arg "$1" "${2:-}"; DBUSER="$2"; shift 2 ;;
    --label) vt_require_arg "$1" "${2:-}"; LABEL="-$(printf '%s' "$2" | tr -c 'A-Za-z0-9_-' '_')"; shift 2 ;;
    *) vt_die "Bilinmeyen argüman: $1 (--help)" ;;
  esac
done

if [ -z "$TYPE" ]; then
  case "$URL" in postgres*://*) TYPE=postgres ;; mysql*://*|mariadb://*) TYPE=mysql ;; sqlite:*|file:*) TYPE=sqlite; FILE="${FILE:-${URL#*:}}"; FILE="${FILE#//}" ;; esac
  [ -z "$TYPE" ] && [ -n "$FILE" ] && TYPE=sqlite
fi
[ -n "$TYPE" ] || { usage; vt_die "--type belirlenemedi."; }

DIR="$VT_DIR/db"; mkdir -p "$DIR"
NAME="$(vt_ts)$LABEL"

# URL ayrıştırma (şifre dosyaya/ekrana yazılmaz)
parse_url() {
  node -e '
    const u=new URL(process.argv[1]);
    console.log([u.hostname.replace(/^\[|\]$/g,""), u.port, decodeURIComponent(u.username), decodeURIComponent(u.password), u.pathname.replace(/^\//,"")].join("\t"));' "$1"
}
check_local_host() {
  case "$1" in
    localhost|127.*|::1|host.docker.internal) return 0 ;;
    *.*|*:*) vt_die "Veritabanı hostu yerel değil: $1 (K1: yalnızca yerel/Docker test veritabanı)" 2 ;;
    *) return 0 ;;  # tek etiketli compose servis adı
  esac
}

case "$TYPE" in
  sqlite)
    [ -n "$FILE" ] && [ -f "$FILE" ] || vt_die "SQLite dosyası bulunamadı: ${FILE:-?} (--file)"
    OUTF="$DIR/$NAME.sqlite"
    if vt_have sqlite3; then
      sqlite3 "$FILE" ".backup '$(vt_native_path "$OUTF")'" || vt_die "sqlite3 .backup başarısız"
    else
      vt_warn "sqlite3 yok; dosya kopyalanıyor (uygulama yazıyorsa tutarsız olabilir; mümkünse uygulamayı durdurun)."
      cp "$FILE" "$OUTF" || vt_die "Kopyalama başarısız"
      for ext in -wal -shm; do [ -f "$FILE$ext" ] && cp "$FILE$ext" "$OUTF$ext"; done
    fi
    META="type=sqlite\nfile=$(cd "$(dirname "$FILE")" && pwd)/$(basename "$FILE")"
    ;;
  postgres|mysql)
    OUTF="$DIR/$NAME.sql"
    if [ -n "$CONTAINER" ]; then
      vt_have docker || vt_die "docker bulunamadı."
      [ -n "$DBNAME" ] || vt_die "--container ile --db-name gerekli."
      if [ "$TYPE" = postgres ]; then
        DBUSER="${DBUSER:-postgres}"
        MSYS_NO_PATHCONV=1 docker exec -e PGPASSWORD="${PGPASSWORD:-}" "$CONTAINER" pg_dump -U "$DBUSER" -d "$DBNAME" --clean --if-exists --no-owner > "$OUTF" \
          || vt_die "pg_dump (konteyner) başarısız"
      else
        DBUSER="${DBUSER:-root}"
        MSYS_NO_PATHCONV=1 docker exec -e MYSQL_PWD="${MYSQL_PWD:-}" "$CONTAINER" mysqldump -u "$DBUSER" --single-transaction --routines --add-drop-table "$DBNAME" > "$OUTF" \
          || vt_die "mysqldump (konteyner) başarısız"
      fi
      META="type=$TYPE\ncontainer=$CONTAINER\ndb_name=$DBNAME\ndb_user=$DBUSER"
    else
      [ -n "$URL" ] || vt_die "--url veya DATABASE_URL gerekli (ya da --container)."
      IFS=$'\t' read -r H P U PW D <<<"$(parse_url "$URL")"
      check_local_host "$H"
      if [ "$TYPE" = postgres ]; then
        vt_have pg_dump || vt_die "pg_dump yok; --container kullanın veya PostgreSQL istemcisini kurun."
        PGPASSWORD="$PW" pg_dump -h "$H" -p "${P:-5432}" -U "$U" -d "$D" --clean --if-exists --no-owner -f "$OUTF" || vt_die "pg_dump başarısız"
      else
        vt_have mysqldump || vt_die "mysqldump yok; --container kullanın veya MySQL istemcisini kurun."
        MYSQL_PWD="$PW" mysqldump -h "$H" -P "${P:-3306}" -u "$U" --single-transaction --routines --add-drop-table "$D" > "$OUTF" || vt_die "mysqldump başarısız"
      fi
      META="type=$TYPE\nhost=$H\nport=$P\ndb_user=$U\ndb_name=$D"
    fi
    ;;
  *) vt_die "Desteklenmeyen tür: $TYPE (sqlite|postgres|mysql)" ;;
esac

[ -s "$OUTF" ] || vt_die "Snapshot boş: $OUTF"
{ printf '%b\n' "$META"; printf 'created=%s\nsnapshot=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$OUTF"; } > "$OUTF.meta"
printf '%s\n' "$OUTF" > "$DIR/latest"
vt_info "Snapshot alındı: $OUTF ($(wc -c < "$OUTF" | tr -d ' ') bayt). Geri yükleme: bash db-restore.sh --confirm"
