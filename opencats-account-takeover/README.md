# OpenCATS Candidate Portal Account Takeover (0.10.0)

**CWE-640 · Unauthenticated account takeover · Low-entropy verification triple (email + last name + ZIP), no captcha, no rate limiting**

> **Vendor:** opencats (https://github.com/opencats)
> **Product:** OpenCATS (custom PHP + MySQL/mysqli, https://github.com/opencats/OpenCATS)
> **Affected version:** 0.10.0 (`CATS_VERSION` in `constants.php`), master branch commit d5cf733 (2026-09-21), latest as of 2026-09-28
> **Affected endpoints:** POST /careers/index.php (`applyToJobSubAction=processLogin`), `pa=updateProfile`, `p=onRegisteredCandidateProfile`
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Validation used seeded example candidates (example.com addresses) only; no real personal data appears in this disclosure.

## 1. Summary

The OpenCATS public careers portal authenticates returning candidates with the verification fields defined by the site's registration template — the shipped default template defines exactly three: **email address, last name and ZIP code**, i.e. the data a candidate prints on the resume submitted through this same portal. A correct triple yields the victim's full profile (pre-filled), the victim's numeric `candidateID`, and a 2-week identity cookie; with only that cookie an attacker reads the profile, overwrites the victim's PII and delete-and-replaces the victim's resume. No captcha protects the login oracle or profile update, and there is no rate limiting (20/20 consecutive guesses processed).

## 2. Root Cause

| File | Line | Role |
|---|---|---|
| `db/cats_schema.sql` | 388 | Default "Content - Candidate Registration" template = `<input-email>` + `<input-lastName>` + `<input-zip>` only |
| `modules/careers/CareersUI.php` | 2080-2084 | `isCandidateRegistered()` |
| `modules/careers/CareersUI.php` | 2086-2178 | `ProcessCandidateRegistration()`: template tag parse (2094-2120), `SELECT candidate_id FROM candidate WHERE LCASE(last_name)=? ... AND (LCASE(email1)=? OR LCASE(email2)=?) LIMIT 1` (2131-2161), accepts ≥1 field by design (2150-2156) |
| `modules/careers/CareersUI.php` | 2171-2178 | Sets 2-week identity cookie `cats<siteid>cw` (value = the verification triple) |
| `modules/careers/CareersUI.php` | 520-592 | `applyToJobSubAction=processLogin` login branch |
| `modules/careers/CareersUI.php` | 278-390 | `p=onRegisteredCandidateProfile`: `Candidates::update` (336); resume delete+replace (380 → 382) |
| `modules/careers/CareersUI.php` | 1169-1172, 804 | Captcha enforced only on the final application POST and only if the template contains `<input-captcha req>` |

```php
// modules/careers/CareersUI.php:2150-2156
// There needs to be 1 verification field (equivilant of a "password"), otherwise anyone
// could change anyone else's candidate information with as little as an e-mail address.
if ($verificationFields < 1)
{
    return false;
}
```

## 3. Prerequisites

- Careers portal enabled with candidate registration enabled (documented operating mode).
- Victim is a pre-existing candidate in the portal.
- Attacker knows email + last name + ZIP (from the victim's resume); unlimited guessing — no captcha on the login oracle, no rate limiting, no lockout.

## 4. Reproduction

```http
POST /careers/index.php?m=careers&p=applyToJob&ID=1 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

applyToJobSubAction=processLogin&isNew=no&email=alice.smith@example.com&lastName=Smith&zip=10001&rememberMe=yes
```

HTTP 200: victim profile pre-filled, `candidateID` hidden field disclosed, `Set-Cookie: cats1cw=...; Max-Age=1209600`. Then, with only the cookie:

```http
GET /careers/index.php?m=careers&p=showAll&pa=updateProfile
Cookie: cats1cw=...

POST /careers/index.php?m=careers&p=onRegisteredCandidateProfile
Cookie: cats1cw=...
(... attacker-chosen PII fields + multipart resume upload ...)
```

Scripted PoC: `poc/takeover.sh` (target source: `poc/TARGET-SOURCE.txt`). Raw verification transcript: `evidence/OPENCATS-D2N1.txt`.

## 5. Confirmed Techniques

- Deterministic 5/5: correct triple → HTTP 200 + full PII prefill + `candidateID` + 2-week identity cookie.
- Controls: wrong ZIP → no prefill/cookie; cross-combination (A's email + B's lastName) → no match; B's own triple → only B.
- Cookie-only takeover: profile render, PII overwrite (DB-confirmed `phone_work 555-0100 → 666-PWNED`, `address → 66 Attacker Lane`, `key_skills → PWNED by attacker`), resume replaced v1 → v2 via `attachmentID`.
- No captcha on login/profile paths; no rate limiting (20/20 wrong-ZIP attempts, all HTTP 200).

## 6. Impact

Unauthenticated attackers authenticate as any candidate whose email + last name + ZIP they know or guess (no lockout), read the profile, overwrite PII and silently replace the resume the recruiter sees — tampering with candidate data and poisoning hiring decisions. Identity cookie re-exfiltrates the verification triple.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` (Base 6.5 — Medium)

## 8. Remediation

1. Require a minimum-entropy secret chosen at first application, or a signed one-time email login link — template fields are not passwords.
2. Per-IP and per-account rate limiting with lockout on the registration-login endpoint.
3. Enforce captcha on login oracle and profile update.
4. Use an opaque server-side session token instead of embedding the triple in the cookie.
5. Re-verify explicitly before portal updates of candidate records.

## 9. References

- Project: https://github.com/opencats/OpenCATS
- CWE-640: https://cwe.mitre.org/data/definitions/640.html
- External disclosure: https://gist.github.com/qianqiusujiu/1eab18f3378c4ead24da99fb2e250945
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
