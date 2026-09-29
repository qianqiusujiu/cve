# Hospital-Management-System Bill PDF SQL Injection (vanilla PHP + MySQLi)

> ⚠️ **COVERED / 勿提交**: 提报前查重发现在先披露——**GitHub issue #64 (Systemic SQL Injection + No Authentication)**。本目录仅作研究存档,不提交 VulDB。
**CWE-89 · Unauthenticated SQL injection (UNION SELECT) · arbitrary data exfiltration into the generated bill PDF**

> **Vendor:** kishan0725
> **Product:** Hospital-Management-System (vanilla PHP + MySQLi)
> **Affected version:** master branch, commit 777fda46b77a820977a5ba616283dbfbc40bf7e1 (last commit 2024-10-07; no official release version)
> **Affected endpoints:** GET /admin-panel.php?ID=<inj>&generate_bill=1
> **Dedup status:** PARTIAL — shares the `?cancel=1&ID=` entry point with the appointment-cancellation UPDATE sinks (separate submission) and with CVE-2025-63513 (IDOR), but this submission is a distinct sink and root cause: raw concatenation of `ID` into the UNION-able prescription/bill SELECT. No prior CVE covers this sink.
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The bill-generation query of `admin-panel.php` concatenates the GET parameter `ID` raw into a SELECT with 11 result columns, and the file has no session check. A UNION injection makes the query return arbitrary rows, which the TCPDF bill generator writes into the downloadable `bill.pdf` — a built-in exfiltration channel that works with `display_errors` disabled. Verified end-to-end: all 11 `patreg` rows (email + adjacent plaintext password) were injected into the bill PDF and recovered by decompressing its FlateDecode streams.

## 2. Root Cause

| File | Line | Statement |
|---|---|---|
| `admin-panel.php` | 86 | prescription/bill SELECT consumed by `generate_bill()` (below) |

```php
// admin-panel.php:86 (entry: GET ?ID=<inj>&generate_bill=1)
// $pid = $_SESSION['pid'] -> empty string when unauthenticated
mysqli_query($con, "select p.pid, ..., a.docFees
                    from prestb p
                    inner join appointmenttb a on p.ID=a.ID
                    and p.pid = '$pid'
                    and p.ID = '".$_GET['ID']."'");
// rows are rendered into the page and into the TCPDF bill: $pdf->Output('bill.pdf', 'I')
```

Raw concatenation of `$_GET['ID']`, no prepared statement, no authentication gate anywhere in the file. Column list elided (`...`) between `p.pid` and `a.docFees`; the result set has exactly 11 columns.

## 3. Prerequisites

None. The request is a plain GET without a Cookie header; `$pid` interpolates as an empty string when unauthenticated and the injection in the `ID` position controls the returned rows regardless.

## 4. Reproduction

Baseline (benign bill):

```http
GET /admin-panel.php?ID=1&generate_bill=1 HTTP/1.1
# -> HTTP 200, 7022-byte PDF
```

UNION injection (harmless extraction target):

```http
GET /admin-panel.php?ID=9999%27%20UNION%20SELECT%201%2C@@version%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2C11%20FROM%20patreg--%20-&generate_bill=1 HTTP/1.1
# decodes to: 9999' UNION SELECT 1,@@version,3,4,5,6,7,8,9,10,11 FROM patreg-- -
# -> HTTP 200, 11844-byte PDF
```

Verification of the exfiltration channel:

- zlib-decompress the PDF's FlateDecode content streams: the injected row (MySQL `@@version` string) is present in the payload PDF and absent in the baseline.
- Substituting the `patreg` `email` and `password` columns for the `@@version` position injected all 11 patient rows (email + adjacent plaintext password) into the bill PDF: `<REDACTED>` (seed credential values withheld; presence proven by decompressed-stream diff, baseline contains none of them).

Runnable PoC: `poc/poc.sh`.

## 5. Confirmed Techniques

- Manual verification on a local instance: MySQL 8.0.39 (127.0.0.1:3307), PHP 8.4.26 built-in server, `display_errors=0`, seeded `myhmsdb.sql`.
- UNION SELECT with 11 columns (audit-era PoCs listing 10 columns were corrected during verification).
- Exfiltration channel: TCPDF bill PDF, content streams FlateDecode-compressed; recovery by zlib decompression and string diff against the baseline PDF (11844 vs 7022 bytes).
- Works with `display_errors=0` — no error output required.

## 6. Impact

Unauthenticated arbitrary reads against the entire backend database, with the bill PDF as a reliable file-based exfiltration channel. In the seeded schema this immediately exposes every patient's email and plaintext password (`patreg`), plus prescription and billing tables reachable via further UNION shapes. Extracted credential values are withheld: `<REDACTED>` (verified locally against a throwaway DB).

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (Base 7.5, High)

## 8. Remediation

- Use a prepared statement with a bound parameter for `ID` (and for `pid`).
- Enforce an authenticated session before any database access in `admin-panel.php`.
- Hash stored passwords (`password_hash()`); the current plaintext storage turns this read into immediate credential compromise.

## 9. References

- Project: https://github.com/kishan0725/Hospital-Management-System
- Commit: 777fda46b77a820977a5ba616283dbfbc40bf7e1 (master, 2024-10-07)
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- External disclosure: https://gist.github.com/qianqiusujiu/d02815e9261c8de9e8afc46db844ec16
- VulDB submission #xxxxxx
- Local verification record: `evidence/HMS-02.txt`; PoC: `poc/poc.sh`

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
