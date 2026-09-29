# card-system Hardcoded Credential (Laravel 5.5)

**CWE-798 · Public source · Hardcoded third-party MySQL credential exercised by the shipped API-delivery code path**

> **Vendor:** Tai7sy
> **Product:** card-system (Laravel 5.5)
> **Affected version:** master branch, latest as of 2026-09-30 (commit 4e908dd); no official release version
> **Affected component:** `app/Product.php` — `createApiCards()` (source file shipped as a single line)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The product model `app/Product.php` contains `createApiCards()`, which connects to the vendor's own external card-delivery MySQL database using **hardcoded credentials** (`mysqli_connect('localhost', '<REDACTED>', '<REDACTED>', '<REDACTED>', '3306')`) and writes generated card codes into the `<REDACTED>`.ac_kms table. The code path runs for every order of an API-delivery product (`delivery = DELIVERY_API = 2`) via `Shop\Pay@buy -> shipOrder()`. The credential is therefore a **live, working database credential published in the public repository** — verified end-to-end at runtime (authentication + INSERT succeeded against a locally provisioned server with the same pair).

## 2. Root Cause

| File | Location | Role |
|---|---|---|
| `app/Product.php` | function `createApiCards()` (single-line source) | hardcoded `mysqli_connect` to the vendor's external card-delivery database |
| `app/Product.php` | same function | `INSERT INTO `<REDACTED>`.`ac_kms` ...` built by string concatenation |

```php
$conn = mysqli_connect('localhost', '<REDACTED>', '<REDACTED>', '<REDACTED>', '3306');
...
$sql = 'INSERT INTO `<REDACTED>`.`ac_kms` (`id`, `km`, `value`, `task`, `udid`, `diz`,
        `task_id`, `install_url`, `plist_url`, `jh`, `addtime`, `tjtime`)
        VALUES ' . join(',', $rows);
```

- Runtime entry: `POST /api/shop/buy` (API-delivery product) → `Shop\Pay::buy()` → `shipOrder()` → `delivery === DELIVERY_API` branch → `Product::createApiCards($order)`.
- No environment/config indirection: the secret ships in version control.

## 3. Prerequisites

- To obtain the secret: none — it is in the public repository source.
- To use the credential against the vendor's own database: network reachability to the vendor's MySQL host. The code configures `'localhost'`, so direct remote use is limited by that — stated as-is; it does not change the fact that a valid third-party DB password is public (and such passwords are commonly reused).

## 4. Reproduction

Obtain the credential from the public source:

```bash
git clone https://github.com/Tai7sy/card-system.git
git -C card-system checkout 4e908dd55f50f1cb6d70eba0d34efb1ec7d74ea3
grep -o "mysqli_connect([^)]*)" card-system/app/Product.php
# -> mysqli_connect('localhost', '<REDACTED>', '<REDACTED>', '<REDACTED>', '3306')
```

Runtime proof (fully local, isolated instance — Laravel 5.5, PHP 7.4.33, MySQL 8.0.39):

1. Provision a local MySQL with the exact hardcoded pair (`CREATE USER '<REDACTED>'@'localhost' ... ; CREATE DATABASE <REDACTED>; CREATE TABLE ac_kms (...)`); independent `mysql -h 127.0.0.1 -u <REDACTED> -p ...` login confirms the pair authenticates.
2. Drive the real shipped path: `POST /api/shop/buy` on an API-delivery product with a full-discount coupon → `paid=0` → `shipOrder()` → `createApiCards()`.
3. Run #1 (MySQL 8 default `sql_mode`): application log proves the connection with the hardcoded credential **succeeded** and the INSERT was issued — it failed only on the zero-date `sql_mode` rule, which happens *after* successful connect/auth.
4. Run #2 (zero-date relaxed on the local test server): full end-to-end success — row written into `<REDACTED>`.ac_kms through the hardcoded credential, and the same generated card code delivered to the buyer as a sold card.

## 5. Confirmed Techniques

- Credential extraction from public source (`grep` on `app/Product.php`, master branch).
- Live runtime exercise of the shipped code path (connect + auth + INSERT) against a locally provisioned server using the exact hardcoded pair.
- The credential is exercised by the shipped code on every API-delivery order — it is not dead/test code.

## 6. Impact

- Anyone who obtains the public source holds a valid credential for the vendor's card-delivery database (schema name `<REDACTED>` — card/fulfillment records).
- If the database host ever becomes reachable (misconfiguration, lateral movement, cloud port exposure), the holder can read and insert card records directly.
- Password reuse extends the exposure beyond this single host. Real credential values are `<REDACTED>` in public copies of this disclosure (presence and validity documented above).

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (Base 5.3 Medium)

## 8. Remediation

- Remove the credentials from source; load them from environment variables or configuration kept outside version control.
- Rotate the exposed database password immediately.
- Restrict database network access (bind to localhost / private network, firewall rules).
- Enable secret scanning on the repository and purge the secret from git history.

## 9. References

- Project: https://github.com/Tai7sy/card-system
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
- External disclosure: https://gist.github.com/qianqiusujiu/456434356e004668a923d9f6db8f5885
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
