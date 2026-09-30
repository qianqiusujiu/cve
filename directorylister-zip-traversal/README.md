# DirectoryLister Path Traversal Arbitrary Directory Archive Download

**CWE-22 · Unauthenticated path traversal in the `?zip=` endpoint · Bulk archive of arbitrary open_basedir-local directories, hidden-files restriction bypassed**

> **Vendor:** Chris Kankiewicz / DirectoryLister (https://github.com/DirectoryLister)
> **Product:** DirectoryLister (Slim 4 PHP application, https://github.com/DirectoryLister/DirectoryLister)
> **Affected version:** 5.7.0 (commit 0cf8ee1, 2026-09-07; latest release as of 2026-09-29)
> **Affected endpoints:** `GET /?zip=<dir>` (zip archive download)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Validation used only harmless marker files created in the test instance; no real credentials or sensitive values appear in this disclosure.

## 1. Summary

The `GET /?zip=<dir>` endpoint resolves the user-supplied path through the shared `full_path` helper (`app/config/container.php:115`) — a raw `files_path . '/' . $path` concatenation with no normalization and no containment check — and `ZipController` gates it only with `is_dir()` (`app/src/Controllers/ZipController.php:40-44`). The hidden `app_files` list (`app`, `app/**`, `.env`, …) is never consulted, and `../` segments are not filtered, so any unauthenticated user can download a zip archive of any directory under the `open_basedir` scope — including directories outside `files_path` — exfiltrating the entire application tree in one request.

> **Dedup note (partial overlap, disclosed honestly):** the same project's `?file=` parameter path traversal was previously disclosed (GitHub issue #1456 on the upstream repository, 2025-10-09). This finding is the **distinct `?zip=` endpoint** — different parameter, different controller (`ZipController`, `is_dir()`-only gate vs `FileController`) and different sink (bulk directory archive vs single-file stream) — while partially overlapping the prior issue in the shared unchecked `full_path` resolution helper.

## 2. Root Cause

| File | Line | Role |
|---|---|---|
| `app/config/container.php` | 112 | `'app_files' => ['app', 'app/**', 'index.php', '.analytics', '.customizations.html', '.env', '.env.example', '.hidden']` — the list ZipController ignores |
| `app/config/container.php` | 115 | `'full_path'` helper: `files_path . '/' . $path` — **raw concat, no normalization, no containment check** |
| `app/src/Controllers/IndexController.php` | 22-28 | dispatch on the first query-param key: `zip` → `ZipController` |
| `app/src/Controllers/ZipController.php` | 40-44 | `$path = $this->container->call('full_path', ['path' => $request->getQueryParams()['zip']]);` then `if (! $this->zipDownloads \|\| ! is_dir($path)) return 404;` — **the only gate is `is_dir()`** |
| `app/src/Controllers/ZipController.php` | 54 | Symfony Finder `$this->finder->in($path)->files()` (dotfiles ignored by default) → ZipStream archive to the client |

```php
// app/src/Controllers/ZipController.php:40-44
$path = $this->container->call('full_path', ['path' => $request->getQueryParams()['zip']]);

if (! $this->zipDownloads || ! is_dir($path)) {          // only gate: is_dir()
    return $response->withStatus(404, ...);
}
```

## 3. Prerequisites

- **None** — unauthenticated; no session, token or CSRF involved.
- `zip_downloads` enabled (default `true`, `app/config/app.php:79`).
- Target must resolve under `open_basedir = [app_dir, FILES_PATH]` (set by `index.php`) and be a directory.

## 4. Reproduction

```http
GET /?zip=app HTTP/1.1     # entire app/ tree despite the hidden app_files entry
GET /?zip=.   HTTP/1.1     # entire application root (7.5 MB)
GET /?zip=../app HTTP/1.1  # directory OUTSIDE files_path (FILES_PATH deployment)
```

- `?zip=app` → HTTP 200 `application/zip`, `Content-Disposition: attachment; filename="DirectoryLister/app.zip"`, 6,803,444 bytes, 1,861 entries (config, controllers, compiled DI container, view caches, `app/vendor/**`).
- `?zip=.` → HTTP 200, 7,568,296 bytes (dotfiles excluded only by Symfony Finder's default).
- `?zip=../app` → HTTP 200, same 6.8 MB archive of a directory outside `files_path`.
- Honest boundary: outside `open_basedir` → 404 (control request).

Scripted PoC: `poc/poc-zip-traversal.sh` (target source: `poc/TARGET-SOURCE.txt`). Raw verification transcripts: `evidence/B1-zip-app.txt`, `evidence/B2-zip-dot.txt`, `evidence/C3-zip-traversal-app.txt`, `evidence/C5-file-outside-basedir.txt`.

## 5. Confirmed Techniques

- Verified on a default installation of release **5.7.0** (commit `0cf8ee1`, PHP 8.4.26 built-in server, stock config, `zip_downloads = true`).
- B1 (`?zip=app`): 6,803,444 bytes / 1,861 entries, full `app/` tree despite `app` + `app/**` in the hidden `app_files` list — ZipController never consults it.
- B2 (`?zip=.`): 7,568,296 bytes, whole root; `.env`/`.git` excluded only by Symfony Finder's default dotfile ignore.
- C3 (`?zip=../app`, FILES_PATH set): directories outside `files_path` archived — unchecked resolution confirmed.
- Scope control (honest negative): outside `open_basedir` → 404 (`evidence/C5-file-outside-basedir.txt`).

## 6. Impact

Any unauthenticated remote user can bulk-exfiltrate complete application trees in a single request: source code, configuration PHP files, compiled DI containers and view caches (which can embed environment-derived values), and vendored dependencies — bypassing the `hidden_files`/`app_files` restriction that exists precisely to shield these paths from listing. Scope is capped by `open_basedir` (anything under the app root or `FILES_PATH`); no integrity or availability impact.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (Base 5.3 — Medium)

## 8. Remediation

1. After `realpath()` resolution, require the resolved path to be strictly contained in `files_path` (e.g. `str_starts_with($real, $filesPath . DIRECTORY_SEPARATOR)`) before archiving.
2. Apply the hidden-files (`app_files`/`hidden_files`) filter inside `ZipController` instead of relying on `is_dir()` alone.
3. Apply the same containment check to the sibling `?file=`/`?info=` controllers, which share the `full_path` helper.

## 9. References

- Project: https://github.com/DirectoryLister/DirectoryLister
- Prior related disclosure on the same project: `?file=` path traversal, upstream GitHub issue #1456 (2025-10-09)
- CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')): https://cwe.mitre.org/data/definitions/22.html
- External disclosure: [GIST_URL]
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
