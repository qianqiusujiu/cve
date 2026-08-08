# Server-Side Request Forgery in athlon1600/youtube-downloader (public/stream.php)

**CWE-918 · Unauthenticated full-read SSRF · Internal services reachable and readable**

## Product Information

| Field | Value |
|---|---|
| Product | youtube-downloader (PHP package `athlon1600/youtube-downloader`) |
| Stack | Native PHP 7.4+/8.x, ext-curl (no framework, no DB) |
| Affected version | commit `6c117f09acfa91c04ce512ad864a7a80ecd13b34` (master, 2026-06-02) |
| Repository | https://github.com/Athlon1600/youtube-downloader |
| Affected endpoint | `GET /public/stream.php?url=<attacker-url>` |
| Severity | High (CVSS 3.1 7.5, AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |

## Summary

The demo web endpoint `public/stream.php` passes the user-supplied `url` query
parameter verbatim to cURL with no validation. The intended design proxies only
YouTube CDN (`googlevideo.com`) stream URLs to the browser, but no allow-list exists.
An unauthenticated remote attacker can make the server fetch any `http://`/`https://`
target — loopback, RFC1918 private ranges, cloud metadata (`169.254.169.254`) — and
the full upstream response body plus `content-type`/`content-length`/`content-range`
headers are streamed back to the attacker (full read-back SSRF).

## Root Cause

`public/stream.php:7,14` → `src/YouTubeStreamer.php:68-114` (`stream()`, `CURLOPT_URL` at L89):

```php
// public/stream.php
$url = isset($_GET['url']) ? $_GET['url'] : null;   // NO validation
$youtube = new \YouTube\YouTubeStreamer();
$youtube->stream($url);

// src/YouTubeStreamer.php stream()
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);          // L85
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);      // L86
curl_setopt($ch, CURLOPT_URL, $url);                  // L89  <- attacker URL verbatim
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);       // L96
curl_setopt($ch, CURLOPT_MAXREDIRS, 5);               // L97
curl_setopt($ch, CURLOPT_WRITEFUNCTION, [$this,'bodyCallback']);    // L106 echoes body
curl_setopt($ch, CURLOPT_HEADERFUNCTION, [$this,'headerCallback']); // L103 forwards headers
```

No check anywhere restricts `$url` to YouTube/googlevideo hosts. The upstream body is
streamed to the attacker and response headers are forwarded, giving full read-back.

## Reproduction

Full PoC: `poc/request.txt`. Empirically verified in a local isolated environment
(transcript in `evidence/ssrf-proof.txt`):

```http
GET /public/stream.php?url=http%3A%2F%2F127.0.0.1%3A8899%2Finternal-secret HTTP/1.1
Host: VICTIM
```

With an internal service on `127.0.0.1:8899` returning
`{"secret":"INTERNAL_DB_PASSWORD_7f8c3","service":"internal-admin"}`, the response
returned to the attacker is `HTTP/1.1 200` with `Content-Type: application/json`
and that body verbatim.

## Impact

- Read internal-only HTTP(S) endpoints: admin panels, internal APIs, configs, cloud
  metadata (may expose IAM/instance credentials).
- Bypass firewalls/NAT to reach private-network hosts; internal discovery and port
  scanning via forwarded status code + headers.
- SSL peer/host verification is disabled, so internal HTTPS with self-signed certs
  is reachable too.

## Remediation

- Restrict the accepted URL to the YouTube CDN host, e.g.
  `^https://[\w.-]*\.googlevideo\.com/`.
- Add a blocklist for loopback/RFC1918/link-local/cloud-metadata IPs with
  DNS-rebinding-safe resolution before the cURL request.
- Re-enable cURL SSL peer/host verification.

## References

- Project: https://github.com/Athlon1600/youtube-downloader
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- External disclosure: https://gist.github.com/qianqiusujiu/87a7d7d8bd7fb53cf8529e0bafbeafba
- VulDB submission: pending — entry ID to be backfilled once assigned

---
*All validation was performed in a local, isolated environment (PHP 8.5.9 + ext-curl).
The temporary environment was destroyed after testing.*
