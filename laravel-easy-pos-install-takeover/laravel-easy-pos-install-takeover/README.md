# laravel-easy-pos Hardcoded Default Credentials (Laravel 11 / Filament 4)

**CWE-798 · Unauthenticated · hardcoded default admin credentials + unauthenticated installer give out-of-the-box panel takeover**

> **Vendor:** mailmug (https://github.com/mailmug)
> **Product:** laravel-easy-pos (Laravel 11 / Filament 4)
> **Affected version:** master @ 40299656b9936cd1e8f08de7bd390df669a348b9 (2026-08-28); no official release version
> **Affected endpoints:** `GET /install` (also bound to `GET /`), Filament panel `/admin` (login at `/admin/login`)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** The credential pair below is hardcoded in the product's own public repository (`database/seeders/UserSeeder.php`) and is the vulnerability itself, not an extracted secret.

## 1. Summary

laravel-easy-pos provisions a hardcoded administrator account (`admin@admin.com` / `pass@123`) through its own unauthenticated installer: `GET /install` (and the `GET /` catch-all) runs `migrate --force` + `db:seed --force` whenever the `settings` table is absent, and the application never forces the seeded password to be rotated. `canAccessPanel()` returns `true` unconditionally, so anyone who can reach the deployment can take over the full Filament POS panel with one GET and one public login.

## 2. Root Cause

| File | Lines | Role |
|---|---|---|
| `routes/web.php` | 18-22, 25 | `GET /` closure and `GET /install` both call `InstallController@install` with no auth middleware |
| `app/Http/Controllers/InstallController.php` | 13-46 | `Schema::hasTable('settings')` guard only; runs `migrate --force` (L27) + `db:seed --force` (L30) |
| `database/seeders/UserSeeder.php` | 17-21 | Creates `admin@admin.com` with hardcoded `Hash::make('pass@123')` |
| `app/Models/User.php` | 57-60 | `canAccessPanel()` returns `true` unconditionally |

```php
// database/seeders/UserSeeder.php:17-21
User::create([
    'name' => 'Admin User',
    'email' => 'admin@admin.com',
    'password' => Hash::make('pass@123'),
]);

// app/Models/User.php:57-60
public function canAccessPanel(Panel $panel): bool
{
    return true;
}
```

## 3. Prerequisites

- None (unauthenticated attacker).
- Target is network-reachable either while not yet installed, or at any point before the operator manually changes the seeded password. There is no forced password-change workflow, so existing installations that kept the seed stay exposed indefinitely.

## 4. Reproduction

```http
GET /install HTTP/1.1
Host: target

-> HTTP 200 {"message":"Installation completed successfully!"}
   (migrate --force + db:seed --force have now created admin@admin.com)
```

```http
GET /admin/login HTTP/1.1          # Filament login (Livewire form)
Host: target

# Submit the Livewire "authenticate" action with the hardcoded pair:
#   email:    admin@admin.com
#   password: pass@123
# -> 200 with effects.redirect = /admin and a session cookie

GET /admin HTTP/1.1                # with the session cookie
Host: target

-> HTTP 200, full POS admin panel (Dashboard / Products / Customers / Orders)
```

On any legitimately installed instance that kept the seeded account, the login step alone is sufficient.

## 5. Confirmed Techniques

Verified end-to-end on a fresh local deployment (Laravel 11, Filament 4, PHP 8.4, MySQL 8.0):

1. Unauthenticated `GET /install` on an empty database returned 200 and executed `migrate --force` + `db:seed --force`; `users` gained id=1 `admin@admin.com`.
2. Livewire `authenticate` at `/admin/login` with `admin@admin.com` / `pass@123` succeeded; `GET /admin` then rendered the full admin panel (51,934-byte `fi-layout` page).
3. Control: `GET /admin` without a session redirected to `/admin/login`, so the gain comes from the seeded credentials.
4. `canAccessPanel()` (`app/Models/User.php:57-60`) places no additional gate on the seeded account.

## 6. Impact

Complete application takeover out of the box: an unauthenticated attacker reads and manipulates orders, customers and products, changes prices, imports attacker-controlled products, and alters application settings. Because the pair is public in the repository and no rotation is enforced, every default installation is guarded by a publicly known administrator password.

## 7. CVSS 3.1

`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (Base 9.8 - Critical)

## 8. Remediation

- Remove the hardcoded credential pair from `UserSeeder`; generate a random password printed once to the operator, or prompt for administrator credentials during install.
- Require an installer token or interactive confirmation before `GET /install` runs `migrate`/`seed`; return an error once the application is installed.
- Force a password change on first panel login for seeded accounts.

## 9. References

- Project: https://github.com/mailmug/laravel-easy-pos
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
- External disclosure: [GIST_URL]
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
