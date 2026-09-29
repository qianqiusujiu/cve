<!-- gist description (stage 6): openvk Poll Information Disclosure -->

# openvk Poll Information Disclosure

**CWE-639 · Unauthenticated disclosure of poll options, results and voter identities, bypassing the parent wall's privacy**

> **Vendor:** OpenVK
> **Product:** openvk (open-source VKontakte-style social network, PHP / Chandler framework)
> **Affected version:** master branch, commit 8316cfc7eabf8426603f9b2a582d8396e8dc81b7 (2026-09-20)
> **Affected endpoints:** GET /poll{id} and GET /poll{id}/voters?option={base32 option} (Web/routes.yml:324-327)
> **Disclosed via:** VulDB (submission #xxxxxx)
> **Note:** Sensitive extracted values (credentials) have been redacted from this public disclosure.

## 1. Summary

`/poll{id}` and `/poll{id}/voters` require no session and never check the visibility of the post/wall the poll is attached to: `Poll::canBeViewedBy()` returns `true` unconditionally (the real check is commented out, "waiting for #935"). A logged-out outsider can therefore read the title, options, results and — for non-anonymous polls — the full per-option voter list of any poll, including polls embedded in posts on walls guests cannot view. Poll and option ids are sequential integers, so every poll on the instance enumerates.

## 2. Root Cause

| File:Line | Role |
|---|---|
| `Web/routes.yml:324-327` | `/poll{num}` → `Poll->view`; `/poll{num}/voters` → `Poll->voters` — no auth requirement |
| `Web/Presenters/PollPresenter.php:23-66` | `renderView()`: loads poll by id, serves title/options/results; no parent-visibility check |
| `Web/Presenters/PollPresenter.php:68-102` | `renderVoters()`: only refuses `isAnonymous()`; returns voter entities for an option |
| `Web/Models/Entities/Poll.php:318-327` | `canBeViewedBy()`: hardcoded `return true;` — delegation to the attached post is commented out (#935) |

```php
// Web/Models/Entities/Poll.php:318-327
public function canBeViewedBy(?User $user = null): bool
{
    # waiting for #935 :(
    /*if(!is_null($this->getAttachedPost())) {
        return $this->getAttachedPost()->canBeViewedBy($user);
    } else {*/
    return true;
    #}
}

// Web/Presenters/PollPresenter.php (renderVoters, excerpt) - no auth, no visibility check
$poll = $this->polls->get($pollId);
if (!$poll) { $this->notFound(); }
if ($poll->isAnonymous()) { $this->flashFail("err", ...); }
$option = (int) base_convert($this->queryParam("option"), 32, 10);
...
$this->template->iterator = $voters;   // voter identities for the chosen option
```

## 3. Prerequisites

- None (guest access; no account required).
- Poll ids are sequential integers (`/poll{num}`); option ids are sequential integers exposed base-32-encoded in the `option` query parameter.
- Applies to polls attached to posts on walls the visitor cannot view — the verified restricted case is the **closed profile** (`profile_type=1`); note that on current master closed-club walls are publicly readable by design (`Club::canBeViewedBy` only checks the ban flag).

## 4. Reproduction

Setup: a member publishes a non-anonymous poll on a CLOSED profile's wall (poll id 2, options 4/5).

Controls — the wall and the post itself are hidden from guests:

```http
GET /wall2 HTTP/1.1
→ 302 redirect to /          (denied)

GET /wall2_2 HTTP/1.1
→ 404                        (denied)
```

Leaks — same guest, no session, poll pages only:

```http
GET /poll2 HTTP/1.1
→ 200, page contains the poll title ("Secret leadership vote") and options
   ("Candidate A" / "Candidate B")

GET /poll2/voters?option=4 HTTP/1.1
→ 200, page shows voter identity "<REDACTED> (regular member)" next to option 4

GET /poll2/voters?option=5 HTTP/1.1
→ 200, page shows voter identity "<REDACTED> (instance administrator)" next to option 5
```

(`option` = `base_convert(<numeric option id>, 32, 10)` input; ids are sequential, so `/poll{N}` and options enumerate trivially.)

## 5. Confirmed Techniques

- End-to-end runtime reproduction on a fresh instance (closed profile `profile_type=1`; `User::canBeViewedBy` denies guests the wall: `/wall2` 302, `/wall2_2` 404) while both poll endpoints returned 200 with options and per-option voter identities (a regular user and the instance administrator).
- Root cause confirmed in code: no auth in `PollPresenter`, `Poll::canBeViewedBy()` hardcoded `true` (#935 delegation commented out).

## 6. Impact

- Unauthenticated disclosure of restricted-community poll content: title, options and aggregate results of polls that live behind walls guests cannot view.
- Per-user voting behavior (identity + chosen option) for every non-anonymous poll — a privacy leak of member activity visible to anyone.
- Sequential ids allow enumerating and dumping every poll on the instance.

## 7. CVSS 3.1

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (Base 5.3, Medium)

## 8. Remediation

1. In `PollPresenter::renderView()`/`renderVoters()`, resolve the poll's parent post/wall and apply the same visibility check used for wall posts (profile/club `canBeViewedBy`) before rendering options, results or voters.
2. Implement the `Poll::canBeViewedBy()` delegation that is currently commented out (upstream issue #935).
3. Additionally gate `/poll{id}/voters` behind authentication.

## 9. References

- Project: https://github.com/OpenVK/openvk
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- External disclosure: https://gist.github.com/qianqiusujiu/08a7c4a89681864e3e7650df645d65dc
- VulDB submission #xxxxxx

---
*All validation was performed in a local, isolated environment. The temporary environment was destroyed after testing.*
