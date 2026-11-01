#!/bin/sh
# Serve. deploy/compose.yml migrates and bootstraps in tinyserver-init, which is the only place
# the owner role's password is, so this process starts with the runtime role alone.
#
# A single-container setup that still passes DATABASE_URL_MIGRATE migrates and bootstraps here,
# as it always did. That keeps the owner role inside the serving process; the compose file does
# not do it, and a deployment that can should not either.
set -eu
if [ -n "${DATABASE_URL_MIGRATE:-}" ]; then
    tinyserver migrate
    tinyserver bootstrap
    unset DATABASE_URL_MIGRATE
fi
exec tinyserver serve
