#!/bin/sh
# Migrate, print an owner invite while there is no owner, then serve. Once someone has signed in
# with the invite, bootstrap does nothing. Until then a start keeps the invite printed earlier
# while it works (24 hours) and prints a new one once it has expired; `tinyserver bootstrap
# --owner-invite` makes a new one at any time.
set -eu
tinyserver migrate
tinyserver bootstrap
exec tinyserver serve
