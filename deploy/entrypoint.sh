#!/bin/sh
# Migrate, print an owner invite while there is no owner, then serve. Once someone has signed in
# with the invite, bootstrap does nothing. Until then every start prints a fresh invite and the
# earlier one stops working.
set -eu
tinyserver migrate
tinyserver bootstrap
exec tinyserver serve
