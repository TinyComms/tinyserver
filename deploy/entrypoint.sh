#!/bin/sh
# Migrate, create the first owner once, then serve. A second start leaves the owner in place.
# bootstrap reports an existing owner before it reads the owner variables, so they can be unset
# after first boot. With no owner and no variables, bootstrap fails and the container stops.
set -eu
tinyserver migrate
set +e
out=$(tinyserver bootstrap 2>&1)
code=$?
set -e
if [ "$code" -ne 0 ]; then
  case "$out" in
    *"an owner already exists"*) ;;
    *)
      printf '%s\n' "$out" >&2
      exit 1
      ;;
  esac
fi
exec tinyserver serve
