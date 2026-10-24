#!/bin/sh
# Migrate, create the first owner once, then serve. A second start leaves the owner in place.
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
