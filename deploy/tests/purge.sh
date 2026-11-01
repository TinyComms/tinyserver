#!/bin/sh
# Removes everything the checks in this directory create: containers, networks and volumes named
# tinytenant-test-*. Nothing else. Run it after `isolation.sh --keep`, or after an aborted run.
set -u
. "$(dirname "$0")/lib.sh"
need_docker
purge
echo "removed what was named ${PREFIX}-*"
