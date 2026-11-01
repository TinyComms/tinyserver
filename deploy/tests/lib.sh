#!/bin/sh
# Shared by the scripts in this directory. Source it; do not run it.
#
# Everything these checks create is named tinytenant-test-*: containers, networks, volumes, the
# compose projects. Nothing else is ever stopped, removed or inspected for cleanup. A previous
# aborted run's leftovers have that prefix and are removed at the start of the next.

# Docker on Windows under Git Bash rewrites anything that looks like a path, including the ones
# meant for the inside of a container.
export MSYS_NO_PATHCONV=1

TESTS_DIR=$(cd "$(dirname "$0")" && pwd)
DEPLOY_DIR=$(cd "$TESTS_DIR/.." && pwd)
REPO_DIR=$(cd "$DEPLOY_DIR/.." && pwd)
PREFIX=tinytenant-test
# What the stand-in containers run. Present wherever the real stack's Postgres is, so no pull.
STANDIN_IMAGE=postgres:17-alpine

PASSES=0
FAILS=0

# A path docker.exe understands under Git Bash, the same path elsewhere.
hostpath() {
    (cd "$1" && { pwd -W 2>/dev/null || pwd; })
}

say() {
    printf '%s\n' "$*"
}

pass() {
    PASSES=$((PASSES + 1))
    say "ok   $*"
}

fail() {
    FAILS=$((FAILS + 1))
    say "FAIL $*"
}

info() {
    say "info $*"
}

# check "description" command...   passes when the command succeeds
check() {
    desc=$1
    shift
    if "$@" >/dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc"
    fi
}

# check_not "description" command...   passes when the command fails
check_not() {
    desc=$1
    shift
    if "$@" >/dev/null 2>&1; then
        fail "$desc"
    else
        pass "$desc"
    fi
}

# equals "description" expected actual
equals() {
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1: expected '$2', got '$3'"
    fi
}

# differs "description" a b
differs() {
    if [ "$2" != "$3" ] && [ -n "$2" ] && [ -n "$3" ]; then
        pass "$1"
    else
        fail "$1: '$2' and '$3'"
    fi
}

# contains "description" haystack needle
contains() {
    case "$2" in
        *"$3"*) pass "$1" ;;
        *) fail "$1: no '$3' in '$2'" ;;
    esac
}

# lacks "description" haystack needle
lacks() {
    case "$2" in
        *"$3"*) fail "$1: found '$3'" ;;
        *) pass "$1" ;;
    esac
}

summary() {
    say ""
    say "$PASSES passed, $FAILS failed"
    [ "$FAILS" -eq 0 ]
}

need_docker() {
    if ! docker info >/dev/null 2>&1; then
        say "these checks need Docker and a running daemon" >&2
        exit 2
    fi
    if ! docker image inspect "$STANDIN_IMAGE" >/dev/null 2>&1; then
        say "the image $STANDIN_IMAGE is needed locally; run: docker pull $STANDIN_IMAGE" >&2
        exit 2
    fi
}

# Removes every container, network and volume named tinytenant-test-*, and only those.
purge() {
    ids=$(docker ps -aq --filter "name=^${PREFIX}-" 2>/dev/null || true)
    if [ -n "$ids" ]; then
        # shellcheck disable=SC2086
        docker rm -f -v $ids >/dev/null 2>&1 || true
    fi
    nets=$(docker network ls -q --filter "name=^${PREFIX}-" 2>/dev/null || true)
    if [ -n "$nets" ]; then
        # shellcheck disable=SC2086
        docker network rm $nets >/dev/null 2>&1 || true
    fi
    vols=$(docker volume ls -q --filter "name=^${PREFIX}-" 2>/dev/null || true)
    if [ -n "$vols" ]; then
        # shellcheck disable=SC2086
        docker volume rm -f $vols >/dev/null 2>&1 || true
    fi
}

# The IP addresses a container has, on every network, space separated.
ips_of() {
    docker inspect -f '{{range $name, $net := .NetworkSettings.Networks}}{{$net.IPAddress}} {{end}}' "$1"
}

# A container's /proc/self/status line, run as the container's own user.
status_of() {
    docker exec "$1" sh -c "grep '^$2' /proc/self/status" | tr -d '\r' | tr '\t' ' ' | tr -s ' '
}

# nc to host port; succeeds when the connection is made, fails on refusal, timeout or no route.
# busybox nc has no -z, so stdin is closed and a connection ends at once.
can_connect() {
    docker exec "$1" sh -c "nc -w 3 '$2' '$3' </dev/null" >/dev/null 2>&1
}

can_resolve() {
    docker exec "$1" sh -c "getent hosts '$2'" >/dev/null 2>&1
}

# value_of FILE KEY
value_of() {
    sed -n "s/^$2=//p" "$1" | head -n 1
}
