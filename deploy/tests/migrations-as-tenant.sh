#!/bin/sh
# Runs the real migrations and the API's integration tests against a database set up the way a
# tenant's is: a tenant-named database, a tenant-named owner and runtime login role, and the
# NOLOGIN group `app_runtime` the migrations grant to. The migrations name `app_runtime`; this
# shows that a runtime role with another name works, through that group, with the real schema.
#
#   sh deploy/tests/migrations-as-tenant.sh [cargo test arguments...]
#
# Needs Docker, the image postgres:17-alpine, and a Rust toolchain (cargo on PATH). The first run
# compiles the tests, which takes minutes. Starts one throwaway Postgres container,
# tinytenant-test-migrate, published on a free port of 127.0.0.1 only, and removes it afterwards.
#
# Default tests: privacy, reports, server and operator, which exercise row level security, the definer
# functions and the permission bits. Pass your own `-p api --test ...` to run others.

set -u
. "$(dirname "$0")/lib.sh"

need_docker
command -v cargo >/dev/null 2>&1 || {
    say "cargo is not on PATH" >&2
    exit 2
}
purge
trap purge EXIT INT TERM

C="${PREFIX}-migrate"
OPW=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
RPW=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
init_dir=$(hostpath "$REPO_DIR/docker/postgres/init")

# TINYSERVER_OWNER_CREATEDB=yes: the test suite makes a database for each test as the owner. A
# tenant's own owner role does not have CREATEDB.
docker run -d --name "$C" --pull never -p 127.0.0.1::5432 \
    -e POSTGRES_PASSWORD=superpw -e POSTGRES_DB=tenant_acme \
    -e TINYSERVER_OWNER_ROLE=acme_owner -e TINYSERVER_RUNTIME_ROLE=acme_runtime -e TINYSERVER_OWNER_CREATEDB=yes \
    -e APP_OWNER_PASSWORD="$OPW" -e APP_RUNTIME_PASSWORD="$RPW" \
    -v "$init_dir:/docker-entrypoint-initdb.d:ro" "$STANDIN_IMAGE" >/dev/null || exit 2
i=0
until docker exec "$C" pg_isready -q -h 127.0.0.1 -U postgres >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 90 ] || {
        docker logs "$C" 2>&1 | tail -20
        fail "Postgres starts"
        exit 1
    }
    sleep 1
done
port=$(docker port "$C" 5432/tcp | head -n 1 | sed 's/.*://')
say "Postgres is on 127.0.0.1:$port, database tenant_acme, roles acme_owner and acme_runtime"

[ $# -gt 0 ] || set -- -p api --test privacy --test reports --test server --test operator
out="${TMPDIR:-/tmp}/tenant-migrations.out"
(
    cd "$REPO_DIR" || exit 2
    env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
        TEST_DATABASE_URL_MIGRATE="postgres://acme_owner:$OPW@127.0.0.1:$port/tenant_acme?sslmode=disable" \
        TEST_DATABASE_URL="postgres://acme_runtime:$RPW@127.0.0.1:$port/tenant_acme?sslmode=disable" \
        cargo test "$@"
) >"$out" 2>&1
status=$?
tail -n 40 "$out"
if [ "$status" -eq 0 ]; then
    pass "the tests pass as a tenant-named owner and runtime role"
else
    fail "the tests failed as a tenant-named owner and runtime role (status $status)"
fi
summary
