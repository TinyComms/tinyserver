#!/bin/sh
# Checks docker/postgres/init/01-roles.sh: that it still makes exactly what a single community has
# always had when nothing is set, and that run for two tenants in one Postgres cluster it leaves
# one tenant's roles unable to connect to the other's database.
#
#   sh deploy/tests/roles.sh
#
# Needs Docker and the image postgres:17-alpine locally. No root, no cgroup access. It starts two
# throwaway Postgres containers (tinytenant-test-roles-*) on a throwaway network and removes them,
# the network and their volumes at the end. It does not need the tinyserver image or any host port.
#
# Logins here go over TCP to the container's own address, where the Postgres image's pg_hba
# requires a password (SCRAM), so a wrong password or a quoting bug in the script fails the check.
# Over the loopback and the socket the image trusts everyone, which would hide both.

set -u
. "$(dirname "$0")/lib.sh"

need_docker
purge

NET="${PREFIX}-roles"
trap purge EXIT INT TERM
docker network create "$NET" >/dev/null || {
    say "could not create network $NET" >&2
    exit 2
}
init_dir=$(hostpath "$REPO_DIR/docker/postgres/init")

wait_ready() {
    i=0
    while [ "$i" -lt 90 ]; do
        if docker exec "$1" pg_isready -q -h 127.0.0.1 -U postgres >/dev/null 2>&1; then
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

# sql CONTAINER USER PASSWORD DATABASE 'statement'   over TCP, with the password checked
sql() {
    docker exec -e PGPASSWORD="$3" -e PGCONNECT_TIMEOUT=5 "$1" \
        sh -c 'psql -h "$(hostname -i)" -U "$1" -d "$2" -Atc "$3"' _ "$2" "$4" "$5" 2>&1 | tr -d '\r'
}

as_pg() {
    docker exec "$1" psql -U postgres -d "${3:-postgres}" -Atc "$2" 2>&1 | tr -d '\r'
}

# ---------------------------------------------------------------------------------------------
say "== Nothing set: the single-community defaults"

C1="${PREFIX}-roles-default"
OPW='o''wn"er$pw `x` \y'
RPW="runtime-pw"
docker run -d --name "$C1" --network "$NET" --pull never \
    -e POSTGRES_PASSWORD=superpw -e POSTGRES_DB=tinyserver \
    -e APP_OWNER_PASSWORD="$OPW" -e APP_RUNTIME_PASSWORD="$RPW" \
    -v "$init_dir:/docker-entrypoint-initdb.d:ro" "$STANDIN_IMAGE" >/dev/null || exit 2
if ! wait_ready "$C1"; then
    docker logs "$C1" 2>&1 | tail -20
    fail "the default cluster starts"
    exit 1
fi
equals "the roles are app_owner and app_runtime, and postgres, and no others" \
    "app_owner app_runtime postgres " \
    "$(as_pg "$C1" "select rolname from pg_roles where rolname !~ '^pg_' order by rolname collate \"C\"" | tr '\n' ' ')"
equals "the database is tinyserver" "tinyserver" \
    "$(as_pg "$C1" "select datname from pg_database where datname = 'tinyserver'")"
equals "app_owner is as it was: login, CREATEDB, BYPASSRLS" "t|t|t" \
    "$(as_pg "$C1" "select format('%s|%s|%s', rolcanlogin, rolcreatedb, rolbypassrls) from pg_roles where rolname = 'app_owner'")"
equals "app_runtime is as it was: login, NOSUPERUSER, NOBYPASSRLS" "t|f|f" \
    "$(as_pg "$C1" "select format('%s|%s|%s', rolcanlogin, rolsuper, rolbypassrls) from pg_roles where rolname = 'app_runtime'")"
equals "the owner logs in over SCRAM with a password full of quotes, \$ and backticks" "app_owner" \
    "$(sql "$C1" app_owner "$OPW" tinyserver "select current_user")"
equals "the runtime role logs in" "app_runtime" "$(sql "$C1" app_runtime "$RPW" tinyserver "select current_user")"
contains "a wrong password is refused" "$(sql "$C1" app_runtime wrong tinyserver "select 1")" "password authentication failed"
contains "the owner's password is not the runtime role's" "$(sql "$C1" app_runtime "$OPW" tinyserver "select 1")" "password authentication failed"
equals "PUBLIC cannot connect to the database" "f" "$(as_pg "$C1" "select has_database_privilege('public', 'tinyserver', 'CONNECT')")"
equals "PUBLIC has no privileges on the public schema" "f|f" \
    "$(as_pg "$C1" "select format('%s|%s', has_schema_privilege('public', 'public', 'USAGE'), has_schema_privilege('public', 'public', 'CREATE'))" tinyserver)"
equals "the owner owns the public schema" "app_owner" \
    "$(as_pg "$C1" "select pg_get_userbyid(nspowner) from pg_namespace where nspname = 'public'" tinyserver)"
# The default privileges the migrations rely on for tables, sequences and functions the owner makes.
sql "$C1" app_owner "$OPW" tinyserver "create table t (id serial primary key, v int); create function f() returns int language sql as 'select 1'" >/dev/null
equals "a table the owner creates is readable and writable by the runtime role" "t|t" \
    "$(as_pg "$C1" "select format('%s|%s', has_table_privilege('app_runtime', 't', 'SELECT'), has_table_privilege('app_runtime', 't', 'INSERT'))" tinyserver)"
equals "its sequence is usable by the runtime role" "t" "$(as_pg "$C1" "select has_sequence_privilege('app_runtime', 't_id_seq', 'USAGE')" tinyserver)"
equals "its function is executable by the runtime role" "t" "$(as_pg "$C1" "select has_function_privilege('app_runtime', 'f()', 'EXECUTE')" tinyserver)"

# ---------------------------------------------------------------------------------------------
say "== Two tenants in one cluster"

C2="${PREFIX}-roles-shared"
docker run -d --name "$C2" --network "$NET" --pull never \
    -e POSTGRES_PASSWORD=superpw -e POSTGRES_DB=tenant_one \
    -e TINYSERVER_OWNER_ROLE=one_owner -e TINYSERVER_RUNTIME_ROLE=one_runtime -e TINYSERVER_OWNER_CREATEDB=no \
    -e APP_OWNER_PASSWORD=one-owner-pw -e APP_RUNTIME_PASSWORD=one-runtime-pw \
    -v "$init_dir:/docker-entrypoint-initdb.d:ro" "$STANDIN_IMAGE" >/dev/null || exit 2
if ! wait_ready "$C2"; then
    docker logs "$C2" 2>&1 | tail -20
    fail "the shared cluster starts"
    exit 1
fi
# The second tenant: the image only runs the script for the first. An operator who shares a
# cluster runs it the same way for each tenant.
as_pg "$C2" "create database tenant_two" >/dev/null
docker exec -e POSTGRES_USER=postgres -e POSTGRES_DB=tenant_two \
    -e TINYSERVER_OWNER_ROLE=two_owner -e TINYSERVER_RUNTIME_ROLE=two_runtime -e TINYSERVER_OWNER_CREATEDB=no \
    -e APP_OWNER_PASSWORD=two-owner-pw -e APP_RUNTIME_PASSWORD=two-runtime-pw \
    "$C2" sh /docker-entrypoint-initdb.d/01-roles.sh >/dev/null 2>"$(mktemp)" && pass "the script runs a second time, for the second tenant" || fail "the script runs for the second tenant"

equals "app_runtime exists once, as a group that cannot log in" "f|1" \
    "$(as_pg "$C2" "select format('%s|%s', rolcanlogin, (select count(*) from pg_roles where rolname = 'app_runtime')) from pg_roles where rolname = 'app_runtime'")"
equals "both runtime logins are in it" "t|t" \
    "$(as_pg "$C2" "select format('%s|%s', pg_has_role('one_runtime', 'app_runtime', 'member'), pg_has_role('two_runtime', 'app_runtime', 'member'))")"
equals "neither owner is" "f|f" \
    "$(as_pg "$C2" "select format('%s|%s', pg_has_role('one_owner', 'app_runtime', 'member'), pg_has_role('two_owner', 'app_runtime', 'member'))")"
equals "tenant one's runtime role connects to tenant one" "one_runtime|tenant_one" \
    "$(sql "$C2" one_runtime one-runtime-pw tenant_one "select current_user || '|' || current_database()")"
equals "tenant one's owner connects to tenant one" "one_owner" "$(sql "$C2" one_owner one-owner-pw tenant_one "select current_user")"
equals "tenant two's runtime role connects to tenant two" "two_runtime|tenant_two" \
    "$(sql "$C2" two_runtime two-runtime-pw tenant_two "select current_user || '|' || current_database()")"
equals "tenant two's owner connects to tenant two" "two_owner" "$(sql "$C2" two_owner two-owner-pw tenant_two "select current_user")"
contains "tenant one's runtime role is refused by tenant two's database" \
    "$(sql "$C2" one_runtime one-runtime-pw tenant_two "select 1")" 'permission denied for database "tenant_two"'
contains "tenant one's owner is refused by tenant two's database" \
    "$(sql "$C2" one_owner one-owner-pw tenant_two "select 1")" 'permission denied for database "tenant_two"'
contains "tenant two's runtime role is refused by tenant one's database" \
    "$(sql "$C2" two_runtime two-runtime-pw tenant_one "select 1")" 'permission denied for database "tenant_one"'
contains "tenant two's owner is refused by tenant one's database" \
    "$(sql "$C2" two_owner two-owner-pw tenant_one "select 1")" 'permission denied for database "tenant_one"'
equals "tenant one's runtime role can connect to exactly one non-template database" "1" \
    "$(as_pg "$C2" "select count(*) from pg_database where datname not in ('postgres','template0','template1') and has_database_privilege('one_runtime', datname, 'CONNECT')")"
# The migrations grant to app_runtime. Here that is a group in both databases. The grants are
# per database, and a role that cannot connect cannot use them.
sql "$C2" one_owner one-owner-pw tenant_one "create table t (id int); grant select on t to app_runtime" >/dev/null
equals "a grant to app_runtime in tenant one reaches tenant one's runtime role" "t" \
    "$(as_pg "$C2" "select has_table_privilege('one_runtime', 't', 'SELECT')" tenant_one)"
contains "and tenant two's runtime role, which inherits the group, still cannot reach tenant one" \
    "$(sql "$C2" two_runtime two-runtime-pw tenant_one "select * from t")" "permission denied for database"
# The runtime login role has nothing of its own: everything comes through the group, so what a
# migration revokes from app_runtime is gone for the login role too.
sql "$C2" one_owner one-owner-pw tenant_one "create table w (id int); revoke insert, update, delete on w from app_runtime" >/dev/null
equals "a table the owner makes is readable by tenant one's runtime role through the group" "t"     "$(as_pg "$C2" "select has_table_privilege('one_runtime', 'w', 'SELECT')" tenant_one)"
equals "and a REVOKE from app_runtime takes INSERT, UPDATE and DELETE from the login role" "f|f|f"     "$(as_pg "$C2" "select format('%s|%s|%s', has_table_privilege('one_runtime', 'w', 'INSERT'), has_table_privilege('one_runtime', 'w', 'UPDATE'), has_table_privilege('one_runtime', 'w', 'DELETE'))" tenant_one)"
equals "no privilege anywhere names the login role itself" "0"     "$(as_pg "$C2" "select count(*) from information_schema.role_table_grants where grantee = 'one_runtime'" tenant_one)"
contains "the login role cannot insert, as the database says"     "$(sql "$C2" one_runtime one-runtime-pw tenant_one "insert into w values (1)")" "permission denied for table w"
# Running the script again, as a restore does, changes nothing and leaves the logins working.
docker exec -e POSTGRES_USER=postgres -e POSTGRES_DB=tenant_one     -e TINYSERVER_OWNER_ROLE=one_owner -e TINYSERVER_RUNTIME_ROLE=one_runtime -e TINYSERVER_OWNER_CREATEDB=no     -e APP_OWNER_PASSWORD=one-owner-pw -e APP_RUNTIME_PASSWORD=one-runtime-pw     "$C2" sh /docker-entrypoint-initdb.d/01-roles.sh >/dev/null 2>&1 && pass "the script runs again over an existing tenant" || fail "the script runs again"
equals "after it, tenant one's runtime role still logs in" "one_runtime" "$(sql "$C2" one_runtime one-runtime-pw tenant_one "select current_user")"
equals "and still cannot insert into w" "f" "$(as_pg "$C2" "select has_table_privilege('one_runtime', 'w', 'INSERT')" tenant_one)"
equals "the owner is still without CREATEDB and with BYPASSRLS" "f|t"     "$(as_pg "$C2" "select format('%s|%s', rolcreatedb, rolbypassrls) from pg_roles where rolname = 'one_owner'")"

# What a shared cluster does leak, said plainly so nobody reads a pass above as more than it is.
leak=$(sql "$C2" one_runtime one-runtime-pw tenant_one "select count(*) from pg_roles where rolname in ('two_owner', 'two_runtime')")
equals "KNOWN LIMIT: tenant one's role can list tenant two's role names (and database names)" "2" "$leak"
info "a shared cluster discloses tenant names to every tenant, and shares one postgres process, one WAL, one set of memory and connection limits. The default stack gives each tenant its own cluster."

# ---------------------------------------------------------------------------------------------
say "== What the script refuses"

try_script() {
    docker exec -e POSTGRES_USER=postgres -e POSTGRES_DB=tenant_two \
        -e APP_OWNER_PASSWORD=a -e APP_RUNTIME_PASSWORD=b "$@" "$C2" sh /docker-entrypoint-initdb.d/01-roles.sh
}
check_not "a role name with an uppercase letter, a semicolon or a space" \
    try_script -e 'TINYSERVER_OWNER_ROLE=Bad;drop' -e TINYSERVER_RUNTIME_ROLE=x_runtime
check_not "a role name that starts with a digit" try_script -e TINYSERVER_OWNER_ROLE=1owner -e TINYSERVER_RUNTIME_ROLE=x_runtime
check_not "the same name for both roles" try_script -e TINYSERVER_OWNER_ROLE=same -e TINYSERVER_RUNTIME_ROLE=same
check_not "postgres as a role name" try_script -e TINYSERVER_OWNER_ROLE=postgres -e TINYSERVER_RUNTIME_ROLE=x_runtime
check_not "a database name that is not an identifier" try_script -e 'POSTGRES_DB=a-b' -e TINYSERVER_OWNER_ROLE=x_owner -e TINYSERVER_RUNTIME_ROLE=x_runtime
check_not "a name over 63 characters" try_script -e "TINYSERVER_OWNER_ROLE=$(printf 'a%.0s' $(seq 1 64))" -e TINYSERVER_RUNTIME_ROLE=x_runtime
check_not "TINYSERVER_OWNER_CREATEDB other than yes or no" try_script -e TINYSERVER_OWNER_CREATEDB=maybe -e TINYSERVER_OWNER_ROLE=x_owner -e TINYSERVER_RUNTIME_ROLE=x_runtime
equals "none of those made a role" "0" "$(as_pg "$C2" "select count(*) from pg_roles where rolname in ('Bad;drop', '1owner', 'same', 'x_owner', 'x_runtime')")"

summary
