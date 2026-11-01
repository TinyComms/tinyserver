#!/bin/sh
# The operator's hooks in deploy/tenant/operator.sh, run on real tenants: backup, restore into a
# new tenant, export, the legal hold, and delete. Two tenants run throughout, and every check on
# one also checks the other is untouched.
#
#   sh deploy/tests/hooks.sh            run, then remove everything this created
#   KEEP=1 sh deploy/tests/hooks.sh     leave what is left up to look at; run purge.sh after
#
# Needs what isolation.sh needs, and age: `age` and `age-keygen` on PATH, or TINYSERVER_AGE_IMAGE
# naming an image whose entrypoint is age and that has age-keygen. The database is the real
# schema: every migration in crates/db/migrations, applied as the tenant's owner role. The
# serving container is the stand-in from compose.test.yml, as in isolation.sh, so suspend and
# resume (which need the tinyserver binary) are covered by crates/api/tests/operator.rs instead.

set -u
. "$(dirname "$0")/lib.sh"

need_docker
if ! command -v age >/dev/null 2>&1 && [ -z "${TINYSERVER_AGE_IMAGE:-}" ]; then
    say "these checks need age on PATH, or TINYSERVER_AGE_IMAGE" >&2
    exit 2
fi
purge

work=$(mktemp -d)
export TENANT_DIR="$work"
export TENANT_COMPOSE_FILES="$(hostpath "$TESTS_DIR")/compose.test.yml"
tenant() { sh "$DEPLOY_DIR/tenant/tenant.sh" "$@"; }
op() { sh "$DEPLOY_DIR/tenant/operator.sh" "$@"; }

cleanup() {
    for t in alpha bravo charlie; do
        [ -f "$work/$t/tenant.env" ] && tenant compose "$t" down -v --remove-orphans >/dev/null 2>&1
    done
    purge
    rm -rf "$work"
}
[ "${KEEP:-0}" = 1 ] || trap cleanup EXIT INT TERM

keygen() {
    if command -v age-keygen >/dev/null 2>&1; then
        age-keygen 2>/dev/null
    else
        docker run --rm --network none --entrypoint age-keygen "$TINYSERVER_AGE_IMAGE" 2>/dev/null
    fi
}

# psql as a tenant's owner, over TCP inside its own Postgres, where a password is required.
as_owner() {
    t=$1
    shift
    E="$work/$t/tenant.env"
    docker exec -i -e PGPASSWORD="$(value_of "$E" APP_OWNER_PASSWORD)" "${PREFIX}-$t-postgres-1" \
        sh -c 'psql -v ON_ERROR_STOP=1 -h "$(hostname -i)" -U "$1" -d "$2" -Atq "$@"' _ \
        "$(value_of "$E" TINYSERVER_OWNER_ROLE)" "$(value_of "$E" TINYSERVER_DB_NAME)" "$@" | tr -d '\r'
}

as_pg() {
    docker exec "${PREFIX}-$1-postgres-1" psql -U postgres -d "$(value_of "$work/$1/tenant.env" TINYSERVER_DB_NAME)" -Atc "$2" | tr -d '\r'
}

# ---------------------------------------------------------------------------------------------
say "== Two tenants with the real schema and some data"

for t in alpha bravo charlie; do
    tenant new "$t" --dir "$work" --prefix "$PREFIX" --tunnel-token placeholder >/dev/null || fail "new $t"
done
for t in alpha bravo; do
    if ! tenant compose "$t" up -d tinyserver >"$work/$t.up" 2>&1; then
        cat "$work/$t.up"
        fail "$t starts"
        exit 1
    fi
    # Every migration, in order, as this tenant's owner.
    migrations=$(ls "$REPO_DIR/crates/db/migrations"/*.sql | sort)
    # shellcheck disable=SC2086
    if cat $migrations | as_owner "$t" -1 -f - >"$work/$t.migrate" 2>&1; then
        pass "the real migrations apply as $t's owner"
    else
        tail -5 "$work/$t.migrate"
        fail "the real migrations apply as $t's owner"
        exit 1
    fi
    as_owner "$t" -c "CREATE TABLE hooks_marker (v text); INSERT INTO hooks_marker VALUES ('$t-row'); GRANT SELECT ON hooks_marker TO app_runtime"
    docker exec "${PREFIX}-$t-tinyserver-1" sh -c "echo $t-upload > /data/uploads/one && mkdir -p /data/uploads/d && echo $t-two > /data/uploads/d/two"
    docker run --rm --pull never -v "${PREFIX}-${t}_pocketid_data:/d" "$STANDIN_IMAGE" \
        sh -c "echo $t-pocket > /d/pocket-id.db && chown -R 65532:65532 /d" >/dev/null
done
A_ENV="$work/alpha/tenant.env"
C_ENV="$work/charlie/tenant.env"
A_RUN=$(value_of "$A_ENV" TINYSERVER_RUNTIME_ROLE)
equals "control: alpha's runtime role reads reports" "t" "$(as_pg alpha "select has_table_privilege('$A_RUN', 'reports', 'SELECT')")"
equals "a migration's REVOKE from app_runtime reaches alpha's login role: it cannot insert a report" "f" \
    "$(as_pg alpha "select has_table_privilege('$A_RUN', 'reports', 'INSERT')")"
equals "nor write the outbox" "f|f" "$(as_pg alpha "select format('%s|%s', has_table_privilege('$A_RUN', 'outbox', 'INSERT'), has_table_privilege('$A_RUN', 'outbox', 'DELETE'))")"
equals "nor the operator's state" "t|f" "$(as_pg alpha "select format('%s|%s', has_table_privilege('$A_RUN', 'operator_state', 'SELECT'), has_table_privilege('$A_RUN', 'operator_state', 'UPDATE'))")"
# alpha is suspended and its owner holds a report; both must survive a restore.
as_owner alpha -c "UPDATE operator_state SET mode = 'read_only', notice = 'alpha is read-only'"
src_rls=$(as_pg alpha "select count(*) from pg_class where relrowsecurity and relnamespace = 'public'::regnamespace")
src_definers=$(as_pg alpha "select count(*) from pg_proc where prosecdef and pronamespace = 'public'::regnamespace")
src_tables=$(as_pg alpha "select count(*) from pg_tables where schemaname = 'public'")
# Every privilege on every table, sequence, view and function, with the owner's name taken out.
# No ACL at all is the default one, which is what an explicit owner-only ACL also says.
acls() {
    own=$(value_of "$work/$1/tenant.env" TINYSERVER_OWNER_ROLE)
    as_pg "$1" "select string_agg(n || '=' || a, ';' order by n) from (
        select c.relname as n, coalesce(array_to_string(array(select replace(u::text, '$own', 'OWNER') from unnest(coalesce(c.relacl, acldefault(case c.relkind when 'S' then 's' else 'r' end, c.relowner))) u order by 1), ','), '-') as a
        from pg_class c where c.relnamespace = 'public'::regnamespace
        union all
        select p.oid::regprocedure::text, coalesce(array_to_string(array(select replace(u::text, '$own', 'OWNER') from unnest(coalesce(p.proacl, acldefault('f', p.proowner))) u order by 1), ','), '-')
        from pg_proc p where p.pronamespace = 'public'::regnamespace) x" | sed "s/$own/OWNER/g"
}
src_acls=$(acls alpha)

# ---------------------------------------------------------------------------------------------
say "== Backup"

keyfile="$work/operator.key"
(umask 077 && keygen >"$keyfile")
recipient=$(sed -n 's/^# public key: //p' "$keyfile" | tr -d '\r')
check "an age key for the operator" test -n "$recipient"
check_not "a backup without a recipient is refused" op backup alpha --out "$work/none.age"
check_not "a recipient that is not an age key is refused" op backup alpha --out "$work/bad.age" --recipient 'x; rm -rf /'
if op backup alpha --out "$work/alpha.age" --recipient "$recipient" >"$work/backup.out" 2>&1; then
    pass "alpha is backed up"
else
    cat "$work/backup.out"
    fail "alpha is backed up"
fi
equals "the backup is an age file" "age-encryption.org/v1" "$(head -c 21 "$work/alpha.age")"
for marker in alpha-row alpha-upload alpha-two alpha-pocket "$(cat "$work/alpha/secrets/pocketid_encryption_key")" "$(value_of "$A_ENV" APP_OWNER_PASSWORD)"; do
    equals "no plaintext of alpha in the backup (${marker%"${marker#????????}"}...)" "0" "$(grep -c -a -F "$marker" "$work/alpha.age" || true)"
done
check_not "no .partial file is left behind" test -e "$work/alpha.age.partial"
check_not "nothing is written to an existing file" op backup alpha --out "$work/alpha.age" --recipient "$recipient"
other_key="$work/other.key"
(umask 077 && keygen >"$other_key")
check_not "another key cannot decrypt it" sh -c "sh '$DEPLOY_DIR/tenant/operator.sh' restore charlie --in '$work/alpha.age' --identity '$other_key' --yes"
lacks "no helper container is left running" "$(docker ps -a --format '{{.Names}}')" "operator-"

# ---------------------------------------------------------------------------------------------
say "== Restore into a new tenant, charlie (a move to another slot or host)"

if ! tenant compose charlie up -d tinyserver >"$work/charlie.up" 2>&1; then
    cat "$work/charlie.up"
    fail "charlie starts"
    exit 1
fi
if op restore charlie --in "$work/alpha.age" --identity "$keyfile" --yes >"$work/restore.out" 2>&1; then
    pass "alpha's backup restores into charlie"
else
    cat "$work/restore.out"
    fail "alpha's backup restores into charlie"
fi
C_OWN=$(value_of "$C_ENV" TINYSERVER_OWNER_ROLE)
C_RUN=$(value_of "$C_ENV" TINYSERVER_RUNTIME_ROLE)
equals "the data came across" "alpha-row" "$(as_pg charlie "select v from hooks_marker")"
equals "so did the suspension" "read_only|alpha is read-only" "$(as_pg charlie "select mode || '|' || notice from operator_state")"
equals "the same number of tables" "$src_tables" "$(as_pg charlie "select count(*) from pg_tables where schemaname = 'public'")"
equals "the same tables under row level security" "$src_rls" "$(as_pg charlie "select count(*) from pg_class where relrowsecurity and relnamespace = 'public'::regnamespace")"
equals "the same SECURITY DEFINER functions" "$src_definers" "$(as_pg charlie "select count(*) from pg_proc where prosecdef and pronamespace = 'public'::regnamespace")"
equals "every table is charlie's owner's, none alpha's or the superuser's" "$C_OWN" \
    "$(as_pg charlie "select string_agg(distinct tableowner, ',') from pg_tables where schemaname = 'public'")"
equals "every function is charlie's owner's, so a definer runs as charlie's owner" "$C_OWN" \
    "$(as_pg charlie "select string_agg(distinct pg_get_userbyid(proowner), ',') from pg_proc where pronamespace = 'public'::regnamespace")"
equals "no grant names one of alpha's roles" "0" \
    "$(as_pg charlie "select count(*) from information_schema.role_table_grants where grantee like 'alpha%' or grantor like 'alpha%'")"
equals "charlie's runtime role reads what the runtime may read" "t|t" \
    "$(as_pg charlie "select format('%s|%s', has_table_privilege('$C_RUN', 'reports', 'SELECT'), has_table_privilege('$C_RUN', 'hooks_marker', 'SELECT'))")"
equals "and the restore did not widen it: no insert on reports or the outbox, no write to the operator state" "f|f|f" \
    "$(as_pg charlie "select format('%s|%s|%s', has_table_privilege('$C_RUN', 'reports', 'INSERT'), has_table_privilege('$C_RUN', 'outbox', 'INSERT'), has_table_privilege('$C_RUN', 'operator_state', 'UPDATE'))")"
equals "every privilege on every table, sequence and function is as it was in alpha" "$src_acls" "$(acls charlie)"
as_owner charlie -c "CREATE TABLE hooks_after (v int)"
equals "the default privileges are back for what charlie's owner makes next" "t"     "$(as_pg charlie "select has_table_privilege('$C_RUN', 'hooks_after', 'INSERT')")"
equals "charlie's runtime role can connect to its own database only" "1" \
    "$(docker exec "${PREFIX}-charlie-postgres-1" psql -U postgres -Atc "select count(*) from pg_database where datname not in ('postgres','template0','template1') and has_database_privilege('$C_RUN', datname, 'CONNECT')" | tr -d '\r')"
equals "PUBLIC still cannot connect" "f" "$(as_pg charlie "select has_database_privilege('public', current_database(), 'CONNECT')")"
equals "the uploads came across, owned by tinyserver's user" "alpha-upload|alpha-two|10001" \
    "$(docker exec "${PREFIX}-charlie-tinyserver-1" sh -c 'printf "%s|%s|%s" "$(cat /data/uploads/one)" "$(cat /data/uploads/d/two)" "$(stat -c %u /data/uploads/one)"')"
equals "Pocket ID's data came across, owned by its user" "alpha-pocket|65532" \
    "$(docker run --rm --pull never -v "${PREFIX}-charlie_pocketid_data:/d:ro" "$STANDIN_IMAGE" sh -c 'printf "%s|%s" "$(cat /d/pocket-id.db)" "$(stat -c %u /d/pocket-id.db)"')"
equals "the sign-in secrets came across" "$(cat "$work/alpha/secrets/pocketid_encryption_key")" "$(cat "$work/charlie/secrets/pocketid_encryption_key")"
equals "charlie's database passwords are still charlie's" "charlie_runtime|tenant_charlie" \
    "$(docker exec "${PREFIX}-charlie-tinyserver-1" sh -c 'psql "$DATABASE_URL" -Atc "select current_user || chr(124) || current_database()"' 2>&1 | tr -d '\r')"

say ""
say "== alpha and bravo are untouched"
equals "alpha still has its data" "alpha-row" "$(as_pg alpha "select v from hooks_marker")"
equals "bravo still has its own data" "bravo-row" "$(as_pg bravo "select v from hooks_marker")"
equals "bravo's uploads are bravo's" "bravo-upload" "$(docker exec "${PREFIX}-bravo-tinyserver-1" cat /data/uploads/one | tr -d '\r')"
differs "bravo's secrets are not alpha's" "$(cat "$work/alpha/secrets/pocketid_encryption_key")" "$(cat "$work/bravo/secrets/pocketid_encryption_key")"

# ---------------------------------------------------------------------------------------------
say "== Export for the owner"

owner_key="$work/owner.key"
(umask 077 && keygen >"$owner_key")
owner_recipient=$(sed -n 's/^# public key: //p' "$owner_key" | tr -d '\r')
printf '# the owner\n%s\n' "$owner_recipient" >"$work/owner.recipients"
if op export bravo --out "$work/bravo-export.age" --recipients-file "$work/owner.recipients" >"$work/export.out" 2>&1; then
    pass "bravo is exported to its owner's key"
else
    cat "$work/export.out"
    fail "bravo is exported"
fi
if command -v age >/dev/null 2>&1; then
    listing=$(age -d -i "$owner_key" <"$work/bravo-export.age" | tar -tf - 2>/dev/null)
else
    listing=$(docker run --rm -i --network none -v "$(hostpath "$work"):/k:ro" "$TINYSERVER_AGE_IMAGE" -d -i /k/owner.key <"$work/bravo-export.age" | tar -tf - 2>/dev/null)
fi
for f in ./manifest ./SHA256SUMS ./db.dump ./uploads.tar ./pocketid.tar ./secrets/pocketid_encryption_key ./self-host/compose.yml ./self-host/README.txt; do
    contains "the export has $f" "$listing" "$f"
done
lacks "the export has no env file, so no database passwords" "$listing" "tenant.env"
check_not "the operator's key cannot read the owner's export" sh -c "sh '$DEPLOY_DIR/tenant/operator.sh' restore charlie --in '$work/bravo-export.age' --identity '$keyfile' --yes"
equals "and charlie was not touched by the failed restore" "alpha-row" "$(as_pg charlie "select v from hooks_marker")"

# ---------------------------------------------------------------------------------------------
say "== A tenant's own key, the legal hold, and delete"

op keygen alpha >/dev/null || fail "keygen for alpha"
check "alpha has its own backup key, readable by the operator only" test -f "$work/alpha/backup.key"
if op backup alpha --out "$work/alpha-own.age" >"$work/own.out" 2>&1; then
    pass "a backup to the tenant's key alone"
else
    cat "$work/own.out"
    fail "a backup to the tenant's key alone"
fi
as_owner alpha -c "UPDATE operator_state SET legal_hold = true, legal_hold_since = now()"
check_not "delete is refused under the operator's legal hold" op delete alpha --confirm alpha
equals "and nothing was removed" "alpha-row" "$(as_pg alpha "select v from hooks_marker")"
check_not "a restore is refused under a hold too" op restore alpha --in "$work/alpha.age" --identity "$keyfile" --yes
as_owner alpha -c "UPDATE operator_state SET legal_hold = false, legal_hold_since = NULL"
# An owner's hold on a report inside the community holds the community too.
as_pg alpha "ALTER TABLE reports DISABLE TRIGGER ALL" >/dev/null
as_pg alpha "INSERT INTO reports (kind, category, preserve, preserved_at) VALUES ('channel', 'spam', true, now())" >/dev/null
check_not "delete is refused while a report is on hold" op delete alpha --confirm alpha
as_pg alpha "DELETE FROM reports" >/dev/null
check_not "delete without the name is refused" op delete alpha --confirm bravo
if op delete alpha --confirm alpha >"$work/delete.out" 2>&1; then
    pass "alpha is deleted once nothing holds it"
else
    cat "$work/delete.out"
    fail "alpha is deleted"
fi
equals "no container of alpha's is left" "" "$(docker ps -aq --filter "name=^${PREFIX}-alpha-")"
equals "no volume of alpha's is left" "" "$(docker volume ls -q --filter "name=^${PREFIX}-alpha_")"
equals "no network of alpha's is left" "" "$(docker network ls -q --filter "name=^${PREFIX}-alpha_")"
check_not "alpha's directory, env file, secrets and backup key are gone" test -e "$work/alpha"
check_not "a backup to alpha's key alone cannot be restored any more: there is no key" test -e "$work/alpha/backup.key"
equals "bravo is still up and still has its data" "bravo-row" "$(as_pg bravo "select v from hooks_marker")"
equals "charlie too" "alpha-row" "$(as_pg charlie "select v from hooks_marker")"

summary
