#!/bin/sh
# The operator's hooks for one community: suspend and resume it, place a legal hold, back it up
# and restore it, export it for its owner to run themselves, and delete it.
#
#   operator.sh status   TARGET [--json]
#   operator.sh suspend  TARGET (--read-only | --offline) --notice TEXT
#   operator.sh resume   TARGET
#   operator.sh hold     TARGET [--reason TEXT]
#   operator.sh release  TARGET [--reason TEXT]
#   operator.sh keygen   TARGET
#   operator.sh backup   TARGET --out FILE [--recipient AGE1...]... [--recipients-file FILE]
#   operator.sh export   TARGET --out FILE (--recipient AGE1... | --recipients-file FILE)...
#   operator.sh restore  TARGET --in FILE --identity FILE [--yes]
#   operator.sh delete   TARGET --confirm NAME
#
# TARGET is a tenant's name, made by tenant.sh, under TENANT_DIR (default ./tenants next to this
# script). Or `--stack ENV_FILE` for a single community run straight from deploy/compose.yml with
# that env file; its project is COMPOSE_PROJECT_NAME from the file, else `tinyserver`.
#
# Nothing here listens anywhere. Every hook is this script on the host, run by whoever can run
# docker there. status, suspend, resume, hold and release run `tinyserver operator` in a one-off
# copy of the init container, the only place the database owner's password is. See
# docs/privacy/tenancy.md for what each hook does and does not promise.
#
# Backups and exports are age files (https://age-encryption.org), encrypted on the host to the
# recipients given and to the tenant's own key when `keygen` made one. The plaintext exists only
# in a tmpfs inside a throwaway container and in the pipe to age; it is never written to the
# host's disk. `age` must be on PATH, or TINYSERVER_AGE_IMAGE names an image whose entrypoint is
# age and which has age-keygen.
#
# A bundle holds the database (pg_dump), the uploads, Pocket ID's data (its passkeys: without it
# nobody can sign in), the three sign-in secrets and, when the server has one, the external
# sender key file, plus a manifest and checksums. A restore replaces those in the target and
# then starts it, which migrates an older bundle forward. A database dump on its own does not
# hold that key. An older bundle has the key in the dump instead, and the new server copies it
# out on start.
#
# Environment: TENANT_DIR; TENANT_COMPOSE_FILES, more compose files after deploy/compose.yml;
# TINYSERVER_BACKUP_TMPFS, the tmpfs a backup or restore works in, default 4g;
# TINYSERVER_HELPER_IMAGE, the image that runs pg_dump and tar, default postgres:17-alpine.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
deploy_dir=$(cd "$here/.." && pwd)
repo_dir=$(cd "$deploy_dir/.." && pwd)
# Docker on Windows under Git Bash rewrites anything that looks like a path, including the ones
# meant for the inside of a container.
export MSYS_NO_PATHCONV=1

HELPER_IMAGE=${TINYSERVER_HELPER_IMAGE:-postgres:17-alpine}
TMPFS_SIZE=${TINYSERVER_BACKUP_TMPFS:-4g}
BUNDLE_FORMAT=tinyserver-bundle-1

die() {
    echo "operator.sh: $*" >&2
    exit 1
}

say() {
    printf '%s\n' "$*"
}

hostpath() {
    (cd "$1" && { pwd -W 2>/dev/null || pwd; })
}

hostfile() {
    printf '%s/%s' "$(hostpath "$(dirname "$1")")" "$(basename "$1")"
}

value_of() {
    sed -n "s/^$2=//p" "$1" | head -n 1
}

# ------------------------------------------------------------------------------------------------
# The target: env file, compose project, secrets directory, and the tenant's own directory.

target() {
    [ $# -ge 1 ] || die "which community? a tenant name, or --stack ENV_FILE"
    if [ "$1" = --stack ]; then
        [ $# -ge 2 ] || die "--stack needs the env file"
        [ -f "$2" ] || die "no env file $2"
        ENV_FILE=$(hostfile "$2")
        PROJECT=$(value_of "$2" COMPOSE_PROJECT_NAME)
        [ -n "$PROJECT" ] || PROJECT=tinyserver
        NAME=$PROJECT
        HOME_DIR=
        SECRETS=$(value_of "$2" TINYSERVER_SECRETS_DIR)
        [ -n "$SECRETS" ] || SECRETS="$deploy_dir/secrets"
        ENV_PATH=$2
        SHIFT=2
    else
        NAME=$1
        dir=${TENANT_DIR:-$here/tenants}
        [ -f "$dir/$NAME/tenant.env" ] || die "no tenant $NAME in $dir"
        HOME_DIR=$(cd "$dir/$NAME" && pwd)
        ENV_PATH="$HOME_DIR/tenant.env"
        ENV_FILE="$(hostpath "$HOME_DIR")/tenant.env"
        PROJECT=$(value_of "$ENV_PATH" COMPOSE_PROJECT_NAME)
        [ -n "$PROJECT" ] || die "$ENV_PATH has no COMPOSE_PROJECT_NAME"
        SECRETS=$(value_of "$ENV_PATH" TINYSERVER_SECRETS_DIR)
        [ -n "$SECRETS" ] || SECRETS="$HOME_DIR/secrets"
        SHIFT=1
    fi
    DB=$(value_of "$ENV_PATH" TINYSERVER_DB_NAME)
    [ -n "$DB" ] || DB=tinyserver
    OWNER=$(value_of "$ENV_PATH" TINYSERVER_OWNER_ROLE)
    [ -n "$OWNER" ] || OWNER=app_owner
    RUNTIME=$(value_of "$ENV_PATH" TINYSERVER_RUNTIME_ROLE)
    [ -n "$RUNTIME" ] || RUNTIME=app_runtime
    POCKETID_DIR=$(value_of "$ENV_PATH" POCKETID_DATA_DIR)
    UPLOADS_VOLUME="${PROJECT}_tinyserver_uploads"
    KEYS_VOLUME="${PROJECT}_tinyserver_keys"
    if [ -n "$POCKETID_DIR" ]; then
        POCKETID_MOUNT=$POCKETID_DIR
    else
        POCKETID_MOUNT="${PROJECT}_pocketid_data"
    fi
}

secret_of() {
    v=$(value_of "$ENV_PATH" "$1")
    [ -n "$v" ] || die "$ENV_PATH has no $1"
    printf '%s' "$v"
}

dc() {
    files="-f $(hostpath "$deploy_dir")/compose.yml"
    if [ "$(value_of "$ENV_PATH" TENANT_SCAN)" = none ]; then
        files="$files -f $(hostpath "$deploy_dir")/scan-off.yml"
    fi
    for extra in ${TENANT_COMPOSE_FILES:-}; do
        files="$files -f $extra"
    done
    # shellcheck disable=SC2086 # the file list is words by construction
    docker compose -p "$PROJECT" --env-file "$ENV_FILE" $files "$@"
}

# `tinyserver operator ...` as the owner role, in a one-off init container.
owner_cli() {
    dc run --rm --no-deps -T --entrypoint tinyserver tinyserver-init operator "$@"
}

postgres_up() {
    dc up -d --wait postgres >/dev/null 2>&1 || die "Postgres for $NAME does not start"
}

# One SQL value from the community's database, as the superuser inside its own Postgres.
superuser_sql() {
    dc exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d "$DB" -Atc "$1" | tr -d '\r'
}

# True when the community is under any legal hold: the operator's, or an owner's on a report.
on_hold() {
    have_state=$(superuser_sql "SELECT to_regclass('public.operator_state') IS NOT NULL") || return 2
    have_reports=$(superuser_sql "SELECT to_regclass('public.reports') IS NOT NULL") || return 2
    held=f
    if [ "$have_state" = t ]; then
        held=$(superuser_sql "SELECT legal_hold FROM operator_state") || return 2
    fi
    if [ "$held" != t ] && [ "$have_reports" = t ]; then
        held=$(superuser_sql "SELECT EXISTS (SELECT 1 FROM reports WHERE preserve)") || return 2
    fi
    [ "$held" = t ]
}

# ------------------------------------------------------------------------------------------------
# age, on the host or in a container.

AGE_IMAGE=${TINYSERVER_AGE_IMAGE:-}

age_cmd() {
    if command -v age >/dev/null 2>&1; then
        age "$@"
    elif [ -n "$AGE_IMAGE" ]; then
        docker run --rm -i --network none --read-only --cap-drop ALL \
            --security-opt no-new-privileges:true "$AGE_IMAGE" "$@"
    else
        die "age is not on PATH and TINYSERVER_AGE_IMAGE is not set"
    fi
}

# age -d with an identity file, which a container needs mounted.
age_decrypt() {
    identity=$1
    if command -v age >/dev/null 2>&1; then
        age -d -i "$identity"
    elif [ -n "$AGE_IMAGE" ]; then
        docker run --rm -i --network none --read-only --cap-drop ALL \
            --security-opt no-new-privileges:true \
            -v "$(hostfile "$identity"):/run/identity:ro" "$AGE_IMAGE" -d -i /run/identity
    else
        die "age is not on PATH and TINYSERVER_AGE_IMAGE is not set"
    fi
}

age_keygen() {
    if command -v age-keygen >/dev/null 2>&1; then
        age-keygen 2>/dev/null
    elif [ -n "$AGE_IMAGE" ]; then
        docker run --rm --network none --read-only --cap-drop ALL \
            --security-opt no-new-privileges:true --entrypoint age-keygen "$AGE_IMAGE" 2>/dev/null
    else
        die "age-keygen is not on PATH and TINYSERVER_AGE_IMAGE is not set"
    fi
}

valid_recipient() {
    case "$1" in
        age1*) case "$1" in *[!a-z0-9]*) return 1 ;; esac ;;
        ssh-ed25519\ * | ssh-rsa\ *) ;;
        *) return 1 ;;
    esac
}

# ------------------------------------------------------------------------------------------------
# The helper: a throwaway container on the community's internal network, with its volumes, a
# tmpfs to work in, no route out, no capabilities but the ones a step needs. It gets this
# community's volumes and secrets and three files from the repository, never a directory that
# holds another tenant's.

helper() {
    caps=$1
    mode=$2
    shift 2
    capargs=
    for cap in $caps; do
        capargs="$capargs --cap-add $cap"
    done
    secrets_mount=
    if [ -d "$SECRETS" ]; then
        secrets_mount="-v $(hostpath "$SECRETS"):/v/secrets:$mode"
    fi
    pocket=$POCKETID_MOUNT
    case "$pocket" in
        */* | *\\*) pocket=$(hostpath "$pocket") ;;
    esac
    # shellcheck disable=SC2086 # capability and mount lists are words by construction
    docker run --rm -i --name "${PROJECT}-operator-$$" --pull never \
        --network "${PROJECT}_inside" \
        --read-only --tmpfs "/work:size=$TMPFS_SIZE,mode=0700" --tmpfs /tmp:size=16m \
        --cap-drop ALL $capargs --security-opt no-new-privileges:true --pids-limit 128 \
        -v "$UPLOADS_VOLUME:/v/uploads:$mode" -v "$KEYS_VOLUME:/v/keys:$mode" \
        -v "$pocket:/v/pocketid:$mode" $secrets_mount \
        -v "$(hostfile "$repo_dir/docker/postgres/init/01-roles.sh"):/v/init/01-roles.sh:ro" \
        -v "$(hostfile "$deploy_dir/compose.yml"):/v/deploy/compose.yml:ro" \
        -v "$(hostfile "$deploy_dir/scan-off.yml"):/v/deploy/scan-off.yml:ro" \
        -e PGHOST=postgres -e PGCONNECT_TIMEOUT=10 \
        -e TS_DB="$DB" -e TS_OWNER="$OWNER" -e TS_RUNTIME="$RUNTIME" \
        "$@" "$HELPER_IMAGE" sh -c "$HELPER_SCRIPT"
}

# Run inside the helper: writes the bundle as a tar to stdout.
BACKUP_SCRIPT='set -eu
umask 077
mkdir /work/b
cd /work/b
export PGPASSWORD="$TS_OWNER_PW"
pg_dump -U "$TS_OWNER" -d "$TS_DB" -Fc -f db.dump
schema=$(psql -U "$TS_OWNER" -d "$TS_DB" -Atc "SELECT COALESCE(max(version), 0) FROM _sqlx_migrations" 2>/dev/null || echo 0)
tar -C /v/uploads -cf uploads.tar .
tar -C /v/pocketid -cf pocketid.tar .
if [ -f /v/keys/e2ee-server-key ]; then
    cp /v/keys/e2ee-server-key e2ee-server-key
    chmod 600 e2ee-server-key
fi
mkdir secrets
for f in oidc_client_secret pocketid_api_key pocketid_encryption_key; do
    if [ -f "/v/secrets/$f" ]; then cp "/v/secrets/$f" secrets/; fi
done
if [ "$TS_KIND" = export ]; then
    mkdir self-host
    cp /v/deploy/compose.yml /v/deploy/scan-off.yml self-host/
    cp /v/init/01-roles.sh self-host/
    cat > self-host/README.txt <<EOF
An export of one tinyserver community. Run it yourself:

1. Get tinyserver at a version at or after schema $schema, and set up deploy/ as its
   deploy/README.md says, with your own env file and passwords. Do not start it yet.
2. Restore this bundle into it. That puts in the database, the uploads, Pocket ID data,
   the three sign-in secrets and, when this bundle has one, the external sender key
   file, and starts the stack, which migrates it:

     sh deploy/tenant/operator.sh restore --stack deploy/.env --in <this file> --identity <your age key>

3. Point your chat and auth hostnames at your server. With the same auth hostname, the
   passkeys people already have keep working.

compose.yml and 01-roles.sh are the versions this was exported from, for reference.
EOF
fi
cat > manifest <<EOF
format=tinyserver-bundle-1
kind=$TS_KIND
created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
schema=$schema
postgres=$(pg_dump --version | sed "s/[^0-9.]//g")
EOF
find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS
tar -cf - .'

RESTORE_SCRIPT='set -eu
umask 077
mkdir /work/r
cd /work/r
tar -xf -
grep -qx "format=tinyserver-bundle-1" manifest || { echo "not a tinyserver bundle" >&2; exit 3; }
sha256sum -c -s SHA256SUMS || { echo "the bundle does not match its checksums" >&2; exit 3; }
# Empty the database: drop it and make it again, then the same roles and grants as the first start.
export PGPASSWORD="$TS_SUPER_PW"
psql -v ON_ERROR_STOP=1 -U postgres -d postgres -q \
    -v db="$TS_DB" <<SQL
SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = :'"'"'db'"'"' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS :"db";
CREATE DATABASE :"db";
SQL
POSTGRES_USER=postgres POSTGRES_DB="$TS_DB" TINYSERVER_OWNER_ROLE="$TS_OWNER" TINYSERVER_RUNTIME_ROLE="$TS_RUNTIME" \
    TINYSERVER_OWNER_CREATEDB="$TS_CREATEDB" APP_OWNER_PASSWORD="$TS_OWNER_PW" APP_RUNTIME_PASSWORD="$TS_RUNTIME_PW" \
    sh /v/init/01-roles.sh >/dev/null
# The default privileges would give app_runtime everything on each table as pg_restore makes it,
# and the dump only adds grants to that, so a table the migrations narrowed would come back wide.
# They are off while the dump goes in, and back on after.
for kind in TABLES SEQUENCES FUNCTIONS; do
    printf "ALTER DEFAULT PRIVILEGES FOR ROLE :\"owner\" IN SCHEMA public REVOKE ALL ON %s FROM app_runtime;\n" "$kind"
done | psql -v ON_ERROR_STOP=1 -U postgres -d "$TS_DB" -q -v owner="$TS_OWNER"
# As this community'"'"'s owner, so every object is its own. The grants in the dump go to the group
# app_runtime, which every tenant has. The public schema is already set above.
export PGPASSWORD="$TS_OWNER_PW"
pg_restore -l db.dump | grep -v -E "(DEFAULT ACL|ACL - SCHEMA public|SCHEMA - public|COMMENT - SCHEMA public) " > list
pg_restore --no-owner --exit-on-error --single-transaction -L list -U "$TS_OWNER" -d "$TS_DB" db.dump
export PGPASSWORD="$TS_SUPER_PW"
POSTGRES_USER=postgres POSTGRES_DB="$TS_DB" TINYSERVER_OWNER_ROLE="$TS_OWNER" TINYSERVER_RUNTIME_ROLE="$TS_RUNTIME" \
    TINYSERVER_OWNER_CREATEDB="$TS_CREATEDB" APP_OWNER_PASSWORD="$TS_OWNER_PW" APP_RUNTIME_PASSWORD="$TS_RUNTIME_PW" \
    sh /v/init/01-roles.sh >/dev/null
find /v/uploads -mindepth 1 -delete
tar -C /v/uploads -xf uploads.tar
chown -R 10001:10001 /v/uploads
if [ -f e2ee-server-key ]; then
    cp e2ee-server-key /v/keys/e2ee-server-key
    chown 10001:10001 /v/keys/e2ee-server-key
    chmod 600 /v/keys/e2ee-server-key
fi
find /v/pocketid -mindepth 1 -delete
tar -C /v/pocketid -xf pocketid.tar
chown -R 65532:65532 /v/pocketid
if [ -d /v/secrets ] && [ "$TS_SECRETS" = yes ]; then
    for f in secrets/*; do
        [ -f "$f" ] || continue
        cp "$f" "/v/secrets/$(basename "$f")"
        chmod 444 "/v/secrets/$(basename "$f")"
    done
fi
sed -n "s/^schema=//p" manifest'

# ------------------------------------------------------------------------------------------------

cmd_backup() {
    kind=$1
    shift
    target "$@"
    shift "$SHIFT"
    out=
    recipients=
    while [ $# -gt 0 ]; do
        [ $# -ge 2 ] || die "$1 needs a value"
        case "$1" in
            --out) out=$2 ;;
            --recipient)
                valid_recipient "$2" || die "not an age recipient: $2"
                recipients="$recipients -r $2"
                ;;
            --recipients-file)
                [ -f "$2" ] || die "no recipients file $2"
                for r in $(grep -v -e '^#' -e '^[[:space:]]*$' "$2" | tr -d '\r'); do
                    valid_recipient "$r" || die "not an age recipient in $2: $r"
                    recipients="$recipients -r $r"
                done
                ;;
            *) die "unknown option $1" ;;
        esac
        shift 2
    done
    [ -n "$out" ] || die "--out FILE is needed"
    [ ! -e "$out" ] || die "$out exists"
    if [ "$kind" = backup ] && [ -n "$HOME_DIR" ] && [ -f "$HOME_DIR/backup.recipient" ]; then
        recipients="$recipients -r $(cat "$HOME_DIR/backup.recipient")"
    fi
    [ -n "$recipients" ] || die "give at least one --recipient or --recipients-file (or run keygen)"

    postgres_up
    # Pocket ID's SQLite is copied with Pocket ID stopped, so the copy is whole.
    restart_pocketid=no
    if [ -n "$(dc ps -q --status running pocket-id 2>/dev/null)" ]; then
        dc stop pocket-id >/dev/null 2>&1
        restart_pocketid=yes
    fi
    status=$(mktemp)
    partial="$out.partial"
    HELPER_SCRIPT=$BACKUP_SCRIPT
    # shellcheck disable=SC2086 # recipients are words by construction
    {
        helper "DAC_READ_SEARCH" ro -e TS_KIND="$kind" -e TS_OWNER_PW="$(secret_of APP_OWNER_PASSWORD)"
        echo $? >"$status"
    } | age_cmd $recipients >"$partial" || {
        echo 1 >>"$status"
    }
    if [ "$restart_pocketid" = yes ]; then
        dc start pocket-id >/dev/null 2>&1 || say "warning: Pocket ID did not start again; run: compose start pocket-id" >&2
    fi
    if [ "$(sort -u "$status" | tr -d '\n')" != 0 ]; then
        rm -f "$status" "$partial"
        die "$kind of $NAME failed; nothing was written"
    fi
    rm -f "$status"
    mv "$partial" "$out"
    say "$kind of $NAME written to $out, encrypted with age"
}

cmd_restore() {
    target "$@"
    shift "$SHIFT"
    in=
    identity=
    yes=no
    secrets=yes
    while [ $# -gt 0 ]; do
        case "$1" in
            --yes)
                yes=yes
                shift
                continue
                ;;
            --keep-secrets)
                secrets=no
                shift
                continue
                ;;
        esac
        [ $# -ge 2 ] || die "$1 needs a value"
        case "$1" in
            --in) in=$2 ;;
            --identity) identity=$2 ;;
            *) die "unknown option $1" ;;
        esac
        shift 2
    done
    [ -f "$in" ] || die "--in FILE is needed"
    [ -f "$identity" ] || die "--identity FILE is needed"
    if [ "$yes" != yes ]; then
        say "This replaces $NAME's database, uploads, Pocket ID data, sign-in secrets and external sender key with the bundle's."
        printf 'Type the name %s to go on: ' "$NAME"
        read -r answer
        [ "$answer" = "$NAME" ] || die "not restored"
    fi
    postgres_up
    if on_hold; then
        die "$NAME is under a legal hold; a restore would overwrite what it keeps. Release it first."
    else
        [ $? -eq 1 ] || die "could not read $NAME's legal hold; nothing was restored"
    fi
    dc stop tinyserver pocket-id tunnel >/dev/null 2>&1 || true
    status=$(mktemp)
    HELPER_SCRIPT=$RESTORE_SCRIPT
    createdb=$(value_of "$ENV_PATH" TINYSERVER_OWNER_CREATEDB)
    [ -n "$createdb" ] || createdb=yes
    schema=$({
        age_decrypt "$identity" <"$in" || echo 1 >"$status"
    } | helper "CHOWN DAC_OVERRIDE FOWNER" rw \
        -e TS_SUPER_PW="$(secret_of POSTGRES_PASSWORD)" \
        -e TS_OWNER_PW="$(secret_of APP_OWNER_PASSWORD)" \
        -e TS_RUNTIME_PW="$(secret_of APP_RUNTIME_PASSWORD)" \
        -e TS_CREATEDB="$createdb" -e TS_SECRETS="$secrets") || echo 1 >>"$status"
    if [ -s "$status" ]; then
        rm -f "$status"
        die "restore of $NAME failed. Its database may be empty now; restore again from a good bundle."
    fi
    rm -f "$status"
    say "restored $NAME from $in (schema $schema); starting it, which migrates to this version"
    dc up -d >/dev/null 2>&1 || die "restored, but $NAME did not start; see compose logs"
    say "started"
}

cmd_keygen() {
    target "$@"
    [ -n "$HOME_DIR" ] || die "keygen is for a tenant; for --stack keep your own age key"
    [ ! -e "$HOME_DIR/backup.key" ] || die "$HOME_DIR/backup.key exists"
    (
        umask 077
        age_keygen >"$HOME_DIR/backup.key"
    )
    recipient=$(sed -n 's/^# public key: //p' "$HOME_DIR/backup.key" | tr -d '\r')
    valid_recipient "$recipient" || {
        rm -f "$HOME_DIR/backup.key"
        die "age-keygen did not make a key"
    }
    printf '%s\n' "$recipient" >"$HOME_DIR/backup.recipient"
    say "tenant $NAME: backups are now encrypted to $recipient as well as to any --recipient"
    say "keep a copy of $HOME_DIR/backup.key encrypted to your recovery key, off this host."
    say "delete destroys the copy here; destroy your copies too and those backups cannot be read."
}

cmd_delete() {
    target "$@"
    shift "$SHIFT"
    confirm=
    while [ $# -gt 0 ]; do
        [ $# -ge 2 ] || die "$1 needs a value"
        case "$1" in
            --confirm) confirm=$2 ;;
            *) die "unknown option $1" ;;
        esac
        shift 2
    done
    [ "$confirm" = "$NAME" ] || die "pass --confirm $NAME to delete it"
    postgres_up
    if on_hold; then
        die "$NAME is under a legal hold; nothing was deleted"
    else
        [ $? -eq 1 ] || die "could not read $NAME's legal hold; nothing was deleted"
    fi
    dc down -v --remove-orphans >/dev/null 2>&1 || die "compose down for $NAME failed"
    # Volumes a helper or a one-off run made outside compose's own labels.
    for v in tinyserver_pg pocketid_data tinyserver_uploads tinyserver_bootstrap tinyserver_keys clamav_db; do
        docker volume rm -f "${PROJECT}_$v" >/dev/null 2>&1 || true
    done
    removed=
    if [ -d "$SECRETS" ]; then
        for f in "$SECRETS"/*; do
            [ -f "$f" ] || continue
            shred_file "$f"
        done
        removed="secrets"
    fi
    if [ -n "$HOME_DIR" ]; then
        for f in "$HOME_DIR/backup.key" "$HOME_DIR/tenant.env"; do
            [ -f "$f" ] && shred_file "$f"
        done
        rm -rf "$HOME_DIR"
        removed="$removed, backup key, env file and $HOME_DIR"
    fi
    say "deleted $NAME: containers, networks, volumes, $removed"
    say "Volumes are removed, not shredded: on a disk without per-tenant encryption the blocks stay"
    say "until they are reused. Backups encrypted only to this tenant's key can no longer be read once"
    say "every copy of that key is gone; backups also encrypted to another recipient still can."
}

shred_file() {
    if command -v shred >/dev/null 2>&1; then
        shred -u "$1" 2>/dev/null || rm -f "$1"
    else
        rm -f "$1"
    fi
}

cmd_cli() {
    action=$1
    shift
    target "$@"
    shift "$SHIFT"
    postgres_up
    owner_cli "$action" "$@"
}

[ $# -ge 1 ] || die "usage: operator.sh status|suspend|resume|hold|release|keygen|backup|export|restore|delete TARGET ..."
sub=$1
shift
case "$sub" in
    status | suspend | resume | hold | release) cmd_cli "$sub" "$@" ;;
    keygen) cmd_keygen "$@" ;;
    backup) cmd_backup backup "$@" ;;
    export) cmd_backup export "$@" ;;
    restore) cmd_restore "$@" ;;
    delete) cmd_delete "$@" ;;
    *) die "unknown command $sub" ;;
esac
