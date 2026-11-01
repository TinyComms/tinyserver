#!/bin/sh
# One community, one stack. Makes the files that turn deploy/compose.yml into a tenant that
# shares nothing with another tenant, and runs compose for it.
#
#   tenant.sh new <name> [options]      make tenants/<name>/tenant.env and tenants/<name>/secrets/
#   tenant.sh env <name>                print the path of the env file
#   tenant.sh compose <name> [args...]  docker compose for that tenant: up -d, ps, logs, down -v
#
# The stack is deploy/compose.yml, unchanged. What makes it a tenant is the environment this
# writes: a project name (so containers, networks and volumes are named for it), its own subnet,
# media port, database and role names, passwords, media signing secret and secrets directory.
# See deploy/tenant/README.md and docs/privacy/tenancy.md.
#
# Options for `new`:
#   --dir DIR           where tenants live; default ./tenants next to this script
#   --prefix P          project name prefix; default tinyserver, so the project is tinyserver-<name>
#   --index N           1 to 250. Picks the subnet 10.77.N.0/24 and the media port 50000+N.
#                       Default: derived from the name, then checked against the other tenants in DIR
#   --subnet CIDR       a /24 for the inside network, instead of 10.77.N.0/24. The tunnel is .10
#   --media-port P      instead of 50000+N
#   --chat-url URL      TINYSERVER_PUBLIC_URL; default https://<name>.example.invalid
#   --auth-url URL      AUTH_PUBLIC_URL; default https://auth-<name>.example.invalid
#   --tunnel-token T    TUNNEL_TOKEN. Without one the file says to set it, and compose refuses to
#                       start the tunnel until you do
#   --scan clamd|none   clamd (the default) scans uploads as a single community does. none runs
#                       the tenant with deploy/scan-off.yml: no clamd, no scanning. Only for a
#                       community whose attachments are sealed on the sending device
#
# `new` refuses to reuse a name, a project, a subnet, a media port or a database name that another
# tenant in the same directory has. It does not look at what else is on the host: Docker refuses
# an overlapping subnet, and a published port that is taken fails `up`.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
deploy_dir=$(cd "$here/.." && pwd)

# A path docker can use. Under Git Bash on Windows that is C:/..., elsewhere it is the path.
hostpath() {
    (cd "$1" && { pwd -W 2>/dev/null || pwd; })
}

die() {
    echo "tenant.sh: $*" >&2
    exit 1
}

random_hex() {
    # $1 bytes as lower case hex, from the kernel, with tools every POSIX system has.
    head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
}

valid_name() {
    case "$1" in
        '' | *[!a-z0-9-]* | -* | *-) return 1 ;;
    esac
    [ "${#1}" -ge 2 ] && [ "${#1}" -le 24 ] && case "$1" in [0-9]*) return 1 ;; esac
}

value_of() {
    # value_of FILE KEY: the value of KEY=value in an env file
    sed -n "s/^$2=//p" "$1" | head -n 1
}

cmd_new() {
    [ $# -ge 1 ] || die "new needs a name"
    name=$1
    shift
    valid_name "$name" || die "the name is 2 to 24 lower case letters, digits and hyphens, starting with a letter"
    dir="$here/tenants"
    prefix=tinyserver
    index=
    subnet=
    port=
    chat=
    auth=
    token=
    scan=clamd
    while [ $# -gt 0 ]; do
        [ $# -ge 2 ] || die "$1 needs a value"
        case "$1" in
            --dir) dir=$2 ;;
            --prefix) prefix=$2 ;;
            --index) index=$2 ;;
            --subnet) subnet=$2 ;;
            --media-port) port=$2 ;;
            --chat-url) chat=$2 ;;
            --auth-url) auth=$2 ;;
            --tunnel-token) token=$2 ;;
            --scan) scan=$2 ;;
            *) die "unknown option $1" ;;
        esac
        shift 2
    done
    case "$prefix" in
        '' | *[!a-z0-9_-]* | [!a-z0-9]*) die "the prefix is lower case letters, digits, hyphens and underscores" ;;
    esac
    mkdir -p "$dir"
    dir=$(cd "$dir" && pwd)
    project="$prefix-$name"
    id=$(printf '%s' "$name" | tr - _)

    if [ -z "$index" ]; then
        sum=$(printf '%s' "$name" | cksum | cut -d' ' -f1)
        index=$((sum % 200 + 20))
    fi
    case "$index" in
        '' | *[!0-9]*) die "--index is a number from 1 to 250" ;;
    esac
    [ "$index" -ge 1 ] && [ "$index" -le 250 ] || die "--index is a number from 1 to 250"
    [ -n "$subnet" ] || subnet="10.77.$index.0/24"
    case "$subnet" in
        *.*.*.0/24) ;;
        *) die "--subnet is a /24 ending in .0/24, such as 10.77.40.0/24" ;;
    esac
    base=${subnet%.0/24}
    [ -n "$port" ] || port=$((50000 + index))
    case "$port" in
        '' | *[!0-9]*) die "--media-port is a number" ;;
    esac
    [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || die "--media-port is 1024 to 65535"
    case "$scan" in
        clamd | none) ;;
        *) die "--scan is clamd or none" ;;
    esac
    [ -n "$chat" ] || chat="https://$name.example.invalid"
    [ -n "$auth" ] || auth="https://auth-$name.example.invalid"

    target="$dir/$name"
    [ ! -e "$target" ] || die "$target exists; choose another name or remove it"
    for other in "$dir"/*/tenant.env; do
        [ -f "$other" ] || continue
        for key in COMPOSE_PROJECT_NAME TINYSERVER_INSIDE_SUBNET TINYSERVER_MEDIA_PORT TINYSERVER_DB_NAME; do
            case "$key" in
                COMPOSE_PROJECT_NAME) mine=$project ;;
                TINYSERVER_INSIDE_SUBNET) mine=$subnet ;;
                TINYSERVER_MEDIA_PORT) mine=$port ;;
                TINYSERVER_DB_NAME) mine="tenant_$id" ;;
            esac
            [ "$(value_of "$other" "$key")" != "$mine" ] || die "$key $mine is already used by $other"
        done
    done

    mkdir -p "$target/secrets"
    chmod 700 "$target" "$target/secrets"
    # The three files deploy/compose.yml mounts as Docker secrets. Containers read them as their
    # own users, so they are world readable inside a directory only the operator can enter.
    for secret in oidc_client_secret pocketid_api_key pocketid_encryption_key; do
        random_hex 32 >"$target/secrets/$secret"
        chmod 444 "$target/secrets/$secret"
    done

    envfile="$target/tenant.env"
    (
        umask 077
        {
            echo "# Tenant $name. Written by tenant.sh. Holds passwords: keep it 0600 and out of version control."
            echo "COMPOSE_PROJECT_NAME=$project"
            echo "TINYSERVER_DB_NAME=tenant_$id"
            echo "TINYSERVER_OWNER_ROLE=${id}_owner"
            echo "TINYSERVER_RUNTIME_ROLE=${id}_runtime"
            echo "TINYSERVER_OWNER_CREATEDB=no"
            echo "POSTGRES_PASSWORD=$(random_hex 32)"
            echo "APP_OWNER_PASSWORD=$(random_hex 32)"
            echo "APP_RUNTIME_PASSWORD=$(random_hex 32)"
            echo "TINYSERVER_MEDIA_HMAC_SECRET=$(random_hex 32)"
            echo "TINYSERVER_INSIDE_SUBNET=$subnet"
            echo "TINYSERVER_TUNNEL_IP=$base.10"
            echo "TINYSERVER_MEDIA_PORT=$port"
            echo "TINYSERVER_SECRETS_DIR=$(hostpath "$target/secrets")"
            echo "# clamd scans uploads; none adds deploy/scan-off.yml, for sealed attachments only."
            echo "TENANT_SCAN=$scan"
            echo "TINYSERVER_PUBLIC_URL=$chat"
            echo "AUTH_PUBLIC_URL=$auth"
            if [ -n "$token" ]; then
                echo "TUNNEL_TOKEN=$token"
            else
                echo "# Set this to the tunnel token for this tenant's hostnames. Compose refuses to start without it."
                echo "TUNNEL_TOKEN="
            fi
            echo "# Calls need the address members reach, and the media port forwarded to this host."
            echo "#TINYSERVER_PUBLIC_IP="
            echo "# Limits. These are the compose defaults; set them to what the plan allows."
            echo "#TINYSERVER_MEM_LIMIT=1g"
            echo "#TINYSERVER_CPUS=2"
            echo "#TINYSERVER_PIDS_LIMIT=512"
            echo "#TINYSERVER_PG_MEM_LIMIT=1g"
            echo "#TINYSERVER_PG_PIDS_LIMIT=256"
            echo "#TINYSERVER_CLAMD_MEM_LIMIT=3g"
        } >"$envfile"
    )
    echo "tenant $name"
    echo "  project   $project"
    echo "  database  tenant_$id   roles ${id}_owner, ${id}_runtime"
    echo "  subnet    $subnet   media port $port"
    echo "  scanning  $scan"
    echo "  env file  $envfile"
    echo "next:"
    echo "  TENANT_DIR=$dir sh $0 compose $name up -d"
}

tenant_dir() {
    printf '%s' "${TENANT_DIR:-$here/tenants}"
}

cmd_env() {
    [ $# -ge 1 ] || die "env needs a name"
    file="$(tenant_dir)/$1/tenant.env"
    [ -f "$file" ] || die "no tenant $1 in $(tenant_dir)"
    hostpath "$(dirname "$file")" | sed "s|\$|/tenant.env|"
}

cmd_compose() {
    [ $# -ge 1 ] || die "compose needs a name"
    name=$1
    shift
    file="$(tenant_dir)/$name/tenant.env"
    [ -f "$file" ] || die "no tenant $name in $(tenant_dir)"
    project=$(value_of "$file" COMPOSE_PROJECT_NAME)
    [ -n "$project" ] || die "$file has no COMPOSE_PROJECT_NAME"
    # TENANT_COMPOSE_FILES: more compose files, space separated, after deploy/compose.yml.
    files="-f $(hostpath "$deploy_dir")/compose.yml"
    if [ "$(value_of "$file" TENANT_SCAN)" = none ]; then
        files="$files -f $(hostpath "$deploy_dir")/scan-off.yml"
    fi
    for extra in ${TENANT_COMPOSE_FILES:-}; do
        files="$files -f $extra"
    done
    # shellcheck disable=SC2086 # the file list is words by construction
    exec docker compose -p "$project" --env-file "$(hostpath "$(dirname "$file")")/tenant.env" $files "$@"
}

[ $# -ge 1 ] || die "usage: tenant.sh new|env|compose <name> ..."
sub=$1
shift
case "$sub" in
    new) cmd_new "$@" ;;
    env) cmd_env "$@" ;;
    compose) cmd_compose "$@" ;;
    *) die "unknown command $sub; new, env or compose" ;;
esac
