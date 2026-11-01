#!/bin/sh
# Brings up two tenants from deploy/compose.yml, as deploy/tenant/tenant.sh makes them, and checks
# that Docker really confines each the way the contract in docs/privacy/tenancy.md says.
#
#   sh deploy/tests/isolation.sh            run, then remove everything this created
#   sh deploy/tests/isolation.sh --keep     leave the two tenants up to look at; run purge.sh after
#
# Needs: Docker with Compose v2.24 or later, a running daemon, cgroup v2 (the limit checks read
# /sys/fs/cgroup inside the container), and the image postgres:17-alpine locally. Does not need
# root on the host, except that on Linux you may need to be in the docker group. Does not need the
# tinyserver image: see deploy/tests/compose.test.yml for what runs instead and why.
#
# It creates only containers, networks and volumes named tinytenant-test-*, and removes only those.
# Exit status is 0 when every check passed, 1 when one failed, 2 when it could not start.
#
# What the checks do and do not prove is in deploy/tests/README.md. In short: they prove Docker
# applies the settings in the compose file to the containers it makes from it, and that two
# tenants made by tenant.sh cannot reach each other. They do not prove the settings are enough.

set -u
. "$(dirname "$0")/lib.sh"

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

need_docker
purge

work=$(mktemp -d)
export TENANT_DIR="$work"
export TENANT_COMPOSE_FILES="$(hostpath "$TESTS_DIR")/compose.test.yml"
tenant() { sh "$DEPLOY_DIR/tenant/tenant.sh" "$@"; }

cleanup() {
    if [ "$KEEP" -eq 0 ]; then
        for t in alpha bravo; do
            [ -f "$work/$t/tenant.env" ] && tenant compose "$t" down -v --remove-orphans >/dev/null 2>&1
        done
        purge
        rm -rf "$work"
    else
        info "left the tenants up; the env files are in $work"
    fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------------------------
say "== The tenant generator"

tenant new alpha --dir "$work" --prefix "$PREFIX" --tunnel-token placeholder >/dev/null || fail "new alpha"
tenant new bravo --dir "$work" --prefix "$PREFIX" --tunnel-token placeholder >/dev/null || fail "new bravo"
A_ENV="$work/alpha/tenant.env"
B_ENV="$work/bravo/tenant.env"

for key in COMPOSE_PROJECT_NAME TINYSERVER_DB_NAME TINYSERVER_OWNER_ROLE TINYSERVER_RUNTIME_ROLE \
    TINYSERVER_INSIDE_SUBNET TINYSERVER_MEDIA_PORT TINYSERVER_SECRETS_DIR POSTGRES_PASSWORD \
    APP_OWNER_PASSWORD APP_RUNTIME_PASSWORD TINYSERVER_MEDIA_HMAC_SECRET; do
    differs "two tenants have different $key" "$(value_of "$A_ENV" "$key")" "$(value_of "$B_ENV" "$key")"
done
# The generator refuses what would collide with a tenant that is already there.
check_not "a name that exists is refused" \
    tenant new alpha --dir "$work" --prefix "$PREFIX"
check_not "a media port in use by another tenant is refused" \
    tenant new charlie --dir "$work" --prefix "$PREFIX" --media-port "$(value_of "$A_ENV" TINYSERVER_MEDIA_PORT)"
check_not "a subnet in use by another tenant is refused" \
    tenant new delta --dir "$work" --prefix "$PREFIX" --subnet "$(value_of "$A_ENV" TINYSERVER_INSIDE_SUBNET)"
check_not "a bad name is refused" tenant new "Bad_Name" --dir "$work"
equals "passwords are 64 hex characters" "64" "$(value_of "$A_ENV" APP_OWNER_PASSWORD | tr -d '\n' | wc -c | tr -d ' ')"
check "the secrets directory is the tenant's own" \
    test -f "$work/alpha/secrets/oidc_client_secret"

# ---------------------------------------------------------------------------------------------
say "== The compose file as configured for each tenant (nothing started)"

tenant_cfg() { env TENANT_COMPOSE_FILES= sh "$DEPLOY_DIR/tenant/tenant.sh" compose "$1" config 2>&1; }
cfg_a=$(tenant_cfg alpha)
cfg_b=$(tenant_cfg bravo)
contains "alpha's project name" "$cfg_a" "name: ${PREFIX}-alpha"
contains "bravo's project name" "$cfg_b" "name: ${PREFIX}-bravo"
for net in inside media edge; do
    contains "alpha's $net network is its own" "$cfg_a" "name: ${PREFIX}-alpha_$net"
    contains "bravo's $net network is its own" "$cfg_b" "name: ${PREFIX}-bravo_$net"
done
for vol in tinyserver_pg pocketid_data tinyserver_uploads tinyserver_bootstrap clamav_db; do
    contains "alpha's volume $vol is its own" "$cfg_a" "name: ${PREFIX}-alpha_$vol"
    contains "bravo's volume $vol is its own" "$cfg_b" "name: ${PREFIX}-bravo_$vol"
done
a_port=$(value_of "$A_ENV" TINYSERVER_MEDIA_PORT)
b_port=$(value_of "$B_ENV" TINYSERVER_MEDIA_PORT)
contains "alpha publishes its own media port, udp" "$cfg_a" "published: \"$a_port\""
contains "bravo publishes its own media port" "$cfg_b" "published: \"$b_port\""
lacks "alpha does not publish bravo's media port" "$cfg_a" "published: \"$b_port\""
contains "alpha's subnet" "$cfg_a" "subnet: $(value_of "$A_ENV" TINYSERVER_INSIDE_SUBNET)"
contains "alpha's database name reaches the serving process" "$cfg_a" "/$(value_of "$A_ENV" TINYSERVER_DB_NAME)"
contains "alpha's runtime role reaches the serving process" "$cfg_a" "$(value_of "$A_ENV" TINYSERVER_RUNTIME_ROLE):"
lacks "bravo's compose has no trace of alpha's database" "$cfg_b" "$(value_of "$A_ENV" TINYSERVER_DB_NAME)"
lacks "bravo's compose has no trace of alpha's passwords" "$cfg_b" "$(value_of "$A_ENV" APP_RUNTIME_PASSWORD)"
lacks "bravo's compose has no trace of alpha's secrets directory" "$cfg_b" "$(value_of "$A_ENV" TINYSERVER_SECRETS_DIR)"

# The real compose file, without the test override: what every service says about itself.
real=$cfg_a
lacks "no service mounts the container runtime socket" "$real" "docker.sock"
lacks "no service is privileged" "$real" "privileged"
lacks "no service shares the host network" "$real" "network_mode: host"
lacks "no service shares the host's process namespace" "$real" "pid: host"
lacks "no service shares the host's IPC namespace" "$real" "ipc: host"
lacks "no service adds the SYS_ADMIN capability" "$real" "SYS_ADMIN"
lacks "no service maps a device" "$real" "devices:"

svc_block() {
    printf '%s\n' "$2" | awk -v s="$1" '/^[^ ]/ {insvc=0} $0 == "  " s ":" {insvc=1; next} /^  [^ ]/ {insvc=0} insvc {print}'
}
for s in postgres tinyserver tinyserver-init tinyserver-uploads clamd pocket-id-data pocket-id tunnel; do
    block=$(svc_block "$s" "$real")
    if [ -z "$block" ]; then
        fail "service $s is in the compose file"
        continue
    fi
    contains "$s: no-new-privileges" "$block" "no-new-privileges:true"
done
for s in postgres tinyserver tinyserver-init tinyserver-uploads clamd pocket-id-data pocket-id tunnel; do
    block=$(svc_block "$s" "$real")
    contains "$s: cap_drop ALL" "$block" "- ALL"
done
# clamd's entrypoint writes its settings into /etc/clamav, so its root stays writable. Every other
# long-running service has a read-only root.
for s in postgres tinyserver tinyserver-init tinyserver-uploads pocket-id-data pocket-id tunnel; do
    block=$(svc_block "$s" "$real")
    contains "$s: read-only root" "$block" "read_only: true"
done
for s in postgres tinyserver tinyserver-init pocket-id tunnel clamd; do
    block=$(svc_block "$s" "$real")
    contains "$s: a memory limit" "$block" "mem_limit:"
    case "$s" in
        clamd | postgres | tinyserver | tinyserver-init | pocket-id | tunnel) contains "$s: a pids limit" "$block" "pids_limit:" ;;
    esac
done
ts_block=$(svc_block tinyserver "$real")
contains "tinyserver: a cpu limit" "$ts_block" "cpus:"
lacks "tinyserver adds no capability" "$ts_block" "cap_add"
lacks "tinyserver gets no owner database url" "$ts_block" "DATABASE_URL_MIGRATE"
lacks "tinyserver does not hold the owner password" "$ts_block" "APP_OWNER_PASSWORD"
init_block=$(svc_block tinyserver-init "$real")
contains "the init container holds the owner url" "$init_block" "DATABASE_URL_MIGRATE"
pg_block=$(svc_block postgres "$real")
caps=$(printf '%s\n' "$pg_block" | awk '/cap_add:/ {on=1; next} /^    [a-z]/ {on=0} on {print $2}' | sort | tr '\n' ' ')
equals "postgres adds back exactly the five capabilities it needs" "CHOWN DAC_OVERRIDE FOWNER SETGID SETUID " "$caps"
clamd_block=$(svc_block clamd "$real")
caps=$(printf '%s
' "$clamd_block" | awk '/cap_add:/ {on=1; next} /^    [a-z]/ {on=0} on {print $2}' | sort | tr '
' ' ')
equals "clamd adds back exactly the same five" "CHOWN DAC_OVERRIDE FOWNER SETGID SETUID " "$caps"
contains "the serving process scans with clamd by default" "$ts_block" "TINYSERVER_SCAN_ENGINE: clamd"

# A tenant made with --scan none runs without clamd, and only that tenant.
tenant new echo --dir "$work" --prefix "$PREFIX" --tunnel-token placeholder --scan none >/dev/null || fail "new echo"
cfg_e=$(tenant_cfg echo)
contains "--scan none: the serving process has scanning off" "$(svc_block tinyserver "$cfg_e")" "TINYSERVER_SCAN_ENGINE: none"
lacks "--scan none: no clamd socket" "$(svc_block tinyserver "$cfg_e")" "clamd:3310"
equals "--scan none: no clamd service runs" "" "$(svc_block clamd "$cfg_e")"
lacks "--scan none: nothing waits for clamd" "$(svc_block tinyserver "$cfg_e")" "clamd:"
contains "and alpha, beside it, still scans" "$(svc_block tinyserver "$cfg_a")" "TINYSERVER_SCAN_ENGINE: clamd"
check_not "--scan takes clamd or none" tenant new foxtrot --dir "$work" --prefix "$PREFIX" --scan maybe
rm -rf "$work/echo"
# The only host path mounted anywhere is the read-only init directory, for Postgres.
binds=$(printf '%s\n' "$real" | grep -c 'type: bind' || true)
equals "exactly one bind mount in the whole stack" "1" "$binds"
check "that bind mount is read only and is the Postgres init directory" \
    sh -c "printf '%s\n' \"\$1\" | grep -A4 'type: bind' | grep -q 'target: /docker-entrypoint-initdb.d' && printf '%s\n' \"\$1\" | grep -A4 'type: bind' | grep -q 'read_only: true'" _ "$real"
check "the Dockerfile runs as an unprivileged user 10001" grep -q '^USER 10001:10001' "$REPO_DIR/Dockerfile"

# ---------------------------------------------------------------------------------------------
say "== Starting two tenants (a few seconds each: Postgres starts and runs the roles script)"

for t in alpha bravo; do
    # Small limits, so a memory hog and a fork bomb are small. The wiring is the compose file's.
    printf 'TINYSERVER_MEM_LIMIT=64m\nTINYSERVER_PIDS_LIMIT=64\nTINYSERVER_CPUS=0.5\n' >>"$work/$t/tenant.env"
    if ! tenant compose "$t" up -d tinyserver >"$work/$t.up" 2>&1; then
        say "could not start $t:"
        cat "$work/$t.up"
        fail "$t starts"
        exit 1
    fi
done

# A listener in each serving container, so a refused connection means refused and not nobody home.
for t in alpha bravo; do
    docker exec -d "${PREFIX}-$t-tinyserver-1" sh -c 'while true; do echo hi | nc -l -p 8080; done' >/dev/null 2>&1
done
sleep 1

for t in alpha bravo; do
    P="${PREFIX}-$t"
    E="$work/$t/tenant.env"
    SRV="$P-tinyserver-1"
    PG="$P-postgres-1"
    INIT="$P-tinyserver-init-1"
    DBN=$(value_of "$E" TINYSERVER_DB_NAME)
    OWN=$(value_of "$E" TINYSERVER_OWNER_ROLE)
    RUN=$(value_of "$E" TINYSERVER_RUNTIME_ROLE)
    RPW=$(value_of "$E" APP_RUNTIME_PASSWORD)
    OPW=$(value_of "$E" APP_OWNER_PASSWORD)
    SPW=$(value_of "$E" POSTGRES_PASSWORD)

    say ""
    say "== Tenant $t: its own database and roles"
    equals "the init container connected as the owner role, to the tenant's database" \
        "init:$OWN:$DBN" "$(docker logs "$INIT" 2>&1 | tail -n 1 | tr -d '\r')"
    equals "the serving container connects as the runtime role, to the tenant's database" \
        "$RUN|$DBN" \
        "$(docker exec "$SRV" sh -c 'psql "$DATABASE_URL" -Atc "select current_user || chr(124) || current_database()"' 2>&1 | tr -d '\r')"
    roles=$(docker exec "$PG" psql -U postgres -d "$DBN" -Atc "select rolname from pg_roles where rolname !~ '^pg_' order by rolname collate \"C\"" | tr -d '\r' | tr '\n' ' ')
    want=$(printf '%s\n' "$OWN" "$RUN" app_runtime postgres | LC_ALL=C sort | tr '\n' ' ')
    equals "the cluster has this tenant's two roles, the NOLOGIN group app_runtime the migrations grant to, and postgres" "$want" "$roles"
    equals "app_runtime is a group that cannot log in, and the runtime role is in it" "false|true" \
        "$(docker exec "$PG" psql -U postgres -Atc "select (select rolcanlogin from pg_roles where rolname = 'app_runtime')::text || '|' || pg_has_role('$RUN', 'app_runtime', 'member')::text" | tr -d '\r')"
    equals "the runtime role cannot bypass row level security, create roles or databases, or be a superuser" \
        "f|f|f|f" "$(docker exec "$PG" psql -U postgres -Atc "select format('%s|%s|%s|%s', rolbypassrls, rolcreatedb, rolcreaterole, rolsuper) from pg_roles where rolname = '$RUN'" | tr -d '\r')"
    equals "the owner bypasses row level security and, for a tenant, cannot create databases" \
        "t|f|f|f" "$(docker exec "$PG" psql -U postgres -Atc "select format('%s|%s|%s|%s', rolbypassrls, rolcreatedb, rolcreaterole, rolsuper) from pg_roles where rolname = '$OWN'" | tr -d '\r')"
    equals "PUBLIC cannot connect to the tenant's database" \
        "f" "$(docker exec "$PG" psql -U postgres -Atc "select has_database_privilege('public', '$DBN', 'CONNECT')")"
    equals "the tenant's runtime role can connect to exactly one non-template database, its own" \
        "1" "$(docker exec "$PG" psql -U postgres -Atc "select count(*) from pg_database where datname not in ('postgres','template0','template1') and has_database_privilege('$RUN', datname, 'CONNECT')" | tr -d '\r')"
    other=alpha
    [ "$t" = alpha ] && other=bravo
    O_RUN=$(value_of "$work/$other/tenant.env" TINYSERVER_RUNTIME_ROLE)
    O_DB=$(value_of "$work/$other/tenant.env" TINYSERVER_DB_NAME)
    O_PW=$(value_of "$work/$other/tenant.env" APP_RUNTIME_PASSWORD)
    check_not "the other tenant's runtime role, with its own password, cannot log in to this tenant's Postgres" \
        docker exec "$PG" psql "postgres://$O_RUN:$O_PW@127.0.0.1:5432/$DBN?connect_timeout=3" -Atc "select 1"
    check_not "the other tenant's database does not exist here" \
        docker exec "$PG" psql -U postgres -d "$O_DB" -Atc "select 1"

    say ""
    say "== Tenant $t: no route to the other tenant"
    O_P="${PREFIX}-$other"
    O_SRV="$O_P-tinyserver-1"
    O_PG="$O_P-postgres-1"
    O_E="$work/$other/tenant.env"
    check_not "$t's server cannot resolve $other's Postgres by its container name" can_resolve "$SRV" "$O_PG"
    check_not "$t's server cannot resolve $other's server by its container name" can_resolve "$SRV" "$O_SRV"
    own_pg_ip=$(docker exec "$SRV" sh -c "getent hosts postgres" | awk '{print $1}')
    case " $(ips_of "$PG") " in
        *" $own_pg_ip "*) pass "'postgres' from $t's server is $t's own Postgres" ;;
        *) fail "'postgres' from $t's server is $t's own Postgres (got $own_pg_ip)" ;;
    esac
    check "control: $t's server connects to its own Postgres" can_connect "$SRV" postgres 5432
    check "control: $t's Postgres container connects to $t's own server's listener" can_connect "$PG" "$(docker inspect -f "{{(index .NetworkSettings.Networks \"${P}_inside\").IPAddress}}" "$SRV")" 8080
    for ip in $(ips_of "$O_PG"); do
        check_not "$t's server cannot connect to $other's Postgres at $ip:5432" can_connect "$SRV" "$ip" 5432
    done
    for ip in $(ips_of "$O_SRV"); do
        check_not "$t's server cannot connect to $other's server at $ip:8080" can_connect "$SRV" "$ip" 8080
    done
    for ip in $(ips_of "$O_PG"); do
        check_not "$t's server cannot log in to $other's Postgres with $other's own credentials ($ip)" \
            docker exec "$SRV" psql "postgres://$O_RUN:$O_PW@$ip:5432/$O_DB?connect_timeout=3" -Atc "select 1"
    done
    for ip in $(ips_of "$O_SRV"); do
        check_not "$t's Postgres cannot connect to $other's server at $ip:8080" can_connect "$PG" "$ip" 8080
    done

    say ""
    say "== Tenant $t: the serving container"
    # No container-runtime socket.
    check_not "no docker.sock inside" docker exec "$SRV" sh -c 'test -e /var/run/docker.sock -o -e /run/docker.sock'
    equals "nothing in /proc/mounts names a docker socket" "0" "$(docker exec "$SRV" sh -c 'grep -c docker.sock /proc/mounts' | tr -d '\r')"
    lacks "no DOCKER_HOST in the environment" "$(docker exec "$SRV" env)" "DOCKER_HOST"
    mounts=$(docker inspect -f '{{range .Mounts}}{{.Type}} {{.Destination}} rw={{.RW}}{{println}}{{end}}' "$SRV")
    lacks "no mount source or destination names the docker socket" "$mounts" "docker.sock"
    lacks "nothing from the host's /var/run, /run, / or /etc is mounted" "$(docker inspect -f '{{range .Mounts}}{{.Source}}{{println}}{{end}}' "$SRV" | grep -E '^(/var/run|/run|/|/etc|/proc|/sys)$' || true)" "/"
    # Bind mounts are the secrets, and nothing else, read only.
    binds=$(printf '%s\n' "$mounts" | grep '^bind' || true)
    bad=$(printf '%s\n' "$binds" | grep -v -E '^bind /run/secrets/[a-z_]+ rw=false$' | grep -v '^$' || true)
    equals "the only bind mounts are Docker secrets under /run/secrets, read only" "" "$bad"
    equals "the container is not privileged" "false" "$(docker inspect -f '{{.HostConfig.Privileged}}' "$SRV")"
    equals "no host PID namespace" "" "$(docker inspect -f '{{.HostConfig.PidMode}}' "$SRV")"
    case "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$SRV")" in host) fail "host network" ;; *) pass "not on the host network" ;; esac
    equals "no devices" "[]" "$(docker inspect -f '{{json .HostConfig.Devices}}' "$SRV" | sed 's/null/[]/')"
    equals "no added capabilities" "[]" "$(docker inspect -f '{{json .HostConfig.CapAdd}}' "$SRV" | sed 's/null/[]/')"
    equals "all capabilities dropped" '["ALL"]' "$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$SRV")"

    # Read only root.
    equals "the root filesystem is read only to Docker" "true" "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$SRV")"
    # As root inside the container, so that only the read-only mount can be what says no: a plain
    # user cannot write to / on a writable root either.
    for path in /rofs-test /etc/rofs-test /usr/rofs-test /var/lib/rofs-test; do
        contains "root cannot write $path" "$(docker exec -u 0 "$SRV" sh -c "touch $path 2>&1")" "Read-only file system"
    done
    check "control: the tmpfs the server is given is writable" docker exec "$SRV" sh -c 'echo ok > /var/lib/tinyserver/w && rm /var/lib/tinyserver/w'
    equals "the process is not root (user 10001)" "10001" "$(docker exec "$SRV" id -u | tr -d '\r')"

    # Capabilities, no-new-privileges, seccomp.
    for field in CapEff CapPrm CapBnd CapAmb CapInh; do
        equals "$field is empty" "$field: 0000000000000000" "$(status_of "$SRV" "$field")"
        # A process that is not root has no effective capabilities whatever the container allows,
        # so the same is read as root, which is what the bounding set is for.
        equals "$field is empty for root inside the container" "$field: 0000000000000000" \
            "$(docker exec -u 0 "$SRV" sh -c "grep '^$field' /proc/self/status" | tr -d '\r' | tr '\t' ' ' | tr -s ' ')"
    done
    equals "NoNewPrivs is set for root too" "NoNewPrivs: 1" \
        "$(docker exec -u 0 "$SRV" sh -c "grep '^NoNewPrivs' /proc/self/status" | tr -d '\r' | tr '\t' ' ' | tr -s ' ')"
    check_not "root cannot chown a file to another user (CAP_CHOWN is gone)" \
        docker exec -u 0 "$SRV" sh -c 'chown 12345 /var/lib/tinyserver'
    check_not "root cannot mount a filesystem (CAP_SYS_ADMIN is gone)" \
        docker exec -u 0 "$SRV" sh -c 'mkdir -p /var/lib/tinyserver/m && mount -t tmpfs none /var/lib/tinyserver/m'
    equals "NoNewPrivs is set" "NoNewPrivs: 1" "$(status_of "$SRV" NoNewPrivs)"
    contains "no-new-privileges is in the container's security options" \
        "$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$SRV")" "no-new-privileges"
    equals "a seccomp filter is installed (Docker's default profile)" "Seccomp: 2" "$(status_of "$SRV" 'Seccomp:')"
    lacks "seccomp is not turned off" "$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$SRV")" "seccomp"

    # Environment: only the runtime role, no owner, no cloud credentials, no tunnel token.
    env_run=$(docker exec "$SRV" env)
    env_cfg=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SRV")
    for source in "$env_run" "$env_cfg"; do
        lacks "no DATABASE_URL_MIGRATE" "$source" "DATABASE_URL_MIGRATE"
        lacks "the owner password is not in the environment" "$source" "$OPW"
        lacks "the Postgres superuser password is not in the environment" "$source" "$SPW"
        lacks "the owner role name is not in the environment" "$source" "$OWN"
        lacks "no APP_OWNER_PASSWORD or POSTGRES_PASSWORD variable" "$source" "APP_OWNER_PASSWORD"
        lacks "no tunnel token" "$source" "TUNNEL_TOKEN"
        for prefix in AWS_ AZURE_ GOOGLE_ GCP_ GCLOUD CLOUDSDK DIGITALOCEAN LINODE OCI_ ALIBABA ECS_CONTAINER KUBERNETES_ CF_API; do
            lacks "no cloud credential variable ($prefix...)" "$source" "
$prefix"
        done
    done
    contains "the runtime role's URL is there, which is all the server holds" "$env_run" "DATABASE_URL=postgres://$RUN:"
    check "the runtime password is only in DATABASE_URL" \
        sh -c "printf '%s\n' \"\$1\" | grep -c '$RPW' | grep -q '^1\$'" _ "$env_run"
    lacks "the process environment (PID 1) holds no owner credentials either" \
        "$(docker exec "$SRV" sh -c 'tr "\0" "\n" </proc/1/environ')" "$OPW"
    init_env=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$INIT")
    contains "control: the init container, and only it, holds the owner url" "$init_env" "DATABASE_URL_MIGRATE=postgres://$OWN:"
    lacks "the init container does not hold the runtime password" "$init_env" "$RPW"

    # Limits.
    mem=$(docker exec "$SRV" cat /sys/fs/cgroup/memory.max | tr -d '\r')
    pids=$(docker exec "$SRV" cat /sys/fs/cgroup/pids.max | tr -d '\r')
    cpu=$(docker exec "$SRV" cat /sys/fs/cgroup/cpu.max | tr -d '\r')
    equals "memory.max in the container's cgroup is 64m, as the tenant's env says" "67108864" "$mem"
    equals "pids.max is 64" "64" "$pids"
    equals "cpu.max is half a core" "50000 100000" "$cpu"
    oom_before=$(docker exec "$SRV" sh -c "grep '^oom_kill ' /sys/fs/cgroup/memory.events | cut -d' ' -f2" | tr -d '\r')
    # About 400 MB held in a shell variable, against a 64 MB limit.
    docker exec "$SRV" sh -c 'x=$(head -c 400000000 /dev/zero | tr "\0" a); echo survived-${#x}' >"$work/hog.out" 2>&1
    hog=$?
    oom_after=$(docker exec "$SRV" sh -c "grep '^oom_kill ' /sys/fs/cgroup/memory.events | cut -d' ' -f2" | tr -d '\r')
    equals "a memory hog is killed (exit 137)" "137" "$hog"
    lacks "the hog never finished" "$(cat "$work/hog.out")" "survived"
    if [ "$oom_after" -gt "$oom_before" ]; then pass "the kernel counted an OOM kill in the cgroup ($oom_before to $oom_after)"; else fail "the kernel counted an OOM kill ($oom_before to $oom_after)"; fi
    equals "the container itself is still running after its hog was killed" "true" "$(docker inspect -f '{{.State.Running}}' "$SRV")"
    # 400 background sleeps against a limit of 64. When the limit is hit the shell cannot fork and
    # stops, and the sleeps it did start hold the limit full for five seconds; not even `docker exec`
    # can start a process until they end. The counters are read after.
    bomb=$(docker exec "$SRV" sh -c 'i=0; while [ $i -lt 400 ]; do sleep 5 & i=$((i+1)); done; wait' 2>&1)
    sleep 7
    refused=$(docker exec "$SRV" sh -c "grep '^max ' /sys/fs/cgroup/pids.events | cut -d' ' -f2" | tr -d '
')
    peak=$(docker exec "$SRV" sh -c 'cat /sys/fs/cgroup/pids.peak 2>/dev/null || echo none' | tr -d '
')
    contains "the shell was told it could not fork" "$bomb" "fork"
    case "$refused" in '' | *[!0-9]*) refused=0 ;; esac
    if [ "$refused" -gt 0 ]; then pass "the kernel refused $refused forks at the pids limit"; else fail "the kernel refused no forks"; fi
    case "$peak" in
        none) info "this kernel has no pids.peak; the refused-fork count above is the evidence" ;;
        *) if [ "$peak" -le 64 ]; then pass "the most processes the container ever held was $peak (limit 64)"; else fail "the container held $peak processes"; fi ;;
    esac
    equals "the container is still running after the fork bomb" "true" "$(docker inspect -f '{{.State.Running}}' "$SRV")"
    thr_before=$(docker exec "$SRV" sh -c "grep '^nr_throttled ' /sys/fs/cgroup/cpu.stat | cut -d' ' -f2" | tr -d '\r')
    docker exec "$SRV" sh -c 'timeout 3 sh -c "while :; do :; done" & timeout 3 sh -c "while :; do :; done" & wait' >/dev/null 2>&1
    thr_after=$(docker exec "$SRV" sh -c "grep '^nr_throttled ' /sys/fs/cgroup/cpu.stat | cut -d' ' -f2" | tr -d '\r')
    if [ "$thr_after" -gt "$thr_before" ]; then pass "two busy loops were throttled by the cpu limit ($thr_before to $thr_after periods)"; else fail "cpu was not throttled ($thr_before to $thr_after)"; fi
    equals "Docker records the limits it was given" "67108864 64 500000000" \
        "$(docker inspect -f '{{.HostConfig.Memory}} {{.HostConfig.PidsLimit}} {{.HostConfig.NanoCpus}}' "$SRV")"
    # Postgres has a read-only root too.
    equals "Postgres's root filesystem is read only" "true" "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$PG")"
    contains "root in Postgres cannot write /etc" "$(docker exec -u 0 "$PG" sh -c 'touch /etc/rofs-test 2>&1')" "Read-only file system"
    # Postgres and the init container have limits too.
    for c in "$PG" "$INIT"; do
        case "$(docker inspect -f '{{.HostConfig.Memory}}' "$c")" in 0) fail "$c has no memory limit" ;; *) pass "$c has a memory limit" ;; esac
        case "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$c")" in 0 | -1 | null | '<nil>') fail "$c has no pids limit" ;; *) pass "$c has a pids limit" ;; esac
    done

    say ""
    say "== Tenant $t: the way out"
    check_not "the cloud metadata address 169.254.169.254:80 is unreachable from the serving container" can_connect "$SRV" 169.254.169.254 80
    check_not "an HTTP request to the metadata service gets nothing" docker exec "$SRV" sh -c 'wget -T 3 -q -O- http://169.254.169.254/latest/meta-data/'
    check_not "169.254.169.254 is unreachable from Postgres, which has no route out at all" can_connect "$PG" 169.254.169.254 80
    if can_connect "$SRV" 1.1.1.1 53; then
        pass "control: the serving container, on the media network, can reach the internet"
        check_not "Postgres has no route to the internet (inside is an internal network)" can_connect "$PG" 1.1.1.1 53
    else
        info "no internet from the serving container here, so Postgres having none proves nothing"
    fi
done

say ""
info "169.254.169.254 is not reachable from this machine's Docker. On a cloud VM it is reachable from a container on the media network unless the host drops it; docs/privacy/tenancy.md has the rule, and this script is how to check it holds there."
summary
