#!/bin/sh
# The release captain's check for tinyserver. Read AGENTS.md ("Release captain") first.
#
# Prints the cut (every commit on origin/main since the SHA last deployed to the community), the
# migration files in that range, and every reason it may not deploy today, then exits: 0 when it
# may deploy, 1 when something blocks it, 2 when the cut cannot be worked out. It changes nothing
# unless --apply is passed, and an agent passes --apply only when Justin explicitly said to deploy
# the server.
#
#   deploy/release-cut.sh                  dry run
#   deploy/release-cut.sh --deployed SHA   dry run against a SHA read from the host instead
#   deploy/release-cut.sh --apply          back up, swap the tree, build and start
#
# --through-freeze only when Justin said "ship through the freeze".
#
# The deployed SHA is recorded in $(git rev-parse --git-common-dir)/tinyserver-community-deployed,
# shared by every worktree of this clone and never committed. --apply rewrites it after a deploy.
# The host and its directory are the "Community host" and "Community dir" lines in AGENTS.md.
# "Today" is this machine's local date. The freeze file is deploy/release-freeze.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
freeze=$here/release-freeze
repo=TinyComms/tinyserver

die() { echo "release-cut: $*" >&2; exit 2; }

apply= through= deployed=
while [ $# -gt 0 ]; do
    case "$1" in
        --apply) apply=1 ;;
        --through-freeze) through=1 ;;
        --deployed) [ $# -ge 2 ] || die "--deployed needs a SHA"; deployed=$2; shift ;;
        -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done

git() { command git -C "$root" "$@"; }

record=$(git rev-parse --path-format=absolute --git-common-dir)/tinyserver-community-deployed
today=$(date +%F)
git fetch -q origin main || die "cannot fetch origin"
head=$(git rev-parse origin/main)

source="--deployed"
if [ -z "$deployed" ]; then
    [ -f "$record" ] || die "no recorded deploy at $record. Read the deployed SHA from the host and pass --deployed SHA."
    deployed=$(awk 'NR == 1 { print $1 }' "$record")
    source="$record: $(head -1 "$record" | cut -d' ' -f2-)"
fi
deployed=$(git rev-parse -q --verify "$deployed^{commit}") || die "the deployed SHA is not a commit in this clone"

# Read from AGENTS.md so the alias lives in one place. Blank means: stop and ask Justin once.
host= dir=
if [ -f "$root/AGENTS.md" ]; then
    host=$(sed -n 's/^Community host: `\([^`]*\)`.*/\1/p' "$root/AGENTS.md" | head -1)
    dir=$(sed -n 's/^Community dir: `\([^`]*\)`.*/\1/p' "$root/AGENTS.md" | head -1)
fi
build=$(sed -n 's/^Build host: `\([^`]*\)`.*/\1/p' "$root/AGENTS.md" | head -1)
build=${build:-atomicstudio}

echo "tinyserver deploy cut ($( [ -n "$apply" ] && echo apply || echo dry run ))"
echo "today (local)  $today"
echo "origin/main    $(git log -1 --format='%h %s' "$head")"
echo "deployed       $(git log -1 --format='%h %ad %s' --date=format-local:%F "$deployed")"
echo "               from $source"
echo "host           ${host:-(not recorded: stop and ask Justin once, then record it in AGENTS.md)}${dir:+ $dir}"
echo

blocked=0
ok() { echo "  ok     $*"; }
block() { echo "  BLOCK  $*"; blocked=$((blocked + 1)); }
over() { echo "  over   $*"; }

if git merge-base --is-ancestor "$deployed" "$head"; then
    count=$(git rev-list --count "$deployed..$head")
    echo "merged, not deployed ($count):"
    if [ "$count" -eq 0 ]; then
        echo "  (none)"
    else
        git log --format='  %h %ad %s' --date=format-local:%F "$deployed..$head"
    fi
    echo
    echo "migrations in that range:"
    migrations=$(git diff --name-status "$deployed" "$head" -- crates/db/migrations)
    if [ -z "$migrations" ]; then
        echo "  (none)"
    else
        printf '%s\n' "$migrations" | sed 's/^/  /'
    fi
else
    count=0
    echo "merged, not deployed: unknown"
fi
echo

echo "checks:"
if git merge-base --is-ancestor "$deployed" "$head"; then
    ok "record: the deployed SHA is on origin/main"
else
    block "record: the deployed SHA is not on origin/main; the record or the host is wrong"
fi

# Freeze: one inclusive range per line, YYYY-MM-DD YYYY-MM-DD. A line that does not parse blocks.
if [ ! -f "$freeze" ]; then
    block "freeze: $freeze is missing"
else
    hit= bad= n=0
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        line=$(printf '%s' "$line" | sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//' | tr -d '\r')
        [ -n "$line" ] || continue
        if ! printf '%s\n' "$line" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
            bad="$bad line $n"; continue
        fi
        from=${line%%[[:space:]]*} to=${line##*[[:space:]]}
        f=$(echo "$from" | tr -d -) t=$(echo "$to" | tr -d -) d=$(echo "$today" | tr -d -)
        if [ "$f" -gt "$t" ]; then bad="$bad line $n"; continue; fi
        if [ "$d" -ge "$f" ] && [ "$d" -le "$t" ]; then hit="$from to $to (line $n)"; fi
    done < "$freeze"
    if [ -n "$bad" ]; then
        block "freeze: release-freeze does not parse at$bad"
    elif [ -z "$hit" ]; then
        ok "freeze: $today is not frozen"
    elif [ -n "$through" ]; then
        over "freeze: $today is inside $hit; Justin said \"ship through the freeze\""
    else
        block "freeze: $today is inside $hit"
    fi
fi

if [ "$count" -gt 0 ]; then
    ok "cut: $count commit(s) to deploy"
else
    block "cut: nothing merged since the deployed SHA"
fi

ci=$(gh run list -R "$repo" --workflow ci.yml --commit "$head" -L 1 --json status,conclusion,url \
    --jq '.[0] | "\(.status) \(.conclusion) \(.url)"' 2>/dev/null) || ci=
case "$ci" in
    "completed success "*) ok "CI: green on $(git rev-parse --short "$head")" ;;
    "") block "CI: no ci run found for $(git rev-parse --short "$head")" ;;
    *) block "CI: $(git rev-parse --short "$head") is $ci" ;;
esac

if [ -z "$host" ] || [ -z "$dir" ]; then
    block "host: Community host or Community dir is blank in AGENTS.md; stop and ask Justin once"
elif ! printf '%s\n' "$dir" | grep -Eq '^/[A-Za-z0-9._/-]+$'; then
    block "host: Community dir is not a plain absolute path"
else
    ok "host: $host $dir"
fi

echo
if [ "$blocked" -gt 0 ]; then
    echo "verdict: BLOCKED ($blocked). Nothing was changed."
    exit 1
fi
if [ -z "$apply" ]; then
    echo "verdict: READY to deploy $(git rev-parse --short "$head"). Dry run: nothing was changed."
    exit 0
fi

# Apply: the deploy in use since 2026-11-02. The community host cannot build, so the build host
# builds the image from an LF archive of origin/main (CRLF breaks entrypoint.sh) and streams it
# into docker load on the community host. Then the same archive goes to the community host as the
# new tree, with the host's own compose.vps.yml copied in, pg_dump into backups, the live tree
# swapped for the new one, and up from the deploy directory with the image already loaded.
echo "verdict: READY. Deploying $(git rev-parse --short "$head") to $host (built on $build)."
short=$(git rev-parse --short=7 "$head")
ts=$(date +%Y%m%d-%H%M%S)
# The community host is behind the 1Password agent, which only Windows' own ssh can reach.
cssh=${SSH:-ssh}
[ -n "${SSH:-}" ] || [ ! -x /c/Windows/System32/OpenSSH/ssh.exe ] || cssh=/c/Windows/System32/OpenSSH/ssh.exe
archive() { command git -C "$root" -c core.autocrlf=false archive --format=tar "$head"; }
echo "building tinyserver:$short on $build and loading it on $host"
archive | ssh "$build" "set -eu
rm -rf /tmp/tinyserver-$short && mkdir -p /tmp/tinyserver-$short && tar -xf - -C /tmp/tinyserver-$short
cd /tmp/tinyserver-$short && docker build -q -t tinyserver:$short -f Dockerfile . >&2
docker save tinyserver:$short | gzip -1" | $cssh "$host" "gunzip | docker load" ||
    die "building or loading tinyserver:$short failed; nothing on $host was changed"
compose="docker compose -p tinyserver --env-file ../../.env -f compose.yml -f compose.vps.yml"
remote="set -eu
cd '$dir'
rm -rf src-new
mkdir src-new
tar -xf - -C src-new
cp src/deploy/compose.vps.yml src-new/deploy/compose.vps.yml
mkdir -p backups
(cd src/deploy && $compose exec -T postgres pg_dump -U postgres tinyserver) > backups/before-$short-$ts.sql
test -s backups/before-$short-$ts.sql
mv src src-pre-$short-$ts
mv src-new src
docker tag tinyserver:$short tinyserver:local
cd src/deploy
$compose up -d --no-build --remove-orphans
$compose ps
$compose logs --tail 60 tinyserver"
archive | $cssh "$host" "$remote" ||
    die "the deploy failed on $host; nothing was recorded. The old tree, if swapped, is $dir/src-pre-$short-$ts"
echo "$head $today $host" > "$record"
echo
echo "Deployed $short to $host and recorded it in $record."
echo "Next: check GET /health on the chat hostname and that the migrations above ran."
