#!/bin/sh
# First-boot only. The volume keeps these roles afterwards.
#
# One community has one database and two login roles:
#
#   owner    migrates the schema and writes the owner invite. CREATEDB and BYPASSRLS. Only
#            tinyserver-init holds its password.
#   runtime  what the serving process connects as. NOSUPERUSER and NOBYPASSRLS, so row level
#            security applies to it. No write access to tables that only a function may write.
#
# The names default to what a single community has always used, so nothing changes for it:
#
#   POSTGRES_DB                database, `tinyserver`
#   TINYSERVER_OWNER_ROLE      `app_owner`
#   TINYSERVER_RUNTIME_ROLE    `app_runtime`
#   TINYSERVER_OWNER_CREATEDB  `yes`; `no` leaves the owner without CREATEDB. Only the test
#                              suite creates databases as the owner. A tenant does not need it.
#   APP_OWNER_PASSWORD, APP_RUNTIME_PASSWORD   required
#
# A tenant (deploy/tenant/) sets all of them, so its database and roles have names no other
# tenant's have, and a credential for one is not a credential for another even if two
# communities ever shared a Postgres cluster.
#
# The migrations grant to and revoke from the role named `app_runtime`. When TINYSERVER_RUNTIME_ROLE
# is something else, this script also makes a NOLOGIN group `app_runtime` and puts the login role
# in it. Every privilege the runtime has, here and in the migrations, is granted to that group and
# never to the login role directly, so a migration's REVOKE ... FROM app_runtime takes it away from
# the login role too. The group has no password and no CONNECT; only a login role named here gets
# CONNECT, on this database. See docs/privacy/tenancy.md for what this does and does not isolate
# when tenants do share a cluster.
#
# Running it again is safe: roles that exist get the attributes and passwords set here, and the
# grants are the same. deploy/tenant/operator.sh runs it again after it empties a database for a
# restore.
set -eu

db="${POSTGRES_DB:-tinyserver}"
owner="${TINYSERVER_OWNER_ROLE:-app_owner}"
runtime="${TINYSERVER_RUNTIME_ROLE:-app_runtime}"
createdb="${TINYSERVER_OWNER_CREATEDB:-yes}"

# Names go into SQL as identifiers. They are checked here as well as quoted there.
for name in "$db" "$owner" "$runtime"; do
    case "$name" in
        '' | *[!a-z0-9_]* | [0-9]*)
            echo "01-roles.sh: '$name' must be lower case letters, digits and underscores, and not start with a digit" >&2
            exit 1
            ;;
    esac
    if [ "${#name}" -gt 63 ]; then
        echo "01-roles.sh: '$name' is longer than 63 characters" >&2
        exit 1
    fi
done
if [ "$owner" = "$runtime" ] || [ "$owner" = postgres ] || [ "$runtime" = postgres ]; then
    echo "01-roles.sh: the owner and runtime roles must differ from each other and from postgres" >&2
    exit 1
fi
case "$createdb" in
    yes) owner_attrs="CREATEDB BYPASSRLS" ;;
    no) owner_attrs="NOCREATEDB BYPASSRLS" ;;
    *)
        echo "01-roles.sh: TINYSERVER_OWNER_CREATEDB is yes or no" >&2
        exit 1
        ;;
esac
: "${APP_OWNER_PASSWORD:?set APP_OWNER_PASSWORD}"
: "${APP_RUNTIME_PASSWORD:?set APP_RUNTIME_PASSWORD}"

export TS_DB="$db" TS_OWNER="$owner" TS_RUNTIME="$runtime" TS_OWNER_ATTRS="$owner_attrs"

# Identifiers and passwords reach SQL through psql variables, quoted by psql (:"x" for an
# identifier, :'x' for a literal), so no character in a password can end the statement.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" <<'SQL'
\getenv db TS_DB
\getenv owner TS_OWNER
\getenv runtime TS_RUNTIME
\getenv owner_attrs TS_OWNER_ATTRS
\getenv owner_pw APP_OWNER_PASSWORD
\getenv runtime_pw APP_RUNTIME_PASSWORD

-- A role named `app_runtime` that is not the login role is a group the migrations' grants land on.
SELECT :'runtime' <> 'app_runtime' AS grouped \gset
\if :grouped
    SELECT 'CREATE ROLE app_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS'
    WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') \gexec
\endif

-- Made once, brought back to these attributes and passwords on every later run.
SELECT format('CREATE ROLE %I', :'owner')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'owner') \gexec
SELECT format('CREATE ROLE %I', :'runtime')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'runtime') \gexec
SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEROLE PASSWORD %L %s', :'owner', :'owner_pw', :'owner_attrs') \gexec
SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS PASSWORD %L', :'runtime', :'runtime_pw') \gexec
\if :grouped
    GRANT app_runtime TO :"runtime";
\endif

-- Nobody connects to this community's database unless named here. By default Postgres lets
-- every role connect to every database and use the public schema.
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO :"owner", :"runtime";
ALTER SCHEMA public OWNER TO :"owner";
GRANT CREATE ON SCHEMA public TO :"owner";

-- To the group, not the login role: see the top of this file.
GRANT USAGE ON SCHEMA public TO app_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO app_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner" IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO app_runtime;
SQL
