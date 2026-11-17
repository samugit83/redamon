#!/usr/bin/env bash
# =============================================================================
# Disposable Postgres for the tradecraft database tests
# =============================================================================
# One container, `redamon-tc-pgtest` (postgres:16-alpine, the stack's version), bound
# to 127.0.0.1 only. The webapp schema is pushed into a TEMPLATE database that no test
# opens; every test run uses a copy of it named by TC_PG_DB, so sessions running at
# the same time never share a database (a plain `CREATE DATABASE ... TEMPLATE` copy
# takes a second, a push takes much longer).
#
# The password is generated once and kept in a mode-600 state file outside the
# repository. Nothing this script prints itself carries it: the connection URL reaches
# a child process through its environment (never its command line), and only `url`
# prints it, for inline use: PLUGINS_PG_TEST_URL="$(tooling/scripts/tradecraft_pg_testdb.sh url)".
#
# Usage:
#   tradecraft_pg_testdb.sh up               start (or reuse) the container
#   tradecraft_pg_testdb.sh push             push webapp/prisma/schema.prisma into the
#                                            template, then `db`
#   tradecraft_pg_testdb.sh db               (re)create the TC_PG_DB copy of the template
#   tradecraft_pg_testdb.sh url              print the URL of TC_PG_DB
#   tradecraft_pg_testdb.sh web <files>...   vitest on TC_PG_DB (PLUGINS_PG_TEST_URL and
#                                            TRADECRAFT_PG_TEST_URL set)
#   tradecraft_pg_testdb.sh agent <targets>  pytest in redamon-agent:latest on TC_PG_DB
#   tradecraft_pg_testdb.sh reset            drop and push the template again, then `db`
#   tradecraft_pg_testdb.sh down             remove the container and the state file
#
# TC_PG_DB defaults to redamon_tc_test. `up`, `push` and `reset` are heavy (they rebuild the
# template every copy is made from): run one at a time. A copy (`db`, `web`, `agent`) is not.
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER="redamon-tc-pgtest"
IMAGE="postgres:16-alpine"
PORT=55432
PGUSER_NAME="tctest"
TEMPLATE_DB="redamon_tc_template"
STATE_FILE="${XDG_RUNTIME_DIR:-/tmp}/redamon-tc-pgtest.env"
WEBAPP_IMAGE="redamon-webapp:latest"
AGENT_IMAGE="redamon-agent:latest"
# The marker the existing pg tests require before they empty a database that holds users.
MARKER_TABLE="plugins_pg_integration_test_marker"
DB_NAME="${TC_PG_DB:-redamon_tc_test}"

log() { echo "[tc-pgtest] $*" >&2; }
die() { log "error: $*"; exit 1; }

check_db_name() {
    # The name is spliced into SQL; only plain lowercase identifiers are accepted.
    [[ "$1" =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || die "TC_PG_DB must match ^[a-z_][a-z0-9_]{0,62}\$ (got '$1')"
    case "$1" in
        "$TEMPLATE_DB"|postgres|template0|template1) die "TC_PG_DB may not be '$1'" ;;
    esac
}

password() {
    [[ -f "$STATE_FILE" ]] || die "not started: run '$0 up' first"
    sed -n 's/^TC_PG_PASSWORD=//p' "$STATE_FILE"
}

db_url() {  # database name
    printf 'postgresql://%s:%s@127.0.0.1:%s/%s' "$PGUSER_NAME" "$(password)" "$PORT" "$1"
}

container_state() {
    local running
    if running="$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)"; then
        echo "$running"
    else
        echo missing
    fi
}

# psql over the container's local socket (trust auth inside the official image), so no
# password is handled here.
psql_admin() {
    docker exec -i -e PGOPTIONS='-c client_min_messages=warning' "$CONTAINER" \
        psql -U "$PGUSER_NAME" -d postgres -qtAX -v ON_ERROR_STOP=1 "$@"
}

wait_ready() {
    local i
    for i in $(seq 1 60); do
        if docker exec "$CONTAINER" pg_isready -q -U "$PGUSER_NAME" -d postgres -h 127.0.0.1 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    die "Postgres did not become ready in 60 s"
}

cmd_up() {
    local state
    state="$(container_state)"
    if [[ "$state" != missing && ! -f "$STATE_FILE" ]]; then
        # The password lives only in the state file: without it the container is unusable.
        log "state file missing for an existing container: recreating it"
        docker rm -f -v "$CONTAINER" >/dev/null
        state=missing
    fi
    if [[ "$state" == missing ]]; then
        (umask 077 && printf 'TC_PG_PASSWORD=%s\n' "$(openssl rand -hex 16)" > "$STATE_FILE")
        chmod 600 "$STATE_FILE"
        # The password passes by name: a snap-packaged docker CLI sees neither /tmp nor
        # /run/user, so no temporary env file, and the value stays off the command line.
        if ! POSTGRES_PASSWORD="$(password)" docker run -d --name "$CONTAINER" \
                -e POSTGRES_USER="$PGUSER_NAME" -e POSTGRES_PASSWORD -e POSTGRES_DB=postgres \
                -p "127.0.0.1:${PORT}:5432" --label redamon.purpose=tradecraft-pg-tests \
                "$IMAGE" >/dev/null; then
            die "docker run failed"
        fi
        log "started $CONTAINER on 127.0.0.1:$PORT"
    elif [[ "$state" == false ]]; then
        docker start "$CONTAINER" >/dev/null
        log "restarted $CONTAINER"
    else
        log "$CONTAINER already running"
    fi
    wait_ready
    if [[ "$(psql_admin -c "SELECT 1 FROM pg_database WHERE datname = '$TEMPLATE_DB'")" != 1 ]]; then
        psql_admin -c "CREATE DATABASE $TEMPLATE_DB"
        log "created the template database (empty until 'push')"
    fi
}

require_up() {
    [[ "$(container_state)" == true ]] || die "not running: run '$0 up' first"
    [[ -f "$STATE_FILE" ]] || die "state file missing: run '$0 up' first"
}

# Runs a shell command inside the webapp image with the repository's prisma/ and scripts/
# mounted over the image's own, so the schema pushed is the working tree's.
in_webapp_image() {  # command
    DATABASE_URL="$(db_url "$TEMPLATE_DB")" docker run --rm --network host \
        -e DATABASE_URL -e HOME=/tmp \
        -v "$REPO/webapp/prisma:/app/prisma:ro" \
        -v "$REPO/webapp/scripts:/app/scripts:ro" \
        --entrypoint sh "$WEBAPP_IMAGE" -c "$1"
}

cmd_push() {
    require_up
    docker image inspect "$WEBAPP_IMAGE" >/dev/null 2>&1 || die "$WEBAPP_IMAGE is not built"
    log "pushing webapp/prisma/schema.prisma into the template"
    in_webapp_image 'npx prisma db push --skip-generate --accept-data-loss --schema ./prisma/schema.prisma' >&2
    if [[ -f "$REPO/webapp/scripts/apply-tradecraft-search.mjs" ]]; then
        log "applying scripts/apply-tradecraft-search.mjs"
        in_webapp_image 'node scripts/apply-tradecraft-search.mjs' >&2
    fi
    # The plugin pg tests need these constraints; never fatal, as in the image entrypoint.
    in_webapp_image 'node scripts/apply-plugin-constraints.mjs' >&2 || log "plugin constraints not applied (continuing)"
    docker exec -i "$CONTAINER" psql -U "$PGUSER_NAME" -d "$TEMPLATE_DB" -qtAX -v ON_ERROR_STOP=1 \
        -c "CREATE TABLE IF NOT EXISTS $MARKER_TABLE (created_at timestamptz DEFAULT now())"
    log "template ready"
    cmd_db
}

cmd_db() {
    require_up
    check_db_name "$DB_NAME"
    psql_admin -c "DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE)"
    # Two sessions copying the template at the same moment can collide on its lock; retry.
    local i err=""
    for i in 1 2 3 4 5; do
        if err="$(psql_admin -c "CREATE DATABASE $DB_NAME TEMPLATE $TEMPLATE_DB" 2>&1)"; then
            log "database $DB_NAME ready (copy of the template)"
            return 0
        fi
        sleep "$i"
    done
    die "could not copy the template into $DB_NAME: $err"
}

cmd_url() {
    require_up
    check_db_name "$DB_NAME"
    db_url "$DB_NAME"
    echo
}

cmd_web() {
    require_up
    check_db_name "$DB_NAME"
    [[ $# -gt 0 ]] || die "usage: $0 web <vitest file>..."
    local url
    url="$(db_url "$DB_NAME")"
    cd "$REPO/webapp"
    PLUGINS_PG_TEST_URL="$url" TRADECRAFT_PG_TEST_URL="$url" npx vitest run --no-file-parallelism "$@"
}

cmd_agent() {
    require_up
    check_db_name "$DB_NAME"
    [[ $# -gt 0 ]] || die "usage: $0 agent <pytest target>..."
    docker image inspect "$AGENT_IMAGE" >/dev/null 2>&1 || die "$AGENT_IMAGE is not built"
    local url
    url="$(db_url "$DB_NAME")"
    # Same mount, workdir and PYTHONPATH as agentic/run_tests.sh; the URL passes by name.
    TRADECRAFT_PG_TEST_URL="$url" PLUGINS_PG_TEST_URL="$url" docker run --rm --network host \
        -v "$REPO:/repo" -w /repo/agentic \
        -e PYTHONPATH=/repo/agentic:/repo:/repo/mcp/servers:/repo/recon_orchestrator:/repo/services \
        -e HOME=/tmp -e TRADECRAFT_PG_TEST_URL -e PLUGINS_PG_TEST_URL \
        --entrypoint sh "$AGENT_IMAGE" -c \
        'python -c "import pytest" 2>/dev/null || pip install -q -r /repo/requirements-test.txt >/dev/null 2>&1;
         git config --global --add safe.directory "*" 2>/dev/null || true;
         exec python -m pytest "$@"' sh "$@"
}

cmd_reset() {
    require_up
    psql_admin -c "DROP DATABASE IF EXISTS $TEMPLATE_DB WITH (FORCE)"
    psql_admin -c "CREATE DATABASE $TEMPLATE_DB"
    cmd_push
}

cmd_down() {
    if [[ "$(container_state)" != missing ]]; then
        docker rm -f -v "$CONTAINER" >/dev/null
        log "removed $CONTAINER"
    fi
    rm -f "$STATE_FILE"
}

main() {
    local sub="${1:-}"
    [[ $# -gt 0 ]] && shift
    case "$sub" in
        up)    cmd_up ;;
        push)  cmd_push ;;
        db)    cmd_db ;;
        url)   cmd_url ;;
        web)   cmd_web "$@" ;;
        agent) cmd_agent "$@" ;;
        reset) cmd_reset ;;
        down)  cmd_down ;;
        *)     sed -n '2,30p' "$0" >&2; exit 2 ;;
    esac
}

main "$@"
