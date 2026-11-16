#!/usr/bin/env bash
# =============================================================================
# Webapp start-up with a 1 GB Tradecraft page store (T2.8 of the Tradecraft 2.0 plan)
# =============================================================================
# Every webapp start runs `db push` and then scripts/apply-tradecraft-search.mjs
# (webapp/Dockerfile's entrypoint list). The page store's search objects (the tsvector
# columns, their GIN indexes, the trigram index, the triggers) must survive both without
# being rebuilt, or a start would take minutes once a library is large (master plan TD-6,
# D-17). This script measures it on the disposable Postgres of tradecraft_pg_testdb.sh:
#
#   1. two copies of the template: one empty, one filled with synthetic stored pages
#      (entries with their stored text, one section each, vectors filled by the triggers)
#      up to TC_PERF_TARGET_MB (1024) of table, index and TOAST size;
#   2. on each, twice: the entrypoint's `node scripts/db-push-locked.mjs db push ...`, then
#      `node scripts/apply-tradecraft-search.mjs`, timed, in the webapp image with the
#      working tree's prisma/ and scripts/ mounted (as tradecraft_pg_testdb.sh push does);
#   3. whether any tradecraft index was rebuilt: its relfilenode before and after.
#
# Prints a Markdown report on stdout. Heavy: run it through the plan's lock. Synthetic
# text only; the databases it makes are dropped at the end (TC_PERF_KEEP=1 keeps them).
#
# Usage: tooling/scripts/tradecraft_store_perf.sh > report.md
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="$REPO/tooling/scripts/tradecraft_pg_testdb.sh"
CONTAINER="redamon-tc-pgtest"
WEBAPP_IMAGE="redamon-webapp:latest"
EMPTY_DB="${TC_PERF_EMPTY_DB:-tc_perf_empty}"
FULL_DB="${TC_PERF_FULL_DB:-tc_perf_full}"
TARGET_MB="${TC_PERF_TARGET_MB:-1024}"
BATCH="${TC_PERF_BATCH:-5000}"

log() { echo "[tc-perf] $*" >&2; }

psql_db() {  # database, then psql arguments
    local db="$1"; shift
    docker exec -i -e PGOPTIONS='-c client_min_messages=warning' "$CONTAINER" \
        psql -U tctest -d "$db" -qtAX -v ON_ERROR_STOP=1 "$@"
}

in_webapp_image() {  # database, command; the URL reaches the container by name, never on a command line
    DATABASE_URL="$(TC_PG_DB="$1" "$HARNESS" url)" docker run --rm --network host \
        -e DATABASE_URL -e HOME=/tmp \
        -v "$REPO/webapp/prisma:/app/prisma:ro" \
        -v "$REPO/webapp/scripts:/app/scripts:ro" \
        --entrypoint sh "$WEBAPP_IMAGE" -c "$2"
}

timed() {  # database, command -> seconds on stdout
    local start end
    start=$(date +%s.%N)
    in_webapp_image "$1" "$2" >&2
    end=$(date +%s.%N)
    awk -v s="$start" -v e="$end" 'BEGIN { printf "%.1f", e - s }'
}

store_mb() {
    psql_db "$1" -c "SELECT round(sum(pg_total_relation_size(c.oid)) / 1048576.0) FROM pg_class c
        WHERE c.relkind = 'r' AND c.relname IN ('tradecraft_entries', 'tradecraft_sections', 'tradecraft_page_ids')"
}

index_files() {
    psql_db "$1" -c "SELECT c.relname || '=' || c.relfilenode FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
        JOIN pg_class t ON t.oid = i.indrelid WHERE t.relname LIKE 'tradecraft\_%' ORDER BY 1"
}

# One batch of synthetic stored pages: an entry of about 11 KB of text and one section with the
# same text, both indexed by the triggers. Words come from a fixed list, each with a number, so
# the text neither compresses away in TOAST nor collapses into a few lexemes.
fill_batch() {  # database, first page number, last page number
    psql_db "$1" <<SQL
WITH w AS (SELECT string_to_array('payload injection bypass filter header token kerberos ticket delegation relay
 certificate template escalation privilege kernel container escape socket metadata credential request response
 encoding traversal include wrapper upload template expression gadget chain serialize deserialize session cookie
 redirect smuggling desync cache poisoning union select error boolean blind delay sleep stacked query table column
 schema database server client browser script event handler attribute context polyglot sandbox policy nonce hash
 crack wordlist spray brute force default password account service principal name replication domain controller
 forest trust group policy object registry hive dump memory process thread module library function parameter
 argument option flag value path folder file archive extract compress decode encode base64 hex unicode overlong
 lab target tester exploit proof concept writeup walkthrough methodology technique step command tool usage', ' ') AS words),
pages AS (
  INSERT INTO tradecraft_page_ids (resource_id, url)
  SELECT 'tc-perf-res', 'https://perf.tc-fixture.test/p/' || g FROM generate_series($2, $3) g
  RETURNING id, url),
txt AS (
  SELECT p.id, p.url, (SELECT string_agg(w.words[1 + ((p.id * 7 + j * 13) % array_length(w.words, 1))]
                                         || ((p.id * 31 + j * 17) % 9973)::text, ' ')
                       FROM w, generate_series(1, 1000) j) AS t FROM pages p),
ins AS (
  INSERT INTO tradecraft_entries (user_id, resource_id, generation, page_id, url, title, title_source, breadcrumb,
                                  headings, description, topics, kinds, stored_text, stored_bytes, size_chars,
                                  fetched_at)
  SELECT 'tc-perf-user', 'tc-perf-res', 1, x.id, x.url, 'Synthetic page ' || x.id, 'real', ARRAY['perf'],
         '[{"level": 2, "text": "Section"}]'::jsonb, 'A synthetic stored page.', ARRAY['sql_injection'],
         ARRAY['payloads'], x.t, octet_length(x.t), length(x.t), now()
  FROM txt x RETURNING id, stored_text)
INSERT INTO tradecraft_sections (entry_id, resource_id, user_id, generation, ord, heading, level, anchor, text, chars)
SELECT id, 'tc-perf-res', 'tc-perf-user', 1, 0, 'Section', 2, 'section', stored_text, length(stored_text) FROM ins;
SQL
}

fill() {  # database
    psql_db "$1" -c "INSERT INTO users (id, name, email, updated_at) VALUES
        ('tc-perf-user', 'Perf', 'tc-perf@example.test', now())"
    psql_db "$1" -c "INSERT INTO user_tradecraft_resources (id, user_id, name, slug, url, storage_mode, map_version,
        resource_type, generation, updated_at) VALUES ('tc-perf-res', 'tc-perf-user', 'Perf', 'perf',
        'https://perf.tc-fixture.test/', 'stored', 3, 'mkdocs-wiki', 1, now())"
    local first=1 mb=0
    while (( mb < TARGET_MB )); do
        fill_batch "$1" "$first" "$((first + BATCH - 1))"
        first=$((first + BATCH))
        mb="$(store_mb "$1")"
        log "filled $((first - 1)) pages, ${mb} MB"
    done
    psql_db "$1" -c "VACUUM ANALYZE tradecraft_entries" -c "VACUUM ANALYZE tradecraft_sections"
}

PUSH='node scripts/db-push-locked.mjs db push --skip-generate --accept-data-loss --schema ./prisma/schema.prisma'
APPLY='node scripts/apply-tradecraft-search.mjs'

measure() {  # database -> "push1 apply1 push2 apply2 rebuilt"
    local before after p1 a1 p2 a2
    before="$(index_files "$1")"
    p1="$(timed "$1" "$PUSH")"; a1="$(timed "$1" "$APPLY")"
    p2="$(timed "$1" "$PUSH")"; a2="$(timed "$1" "$APPLY")"
    after="$(index_files "$1")"
    local rebuilt
    rebuilt="$(comm -3 <(echo "$before" | LC_ALL=C sort) <(echo "$after" | LC_ALL=C sort) | sed 's/^[[:space:]]*//; s/=.*//' \
        | LC_ALL=C sort -u | tr '\n' ' ')"
    echo "$p1 $a1 $p2 $a2 ${rebuilt:-none}"
}

main() {
    docker image inspect "$WEBAPP_IMAGE" >/dev/null 2>&1 || { log "$WEBAPP_IMAGE is not built"; exit 1; }
    for db in "$EMPTY_DB" "$FULL_DB"; do TC_PG_DB="$db" "$HARNESS" db; done
    local fill_start fill_s
    fill_start=$(date +%s)
    fill "$FULL_DB"
    fill_s=$(( $(date +%s) - fill_start ))
    local pages full_mb sections_with_vector
    pages="$(psql_db "$FULL_DB" -c "SELECT count(*) FROM tradecraft_entries")"
    sections_with_vector="$(psql_db "$FULL_DB" -c "SELECT count(*) FROM tradecraft_sections WHERE search_vector IS NOT NULL")"
    full_mb="$(store_mb "$FULL_DB")"
    log "measuring the empty store"
    read -r ep1 ea1 ep2 ea2 erebuilt <<<"$(measure "$EMPTY_DB")"
    log "measuring the full store"
    read -r fp1 fa1 fp2 fa2 frebuilt <<<"$(measure "$FULL_DB")"
    local verdict
    verdict="$(awk -v e="$ep2" -v ea="$ea2" -v f="$fp2" -v fa="$fa2" \
        'BEGIN { d = (f + fa) - (e + ea); printf "%+.1f s (%s)", d, (d < 10 ? "under 10 s: TD-6 holds" : "10 s or more: TD-6 must change") }')"
    cat <<EOF
# Webapp start-up with a 1 GB Tradecraft page store

Measured with \`tooling/scripts/tradecraft_store_perf.sh\` on the disposable Postgres
(\`redamon-tc-pgtest\`, postgres:16-alpine) and the webapp image \`$WEBAPP_IMAGE\` with the working
tree's \`prisma/\` and \`scripts/\`.

- Full store: $pages synthetic stored pages (an entry of about 11 KB of text and one section each,
  $sections_with_vector sections with a search vector), ${full_mb} MB of tables, indexes and TOAST
  (\`tradecraft_entries\`, \`tradecraft_sections\`, \`tradecraft_page_ids\`); filled in ${fill_s} s.
- Each step is a fresh container: the times include Node's and Prisma's start.

| Step | Empty store | 1 GB store |
|---|---|---|
| \`db push\` (first) | ${ep1} s | ${fp1} s |
| \`apply-tradecraft-search.mjs\` (first) | ${ea1} s | ${fa1} s |
| \`db push\` (second) | ${ep2} s | ${fp2} s |
| \`apply-tradecraft-search.mjs\` (second) | ${ea2} s | ${fa2} s |
| Indexes rebuilt (relfilenode changed) | ${erebuilt} | ${frebuilt} |

Second push plus script, 1 GB store minus empty store: $verdict.
EOF
    if [[ "${TC_PERF_KEEP:-}" != 1 ]]; then
        for db in "$EMPTY_DB" "$FULL_DB"; do
            docker exec -i "$CONTAINER" psql -U tctest -d postgres -qtAX -c "DROP DATABASE IF EXISTS $db WITH (FORCE)"
        done
    fi
}

main "$@"
