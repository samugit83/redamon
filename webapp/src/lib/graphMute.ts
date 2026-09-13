/**
 * The mute exclusion, for Cypher that does not pass a scoping chokepoint.
 *
 * A finding an operator suppressed as noise keeps its own label and gains
 * `:Muted`. Agent queries get this exclusion injected automatically
 * (`graph_db/tenant_filter.py`), and the graph screen gets it from
 * `liveRead.ts` -- but every analytics, RedZone and report query hand-writes its
 * own Cypher, so each one is a separate enforcement site.
 *
 *   MATCH (v:Vulnerability {project_id: $pid})
 *   WHERE ${notMuted('v')}
 *
 * Deliberately a standalone module with no Neo4j dependency, rather than living
 * beside `getGraphSession`: route tests mock the driver module wholesale, and a
 * helper exported from there would come back undefined in every one of them.
 *
 * `NONE(l IN labels(x) ...)` is used rather than `NOT x:Muted` because it reads
 * identically on an untyped variable, which several of these queries bind
 * (`OPTIONAL MATCH (a)-[:HAS_FINDING]->(tf)`).
 */

/** Added to a finding an operator suppressed; never a node's own type. */
export const MUTED_LABEL = 'Muted'

/**
 * A WHERE fragment excluding findings that should not be counted or shown.
 *
 * Two things, because they mean the same thing to a reader: a finding an
 * operator suppressed, and one a scanner has stopped reporting.
 *
 * The second is new with ingest-then-prune (X7). A muted or human-judged
 * finding is no longer DELETED when its scanner stops finding it - deleting it
 * took the operator's own verdict with it - so it is kept and stamped
 * `stale_since` instead. Without this clause every one of the ~97 read sites
 * would start counting resolved findings as live, which is the exact opposite
 * of what a prune is for.
 */
export function notMuted(variable: string): string {
  return (
    `NONE(l IN labels(${variable}) WHERE l = '${MUTED_LABEL}') ` +
    `AND ${variable}.stale_since IS NULL`
  )
}

/** `notMuted` for several variables at once, ANDed together. */
export function noneMuted(...variables: string[]): string {
  return variables.map(notMuted).join(' AND ')
}
