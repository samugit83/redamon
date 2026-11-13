/**
 * Three precomputed views an agent asks for constantly and that natural
 * language answers badly and expensively: describe the surface, what is
 * exploitable, and which vulnerable technology reaches the most of it.
 *
 * Each is ONE purpose-built query sent through `/graph/exec op:cypher`, which
 * is how it inherits `scope_query`, the row and byte caps, the MCP concurrency
 * ceiling, the explicit timeout and the outbound tenant post-validation, for
 * free and with no change to the agent. The analytics routes behind the UI are
 * deliberately not reused: they authorise with the browser session's guard,
 * scope on `project_id` alone rather than the full tenant key, run
 * outside every MCP bound, and each issues 7 to 11 separate queries - which
 * over this surface would be 7 to 11 round trips per call against a concurrency
 * ceiling of two.
 *
 * FOUR THINGS ABOUT THE CYPHER BELOW ARE LOAD-BEARING. Each was measured
 * against `graph_db/tenant_filter.py`, and the routes' own queries get three of
 * them wrong:
 *
 *  1. NO inline tenant property, and no `$pid`. The exec request binds exactly
 *     `tenant_user_id` and `tenant_project_id` and has no params field at all,
 *     so a carried-over `{project_id: $pid}` dies on ParameterMissing - and
 *     injection would first turn it into a DUPLICATED KEY in one map literal.
 *     Scoping is the injector's job.
 *  2. GLOBAL-REFERENCE LABELS ARE SPELLED OUT ON EVERY RE-REFERENCE. A pattern
 *     is exempt from tenant injection only when ALL its labels are global
 *     (CVE, MitreData, Capec). A bare re-reference such as
 *     `OPTIONAL MATCH (c)-[:HAS_CWE]->(m:MitreData)` gets tenant props injected
 *     into `(c)`, and CVE nodes carry no tenant props by design, so it matches
 *     NOTHING. That is not hypothetical: it is why the Red Zone kill-chain view
 *     reports `cisaKev` false for every row and the blast-radius view sorts by
 *     a `kevCount` that is permanently 0. HTTP 200, no error, ranking gone.
 *  3. THE STALE HALF IS WRITTEN BY HAND. `scope_query` injects `!Muted` into
 *     every pattern but never `stale_since IS NULL`, so without the explicit
 *     predicate these tools would count findings a later scan stopped
 *     reporting and disagree with `graph_summary`.
 *  4. NOTHING HERE MAY NAME THE `Muted` LABEL. `scope_query` refuses any query
 *     that so much as mentions it. That is why `notMuted()` from
 *     `@/lib/graphMute` - the helper every browser-side finding query uses - is
 *     deliberately NOT used here: its text contains 'Muted', so it would turn
 *     every one of these into a hard refusal. The exclusion still happens, just
 *     server-side and after this text is written.
 *
 * These views project SCALARS, and the outbound tenant post-validation
 * explicitly cannot check a scalar. So `scope_query` is the sole isolation
 * boundary for them, with nothing behind it: keep each query small enough to
 * read in one sitting.
 */
import { requireScope } from '@/lib/mcpAuth'
import { assertMcpProjectAccess } from '@/lib/mcpAuth'
import { execCypher } from '@/lib/mcp/graphClient'
import { McpToolError } from '@/lib/mcp/errors'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

/** Well under the 1000-row cap: these are top-N views, not exports. */
const TOP_N = 50

interface CensusEntry {
  key: string
  /** The node counted, `variable:Label`. */
  pattern: string
  where?: string
  /** A relationship pattern that reaches `pattern`'s node, counted DISTINCT. */
  match?: string
}

/**
 * The overview census.
 *
 * `OPTIONAL MATCH` rather than `MATCH`: a plain MATCH that finds nothing yields
 * zero rows, which would take the whole chained aggregation to zero rows and
 * return no answer at all for a project whose first label happens to be empty.
 * Every pattern carries a label, because a census is the one shape
 * `has_labelled_node_pattern` hard-rejects.
 */
const CENSUS: CensusEntry[] = [
  { key: 'subdomains', pattern: 'a0:Subdomain' },
  { key: 'ips', pattern: 'a1:IP' },
  { key: 'openPorts', pattern: 'a2:Port' },
  { key: 'services', pattern: 'a3:Service' },
  { key: 'baseUrls', pattern: 'a4:BaseURL' },
  // An endpoint known only from an API specification is documented, not
  // observed, so it is counted apart. The predicate is DECLARED_ONLY written
  // out: tests/test_mcp_cypher_scoping.py reads these entries as string
  // literals, and analyticsTools.test.ts pins them to the helper.
  {
    key: 'endpoints', pattern: 'a5:Endpoint',
    where: 'NOT coalesce(a5.openapi_declared_only, a5.openapi_declared, false)',
  },
  {
    key: 'declaredEndpoints', pattern: 'a5d:Endpoint',
    where: 'coalesce(a5d.openapi_declared_only, a5d.openapi_declared, false)',
  },
  {
    key: 'parameters', pattern: 'a6:Parameter',
    match: '(a6e:Endpoint)-[:HAS_PARAMETER]->(a6:Parameter)',
    where: 'NOT coalesce(a6e.openapi_declared_only, a6e.openapi_declared, false)',
  },
  {
    key: 'declaredParameters', pattern: 'a6p:Parameter',
    match: '(a6f:Endpoint)-[:HAS_PARAMETER]->(a6p:Parameter)',
    where: 'coalesce(a6f.openapi_declared_only, a6f.openapi_declared, false)',
  },
  { key: 'technologies', pattern: 'a7:Technology' },
  { key: 'certificates', pattern: 'a8:Certificate' },
  { key: 'dnsRecords', pattern: 'a9:DNSRecord' },
  // Findings are counted as the client report counts them: a person's False
  // positive and a rule-resolved finding are left out and counted apart in
  // the last three entries; an AI-only false positive stays (its reviewer reads
  // target-controlled text). The predicate is reportCountable /
  // reportBucketCypher written out, pinned to them by analyticsTools.test.ts.
  {
    key: 'criticalVulnerabilities',
    pattern: 'b0:Vulnerability',
    where: "b0.stale_since IS NULL AND toLower(coalesce(b0.severity, '')) = 'critical' AND " +
      "NOT (coalesce(b0.triage_status, '') = 'likely_noise' AND coalesce(b0.triage_source, '') = 'human') " +
      "AND NOT coalesce(b0.triage_state, 'open') IN ['fixed', 'gone', 'inactive']",
  },
  {
    key: 'highVulnerabilities',
    pattern: 'b1:Vulnerability',
    where: "b1.stale_since IS NULL AND toLower(coalesce(b1.severity, '')) = 'high' AND " +
      "NOT (coalesce(b1.triage_status, '') = 'likely_noise' AND coalesce(b1.triage_source, '') = 'human') " +
      "AND NOT coalesce(b1.triage_state, 'open') IN ['fixed', 'gone', 'inactive']",
  },
  {
    key: 'mediumVulnerabilities',
    pattern: 'b2:Vulnerability',
    where: "b2.stale_since IS NULL AND toLower(coalesce(b2.severity, '')) = 'medium' AND " +
      "NOT (coalesce(b2.triage_status, '') = 'likely_noise' AND coalesce(b2.triage_source, '') = 'human') " +
      "AND NOT coalesce(b2.triage_state, 'open') IN ['fixed', 'gone', 'inactive']",
  },
  {
    key: 'otherVulnerabilities',
    pattern: 'b3:Vulnerability',
    where: "b3.stale_since IS NULL AND NOT toLower(coalesce(b3.severity, '')) IN " +
      "['critical', 'high', 'medium'] AND " +
      "NOT (coalesce(b3.triage_status, '') = 'likely_noise' AND coalesce(b3.triage_source, '') = 'human') " +
      "AND NOT coalesce(b3.triage_state, 'open') IN ['fixed', 'gone', 'inactive']",
  },
  {
    key: 'exposedSecrets',
    pattern: 'b4:Secret',
    where: "b4.stale_since IS NULL AND " +
      "NOT (coalesce(b4.triage_status, '') = 'likely_noise' AND coalesce(b4.triage_source, '') = 'human') " +
      "AND NOT coalesce(b4.triage_state, 'open') IN ['fixed', 'gone', 'inactive']",
  },
  {
    key: 'jsFindings',
    pattern: 'b5:JsReconFinding',
    where: "b5.stale_since IS NULL AND " +
      "NOT (coalesce(b5.triage_status, '') = 'likely_noise' AND coalesce(b5.triage_source, '') = 'human') " +
      "AND NOT coalesce(b5.triage_state, 'open') IN ['fixed', 'gone', 'inactive']",
  },
  {
    key: 'maliciousPackages',
    pattern: 'b6:MalPackageFinding',
    where: "b6.stale_since IS NULL AND " +
      "NOT (coalesce(b6.triage_status, '') = 'likely_noise' AND coalesce(b6.triage_source, '') = 'human') " +
      "AND NOT coalesce(b6.triage_state, 'open') IN ['fixed', 'gone', 'inactive']",
  },
  {
    key: 'knownExploits',
    pattern: 'b7:ExploitGvm',
    where: "b7.stale_since IS NULL AND " +
      "NOT (coalesce(b7.triage_status, '') = 'likely_noise' AND coalesce(b7.triage_source, '') = 'human') " +
      "AND NOT coalesce(b7.triage_state, 'open') IN ['fixed', 'gone', 'inactive']",
  },
  {
    key: 'judgedFalsePositiveVulnerabilities',
    pattern: 'b8:Vulnerability',
    where: "b8.stale_since IS NULL AND " +
      "CASE WHEN coalesce(b8.triage_state, 'open') IN ['fixed', 'gone', 'inactive'] THEN 'resolved' " +
      "WHEN coalesce(b8.triage_status, '') = 'likely_noise' AND coalesce(b8.triage_source, '') = 'human' " +
      "THEN 'person_false_positive' " +
      "WHEN coalesce(b8.triage_state, 'open') = 'false_positive' " +
      "OR (coalesce(b8.triage_status, '') = 'likely_noise' AND coalesce(b8.triage_source, '') = 'ai') " +
      "THEN 'ai_flagged' ELSE 'counted' END = 'person_false_positive'",
  },
  {
    key: 'resolvedVulnerabilities',
    pattern: 'b9:Vulnerability',
    where: "b9.stale_since IS NULL AND " +
      "CASE WHEN coalesce(b9.triage_state, 'open') IN ['fixed', 'gone', 'inactive'] THEN 'resolved' " +
      "WHEN coalesce(b9.triage_status, '') = 'likely_noise' AND coalesce(b9.triage_source, '') = 'human' " +
      "THEN 'person_false_positive' " +
      "WHEN coalesce(b9.triage_state, 'open') = 'false_positive' " +
      "OR (coalesce(b9.triage_status, '') = 'likely_noise' AND coalesce(b9.triage_source, '') = 'ai') " +
      "THEN 'ai_flagged' ELSE 'counted' END = 'resolved'",
  },
  {
    key: 'aiFlaggedVulnerabilities',
    pattern: 'b10:Vulnerability',
    where: "b10.stale_since IS NULL AND " +
      "CASE WHEN coalesce(b10.triage_state, 'open') IN ['fixed', 'gone', 'inactive'] THEN 'resolved' " +
      "WHEN coalesce(b10.triage_status, '') = 'likely_noise' AND coalesce(b10.triage_source, '') = 'human' " +
      "THEN 'person_false_positive' " +
      "WHEN coalesce(b10.triage_state, 'open') = 'false_positive' " +
      "OR (coalesce(b10.triage_status, '') = 'likely_noise' AND coalesce(b10.triage_source, '') = 'ai') " +
      "THEN 'ai_flagged' ELSE 'counted' END = 'ai_flagged'",
  },
]

export function attackSurfaceCypher(): string {
  const lines: string[] = []
  const carried: string[] = []
  for (const { key, pattern, where, match } of CENSUS) {
    const variable = pattern.slice(0, pattern.indexOf(':'))
    const prefix = carried.length ? `${carried.join(', ')}, ` : ''
    lines.push(`OPTIONAL MATCH ${match ?? `(${pattern})`}${where ? ` WHERE ${where}` : ''}`)
    lines.push(`WITH ${prefix}count(${match ? 'DISTINCT ' : ''}${variable}) AS ${key}`)
    carried.push(key)
  }
  lines.push(`RETURN ${carried.join(', ')}`)
  return lines.join('\n')
}

/**
 * What is exploitable, ranked by CISA-KEV then CVSS.
 *
 * Aggregated per (technology, CVE) rather than shipped as raw path rows: the
 * UI's equivalent emits one 19-column row per
 * (subdomain, ip, port, service, tech, cve, cwe, capec) combination against a
 * cap of 200,000, which is roughly 200x this path's 1000-row ceiling and would
 * truncate or 413 on any real project.
 */
export const EXPLOIT_PATHS_CYPHER = `MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE)
OPTIONAL MATCH (ex:ExploitGvm)-[:EXPLOITED_CVE]->(c:CVE) WHERE ex.stale_since IS NULL AND NOT (coalesce(ex.triage_status, '') = 'likely_noise' AND coalesce(ex.triage_source, '') = 'human') AND NOT coalesce(ex.triage_state, 'open') IN ['fixed', 'gone', 'inactive']
OPTIONAL MATCH (c:CVE)-[:HAS_CWE]->(m:MitreData)
OPTIONAL MATCH (bu:BaseURL)-[:USES_TECHNOLOGY]->(t)
OPTIONAL MATCH (svc:Service)-[:USES_TECHNOLOGY]->(t)
OPTIONAL MATCH (p:Port)-[:HAS_TECHNOLOGY]->(t)
WITH t, c, count(DISTINCT ex) > 0 AS cisaKev,
     collect(DISTINCT m.cwe_id)[0..3] AS cweIds,
     count(DISTINCT bu) + count(DISTINCT svc) + count(DISTINCT p) AS reachedBy
RETURN t.name AS technology, t.version AS version, c.id AS cve,
       toFloat(c.cvss) AS cvss, c.severity AS severity,
       cisaKev, cweIds, reachedBy
ORDER BY cisaKev DESC, cvss DESC
LIMIT ${TOP_N}`

/** Which vulnerable technology touches the most of the surface. */
export const BLAST_RADIUS_CYPHER = `MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE)
OPTIONAL MATCH (bu:BaseURL)-[:USES_TECHNOLOGY]->(t)
OPTIONAL MATCH (svc:Service)-[:USES_TECHNOLOGY]->(t)
OPTIONAL MATCH (p:Port)-[:HAS_TECHNOLOGY]->(t)
OPTIONAL MATCH (ex:ExploitGvm)-[:EXPLOITED_CVE]->(c:CVE) WHERE ex.stale_since IS NULL AND NOT (coalesce(ex.triage_status, '') = 'likely_noise' AND coalesce(ex.triage_source, '') = 'human') AND NOT coalesce(ex.triage_state, 'open') IN ['fixed', 'gone', 'inactive']
WITH t, count(DISTINCT c) AS cveCount, max(toFloat(c.cvss)) AS maxCvss,
     count(DISTINCT ex) AS knownExploitCount,
     count(DISTINCT bu) AS baseUrlCount,
     count(DISTINCT svc) + count(DISTINCT p) AS hostSurfaceCount,
     collect(DISTINCT c.id)[0..5] AS topCves
RETURN t.name AS technology, t.version AS version, cveCount, maxCvss,
       knownExploitCount, baseUrlCount, hostSurfaceCount, topCves
ORDER BY knownExploitCount DESC, maxCvss DESC, cveCount DESC
LIMIT ${TOP_N}`

async function runAnalytics(
  project: { id: string; userId: string },
  cypher: string,
  what: string
): Promise<Record<string, unknown>[]> {
  const result = await execCypher(project.userId, project.id, cypher)
  if (!Array.isArray(result.records)) {
    throw new McpToolError(`The ${what} could not be read.`, 'agent_failed')
  }
  return result.records as Record<string, unknown>[]
}

const STALE_NOTE =
  'Counts exclude findings someone suppressed and findings a later scan stopped reporting, as ' +
  'graph_summary does and raw Cypher does not.'

/** The Priority Board half, worded as the client report words it. */
const BOARD_NOTE =
  'Every finding count also leaves out what a person judged a false positive on the Priority ' +
  'Board and what the board resolved (fixed, gone, inactive), exactly as the client report does; ' +
  'for vulnerabilities those are counted separately in judgedFalsePositiveVulnerabilities and ' +
  'resolvedVulnerabilities. A finding only an AI review flagged as a false positive is still ' +
  'counted (aiFlaggedVulnerabilities says how many), because a reviewer reads target-controlled text.'

const EXPLOIT_BOARD_NOTE =
  'An exploit record a person judged a false positive, or the Priority Board resolved, does not ' +
  'count as a known exploit.'

/**
 * Why an empty answer is empty.
 *
 * Both of these tools start from `(:Technology)-[:HAS_KNOWN_CVE]->(:CVE)`, so a
 * project whose CVE enrichment never ran returns zero rows however many
 * technologies and vulnerabilities it holds. Without this the caller reads that
 * as "nothing here is exploitable" - the false negative this whole surface is
 * written to avoid - and a project with 19 technologies and 215 findings
 * answers "0 technologies ranked by exposure" with no way to tell why.
 *
 * Added ONLY when the result is empty: on a populated answer it is noise.
 */
const NO_CVE_LINKS_NOTE =
  'This answer is EMPTY, and that is not the same as "nothing is exploitable". Both of these ' +
  'views start from a technology linked to a CVE record, which only exists once CVE lookup has ' +
  'run for this project. Check get_recon_settings for cveLookupEnabled and get_recon_status for ' +
  'whether a scan has completed; list_findings still reports findings that carry no CVE link.'

export async function getAttackSurfaceOverview(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'query')
  const project = await assertMcpProjectAccess(ctx.token, projectId, 'R')

  const rows = await runAnalytics(project, attackSurfaceCypher(), 'attack surface overview')
  // The chained aggregation always produces exactly one row, including on an
  // empty project. No row at all means the query did not run as written.
  const row = rows[0]
  if (!row) throw new McpToolError('The attack surface overview could not be read.', 'agent_failed')

  return {
    projectId,
    surface: row,
    notes: [
      STALE_NOTE,
      BOARD_NOTE,
      'A category at zero means nothing of that kind is in the graph, which can equally mean ' +
        'that surface was never scanned. graph_summary and get_project_activity tell those apart.',
      'endpoints and parameters count what a tool observed. declaredEndpoints and ' +
        'declaredParameters count what only an API specification declares: documented, not ' +
        'confirmed reachable (Endpoint.openapi_declared_only).',
    ],
  }
}

export async function listExploitPaths(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'query')
  const project = await assertMcpProjectAccess(ctx.token, projectId, 'R')

  const rows = await runAnalytics(project, EXPLOIT_PATHS_CYPHER, 'exploit paths')
  return {
    projectId,
    paths: rows,
    returned: rows.length,
    ...(rows.length >= TOP_N ? { truncated: true, limit: TOP_N } : {}),
    notes: [
      `The top ${TOP_N} (technology, CVE) pairs, ordered by whether a known exploit was observed ` +
        'and then by CVSS.',
      'cisaKev true means an exploit record for that CVE exists in THIS project\'s graph, not ' +
        'that the CVE is on a public exploited list.',
      'reachedBy counts the base URLs, services and ports running the technology: it is how ' +
        'widely the problem is exposed, not how severe it is.',
      STALE_NOTE,
      EXPLOIT_BOARD_NOTE,
      ...(rows.length === 0 ? [NO_CVE_LINKS_NOTE] : []),
    ],
  }
}

export async function getBlastRadius(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'query')
  const project = await assertMcpProjectAccess(ctx.token, projectId, 'R')

  const rows = await runAnalytics(project, BLAST_RADIUS_CYPHER, 'blast radius')
  return {
    projectId,
    technologies: rows,
    returned: rows.length,
    ...(rows.length >= TOP_N ? { truncated: true, limit: TOP_N } : {}),
    notes: [
      'Ranked by how much of the surface one vulnerable technology touches, so the top row is ' +
        'usually the highest-leverage single fix.',
      'hostSurfaceCount counts services and ports; baseUrlCount counts web origins.',
      STALE_NOTE,
      EXPLOIT_BOARD_NOTE,
      ...(rows.length === 0 ? [NO_CVE_LINKS_NOTE] : []),
    ],
  }
}
