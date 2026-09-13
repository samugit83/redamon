/**
 * The live-graph read, extracted from GET /api/graph so other routes can render
 * "the current version" through EXACTLY the same path (Scan Timeline Section 4.1:
 * viewing the current version delegates to the live read, past versions come from
 * stored snapshot bytes).
 *
 * Callers own authorization, caching and ETags - this is the raw read.
 */
import prisma from '@/lib/prisma'
import { getGraphSession, neo4j } from './neo4j'
import { GRAPH_PERF_DEBUG, GRAPH_MAX_RECORDS } from './config'
import { formatGraphRecords, type FormattedGraphData } from './format'


/**
 * Read-time reconcile: attack-chain nodes are session-scoped by chain_id (=
 * conversation sessionId). Deleting a conversation is supposed to remove its
 * chain subgraph, but a still-running agent loop can re-MERGE the AttackChain
 * into Neo4j AFTER that delete (cancellation is not instant), orphaning the
 * chain with no matching conversation. Those orphans then render on /graph with
 * no way to remove them. Here we self-heal on every cache-miss read: delete any
 * AttackChain-family node for the project whose chain_id has no live
 * conversation, BEFORE the main query runs, so orphans are both purged from
 * storage and never returned. Best-effort - a failure must not block the graph.
 */
export async function reconcileOrphanChains(
  session: ReturnType<typeof getGraphSession>,
  projectId: string
): Promise<void> {
  try {
    const conversations = await prisma.conversation.findMany({
      where: { projectId },
      select: { sessionId: true },
    })
    const liveSessionIds = conversations.map(c => c.sessionId).filter(Boolean)

    // NOTE: when liveSessionIds is empty, `NOT chain_id IN []` is true for every
    // chain node, so all chains for the project are purged - correct, since no
    // live conversation means every chain is an orphan. Nodes with a null
    // chain_id evaluate to null (not true) and are left untouched.
    const res = await session.run(
      `MATCH (n)
       WHERE n.project_id = $projectId
         AND (n:AttackChain OR n:ChainStep OR n:ChainFinding OR n:ChainDecision OR n:ChainFailure)
         AND NOT n.chain_id IN $liveSessionIds
       DETACH DELETE n
       RETURN count(n) AS purged`,
      { projectId, liveSessionIds }
    )
    const purged = res.records[0]?.get('purged')
    const purgedCount = typeof purged === 'object' && purged?.toNumber ? purged.toNumber() : Number(purged) || 0
    if (GRAPH_PERF_DEBUG && purgedCount > 0) {
      console.log(`[GraphPerf:API] Reconcile purged ${purgedCount} orphan chain node(s) for ${projectId}`)
    }
  } catch (err) {
    console.error('[GraphPerf:API] Orphan-chain reconcile failed (continuing):', err)
  }
}

/** The project subgraph query used by the graph screen. */
export const LIVE_GRAPH_QUERY = `
      // BOUNDED AT THE DATABASE. Truncating in Node after the fact still made
      // the driver materialise every record first, so the peak was unchanged --
      // the cap only shrank the cached copy and the JSON string, not the read
      // that OOM-killed the container in the first place. LIMIT here means the
      // rows never leave Neo4j.
      CALL {
        // Get direct relationships from project nodes
        MATCH (n)-[r]->(m)
        WHERE n.project_id = $projectId
        RETURN n, r, m

        UNION

        // Get CVE chain: Technology -> CVE -> MitreData -> Capec
        MATCH (t:Technology {project_id: $projectId})-[r1:HAS_KNOWN_CVE]->(c:CVE)
        RETURN t as n, r1 as r, c as m

        UNION

        MATCH (t:Technology {project_id: $projectId})-[:HAS_KNOWN_CVE]->(c:CVE)-[r2:HAS_CWE]->(cwe:MitreData)
        RETURN c as n, r2 as r, cwe as m

        UNION

        MATCH (t:Technology {project_id: $projectId})-[:HAS_KNOWN_CVE]->(c:CVE)-[:HAS_CWE]->(cwe:MitreData)-[r3:HAS_CAPEC]->(cap:Capec)
        RETURN cwe as n, r3 as r, cap as m

        UNION

        // Get Vulnerability relationships (FOUND_AT -> Endpoint, AFFECTS_PARAMETER -> Parameter)
        // Note: We don't query BaseURL -> Vulnerability as that's redundant
        // Vulnerabilities connect to Endpoints/Parameters which are already under BaseURL
        MATCH (v:Vulnerability {project_id: $projectId})-[r5]->(target)
        RETURN v as n, r5 as r, target as m

        UNION

        // Get SecurityCheck Vulnerabilities linked to IPs
        MATCH (i:IP {project_id: $projectId})-[r6:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN i as n, r6 as r, v as m

        UNION

        // Get SecurityCheck Vulnerabilities linked to Subdomains
        MATCH (s:Subdomain {project_id: $projectId})-[r7:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN s as n, r7 as r, v as m

        UNION

        // Get SecurityCheck Vulnerabilities linked to Domain
        MATCH (d:Domain {project_id: $projectId})-[r8:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN d as n, r8 as r, v as m

        UNION

        // Get GVM Vulnerability -> CVE chain (for CVE enrichment from GVM findings)
        MATCH (v:Vulnerability {project_id: $projectId})-[r9:HAS_CVE]->(c:CVE)
        RETURN v as n, r9 as r, c as m

        UNION

        // Get CVE -> CWE -> CAPEC chain from GVM-linked CVEs
        MATCH (v:Vulnerability {project_id: $projectId})-[:HAS_CVE]->(c:CVE)-[r10:HAS_CWE]->(cwe:MitreData)
        RETURN c as n, r10 as r, cwe as m

        UNION

        MATCH (v:Vulnerability {project_id: $projectId})-[:HAS_CVE]->(c:CVE)-[:HAS_CWE]->(cwe:MitreData)-[r11:HAS_CAPEC]->(cap:Capec)
        RETURN cwe as n, r11 as r, cap as m

        UNION

        // Get TLS Certificates linked to BaseURLs (httpx)
        MATCH (u:BaseURL {project_id: $projectId})-[r12:HAS_CERTIFICATE]->(c:Certificate)
        RETURN u as n, r12 as r, c as m

        UNION

        // Get TLS Certificates linked to IPs (tlsx / OSINT / GVM, incl. non-HTTP TLS)
        MATCH (ip:IP {project_id: $projectId})-[r12b:HAS_CERTIFICATE]->(c:Certificate)
        RETURN ip as n, r12b as r, c as m

        UNION

        // Certificate -[:COVERS_HOST]-> Subdomain (tlsx SAN coverage)
        MATCH (c:Certificate {project_id: $projectId})-[r12c:COVERS_HOST]->(s:Subdomain)
        RETURN c as n, r12c as r, s as m

        UNION

        // Get AttackChain nodes and their relationships (HAS_STEP, CHAIN_TARGETS)
        MATCH (ac:AttackChain {project_id: $projectId})-[r16]->(target)
        RETURN ac as n, r16 as r, target as m

        UNION

        // Get ChainStep relationships (NEXT_STEP, PRODUCED, FAILED_WITH, LED_TO, STEP_TARGETED, STEP_EXPLOITED)
        MATCH (s:ChainStep {project_id: $projectId})-[r17]->(target)
        RETURN s as n, r17 as r, target as m

        UNION

        // Get ChainFinding bridge relationships (FOUND_ON, FINDING_RELATES_CVE, CREDENTIAL_FOR)
        MATCH (f:ChainFinding {project_id: $projectId})-[r18]->(target)
        RETURN f as n, r18 as r, target as m

        UNION

        // Get ChainDecision outgoing relationships (DECISION_PRECEDED -> ChainStep)
        MATCH (d:ChainDecision {project_id: $projectId})-[r19]->(target)
        RETURN d as n, r19 as r, target as m
      }
      // Mute enforcement, applied ONCE to the union rather than inside each
      // branch: a branch added later is covered without being remembered. It
      // sits before the LIMIT so suppressed findings do not eat the row budget.
      //
      // This is also what keeps labels[0] honest downstream. A muted node is
      // dual-labelled (Vulnerability + Muted) and Neo4j does not order labels,
      // so if one reached formatGraphRecords it could render as type "Muted".
      // Excluding it here is a correctness guarantee, not only a visibility one.
      WITH n, r, m
      WHERE NOT n:Muted AND NOT m:Muted
      RETURN n, r, m
      LIMIT $maxRecords
      `

/**
 * Read the project's live graph as the UI `{nodes, links}` payload.
 * Runs the orphan-chain reconcile first (same as the /api/graph read).
 */
export async function readLiveGraph(projectId: string): Promise<FormattedGraphData> {
  const session = getGraphSession()
  try {
    await reconcileOrphanChains(session, projectId)

    const queryStart = Date.now()
    const result = await session.run(LIVE_GRAPH_QUERY, {
      projectId,
      maxRecords: neo4j.int(GRAPH_MAX_RECORDS()),
    })
    const queryEnd = Date.now()
    if (GRAPH_PERF_DEBUG) {
      console.log(`[GraphPerf:API] Neo4j query completed in ${queryEnd - queryStart}ms -- ${result.records.length} records`)
    }

    const { nodes, links } = formatGraphRecords(result.records)
    if (GRAPH_PERF_DEBUG) {
      console.log(`[GraphPerf:API] Formatted ${nodes.length} nodes, ${links.length} links in ${Date.now() - queryEnd}ms`)
    }
    return { nodes, links }
  } finally {
    await session.close()
  }
}
