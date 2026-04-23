import { NextRequest, NextResponse } from 'next/server'
import { getSession } from './neo4j'
import { formatGraphRecords } from './format'
import { getCached, setCached, invalidateCache } from './cache'

const GRAPH_PERF_DEBUG = true

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const projectId = searchParams.get('projectId')

  if (!projectId) {
    return NextResponse.json(
      { error: 'projectId is required' },
      { status: 400 }
    )
  }

  if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] GET /api/graph projectId=${projectId}`)

  // Allow clients to bypass server cache (used after pipeline completion
  // to ensure background graph-DB writes are picked up)
  const fresh = searchParams.get('fresh') === '1'
  if (fresh) {
    invalidateCache(projectId)
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] Fresh request -- cache invalidated for ${projectId}`)
  }

  // Check If-None-Match header for ETag-based conditional request
  const ifNoneMatch = request.headers.get('if-none-match')

  // Check server-side cache
  const cached = getCached(projectId)
  if (cached) {
    const cacheAge = Date.now() - cached.timestamp
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] Cache HIT for ${projectId} (age=${cacheAge}ms)`)

    // If client has same ETag, return 304
    if (ifNoneMatch && ifNoneMatch === `"${cached.etag}"`) {
      if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] 304 Not Modified -- ETag matched for ${projectId}`)
      return new NextResponse(null, {
        status: 304,
        headers: {
          'ETag': `"${cached.etag}"`,
          'Cache-Control': 'private, no-cache',
        },
      })
    }

    // Return cached data with ETag
    return NextResponse.json(
      { nodes: cached.data.nodes, links: cached.data.links, projectId },
      {
        headers: {
          'ETag': `"${cached.etag}"`,
          'Cache-Control': 'private, no-cache',
        },
      }
    )
  }

  if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] Cache MISS for ${projectId}`)

  const session = getSession()

  try {
    const queryStart = Date.now()

    // Query all nodes and relationships connected to the project
    // Uses UNION to capture:
    // 1. Direct relationships where source has project_id
    // 2. Extended paths for CVE/MITRE chain (Technology -> CVE -> MitreData -> Capec)
    const result = await session.run(
      `
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

      // Get TLS Certificates linked to BaseURLs
      MATCH (u:BaseURL {project_id: $projectId})-[r12:HAS_CERTIFICATE]->(c:Certificate)
      RETURN u as n, r12 as r, c as m

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
      `,
      { projectId }
    )

    const queryEnd = Date.now()
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] Neo4j query completed in ${queryEnd - queryStart}ms -- ${result.records.length} records`)

    const { nodes, links } = formatGraphRecords(result.records)

    const formatEnd = Date.now()
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] Formatted ${nodes.length} nodes, ${links.length} links in ${formatEnd - queryEnd}ms`)

    // Cache the result and get ETag
    const etag = setCached(projectId, { nodes, links })

    // Check if client already has this version
    if (ifNoneMatch && ifNoneMatch === `"${etag}"`) {
      if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] 304 Not Modified -- fresh data matches client ETag for ${projectId}`)
      return new NextResponse(null, {
        status: 304,
        headers: {
          'ETag': `"${etag}"`,
          'Cache-Control': 'private, no-cache',
        },
      })
    }

    const responseData = JSON.stringify({ nodes, links, projectId })
    if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] Response size: ${(responseData.length / 1024).toFixed(1)}KB`)

    return new NextResponse(responseData, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'ETag': `"${etag}"`,
        'Cache-Control': 'private, no-cache',
      },
    })
  } catch (error) {
    console.error('Graph query error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}

export async function DELETE(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const nodeId = searchParams.get('nodeId')
  const projectId = searchParams.get('projectId')

  if (!nodeId || !projectId) {
    return NextResponse.json(
      { error: 'nodeId and projectId are required' },
      { status: 400 }
    )
  }

  const session = getSession()

  try {
    // Delete any node except Domain and Subdomain (protected)
    const result = await session.run(
      `
      MATCH (n)
      WHERE id(n) = toInteger($nodeId)
        AND n.project_id = $projectId
        AND NOT (n:Domain OR n:Subdomain)
      DETACH DELETE n
      RETURN count(n) as deleted
      `,
      { nodeId, projectId }
    )

    const deleted = result.records[0]?.get('deleted')?.low ?? 0

    if (deleted === 0) {
      return NextResponse.json(
        { error: 'Node not found or not deletable' },
        { status: 404 }
      )
    }

    // Invalidate cache after deletion
    invalidateCache(projectId)

    return NextResponse.json({ success: true, deleted })
  } catch (error) {
    console.error('Graph delete error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Delete failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}

// getNodeName and serializeProperties are now in ./format.ts
