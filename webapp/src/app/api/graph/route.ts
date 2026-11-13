import { NextRequest, NextResponse } from 'next/server'
import { getGraphSession } from './neo4j'
import { readLiveGraph } from './liveRead'
import { getCached, setCached, invalidateCache } from './cache'
import { truncateGraph } from './truncate'
import { GRAPH_PERF_DEBUG } from './config'
import { requirePermission } from '@/lib/authz/guards'
import { graphReadView } from '@/lib/authz/graphReadView'
import { withRouteErrors } from '@/lib/routeErrors'
import { graphError } from './graphErrors'

// The ownership checks run before the query's try; a Prisma failure there
// would otherwise be Next's empty-bodied 500.
export const GET = withRouteErrors('The graph could not be loaded', async (request: NextRequest) => {
  const searchParams = request.nextUrl.searchParams
  const projectId = searchParams.get('projectId')

  if (!projectId) {
    return NextResponse.json(
      { error: 'projectId is required' },
      { status: 400 }
    )
  }

  // The graph is the project's, whoever reads it: the owner, or someone the project's
  // access admits (a share, oversight). A project the effective user cannot see answers
  // 404 before any read (the impersonation-URL BOLA where an admin simulating X, or any
  // user, reads another user's graph by id).
  const auth = await requirePermission(request, 'graph:read', { projectId })
  if (auth instanceof NextResponse) return auth

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
    const view = graphReadView({ ...cached.data, etag: cached.etag }, auth.access)

    // If client has same ETag, return 304
    if (ifNoneMatch && ifNoneMatch === `"${view.etag}"`) {
      if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] 304 Not Modified -- ETag matched for ${projectId}`)
      return new NextResponse(null, {
        status: 304,
        headers: {
          'ETag': `"${view.etag}"`,
          'Cache-Control': 'private, no-cache',
        },
      })
    }

    // Return cached data with ETag
    return NextResponse.json(
      // Same condition as the miss path below. Keying on `cached.info` alone
      // meant a NON-truncated graph served from cache carried
      // `truncated: {truncated:false,...}` -- a truthy object -- while the
      // miss omitted the key entirely, so `if (data.truncated)` answered
      // differently for identical data depending on cache state.
      { nodes: view.nodes, links: view.links, projectId,
        ...(cached.info?.truncated ? { truncated: cached.info } : {}) },
      {
        headers: {
          'ETag': `"${view.etag}"`,
          'Cache-Control': 'private, no-cache',
        },
      }
    )
  }

  if (GRAPH_PERF_DEBUG) console.log(`[GraphPerf:API] Cache MISS for ${projectId}`)

  try {
    // Same read path the version endpoint uses for the CURRENT version
    // (Scan Timeline Section 4.1), including the orphan-chain reconcile.
    const full = await readLiveGraph(projectId)

    // Bound the payload BEFORE it is cached or serialised: the response object,
    // the cached copy and the JSON string are all live at once, so an unbounded
    // graph is held three times over.
    const { nodes, links, info } = truncateGraph(full.nodes, full.links)
    if (info.truncated) {
      console.warn(
        `[Graph] project=${projectId} truncated to ${info.returnedNodes}/${info.totalNodes} nodes ` +
        `(${info.returnedLinks}/${info.totalLinks} links); raise GRAPH_MAX_NODES to change`,
      )
    }

    // The cache holds the project's graph; each reader gets its view of it.
    const view = graphReadView({ nodes, links, etag: setCached(projectId, { nodes, links }, info) }, auth.access)
    const etag = view.etag

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

    const responseData = JSON.stringify({ nodes: view.nodes, links: view.links, projectId, ...(info.truncated ? { truncated: info } : {}) })
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
    return graphError(error, 'The graph query failed', 'Graph query error')
  }
})

export const DELETE = withRouteErrors('The node could not be deleted', async (request: NextRequest) => {
  const searchParams = request.nextUrl.searchParams
  const nodeId = searchParams.get('nodeId')
  const projectId = searchParams.get('projectId')

  if (!nodeId || !projectId) {
    return NextResponse.json(
      { error: 'nodeId and projectId are required' },
      { status: 400 }
    )
  }

  // Only the project's effective owner may delete its graph nodes.
  const auth = await requirePermission(request, 'graph:edit', { projectId })
  if (auth instanceof NextResponse) return auth

  const session = getGraphSession()

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
    return graphError(error, 'Delete failed', 'Graph delete error')
  } finally {
    await session.close()
  }
})

// getNodeName and serializeProperties are now in ./format.ts
