/**
 * Scan Timeline - render one version as the graph payload (Section 4.1).
 *
 * GET /api/projects/[id]/versions/[versionId]/graph -> { nodes, links }
 *
 *   current version -> the LIVE graph, through the same read path as /api/graph
 *   past version    -> the stored snapshot bytes, converted to the render shape
 *
 * This endpoint is READ-ONLY and never touches Neo4j for a past version. Making a
 * past version the graph the agent works on is a different, deliberate action
 * (POST .../activate).
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { requireVersionInProject } from '@/lib/scanVersionAccess'
import { loadSnapshot, snapshotToGraphPayload } from '@/lib/scanSnapshot'
import { readLiveGraph } from '@/app/api/graph/liveRead'
import { internalError, withRouteErrors } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string; versionId: string }>
}

export const GET = withRouteErrors('Failed to read version graph', async (request: NextRequest, { params }: RouteParams) => {
  const { id, versionId } = await params

  const auth = await requirePermission(request, 'recon:read', { projectId: id })
  if (auth instanceof NextResponse) return auth

  // Anti-IDOR: the version id is client-supplied and must belong to this project.
  const version = await requireVersionInProject(id, versionId)
  if (version instanceof NextResponse) return version

  try {
    if (version.isCurrent) {
      const { nodes, links } = await readLiveGraph(id)
      return NextResponse.json(
        { nodes, links, projectId: id, versionId, isCurrent: true, live: true },
        { headers: { 'Cache-Control': 'private, no-cache' } }
      )
    }

    const snapshot = await loadSnapshot(versionId)
    if (!snapshot) {
      return NextResponse.json(
        {
          error: 'This version has no stored snapshot (it predates the Scan Timeline or its capture failed).',
          emptySnapshot: true,
        },
        { status: 409 }
      )
    }

    const { nodes, links } = snapshotToGraphPayload(snapshot)
    return NextResponse.json(
      { nodes, links, projectId: id, versionId, isCurrent: false, live: false },
      { headers: { 'Cache-Control': 'private, no-cache' } }
    )
  } catch (error) {
    return internalError(error, 'Failed to read version graph', { log: '[scanTimeline] version graph read failed' })
  }
})
