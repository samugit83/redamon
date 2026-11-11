import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { requireProjectOwner, graphTriage } from '@/lib/triageClient'
import { auditSingleMute } from '@/lib/triage/muteAudit'
import { readJsonBody } from '@/lib/jsonBody'
import { invalidateCache } from '@/app/api/graph/cache'
import { resolveFindingByGraphId, GRAPH_ID_PATTERN } from '@/lib/resolveFindingKey'
import { activationBusy, activationBusyResponse } from '@/lib/activationLock'

/**
 * POST /api/triage/mute-by-graph-id - `/api/triage/mute` for a node known only
 * by its graph id.
 *
 * Body: { projectId, graphId }
 *
 * The graph tables carry Neo4j's internal id per row (the Node ID column), but
 * a mute is keyed on the finding's stored id, which survives the DETACH DELETE
 * and recreate of an import or a version activation. This resolves the one to
 * the other inside the caller's tenant, then issues exactly the mute the
 * Priority Board does.
 *
 * An internal id is reused after its node is deleted, so a row loaded before an
 * activation can point at a different node now. What still holds: the lookup
 * is tenant-scoped, only finding labels resolve, and the result is one
 * reversible mute. A node that is gone answers 409, the same "changed while the
 * page was open" the Priority Board handles. An already-muted node is left as it
 * was (`already: true`), and a version activation in progress answers 409 too.
 */
// Ownership and the activation lock read Postgres before any try; a failure
// there would otherwise be Next's empty-bodied 500.
export const POST = withRouteErrors('The finding could not be muted.', async (request: NextRequest) => {
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { projectId, graphId } = parsed.body as { projectId?: string; graphId?: unknown }

  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller
  if (typeof graphId !== 'string' || !GRAPH_ID_PATTERN.test(graphId)) {
    return NextResponse.json({ error: 'graphId must be a graph node id' }, { status: 400 })
  }
  if (await activationBusy(caller.projectId)) return activationBusyResponse()

  const resolved = await resolveFindingByGraphId(caller, graphId)
  if (!resolved.ok) return resolved.response
  const nodeId = resolved.key

  const answer = await graphTriage('mute', caller, {
    node_id: nodeId,
    reason: '',
    muted_by: caller.userId,
  })
  // The Graph Map serves a cached copy for up to 10 s; a muted finding must
  // leave it now, not then.
  if (answer.status >= 200 && answer.status < 300) invalidateCache(caller.projectId)
  await auditSingleMute(caller, answer, { key: nodeId, reason: '', graphId })
  return NextResponse.json(answer.body, { status: answer.status })
})
