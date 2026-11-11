import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { requireProjectOwner, graphTriage } from '@/lib/triageClient'
import { auditSingleMute } from '@/lib/triage/muteAudit'
import { readJsonBody } from '@/lib/jsonBody'
import { invalidateCache } from '@/app/api/graph/cache'
import { activationBusy, activationBusyResponse } from '@/lib/activationLock'

/**
 * POST /api/triage/mute - suppress one finding as noise.
 *
 * Body: { projectId, nodeId, reason? }
 *
 * NOT cascaded to Remediation here. A CypherFix work item is one triage group
 * (`groupKey`) and lists its members in `findingIds`, so the link exists, but a
 * group usually has other members that still need the fix. The next triage run
 * reconciles instead: muted findings leave the triage queries, so a work item
 * nobody touched whose members are all muted is deleted, and one somebody owns
 * keeps its row with `liveMemberCount` zeroed. Multi mute's apply route counts
 * the open work items a mute touches so the person is told.
 *
 * Never overwrites: an already-muted finding is left exactly as it was (a
 * rule's or an agent's mute keeps its attribution) and the answer carries
 * `already: true`. Refused with 409 while a version activation holds the graph,
 * which would otherwise swallow the mute after reporting success.
 */
// Ownership and the activation lock read Postgres before any try; a failure
// there would otherwise be Next's empty-bodied 500.
export const POST = withRouteErrors('The finding could not be muted.', async (request: NextRequest) => {
  // A plain HTML form cannot send JSON, so a cross-site page cannot drive this.
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { projectId, nodeId, reason } = parsed.body as {
    projectId?: string; nodeId?: unknown; reason?: unknown
  }

  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller
  if (!nodeId || typeof nodeId !== 'string') {
    return NextResponse.json({ error: 'nodeId is required' }, { status: 400 })
  }
  if (await activationBusy(caller.projectId)) return activationBusyResponse()

  const muteReason = typeof reason === 'string' ? reason.slice(0, 500) : ''
  const answer = await graphTriage('mute', caller, {
    node_id: nodeId,
    reason: muteReason,
    muted_by: caller.userId,
  })
  // The Graph Map serves a cached copy for up to 10 s; a muted finding must
  // leave it now, not then.
  if (answer.status >= 200 && answer.status < 300) invalidateCache(caller.projectId)
  await auditSingleMute(caller, answer, { key: nodeId, reason: muteReason })
  return NextResponse.json(answer.body, { status: answer.status })
})
