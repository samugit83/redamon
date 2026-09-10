import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner, callGraphTriage } from '@/lib/triageClient'

/**
 * POST /api/triage/mute - suppress one finding as noise.
 *
 * Body: { projectId, nodeId, reason? }
 *
 * NOT cascaded to Remediation, deliberately. A Remediation is synthesised by the
 * CypherFix LLM from CORRELATED findings -- one work item can cover several, and
 * the model carries no link back to the finding nodes it came from (only
 * `affectedAssets`, `cveIds` and prose). There is therefore no key to cascade on,
 * and matching by title or asset would dismiss the wrong work item.
 *
 * What covers the gap instead: the classify phase drops `likely_noise` before
 * remediations are generated, and both the dashboard and the client report
 * exclude `status = 'dismissed'`. Linking the two properly needs a
 * `findingIds String[]` on Remediation plus attribution from the generator,
 * which is a schema change and is written up as a follow-up.
 */
export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}))
  const { projectId, nodeId, reason } = body ?? {}

  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller
  if (!nodeId || typeof nodeId !== 'string') {
    return NextResponse.json({ error: 'nodeId is required' }, { status: 400 })
  }

  return callGraphTriage('mute', caller, {
    node_id: nodeId,
    reason: typeof reason === 'string' ? reason.slice(0, 500) : '',
    muted_by: caller.userId,
  })
}
