import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import { readJsonBody } from '@/lib/jsonBody'
import { activationBusy } from '@/lib/activationLock'
import { resolveFindingByGraphId } from '@/lib/resolveFindingKey'
import { readFeatureModel, featureModelErrorResponse } from '@/lib/featureModels'
import { callFeatureAgent } from '@/lib/featureAgentCall'
import { activationBusyCoded, exemptPairs } from '@/lib/multiMute'
import { ownerCredentialRefusal, recordFeatureSpend } from '@/lib/authz/ownerSpend'

// 30 s past the agent's own model timeout, so the agent's answer always wins.
const SUGGEST_TIMEOUT_MS = 180_000

/**
 * POST /api/triage/multi-mute/suggest - findings like the one being muted,
 * grouped, for a person to confirm.
 *
 * Body: { projectId, nodeId } (the finding's stored key) or { projectId, graphId }.
 *
 * Read-only. The agent keeps the suggestion as a batch, and the apply route
 * can mute only keys from it. The model is the project owner's saved "Multi
 * mute" model, never one named by the client; a collaborator spends it only
 * with Use AI agent (W+A, which counts only with the owner's consent; the
 * permission itself is W), recorded as theirs (step 5.6, C1). Refused while a version
 * activation holds the graph, failing closed when the lock cannot be read.
 *
 * A 502 whose status is `model_unreadable` still carries the exact groups
 * (all unchecked), so it is passed through with its payload.
 */
export async function POST(request: NextRequest) {
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { projectId, nodeId, graphId } = parsed.body as {
    projectId?: string; nodeId?: unknown; graphId?: unknown
  }

  const auth = await requirePermission(request, 'triage:mute', { projectId })
  if (auth instanceof NextResponse) return auth
  const spendRefused = ownerCredentialRefusal(auth)
  if (spendRefused) return spendRefused
  const caller = triageCaller(auth)
  if (await activationBusy(caller.projectId)) return activationBusyCoded()

  let seedKey: string
  if (typeof nodeId === 'string' && nodeId.length > 0 && nodeId.length <= 300) {
    seedKey = nodeId
  } else if (graphId !== undefined) {
    const resolved = await resolveFindingByGraphId(caller, graphId)
    if (!resolved.ok) return resolved.response
    seedKey = resolved.key
  } else {
    return NextResponse.json({ error: 'nodeId or graphId is required' }, { status: 400 })
  }

  const model = await readFeatureModel(caller.userId, 'multi_mute')
  if (!model) return featureModelErrorResponse('model_required', 'multi_mute')

  let pairs: [string, string][]
  try {
    pairs = await exemptPairs(caller.projectId)
  } catch (e) {
    console.error('[multi-mute] could not load node-filter exemptions:', e)
    return NextResponse.json(
      { error: 'Could not read which findings people brought back; try again.' },
      { status: 503 },
    )
  }

  const unrecorded = await recordFeatureSpend(auth, 'multi_mute')
  if (unrecorded) return unrecorded
  const agent = await callFeatureAgent({
    featureId: 'multi_mute',
    path: '/graph/multi-mute/suggest',
    model,
    body: {
      user_id: caller.userId,
      project_id: caller.projectId,
      seed_key: seedKey,
      model,
      exempt_pairs: pairs,
    },
    timeoutMs: SUGGEST_TIMEOUT_MS,
    notFoundIsOutdated: true,
    marker: 'multi_mute',
    acceptStatus: (status, body) => status === 502 && body.status === 'model_unreadable',
  })
  if (!agent.ok) return agent.response
  const { model_used: _modelUsed, multi_mute: _marker, ...payload } = agent.body
  return NextResponse.json(payload, { status: agent.status })
}
