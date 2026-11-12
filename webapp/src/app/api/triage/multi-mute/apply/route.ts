import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import prisma from '@/lib/prisma'
import { readJsonBody } from '@/lib/jsonBody'
import { graphTriage, realActorUserId } from '@/lib/triageClient'
import { activationBusy } from '@/lib/activationLock'
import { invalidateCache } from '@/app/api/graph/cache'
import { writeAudit } from '@/lib/audit'
import { findLiveTriageRun } from '@/lib/triageRun'
import { featureModelErrorResponse } from '@/lib/featureModels'
import {
  activationBusyCoded,
  exemptPairs,
  isMultiMuteConcept,
  MULTI_BATCH_PATTERN,
  MULTI_MUTE_MAX_KEYS,
  OPEN_REMEDIATION_STATUSES,
} from '@/lib/multiMute'

interface MuteBatchItem {
  key: string
  label: string
  node_id: string
  name: string
  severity: string
  outcome: string
}

/**
 * POST /api/triage/multi-mute/apply - mute findings a person confirmed from a
 * Multi mute suggestion.
 *
 * Body: { projectId, batchId, keys: string[], includeSeed, concept }
 *
 * A person's mute (`muted_by` is the effective user), stamped as a Multi mute
 * with its batch id so it is never read as a finding judged one by one. The
 * agent accepts only keys from its stored batch and re-checks, under each
 * node's lock, everything the suggestion checked minutes earlier (the seed's
 * ceiling, proof, a person's unmute); a finding that fails is reported with
 * its outcome and left alone.
 *
 * Muted findings leave the triage queries, so the next triage run deletes a
 * CypherFix work item nobody touched and zeroes the live count of one somebody
 * owns. The answer says how many open work items reference the muted keys.
 */
export async function POST(request: NextRequest) {
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { projectId, batchId, keys, includeSeed, concept } = parsed.body as {
    projectId?: string; batchId?: unknown; keys?: unknown; includeSeed?: unknown; concept?: unknown
  }

  const auth = await requirePermission(request, 'triage:mute', { projectId })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)

  if (typeof batchId !== 'string' || !MULTI_BATCH_PATTERN.test(batchId)) {
    return NextResponse.json({ error: 'batchId must be a Multi mute batch id' }, { status: 400 })
  }
  if (!isMultiMuteConcept(concept)) {
    return NextResponse.json({ error: 'concept is not a Multi mute grouping' }, { status: 400 })
  }
  const wanted = Array.isArray(keys)
    ? [...new Set(keys.filter((k): k is string => typeof k === 'string' && k.length > 0 && k.length <= 300))]
    : []
  if (wanted.length === 0 || (Array.isArray(keys) && wanted.length !== new Set(keys).size)) {
    return NextResponse.json({ error: 'keys must be a non-empty list of finding keys' }, { status: 400 })
  }
  if (wanted.length > MULTI_MUTE_MAX_KEYS) {
    return NextResponse.json({ error: `at most ${MULTI_MUTE_MAX_KEYS} findings per request` }, { status: 400 })
  }

  if (await activationBusy(caller.projectId)) return activationBusyCoded()

  let pairs: [string, string][]
  try {
    pairs = await exemptPairs(caller.projectId)
  } catch (e) {
    console.error('[multi-mute] could not load node-filter exemptions:', e)
    return NextResponse.json(
      { error: 'Could not read which findings people brought back; nothing was muted. Try again.' },
      { status: 503 },
    )
  }

  const result = await graphTriage('mute_batch', caller, {
    batch_id: batchId,
    keys: wanted,
    include_seed: includeSeed === true,
    concept,
    muted_by: caller.userId,
    exempt_pairs: pairs,
  })
  // An agent that predates Multi mute refuses the op, or answers without the marker.
  if ((result.status === 400 && /unknown op/.test(String(result.body.error ?? '')))
      || (result.status === 200 && result.body.multi_mute !== 1)) {
    return featureModelErrorResponse('agent_outdated', 'multi_mute')
  }
  if (result.status !== 200) return NextResponse.json(result.body, { status: result.status })
  invalidateCache(caller.projectId)

  const items = (Array.isArray(result.body.items) ? result.body.items : []) as MuteBatchItem[]
  const muted = items.filter(i => i.outcome === 'muted').map(i => i.key)

  const [workItemsAffected, liveRun] = await Promise.all([
    muted.length === 0 ? Promise.resolve(0) : prisma.remediation.count({
      where: {
        projectId: caller.projectId,
        status: { in: OPEN_REMEDIATION_STATUSES },
        findingIds: { hasSome: muted },
      },
    }).catch(() => 0),
    findLiveTriageRun(caller.projectId).catch(() => null),
  ])

  if (muted.length > 0) {
    const realActor = await realActorUserId()
    await writeAudit({
      actorId: realActor ?? caller.userId,
      action: 'muted_nodes.multi_muted',
      targetType: 'project',
      targetId: caller.projectId,
      after: {
        realActorUserId: realActor,
        effectiveUserId: caller.userId,
        batchId,
        model: typeof result.body.model === 'string' ? result.body.model : null,
        promptVersion: typeof result.body.prompt_version === 'string' ? result.body.prompt_version : null,
        concept,
        includeSeed: includeSeed === true,
        count: muted.length,
        keys: muted.slice(0, MULTI_MUTE_MAX_KEYS),
      },
      source: 'ui',
    })
  }

  return NextResponse.json({
    batchId,
    items,
    notFound: Array.isArray(result.body.not_found) ? result.body.not_found : [],
    workItemsAffected,
    triageRunLive: liveRun !== null,
  })
}
