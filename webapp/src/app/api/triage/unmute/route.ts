import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { graphTriage, realActorUserId } from '@/lib/triageClient'
import { describeNodeFilterWriter } from '@/lib/nodeFilterRun'
import { activationBusy, activationBusyResponse } from '@/lib/activationLock'
import { auditUnmute, ensureExemptions } from '@/lib/unmuteExemptions'
import { invalidateCache } from '@/app/api/graph/cache'
import { featureModelErrorResponse } from '@/lib/featureModels'
import { MULTI_BATCH_PATTERN } from '@/lib/multiMute'

/**
 * POST /api/triage/unmute - restore suppressed findings.
 *
 * Body: { projectId, keys: string[] }, or the single-finding form { projectId, nodeId }.
 *
 * Lossless: each finding keeps every relationship and property it had. The triage
 * VERDICT is deliberately left in place -- unmuting means "show me this again",
 * not "forget the analysis".
 *
 * Every unmuted finding also gets a NodeFilterExemption, whether a person or a
 * rule had muted it, so an operator's unmute sticks: no filter rule mutes that
 * node again until the exemption is cleared from the Mute Rules page. The
 * exemption is a Postgres row rather than a graph property because the prune,
 * the recon asset clear, version activation and import would each delete a
 * property.
 *
 * The order is graph first, exemptions second: a person watching the table can
 * see a failed exemption and act on it (`exemptionError`). MCP `unmute_findings`
 * uses the same helpers in the opposite order, for an unattended caller.
 *
 * `undoBatch` is the Multi mute modal's Undo. Only findings that batch muted,
 * still stamped with it and still this person's, are unmuted, and no
 * exemption is written: an Undo returns them to how they were before, which
 * includes a Mute Rule being free to hide them again.
 */
const MAX_KEYS = 500

// Ownership and the activation lock read Postgres before any try; a failure
// there would otherwise be Next's empty-bodied 500.
export const POST = withRouteErrors('The findings could not be unmuted.', async (request: NextRequest) => {
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { projectId, nodeId, keys, undoBatch } = parsed.body as {
    projectId?: string; nodeId?: unknown; keys?: unknown; undoBatch?: unknown
  }

  const auth = await requirePermission(request, 'triage:mute', { projectId })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)

  const wanted = Array.isArray(keys)
    ? keys.filter((k): k is string => typeof k === 'string' && k.length > 0 && k.length <= 300)
    : typeof nodeId === 'string' && nodeId ? [nodeId] : []
  if (wanted.length === 0) {
    return NextResponse.json({ error: 'keys (or nodeId) is required' }, { status: 400 })
  }
  if (wanted.length > MAX_KEYS) {
    return NextResponse.json({ error: `at most ${MAX_KEYS} keys per request` }, { status: 400 })
  }
  if (undoBatch !== undefined && (typeof undoBatch !== 'string' || !MULTI_BATCH_PATTERN.test(undoBatch))) {
    return NextResponse.json({ error: 'undoBatch must be a Multi mute batch id' }, { status: 400 })
  }
  const batch = typeof undoBatch === 'string' ? undoBatch : null

  if (await activationBusy(caller.projectId)) return activationBusyResponse()

  // A running apply read the exemptions when it started, so a finding unmuted
  // now would be muted again when its page comes up. Refused until it ends.
  const applying = await describeNodeFilterWriter(caller.projectId)
  if (applying) {
    return NextResponse.json(
      { error: `Cannot unmute while ${applying}. Try again when it finishes.` },
      { status: 409 },
    )
  }

  const result = await graphTriage('unmute_many', caller, {
    keys: [...new Set(wanted)],
    ...(batch ? { only_batch: batch } : {}),
  })
  if (result.status !== 200) return NextResponse.json(result.body, { status: result.status })
  invalidateCache(caller.projectId)

  const items = (Array.isArray(result.body.items) ? result.body.items : []) as {
    key: string; label: string; muted_by: string
  }[]
  const realActor = await realActorUserId()
  const auditItems = items.map(i => ({ key: i.key, label: i.label, mutedBy: i.muted_by }))

  // An agent that predates Multi mute ignores only_batch and has already
  // unmuted every key it was sent. What it did is audited all the same; it is
  // just not presented as an Undo.
  if (batch && result.body.multi_mute !== 1) {
    if (items.length > 0) {
      await auditUnmute({
        actorId: caller.userId, projectId: caller.projectId, source: 'multi_undo',
        realActorUserId: realActor, exempted: 0, batchId: batch, items: auditItems,
      })
    }
    return featureModelErrorResponse('agent_outdated', 'multi_mute')
  }

  let exempted = 0
  let exemptionError: string | null = null
  if (batch) {
    if (items.length > 0) {
      await auditUnmute({
        actorId: caller.userId,
        projectId: caller.projectId,
        source: 'multi_undo',
        realActorUserId: realActor,
        exempted: 0,
        batchId: batch,
        items: auditItems,
      })
    }
    return NextResponse.json({
      unmuted: items.length,
      items,
      exempted: 0,
      skipped: Array.isArray(result.body.skipped) ? result.body.skipped : [],
    })
  }
  try {
    const result = await ensureExemptions(
      caller.projectId,
      items.map(i => ({ label: i?.label, key: i?.key })),
      { createdBy: caller.userId, realActorUserId: realActor },
    )
    exempted = result.total
  } catch (e) {
    // The graph unmute already happened and is not rolled back: the finding is
    // visible, which is what the operator asked for. What is lost is only the
    // guarantee that a rule will not mute it again, so the caller is told.
    console.error('[unmute] could not record node-filter exemptions:', e)
    exemptionError = 'Unmuted, but the exemption was not saved: a mute rule may mute it again.'
  }

  if (items.length > 0) {
    await auditUnmute({
      actorId: caller.userId,
      projectId: caller.projectId,
      source: 'ui',
      realActorUserId: realActor,
      exempted,
      items: items.map(i => ({ key: i.key, label: i.label, mutedBy: i.muted_by })),
    })
  }

  return NextResponse.json({
    unmuted: items.length,
    items,
    exempted,
    ...(exemptionError ? { exemptionError } : {}),
  })
})
