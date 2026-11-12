/**
 * POST /api/projects/[id]/node-filters/apply — apply the SAVED rules.
 *
 * Body: { target: 'current' | 'scans' | 'both', versionId, revision }.
 *
 *  - `scans` arms the rules: every new full or partial recon applies them to
 *    what it writes. Nothing is changed now.
 *  - `current` applies them to the live graph now, as a tracked graph writer
 *    (a NodeFilterRun); `both` does both.
 *
 * In order, all fail-closed: the revision must be the saved one (the modal
 * applies what was saved, never a draft); a current-graph apply must target
 * the ACTIVE version, and nothing else may be writing the graph or activating
 * a version; then the run row is created (refused if one is already live) and
 * the agent is handed its id and nothing else.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { readJsonBody } from '@/lib/jsonBody'
import { realActorUserId } from '@/lib/triageClient'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import { isActivationInProgress } from '@/lib/activationLock'
import { RunAlreadyLiveError, createNodeFilterRun } from '@/lib/nodeFilterRun'
import { activeVersion, loadNodeFilter } from '@/lib/nodeFilters/server'
import { readUpstreamBody, upstreamFailure } from '@/lib/routeErrors'

const TARGETS = new Set(['current', 'scans', 'both'])

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET: whether "current graph" is possible right now, for the Apply modal.
 * The POST checks all of this again; this only lets the modal explain itself
 * before the operator clicks.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const auth = await requirePermission(request, 'triage:read', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)
  const [busy, version, activating] = await Promise.all([
    describeLiveGraphWriters(caller.projectId),
    activeVersion(caller.projectId),
    isActivationInProgress(caller.projectId),
  ])
  return NextResponse.json({
    busy: busy ?? (activating ? 'a version activation is in progress' : null),
    activeVersion: version,
  })
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const auth = await requirePermission(request, 'node_filters:manage', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)

  const { target, versionId, revision } = parsed.body as {
    target?: unknown; versionId?: unknown; revision?: unknown
  }
  if (typeof target !== 'string' || !TARGETS.has(target)) {
    return NextResponse.json({ error: 'target must be current, scans or both' }, { status: 400 })
  }
  const stored = await loadNodeFilter(caller.projectId)
  if (revision !== stored.revision) {
    return NextResponse.json(
      { error: 'The saved rules changed since this was opened. Reload and apply again.', currentRevision: stored.revision },
      { status: 409 },
    )
  }

  const realActor = await realActorUserId()
  const touchesGraph = target === 'current' || target === 'both'
  let runId: string | null = null

  if (touchesGraph) {
    const version = await activeVersion(caller.projectId)
    if ((versionId ?? null) !== (version?.id ?? null)) {
      return NextResponse.json(
        { error: 'Filters can only be applied to the active version. Switch back to it, or choose New scans only.' },
        { status: 409 },
      )
    }
    const busy = await describeLiveGraphWriters(caller.projectId)
    if (busy) {
      return NextResponse.json(
        { error: `Cannot apply to the current graph while ${busy}. Apply when it finishes, or choose New scans only.`, busy },
        { status: 409 },
      )
    }
    if (await isActivationInProgress(caller.projectId)) {
      return NextResponse.json({ error: 'A version activation is in progress.' }, { status: 409 })
    }

    try {
      const run = await createNodeFilterRun({
        projectId: caller.projectId,
        actorUserId: caller.userId,
        realActorUserId: realActor,
        target: target as 'current' | 'both',
        versionId: version?.id ?? '',
        revision: stored.revision,
        mode: stored.mode,
        rules: stored.rules,
      })
      runId = run.id
    } catch (e) {
      if (e instanceof RunAlreadyLiveError) {
        return NextResponse.json({ error: e.message, runId: e.runId }, { status: 409 })
      }
      throw e
    }

    // An activation can take its lock between the check above and the create.
    // It re-checks for a live run under its lock; this is the other half.
    if (await isActivationInProgress(caller.projectId)) {
      await prisma.nodeFilterRun.updateMany({
        where: { id: runId, status: 'running' },
        data: { status: 'failed', error: 'a version activation started', finishedAt: new Date() },
      })
      return NextResponse.json({ error: 'A version activation started. Try again when it finishes.' }, { status: 409 })
    }

    const failRun = async (why: string) => {
      await prisma.nodeFilterRun.updateMany({
        where: { id: runId!, status: 'running' },
        data: { status: 'failed', error: why.slice(0, 500), finishedAt: new Date() },
      })
    }
    try {
      const res = await agentFetch('/graph/node-filters/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_id: runId }),
      })
      if (res.status !== 202) {
        // The agent's refusals (`error`, or FastAPI's `detail` from its auth guard) are
        // sentences its own code writes, so they are shown as they are.
        const body = await readUpstreamBody(res)
        await failRun(body.text || `the agent answered ${res.status}`)
        return NextResponse.json(
          {
            error: body.text || 'The agent refused the apply.',
            code: body.code ?? 'agent_error',
            upstreamStatus: res.status,
          },
          { status: res.status >= 500 ? 502 : res.status },
        )
      }
    } catch (err) {
      const message = err instanceof AgentUnreachableError ? err.message : 'Cannot reach the agent.'
      await failRun(message)
      const failure = upstreamFailure('agent', err instanceof AgentUnreachableError ? err.cause_ : err, message)
      return NextResponse.json(failure.body, { status: failure.status })
    }

    await writeAudit({
      actorId: caller.userId,
      action: 'node_filters.applied',
      targetType: 'project',
      targetId: caller.projectId,
      after: { runId, target, versionId: version?.id ?? null, revision: stored.revision, mode: stored.mode, realActorUserId: realActor },
      source: 'ui',
    })
  }

  let armed = stored.applyToScans
  if (target === 'scans' || target === 'both') {
    await prisma.projectNodeFilter.upsert({
      where: { projectId: caller.projectId },
      create: { projectId: caller.projectId, applyToScans: true, updatedBy: caller.userId },
      update: { applyToScans: true },
    })
    armed = true
    if (!stored.applyToScans) {
      await writeAudit({
        actorId: caller.userId,
        action: 'node_filters.armed',
        targetType: 'project',
        targetId: caller.projectId,
        after: { revision: stored.revision, mode: stored.mode, realActorUserId: realActor },
        source: 'ui',
      })
    }
  }

  return NextResponse.json({ runId, armed }, { status: runId ? 202 : 200 })
}
