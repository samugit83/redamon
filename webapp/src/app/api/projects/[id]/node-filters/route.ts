/**
 * GET / PUT /api/projects/[id]/node-filters — the project's node-filter rules.
 *
 * GET is `triage:read`, so a person the project is shared with at Read sees the
 * rules; PUT is `node_filters:manage`, at the write level, because these rules
 * decide what the AI agent can see. Anyone the project is not visible to gets
 * 404. PUT refuses any document the engine
 * would not run as written, and a stale `revision` (409: someone saved in
 * between; resend with `force: true` to overwrite, which is audited as such).
 * PUT never arms or disarms: that is Apply's and Disarm's job.
 *
 * A PUT that loads a preset also carries `loadedPreset` ({ name, fingerprint },
 * or null to clear it). An ordinary save omits it and leaves the record alone:
 * the header only badges the name while the rules still hash to the fingerprint.
 * The fingerprint is computed here from the rules being stored, never taken
 * from the request, so it always describes exactly what was saved.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { readJsonBody } from '@/lib/jsonBody'
import { realActorUserId } from '@/lib/triageClient'
import { allErrors, validateNodeFilters } from '@/lib/nodeFilters/validate'
import { coerceDoc, type NodeFilterMode } from '@/lib/nodeFilters/model'
import { muteRulesFingerprint, parseLoadedPresetInput } from '@/lib/nodeFilters/presets'
import {
  RUN_SELECT, activeVersion, diffSummary, exemptionCounts, loadNodeFilter,
} from '@/lib/nodeFilters/server'
import { findLiveNodeFilterRun } from '@/lib/nodeFilterRun'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const auth = await requirePermission(request, 'triage:read', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)

  const [stored, exemptions, version, lastRun, lastCompleted, live] = await Promise.all([
    loadNodeFilter(caller.projectId),
    exemptionCounts(caller.projectId),
    activeVersion(caller.projectId),
    prisma.nodeFilterRun.findFirst({
      where: { projectId: caller.projectId }, orderBy: { startedAt: 'desc' }, select: RUN_SELECT,
    }),
    prisma.nodeFilterRun.findFirst({
      where: { projectId: caller.projectId, status: 'completed' }, orderBy: { startedAt: 'desc' },
      select: RUN_SELECT,
    }),
    findLiveNodeFilterRun(caller.projectId),
  ])
  return NextResponse.json({
    ...stored,
    exemptionCounts: exemptions,
    activeVersion: version,
    lastRun,
    lastCompleted,
    liveRunId: live?.id ?? null,
  })
}

export async function PUT(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const auth = await requirePermission(request, 'node_filters:manage', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)

  const { mode, rules, revision, force } = parsed.body as {
    mode?: unknown; rules?: unknown; revision?: unknown; force?: unknown
  }
  const presetGiven = 'loadedPreset' in parsed.body
  const preset = presetGiven ? parseLoadedPresetInput(parsed.body.loadedPreset) : null
  if (preset && !preset.ok) return NextResponse.json({ error: preset.error }, { status: 400 })
  const verdict = validateNodeFilters(mode, rules)
  const errors = allErrors(verdict)
  if (!verdict.ok || errors.length > 0) {
    return NextResponse.json({ error: 'The rules are not valid.', errors }, { status: 400 })
  }
  if (typeof revision !== 'number' || !Number.isInteger(revision) || revision < 0) {
    return NextResponse.json({ error: 'revision is required' }, { status: 400 })
  }

  const before = await loadNodeFilter(caller.projectId)
  const forced = force === true
  if (!forced && revision !== before.revision) {
    return NextResponse.json(
      { error: 'The rules changed elsewhere since you loaded them.', currentRevision: before.revision },
      { status: 409 },
    )
  }

  const doc = coerceDoc(rules)
  const presetData = preset?.ok
    ? {
        loadedPreset: preset.value === null
          ? Prisma.DbNull
          : { name: preset.value.name, fingerprint: muteRulesFingerprint(mode as NodeFilterMode, doc) },
      }
    : {}
  let nextRevision: number
  try {
    if (!before.exists) {
      await prisma.projectNodeFilter.create({
        data: {
          projectId: caller.projectId, mode: mode as string, rules: doc as never, revision: 1,
          updatedBy: caller.userId, ...presetData,
        },
      })
      nextRevision = 1
    } else {
      // Conditional on the revision just read, so two saves racing each other
      // cannot both land: the loser gets the same 409 as a stale page.
      const updated = await prisma.projectNodeFilter.updateMany({
        where: { projectId: caller.projectId, ...(forced ? {} : { revision: before.revision }) },
        data: {
          mode: mode as string, rules: doc as never, revision: { increment: 1 },
          updatedBy: caller.userId, ...presetData,
        },
      })
      if (updated.count !== 1) {
        return NextResponse.json({ error: 'The rules changed elsewhere since you loaded them.' }, { status: 409 })
      }
      const row = await prisma.projectNodeFilter.findUnique({
        where: { projectId: caller.projectId }, select: { revision: true },
      })
      nextRevision = row?.revision ?? before.revision + 1
    }
  } catch (e) {
    if ((e as { code?: string })?.code === 'P2002') {
      return NextResponse.json({ error: 'The rules changed elsewhere since you loaded them.' }, { status: 409 })
    }
    throw e
  }

  const realActor = await realActorUserId()
  await writeAudit({
    actorId: caller.userId,
    action: 'node_filters.saved',
    targetType: 'project',
    targetId: caller.projectId,
    before: { revision: before.revision, mode: before.mode },
    after: {
      revision: nextRevision, mode, forced, realActorUserId: realActor, ...diffSummary(before.rules, doc),
      ...(preset?.ok && preset.value ? { presetLoaded: preset.value.name } : {}),
    },
    source: 'ui',
  })
  if (before.mode !== mode) {
    await writeAudit({
      actorId: caller.userId,
      action: 'node_filters.mode_changed',
      targetType: 'project',
      targetId: caller.projectId,
      before: { mode: before.mode },
      after: { mode, revision: nextRevision, realActorUserId: realActor },
      source: 'ui',
    })
  }
  return NextResponse.json({ ok: true, revision: nextRevision, mode, applyToScans: before.applyToScans })
}
