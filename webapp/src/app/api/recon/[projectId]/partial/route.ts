import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { getEffectiveUser } from '@/lib/session'
import { recordScanStart } from '@/lib/scanTimeline'
import { currentRoeTextSha256 } from '@/lib/engagement'
import { assertEngagementStartable } from '@/lib/engagementGate'
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { scanJobCredential } from '@/lib/scanJobCredential'
import { assertGraphNotActivating } from '@/lib/activationLock'
import { describeNodeFilterWriter } from '@/lib/nodeFilterRun'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'
import { legacyGraphDomains, legacyGraphRefusal } from '@/lib/legacyGraph'
import { resolveScopeGroups } from '@/lib/scopeGroups'
import { classifyOrchestratorThrow } from '@/lib/startFullScan'
import { startUnderGraphLock } from '@/lib/startScan'
import { internalError } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    // S-4: held from the activation check through the orchestrator's answer
    // (startUnderGraphLock), since the run writes the live graph.
    return await startUnderGraphLock(projectId, () => startPartialRecon(request, projectId))
  } catch (error) {
    return internalError(error, 'Failed to start partial recon', { log: 'Error starting partial recon' })
  }
}

async function startPartialRecon(request: NextRequest, projectId: string): Promise<NextResponse> {
  // Scan Timeline 4A.3: a partial recon writes the live graph, so it must not
  // start while a version activation is swapping it.
  const activating = await assertGraphNotActivating(projectId)
  if (activating) return activating
  // Nor while mute rules are being applied: the apply and the scan would
  // race for the same findings' mute state.
  const applying = await describeNodeFilterWriter(projectId)
  if (applying) {
    return NextResponse.json(
      { error: `Cannot start a partial recon while ${applying}. Try again when it finishes.` },
      { status: 409 },
    )
  }

  const body = await request.json()

  // Verify project exists
  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: {
      id: true, userId: true, targetDomain: true, subdomainList: true,
      ipMode: true, domainBatchMode: true, domainBatchHosts: true,
    },
  })

  if (!project) {
    return NextResponse.json({ error: 'Project not found' }, { status: 404 })
  }

  const engagementBlocked = await assertEngagementStartable(projectId)
  if (engagementBlocked) return engagementBlocked

  // A graph built under the old scope model would take this run's results
  // under the wrong Domain node; only a full recon rebuilds it (§4.11.6).
  const legacy = await legacyGraphDomains(project.userId, projectId, resolveScopeGroups(project).groups)
  if (legacy && legacy.length > 0) {
    return NextResponse.json(legacyGraphRefusal(legacy), { status: 409 })
  }

  // Forward to orchestrator
  // Read before the start, so a RoE replaced mid-start cannot misattribute the run.
  const roeTextSha256 = await currentRoeTextSha256(projectId)
  let response: Response
  try {
    response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId,
        user_id: project.userId,
        ...scanJobCredential(projectId, project.userId),
        webapp_api_url: WEBAPP_URL,
        tool_id: body.tool_id,
        graph_inputs: body.graph_inputs,
        user_inputs: body.user_inputs || [],
        user_targets: body.user_targets || null,
        include_graph_targets: body.include_graph_targets ?? true,
        settings_overrides: body.settings_overrides || {},
      }),
    })
  } catch (err) {
    console.error('Partial recon start got no answer from the orchestrator:', err)
    const thrown = classifyOrchestratorThrow(err)
    const why = { code: thrown.code, ...(thrown.cause ? { cause: thrown.cause } : {}) }
    // Partial runs may run in parallel, so retrying a start that may have
    // happened can launch a second one: the caller is told which case it is.
    return NextResponse.json(
      thrown.outcomeUnknown
        ? {
            error: 'The orchestrator did not answer, so it is unknown whether the partial recon started. '
              + 'Check the running partial recons before retrying.',
            startOutcome: 'unknown',
            ...why,
          }
        : { error: 'The orchestrator could not be reached, so the partial recon was not started.', ...why },
      { status: thrown.status },
    )
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}))
    // Governor rejections carry a structured object detail; normalize to a
    // string message (+ limit) so it is never rendered as a raw React child.
    const { error, limit, code } = normalizeOrchestratorStartError(errorData, 'Failed to start partial recon')
    return NextResponse.json(
      { error, ...(limit ? { limit } : {}), ...(code ? { code } : {}), upstreamStatus: response.status },
      { status: response.status }
    )
  }

  const data = await response.json()
  // Run-keyed: several partial recons can be in flight for one project, so the
  // history row carries the orchestrator run id that identifies this one.
  // The scan is already running: recording who started it must never be able
  // to turn a successful start into an error response.
  const __eff = await getEffectiveUser().catch(() => null)
  await recordScanStart({
    roeTextSha256,
    projectId,
    kind: 'partial_recon',
    runId: typeof data?.run_id === 'string' ? data.run_id : '',
    initiatedByUserId: __eff?.userId ?? null,
    // The scope the orchestrator actually granted, not what the client asked for.
    targets: Array.isArray(data?.roots)
      ? data.roots.filter((r: unknown): r is string => typeof r === 'string')
      : [],
  })
  return NextResponse.json(data)
}
