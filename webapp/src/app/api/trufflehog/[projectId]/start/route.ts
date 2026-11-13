import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { getEffectiveUser } from '@/lib/session'
import { recordScanStart } from '@/lib/scanTimeline'
import { currentRoeTextSha256 } from '@/lib/engagement'
import { assertEngagementStartable } from '@/lib/engagementGate'
import { orchestratorFetch } from '@/lib/orchestrator'
import { scanStartFields } from '@/lib/scanJobCredential'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'
import { internalError, readUpstreamBody, upstreamFailureResponse } from '@/lib/routeErrors'
import { assertGraphNotActivating } from '@/lib/activationLock'
import { startUnderGraphLock } from '@/lib/startScan'
import { resolveTrufflehogStart } from '@/lib/trufflehogStart'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

/**
 * Start ONE TruffleHog source.
 *
 * The body names the source (or the profile that defines it); everything else —
 * the target config, the shared options, the credential — is resolved
 * server-side. The run key is the source, so a second run of the same source is
 * refused while other sources start freely.
 *
 * There is deliberately no "recon data must exist" precondition any more. It
 * made sense when the only target was a GitHub org derived from recon; a Docker
 * image or an S3 bucket has nothing to do with the recon graph, and the real
 * authorization gate is the orchestrator's scope/ROE and egress checks.
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:secrets', { projectId })
    if (auth instanceof NextResponse) return auth

    // S-4: held from the activation check through the orchestrator's answer
    // (startUnderGraphLock), since the run writes the live graph.
    return await startUnderGraphLock(projectId, () => startTrufflehogScan(request, projectId, auth.effective.userId))
  } catch (error) {
    return internalError(error, 'Failed to start Secret Multiscanner scan', { log: 'Error starting TruffleHog scan' })
  }
}

async function startTrufflehogScan(request: NextRequest, projectId: string, actorUserId: string): Promise<NextResponse> {
  // A TruffleHog scan writes finding nodes into the live graph, so it must not
  // start into an in-flight version swap.
  const __activating = await assertGraphNotActivating(projectId)
  if (__activating) return __activating

  const body = await request.json().catch(() => ({}))
  const resolved = await resolveTrufflehogStart(projectId, {
    profileId: typeof body.profileId === 'string' ? body.profileId : undefined,
    source: typeof body.source === 'string' ? body.source : undefined,
    webappUrl: WEBAPP_URL,
  })
  if (!resolved.ok) {
    return NextResponse.json({ error: resolved.error }, { status: resolved.status })
  }

  const engagementBlocked = await assertEngagementStartable(projectId)
  if (engagementBlocked) return engagementBlocked

  // Read before the start, so a RoE replaced mid-start cannot misattribute the run.
  const roeTextSha256 = await currentRoeTextSha256(projectId)
  const jobFields = await scanStartFields(projectId, resolved.body.user_id, actorUserId)
  let response: Response
  try {
    response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/start`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...resolved.body, ...jobFields }),
      },
    )
  } catch (error) {
    return upstreamFailureResponse('orchestrator', error, 'Failed to start Secret Multiscanner scan')
  }

  if (!response.ok) {
    // Governor rejections carry a structured object detail; normalize to a
    // string message (+ limit) so it is never rendered as a raw React child.
    // A body that is not JSON (uvicorn's plain-text 500) still says which
    // status the orchestrator answered.
    const upstream = await readUpstreamBody(response)
    const { error, limit, code } = normalizeOrchestratorStartError(
      upstream.json ?? {}, 'Failed to start Secret Multiscanner scan',
    )
    return NextResponse.json(
      { error, code: code ?? upstream.code ?? 'orchestrator_error', upstreamStatus: response.status, ...(limit ? { limit } : {}) },
      { status: response.status },
    )
  }

  // runId is the source: without it the reconcile closes only the newest of N
  // parallel rows and the rest stick at `running` forever.
  const __eff = await getEffectiveUser().catch(() => null)
  await recordScanStart({
    roeTextSha256,
    projectId,
    kind: 'trufflehog',
    runId: resolved.source,
    initiatedByUserId: __eff?.userId ?? null,
  })

  return NextResponse.json(await response.json())
}
