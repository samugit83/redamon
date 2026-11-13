import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { getEffectiveUser } from '@/lib/session'
import { recordScanStart } from '@/lib/scanTimeline'
import { currentRoeTextSha256 } from '@/lib/engagement'
import { assertEngagementStartable } from '@/lib/engagementGate'
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { scanJobCredential } from '@/lib/scanJobCredential'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'
import { internalError, readUpstreamBody, upstreamFailureResponse } from '@/lib/routeErrors'
import { assertGraphNotActivating } from '@/lib/activationLock'
import { startUnderGraphLock } from '@/lib/startScan'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:supply_chain', { projectId })
    if (auth instanceof NextResponse) return auth

    // S-4: held from the activation check through the orchestrator's answer
    // (startUnderGraphLock), since the run writes the live graph.
    return await startUnderGraphLock(projectId, () => startSupplyChainScan(projectId, auth.effective.userId))
  } catch (error) {
    return internalError(error, 'Failed to start Supply-Chain scan', { log: 'Error starting Supply-Chain scan' })
  }
}

async function startSupplyChainScan(projectId: string, actorUserId: string): Promise<NextResponse> {
  // A supply-chain scan writes Package/MalPackageFinding nodes into the live
  // graph, so it must not start into an in-flight version swap.
  const __activating = await assertGraphNotActivating(projectId)
  if (__activating) return __activating

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: {
      id: true, userId: true, supplyChainSbomFile: true,
      supplyChainInputMode: true, supplyChainRepoUrl: true,
    },
  })
  if (!project) {
    return NextResponse.json({ error: 'Project not found' }, { status: 404 })
  }

  const engagementBlocked = await assertEngagementStartable(projectId)
  if (engagementBlocked) return engagementBlocked

  // Gate on the source the operator actually selected. Checking only the
  // uploaded file would refuse to start a perfectly valid GitHub scan, and
  // checking neither would start a scan with no input at all.
  if (project.supplyChainInputMode === 'org') {
    // Not an input this scan can read: the org mode queues one scan per repo
    // (supply_chain_repo) instead of running the project's single scan.
    return NextResponse.json(
      { error: 'This project scans a GitHub organization. Use "Queue org batch" in Other Scans, '
        + 'or set an SBOM/repository input in project settings.' },
      { status: 400 }
    )
  } else if (project.supplyChainInputMode === 'github') {
    if (!project.supplyChainRepoUrl) {
      return NextResponse.json(
        { error: 'No repository set. Add a GitHub repository under Project Settings -> Other Scans -> Supply Chain Scanner first.' },
        { status: 400 }
      )
    }
  } else if (!project.supplyChainSbomFile) {
    return NextResponse.json(
      { error: 'No SBOM/lockfile uploaded. Upload one under Project Settings -> Other Scans -> Supply Chain Scanner first.' },
      { status: 400 }
    )
  }

  // Read before the start, so a RoE replaced mid-start cannot misattribute the run.
  const roeTextSha256 = await currentRoeTextSha256(projectId)
  let response: Response
  try {
    response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/supply-chain/${projectId}/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId,
        user_id: project.userId,
        ...scanJobCredential(projectId, project.userId, actorUserId),
        webapp_api_url: WEBAPP_URL,
      }),
    })
  } catch (error) {
    return upstreamFailureResponse('orchestrator', error, 'Failed to start Supply-Chain scan')
  }

  if (!response.ok) {
    // A body that is not JSON (uvicorn's plain-text 500) still says which
    // status the orchestrator answered.
    const body = await readUpstreamBody(response)
    const { error, limit, code } = normalizeOrchestratorStartError(body.json ?? {}, 'Failed to start Supply-Chain scan')
    return NextResponse.json(
      { error, code: code ?? body.code ?? 'orchestrator_error', upstreamStatus: response.status, ...(limit ? { limit } : {}) },
      { status: response.status },
    )
  }

  // The scan is live now: give it a history row. Only full recon used to get
  // one, so every other kind vanished from Run history the moment it ended.
  // The scan is already running: recording who started it must never be able
  // to turn a successful start into an error response.
  const __eff = await getEffectiveUser().catch(() => null)
  await recordScanStart({ roeTextSha256, projectId, kind: 'supply_chain', initiatedByUserId: __eff?.userId ?? null })

  return NextResponse.json(await response.json())
}
