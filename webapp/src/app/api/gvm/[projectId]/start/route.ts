import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { getEffectiveUser } from '@/lib/session'
import { recordScanStart } from '@/lib/scanTimeline'
import { currentRoeTextSha256 } from '@/lib/engagement'
import { assertEngagementStartable } from '@/lib/engagementGate'
import prisma from '@/lib/prisma'
import { existsSync } from 'fs'
import path from 'path'
import { orchestratorFetch } from '@/lib/orchestrator'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'
import { internalError, readUpstreamBody, upstreamFailureResponse } from '@/lib/routeErrors'
import { assertGraphNotActivating } from '@/lib/activationLock'
import { legacyGraphDomains, legacyGraphRefusal } from '@/lib/legacyGraph'
import { resolveScopeGroups } from '@/lib/scopeGroups'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'
const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/data/recon-output'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    // Scan Timeline (Section 4A.3): a GVM scan writes finding nodes into the live
    // graph, so it must not start into an in-flight version swap.
    const __activating = await assertGraphNotActivating(projectId)
    if (__activating) return __activating

    // Verify project exists
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: {
        id: true, userId: true, name: true, targetDomain: true, ipMode: true, targetIps: true,
        domainBatchMode: true, domainBatchHosts: true, subdomainList: true,
      }
    })

    if (!project) {
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    const engagementBlocked = await assertEngagementStartable(projectId)
    if (engagementBlocked) return engagementBlocked

    if (project.ipMode) {
      if (!project.targetIps || project.targetIps.length === 0) {
        return NextResponse.json(
          { error: 'Project has no target IPs configured' },
          { status: 400 }
        )
      }
    } else if (project.domainBatchMode) {
      // A batch project has no single targetDomain. GVM takes its scope from the
      // recon output file (checked just below), which the batch merges across all
      // its groups, so the host list existing is the only precondition here.
      if (!project.domainBatchHosts || project.domainBatchHosts.length === 0) {
        return NextResponse.json(
          { error: 'Project has no domain batch hostnames configured' },
          { status: 400 }
        )
      }
    } else {
      if (!project.targetDomain) {
        return NextResponse.json(
          { error: 'Project has no target domain configured' },
          { status: 400 }
        )
      }
    }

    // Check that recon data exists - GVM scan requires prior recon
    const reconFilePath = path.join(RECON_OUTPUT_PATH, `recon_${projectId}.json`)
    if (!existsSync(reconFilePath)) {
      return NextResponse.json(
        { error: 'Recon data not found. Run a reconnaissance scan first before starting GVM vulnerability scan.' },
        { status: 400 }
      )
    }

    // GVM attaches its findings to Domain nodes: an old-model graph would take
    // them under the wrong one (§4.11.6).
    const legacy = await legacyGraphDomains(project.userId, projectId, resolveScopeGroups(project).groups)
    if (legacy && legacy.length > 0) {
      return NextResponse.json(legacyGraphRefusal(legacy), { status: 409 })
    }

    // Call recon orchestrator to start the GVM scan
    // Read before the start, so a RoE replaced mid-start cannot misattribute the run.
    const roeTextSha256 = await currentRoeTextSha256(projectId)
    let response: Response
    try {
      response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/gvm/${projectId}/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          project_id: projectId,
          user_id: project.userId,
          webapp_api_url: WEBAPP_URL,
        }),
      })
    } catch (error) {
      return upstreamFailureResponse('orchestrator', error, 'Failed to start GVM scan')
    }

    if (!response.ok) {
      // Governor rejections carry a structured object detail; normalize to a
      // string message (+ limit) so it is never rendered as a raw React child.
      // A body that is not JSON (uvicorn's plain-text 500) still says which
      // status the orchestrator answered.
      const body = await readUpstreamBody(response)
      const { error, limit, code } = normalizeOrchestratorStartError(body.json ?? {}, 'Failed to start GVM scan')
      return NextResponse.json(
        { error, code: code ?? body.code ?? 'orchestrator_error', upstreamStatus: response.status, ...(limit ? { limit } : {}) },
        { status: response.status }
      )
    }

    // The scan is live now: give it a history row. Only full recon used to get
    // one, so every other kind vanished from Run history the moment it ended.
    // The scan is already running: recording who started it must never be able
    // to turn a successful start into an error response.
    const __eff = await getEffectiveUser().catch(() => null)
    await recordScanStart({ roeTextSha256, projectId, kind: 'gvm', initiatedByUserId: __eff?.userId ?? null })

    const data = await response.json()
    return NextResponse.json(data)

  } catch (error) {
    return internalError(error, 'Failed to start GVM scan', { log: 'Error starting GVM scan' })
  }
}
