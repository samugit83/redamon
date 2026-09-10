import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { getEffectiveUser } from '@/lib/session'
import { recordScanStart } from '@/lib/scanTimeline'
import prisma from '@/lib/prisma'
import { existsSync } from 'fs'
import path from 'path'
import { orchestratorFetch } from '@/lib/orchestrator'
import { normalizeOrchestratorStartError } from '@/lib/orchestratorError'
import { assertGraphNotActivating } from '@/lib/activationLock'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'
const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/home/samuele/Progetti didattici/RedAmon/recon/output'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    // Scan Timeline (Section 4A.3): a GitHub Secret Hunt writes finding nodes into
    // the live graph, so it must not start into an in-flight version swap.
    const __activating = await assertGraphNotActivating(projectId)
    if (__activating) return __activating

    // Verify project exists
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: {
        id: true, userId: true, name: true, targetDomain: true, ipMode: true, targetIps: true,
        domainBatchMode: true, domainBatchHosts: true,
      }
    })

    if (!project) {
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    if (project.ipMode) {
      if (!project.targetIps || project.targetIps.length === 0) {
        return NextResponse.json(
          { error: 'Project has no target IPs configured' },
          { status: 400 }
        )
      }
    } else if (project.domainBatchMode) {
      // A batch project has no single targetDomain; the hunt scopes itself from
      // its own org/repo settings and the merged recon file checked below.
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

    // Check that recon data exists - GitHub hunt requires prior recon
    const reconFilePath = path.join(RECON_OUTPUT_PATH, `recon_${projectId}.json`)
    if (!existsSync(reconFilePath)) {
      return NextResponse.json(
        { error: 'Recon data not found. Run a reconnaissance scan first before starting GitHub Secret Hunt.' },
        { status: 400 }
      )
    }

    // Call recon orchestrator to start the GitHub hunt
    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/github-hunt/${projectId}/start`, {
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

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      // Governor rejections carry a structured object detail; normalize to a
      // string message (+ limit) so it is never rendered as a raw React child.
      const { error, limit } = normalizeOrchestratorStartError(errorData, 'Failed to start GitHub Secret Hunt')
      return NextResponse.json(
        { error, ...(limit ? { limit } : {}) },
        { status: response.status }
      )
    }

    // The scan is live now: give it a history row. Only full recon used to get
    // one, so every other kind vanished from Run history the moment it ended.
    // The scan is already running: recording who started it must never be able
    // to turn a successful start into an error response.
    const __eff = await getEffectiveUser().catch(() => null)
    await recordScanStart({ projectId, kind: 'github_hunt', initiatedByUserId: __eff?.userId ?? null })

    const data = await response.json()
    return NextResponse.json(data)

  } catch (error) {
    console.error('Error starting GitHub Secret Hunt:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
