import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'

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
    const body = await request.json().catch(() => ({}))
    const deleteGraph = body?.deleteGraph === true

    // Verify project exists
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, userId: true, name: true, targetDomain: true, ipMode: true, targetIps: true }
    })

    if (!project) {
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    // IP mode needs targetIps; domain mode needs targetDomain
    if (project.ipMode) {
      if (!project.targetIps || project.targetIps.length === 0) {
        return NextResponse.json(
          { error: 'Project has no target IPs configured' },
          { status: 400 }
        )
      }
    } else if (!project.targetDomain) {
      return NextResponse.json(
        { error: 'Project has no target domain configured' },
        { status: 400 }
      )
    }

    // Call recon orchestrator to start the recon
    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        project_id: projectId,
        user_id: project.userId,
        webapp_api_url: WEBAPP_URL,
        delete_graph: deleteGraph,
      }),
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      const detail = errorData.detail
      // Memory governor (Part 5): a structured limit payload {limitType, ...}
      // becomes a tailored message + a `limit` field the UI modal keys off.
      if (detail && typeof detail === 'object' && detail.limitType) {
        const msg =
          detail.limitType === 'hard'
            ? `${detail.detail || 'Configured limit reached'}. This is a configured limit, not a memory issue${detail.settingName ? ` — increase ${detail.settingName} and restart` : ''}.`
            : `${detail.detail || 'Not enough memory to start this scan now'}. This is a RAM limit — please retry once memory frees (finish or stop other running scans, or lower parallelism).`
        return NextResponse.json({ error: msg, limit: detail }, { status: response.status })
      }
      return NextResponse.json(
        { error: (typeof detail === 'string' ? detail : null) || 'Failed to start recon' },
        { status: response.status }
      )
    }

    const data = await response.json()
    return NextResponse.json(data)

  } catch (error) {
    console.error('Error starting recon:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
