import { NextRequest, NextResponse } from 'next/server'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; runId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, runId } = await params

    const response = await fetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial/${runId}/status`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return NextResponse.json(
        { error: errorData.detail || 'Failed to get partial recon status' },
        { status: response.status }
      )
    }

    const data = await response.json()
    return NextResponse.json(data)

  } catch (error) {
    if (error instanceof TypeError && error.message.includes('fetch')) {
      const { projectId, runId } = await params
      return NextResponse.json({
        project_id: projectId,
        run_id: runId,
        tool_id: '',
        status: 'idle',
        container_id: null,
        started_at: null,
        completed_at: null,
        error: null,
        stats: null,
      })
    }

    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
