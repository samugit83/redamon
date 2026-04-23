import { NextRequest, NextResponse } from 'next/server'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params

    // Call recon orchestrator to get TruffleHog status
    const response = await fetch(`${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/status`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return NextResponse.json(
        { error: errorData.detail || 'Failed to get TruffleHog status' },
        { status: response.status }
      )
    }

    const data = await response.json()
    return NextResponse.json(data)

  } catch (error) {
    console.error('Error getting TruffleHog status:', error)

    // If orchestrator is not available, return idle status
    if (error instanceof TypeError && error.message.includes('fetch')) {
      return NextResponse.json({
        project_id: (await params).projectId,
        status: 'idle',
        current_phase: null,
        phase_number: null,
        total_phases: 3,
        started_at: null,
        completed_at: null,
        error: null,
      })
    }

    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
