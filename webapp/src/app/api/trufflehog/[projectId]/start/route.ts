import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { existsSync } from 'fs'
import path from 'path'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'
const RECON_OUTPUT_PATH = process.env.RECON_OUTPUT_PATH || '/home/samuele/Progetti didattici/RedAmon/recon/output'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params

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

    if (project.ipMode) {
      if (!project.targetIps || project.targetIps.length === 0) {
        return NextResponse.json(
          { error: 'Project has no target IPs configured' },
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

    // Check that recon data exists - TruffleHog requires prior recon
    const reconFilePath = path.join(RECON_OUTPUT_PATH, `recon_${projectId}.json`)
    if (!existsSync(reconFilePath)) {
      return NextResponse.json(
        { error: 'Recon data not found. Run a reconnaissance scan first before starting TruffleHog scan.' },
        { status: 400 }
      )
    }

    // Call recon orchestrator to start the TruffleHog scan
    const response = await fetch(`${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/start`, {
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
      return NextResponse.json(
        { error: errorData.detail || 'Failed to start TruffleHog scan' },
        { status: response.status }
      )
    }

    const data = await response.json()
    return NextResponse.json(data)

  } catch (error) {
    console.error('Error starting TruffleHog scan:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
