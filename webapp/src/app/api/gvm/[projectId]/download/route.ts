import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { readFile } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { internalError } from '@/lib/routeErrors'

// Path to GVM scan output directory (mounted volume or local path)
const GVM_OUTPUT_PATH = process.env.GVM_OUTPUT_PATH || '/data/gvm-output'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth

    // Verify project exists
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, name: true }
    })

    if (!project) {
      return NextResponse.json(
        { error: 'Project not found' },
        { status: 404 }
      )
    }

    // Construct the JSON file path using projectId
    const jsonFileName = `gvm_${projectId}.json`
    const jsonFilePath = path.join(GVM_OUTPUT_PATH, jsonFileName)

    // Check if file exists
    if (!existsSync(jsonFilePath)) {
      return NextResponse.json(
        { error: 'GVM scan data not found. Run a GVM vulnerability scan first.' },
        { status: 404 }
      )
    }

    // Read the file
    const fileContent = await readFile(jsonFilePath, 'utf-8')

    // Return as downloadable JSON
    return new NextResponse(fileContent, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="${jsonFileName}"`,
        'Cache-Control': 'no-cache',
      },
    })

  } catch (error) {
    return internalError(error, 'Failed to download GVM scan data', { log: 'Error downloading GVM scan data' })
  }
}

// Also support HEAD request to check if data exists
export async function HEAD(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth

    // Verify project exists
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true }
    })

    if (!project) {
      return new NextResponse(null, { status: 404 })
    }

    const jsonFilePath = path.join(GVM_OUTPUT_PATH, `gvm_${projectId}.json`)

    if (!existsSync(jsonFilePath)) {
      return new NextResponse(null, { status: 404 })
    }

    return new NextResponse(null, { status: 200 })

  } catch (error) {
    // A HEAD answer has no body, so the cause only reaches the log.
    console.error('Error checking GVM scan data:', error)
    return new NextResponse(null, { status: 500 })
  }
}
