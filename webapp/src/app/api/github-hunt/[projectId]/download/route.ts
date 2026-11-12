import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { readFile } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'
import { internalError } from '@/lib/routeErrors'

// Path to GitHub hunt output directory (mounted volume or local path)
const GITHUB_HUNT_OUTPUT_PATH = process.env.GITHUB_HUNT_OUTPUT_PATH || '/data/github-hunt-output'

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
    const jsonFileName = `github_hunt_${projectId}.json`
    const jsonFilePath = path.join(GITHUB_HUNT_OUTPUT_PATH, jsonFileName)

    // Check if file exists
    if (!existsSync(jsonFilePath)) {
      return NextResponse.json(
        { error: 'GitHub hunt data not found. Run a GitHub Secret Hunt first.' },
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
    return internalError(error, 'Failed to download GitHub hunt data', { log: 'Error downloading GitHub hunt data' })
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

    const jsonFilePath = path.join(GITHUB_HUNT_OUTPUT_PATH, `github_hunt_${projectId}.json`)

    if (!existsSync(jsonFilePath)) {
      return new NextResponse(null, { status: 404 })
    }

    return new NextResponse(null, { status: 200 })

  } catch (error) {
    // A HEAD answer has no body, so the cause only reaches the log.
    console.error('Error checking GitHub hunt data:', error)
    return new NextResponse(null, { status: 500 })
  }
}
