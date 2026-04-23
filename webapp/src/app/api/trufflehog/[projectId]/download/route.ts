import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { readFile } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'

// Path to TruffleHog output directory (mounted volume or local path)
const TRUFFLEHOG_OUTPUT_PATH = process.env.TRUFFLEHOG_OUTPUT_PATH || '/home/samuele/Progetti didattici/RedAmon/trufflehog_scan/output'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params

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
    const jsonFileName = `trufflehog_${projectId}.json`
    const jsonFilePath = path.join(TRUFFLEHOG_OUTPUT_PATH, jsonFileName)

    // Check if file exists
    if (!existsSync(jsonFilePath)) {
      return NextResponse.json(
        { error: 'TruffleHog data not found. Run a TruffleHog scan first.' },
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
    console.error('Error downloading TruffleHog data:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}

// Also support HEAD request to check if data exists
export async function HEAD(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params

    // Verify project exists
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true }
    })

    if (!project) {
      return new NextResponse(null, { status: 404 })
    }

    const jsonFilePath = path.join(TRUFFLEHOG_OUTPUT_PATH, `trufflehog_${projectId}.json`)

    if (!existsSync(jsonFilePath)) {
      return new NextResponse(null, { status: 404 })
    }

    return new NextResponse(null, { status: 200 })

  } catch {
    return new NextResponse(null, { status: 500 })
  }
}
