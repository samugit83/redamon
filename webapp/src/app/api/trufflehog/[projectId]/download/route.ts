import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { readFile, readdir } from 'fs/promises'
import path from 'path'
import { TRUFFLEHOG_SOURCE_IDS } from '@/lib/trufflehogSources'
import { internalError } from '@/lib/routeErrors'

// Path to TruffleHog output directory (mounted volume or local path)
const TRUFFLEHOG_OUTPUT_PATH = process.env.TRUFFLEHOG_OUTPUT_PATH || '/data/trufflehog-output'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

/** Filenames the orchestrator writes: one per (project, source). Kept in sync
 *  with `_trufflehog_output_name` in container_manager.py. */
function outputPrefix(projectId: string): string {
  return `trufflehog_${projectId.replace(/[^a-zA-Z0-9_.-]/g, '_')}_`
}

/**
 * The exact filenames this project owns.
 *
 * A bare `startsWith(prefix)` also matches another project whose id begins with
 * this one plus an underscore — `trufflehog_projA_` matches
 * `trufflehog_projA_x_github.json`. Fixed-length cuids make that unreachable
 * today, but it is one id-format change away from serving another project's
 * findings, so the suffix is matched against the known source ids instead.
 */
function ownedFilenames(projectId: string): Set<string> {
  const prefix = outputPrefix(projectId)
  return new Set(TRUFFLEHOG_SOURCE_IDS.map(source => `${prefix}${source}.json`))
}

/**
 * Every source's findings file for a project.
 *
 * Sources run independently, so there is one artifact per source rather than one
 * per project. Returning only the newest would silently hide the other runs, and
 * that is exactly what the operator downloads this to check.
 */
async function findRunFiles(projectId: string): Promise<string[]> {
  const owned = ownedFilenames(projectId)
  try {
    const entries = await readdir(TRUFFLEHOG_OUTPUT_PATH)
    return entries
      .filter(name => owned.has(name))
      .sort()
      .map(name => path.join(TRUFFLEHOG_OUTPUT_PATH, name))
  } catch {
    return []
  }
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, name: true },
    })
    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    const files = await findRunFiles(projectId)
    if (files.length === 0) {
      return NextResponse.json(
        { error: 'Secret Multiscanner data not found. Run a Secret Multiscanner scan first.' },
        { status: 404 },
      )
    }

    const runs = []
    for (const file of files) {
      try {
        runs.push(JSON.parse(await readFile(file, 'utf-8')))
      } catch {
        // One unreadable artifact must not lose the other sources' results.
      }
    }

    const body = JSON.stringify({
      project_id: projectId,
      project_name: project.name,
      runs,
      total_findings: runs.reduce((n, r) => n + (r?.findings?.length ?? 0), 0),
    }, null, 2)

    return new NextResponse(body, {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="trufflehog_${projectId}.json"`,
        'Cache-Control': 'no-cache',
      },
    })
  } catch (error) {
    return internalError(error, 'Failed to download Secret Multiscanner data', { log: 'Error downloading TruffleHog data' })
  }
}

/** HEAD drives the Download button's enabled state. */
export async function HEAD(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth

    const files = await findRunFiles(projectId)
    return new NextResponse(null, { status: files.length > 0 ? 200 : 404 })
  } catch (error) {
    // A HEAD answer has no body, so the cause only reaches the log.
    console.error('Error checking TruffleHog data:', error)
    return new NextResponse(null, { status: 500 })
  }
}
