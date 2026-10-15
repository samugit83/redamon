/**
 * Scan change timeline entry (help-wanted: scan history + change timeline UI).
 *
 * GET /api/projects/[id]/scans/[jobId]/changes — the stored ScanChange for a
 * run (404 when the run predates change tracking or belongs to another
 * project; cross-project ids report 404, never 403, per repo anti-enum
 * convention).
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'

interface RouteParams {
  params: Promise<{ id: string; jobId: string }>
}

export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { id, jobId } = await params
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, id)
  if (access instanceof NextResponse) return access

  try {
    const change = await prisma.scanChange.findUnique({ where: { scanJobId: jobId } })
    if (!change || change.projectId !== id) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }
    return NextResponse.json({ change }, { headers: { 'Cache-Control': 'private, no-cache' } })
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to load changes' },
      { status: 500 }
    )
  }
}
