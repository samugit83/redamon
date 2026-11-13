import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import { requirePermission } from '@/lib/authz/guards'
import { readCapturedBody } from '@/lib/captureBodies'
import { trafficRows } from '../trafficTenant'

// GET /api/traffic/[projectId]/[id] - full transaction including headers + bodies.
// Tenant-enforced: the guard admits the caller to the project (traffic:read is R*:
// the owner, a share with Raw data & files), and the row must belong to the project
// under its owner (trafficRows). A cross-tenant id returns 404 (anti-enumeration),
// identical to a non-existent id.
//
// Phase 0 stores bodies inline (size-capped at ingest). Disk-offloaded bodies
// (*_body_ref) arrive with the Phase 1 content-addressed store; when that lands,
// this handler will read the blob from disk when reqBodyRef/respBodyRef is set.
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ projectId: string; id: string }> },
) {
  try {
    const { projectId, id } = await params

    const auth = await requirePermission(request, 'traffic:read', { projectId })
    if (auth instanceof NextResponse) return auth

    const row = await prisma.capturedHttpTransaction.findFirst({
      where: { id, ...trafficRows(projectId, auth) },
    })
    if (!row) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }

    // Resolve offloaded bodies from the content-addressed store. Served only via
    // this owned row, never by raw sha path (§15.7). Inline bodies pass through.
    if (!row.reqBody && row.reqBodyRef) {
      row.reqBody = await readCapturedBody(row.reqBodyRef)
    }
    if (!row.respBody && row.respBodyRef) {
      row.respBody = await readCapturedBody(row.respBodyRef)
    }

    return NextResponse.json(row)
  } catch (error) {
    return internalError(error, 'Failed to load transaction', { log: 'Failed to load captured transaction' })
  }
}
