import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'

// GET /api/projects/[id]/roe/revisions - The superseded RoE documents, newest first.
// Metadata only: the bytes come from .../revisions/[revId]/download.
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    const auth = await requirePermission(request, 'roe:read', { projectId: id })
    if (auth instanceof NextResponse) return auth

    const revisions = await prisma.roeDocumentRevision.findMany({
      where: { projectId: id },
      orderBy: { supersededAt: 'desc' },
      select: {
        id: true, documentName: true, mimeType: true, bytesSha256: true, textSha256: true,
        appliedAt: true, supersededAt: true, supersededById: true, reason: true,
      },
    })
    return NextResponse.json({ revisions })
  } catch (error) {
    return internalError(error, 'Failed to list RoE revisions', { log: 'RoE revisions error' })
  }
}
