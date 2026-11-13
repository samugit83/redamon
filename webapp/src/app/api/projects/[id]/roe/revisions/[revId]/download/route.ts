import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import { writeAudit } from '@/lib/audit'
import { actingAdminId } from '@/lib/roe/actor'
import { attachmentDisposition, downloadContentType } from '@/lib/roe/limits'
import { ROE_DOCUMENT_OWNER_ONLY, ownerOnlyRefusal } from '@/lib/authz/projectReadView'

// GET /api/projects/[id]/roe/revisions/[revId]/download - One superseded RoE document.
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string; revId: string }> }
) {
  try {
    const { id, revId } = await params
    const auth = await requirePermission(request, 'roe:read', { projectId: id })
    if (auth instanceof NextResponse) return auth
    // A superseded document is still the client's document: the owner's only (OQ-53).
    const refused = ownerOnlyRefusal(auth.access, 'roe:read', ROE_DOCUMENT_OWNER_ONLY)
    if (refused) return refused
    const eff = auth.effective

    // Scoped by project as well as id: a revision id from another project is not found.
    const revision = await prisma.roeDocumentRevision.findFirst({
      where: { id: revId, projectId: id },
      select: { data: true, documentName: true, mimeType: true },
    })
    if (!revision || !revision.data) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }

    await writeAudit({
      actorId: eff.userId,
      action: 'project.roe.download',
      targetType: 'project',
      targetId: id,
      after: {
        revisionId: revId,
        documentName: revision.documentName,
        bytes: revision.data.length,
        actingAdminId: await actingAdminId(eff),
      },
    })

    return new NextResponse(revision.data, {
      headers: {
        'Content-Type': downloadContentType(revision.mimeType),
        'Content-Disposition': attachmentDisposition(revision.documentName || 'roe-document'),
        'Content-Length': String(revision.data.length),
        'X-Content-Type-Options': 'nosniff',
      },
    })
  } catch (error) {
    return internalError(error, 'Failed to download the RoE revision', { log: 'RoE revision download error' })
  }
}
