import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import { writeAudit } from '@/lib/audit'
import { actingAdminId } from '@/lib/roe/actor'
import { attachmentDisposition, downloadContentType } from '@/lib/roe/limits'
import { ROE_DOCUMENT_OWNER_ONLY, ownerOnlyRefusal } from '@/lib/authz/projectReadView'

// GET /api/projects/[id]/roe/download - Download the original RoE document
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params

    // The document names the client, their contacts and what may be attacked:
    // it stays the owner's even on a shared project (OQ-53), whatever roe:read reaches.
    const auth = await requirePermission(request, 'roe:read', { projectId: id })
    if (auth instanceof NextResponse) return auth
    const refused = ownerOnlyRefusal(auth.access, 'roe:read', ROE_DOCUMENT_OWNER_ONLY)
    if (refused) return refused
    const eff = auth.effective

    const project = await prisma.project.findUnique({
      where: { id },
      select: {
        roeDocumentData: true,
        roeDocumentName: true,
        roeDocumentMimeType: true,
      },
    })

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    if (!project.roeDocumentData) {
      return NextResponse.json({ error: 'No RoE document uploaded' }, { status: 404 })
    }

    const fileName = project.roeDocumentName || 'roe-document'

    await writeAudit({
      actorId: eff.userId,
      action: 'project.roe.download',
      targetType: 'project',
      targetId: id,
      after: {
        documentName: fileName,
        bytes: project.roeDocumentData.length,
        actingAdminId: await actingAdminId(eff),
      },
    })

    return new NextResponse(project.roeDocumentData, {
      headers: {
        'Content-Type': downloadContentType(project.roeDocumentMimeType),
        'Content-Disposition': attachmentDisposition(fileName),
        'Content-Length': String(project.roeDocumentData.length),
        'X-Content-Type-Options': 'nosniff',
      },
    })
  } catch (error) {
    return internalError(error, 'Failed to download RoE document', { log: 'RoE download error' })
  }
}
