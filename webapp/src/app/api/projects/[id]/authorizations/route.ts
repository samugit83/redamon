/**
 * The append-only record of what authorized this engagement.
 *
 * Read-only by construction. There is no POST, PUT or DELETE here and there must
 * not be: a record an operator can rewrite from a browser is not evidence, and
 * the Postgres trigger would refuse it anyway. Records are written by
 * `create_project` and `attach_engagement_authorization` on the MCP surface.
 *
 * Tenant-scoped through `requireProjectAccess`, the canonical per-project
 * ownership guard for webapp routes. The MCP surface uses `assertMcpProjectAccess`
 * instead, which takes the token's user rather than a browser session.
 */
import { NextRequest, NextResponse } from 'next/server'

import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { internalError } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    const authorizations = await prisma.engagementAuthorization.findMany({
      where: { projectId: id },
      orderBy: { recordedAt: 'desc' },
      select: {
        id: true,
        documentSha256: true,
        documentKind: true,
        sourceUrl: true,
        programHandle: true,
        issuedAt: true,
        recordedAt: true,
        recordedVia: true,
        recordedByTokenId: true,
        summary: true,
      },
    })

    return NextResponse.json({ authorizations })
  } catch (error) {
    return internalError(error, 'Failed to list engagement authorizations', { log: 'Error listing engagement authorizations' })
  }
}
