/**
 * The append-only record of what authorized this engagement.
 *
 * Read-only by construction. There is no POST, PUT or DELETE here and there must
 * not be: a record an operator can rewrite from a browser is not evidence, and
 * the Postgres trigger would refuse it anyway. Records are written by
 * `create_project` and `attach_engagement_authorization` on the MCP surface.
 *
 * Checked with `requirePermission('engagement:authorize')` on the project, whose
 * project check is projectAccess(), the canonical per-project rule. The MCP surface
 * uses `assertMcpProjectAccess` instead, which takes the token's user rather than a
 * browser session.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'

import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const auth = await requirePermission(request, 'engagement:authorize', { projectId: id })
    if (auth instanceof NextResponse) return auth

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
