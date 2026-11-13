import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import { requirePermission } from '@/lib/authz/guards'
import { visibleProjectsWhere } from '@/lib/authz/visibleProjects'
import { internalError } from '@/lib/routeErrors'

/**
 * GET /api/reports - List the reports of the projects the effective user sees. The list spans
 * projects, so `reports:read` is asked as a capability; the projects are the visible ones.
 */
export async function GET(request: NextRequest) {
  try {
    const auth = await requirePermission(request, 'reports:read')
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective

    const reports = await prisma.report.findMany({
      where: { project: await visibleProjectsWhere(eff) },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        projectId: true,
        title: true,
        filename: true,
        fileSize: true,
        format: true,
        metrics: true,
        hasNarratives: true,
        createdAt: true,
        project: {
          select: {
            id: true,
            name: true,
            targetDomain: true,
            subdomainList: true,
            ipMode: true,
            targetIps: true,
            domainBatchMode: true,
            domainBatchHosts: true,
          },
        },
      },
    })
    return NextResponse.json(reports)
  } catch (error) {
    return internalError(error, 'Failed to list reports', { log: 'List all reports failed' })
  }
}
