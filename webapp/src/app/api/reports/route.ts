import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser } from '@/lib/access'
import { visibleProjectsWhere } from '@/lib/authz/visibleProjects'
import { internalError } from '@/lib/routeErrors'

/** GET /api/reports - List the reports of the projects the effective user sees. */
export async function GET() {
  try {
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff

    const reports = await prisma.report.findMany({
      where: { project: visibleProjectsWhere(eff) },
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
