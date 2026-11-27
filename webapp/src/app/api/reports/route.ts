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
    const params = request.nextUrl.searchParams
    const limitParam = params.get('limit')
    const cursor = params.get('cursor')
    const projectId = params.get('projectId')
    const from = params.get('from')
    const to = params.get('to')
    const limit = limitParam === null ? 100 : Number(limitParam)
    const validDate = (value: string) => {
      if (!/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?$/.test(value)
        || Number.isNaN(Date.parse(value))) return false
      const day = value.slice(0, 10)
      return new Date(`${day}T00:00:00Z`).toISOString().slice(0, 10) === day
    }
    if ((limitParam !== null && (!/^\d+$/.test(limitParam) || !Number.isInteger(limit) || limit < 1 || limit > 200))
      || (cursor !== null && !cursor.trim()) || (projectId !== null && !projectId.trim())
      || (from !== null && !validDate(from)) || (to !== null && !validDate(to))) {
      return NextResponse.json({ error: 'Invalid query parameters', code: 'invalid_query' }, { status: 400 })
    }

    const reports = await prisma.report.findMany({
      where: {
        project: await visibleProjectsWhere(eff),
        ...(projectId !== null && { projectId }),
        ...((from !== null || to !== null) && { createdAt: {
          ...(from !== null && { gte: new Date(from) }),
          ...(to !== null && { lte: new Date(to) }),
        } }),
      },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
      ...(cursor !== null && { cursor: { id: cursor }, skip: 1 }),
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
    const page = reports.slice(0, limit)
    const headers = reports.length > limit ? { 'X-Next-Cursor': page[page.length - 1].id } : undefined
    return NextResponse.json(page, { headers })
  } catch (error) {
    return internalError(error, 'Failed to list reports', { log: 'List all reports failed' })
  }
}
