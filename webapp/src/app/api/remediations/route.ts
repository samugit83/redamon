import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { requirePermission } from '@/lib/authz/guards'

const SORTABLE_FIELDS = new Set(['priority', 'severity', 'createdAt', 'updatedAt'])

// GET /api/remediations?projectId=X - List remediations for project.
// Cypherfix reads/writes remediations with X-Internal-Key (carve-out); a browser
// caller needs remediation:read on the project, which a share at Read reaches.
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const projectId = searchParams.get('projectId')

    if (!projectId) {
      return NextResponse.json(
        { error: 'projectId is required' },
        { status: 400 }
      )
    }

    if (!isInternalRequest(request)) {
      const auth = await requirePermission(request, 'remediation:read', { projectId })
      if (auth instanceof NextResponse) return auth
    }

    const status = searchParams.get('status')
    const severity = searchParams.get('severity')
    // `sort` went straight into orderBy, so any column name in the query string
    // became an ordering key - including ones a caller can use to probe values.
    const requestedSort = searchParams.get('sort') || 'priority'
    if (!SORTABLE_FIELDS.has(requestedSort)) {
      return NextResponse.json(
        { error: `Cannot sort by: ${requestedSort}` },
        { status: 400 }
      )
    }
    const sort = requestedSort
    const order = (searchParams.get('order') === 'desc' ? 'desc' : 'asc') as 'asc' | 'desc'

    const where: Record<string, unknown> = { projectId }
    if (status) where.status = status
    if (severity) where.severity = severity

    const remediations = await prisma.remediation.findMany({
      where,
      orderBy: { [sort]: order },
    })

    return NextResponse.json(remediations)
  } catch (error) {
    return internalError(error, 'Failed to fetch remediations')
  }
}

// POST /api/remediations - Create a single remediation
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { projectId, title, description, ...rest } = body

    if (!projectId || !title || !description) {
      return NextResponse.json(
        { error: 'projectId, title, and description are required' },
        { status: 400 }
      )
    }

    if (!isInternalRequest(request)) {
      const auth = await requirePermission(request, 'remediation:write', { projectId })
      if (auth instanceof NextResponse) return auth
    }

    const remediation = await prisma.remediation.create({
      data: { projectId, title, description, ...rest },
    })

    return NextResponse.json(remediation, { status: 201 })
  } catch (error) {
    return internalError(error, 'Failed to create remediation')
  }
}
