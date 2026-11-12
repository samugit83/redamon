import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { requireEffectiveUser } from '@/lib/access'
import { requirePermission } from '@/lib/authz/guards'

interface RouteParams {
  params: Promise<{ id: string }>
}

// PUT /api/remediations/[id]/blocks - Update individual block statuses
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    if (!isInternalRequest(request)) {
      const eff = await requireEffectiveUser()
      if (eff instanceof NextResponse) return eff
      const r = await prisma.remediation.findUnique({ where: { id }, select: { projectId: true } })
      if (!r?.projectId) return NextResponse.json({ error: 'Not found' }, { status: 404 })
      const auth = await requirePermission(request, 'remediation:write', { projectId: r.projectId })
      if (auth instanceof NextResponse) return auth
    }

    const body = await request.json()
    const { fileChanges } = body

    if (!fileChanges) {
      return NextResponse.json(
        { error: 'fileChanges is required' },
        { status: 400 }
      )
    }

    const remediation = await prisma.remediation.update({
      where: { id },
      data: { fileChanges },
    })

    return NextResponse.json(remediation)
  } catch (error: unknown) {

    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'Remediation not found' },
        { status: 404 }
      )
    }

    return internalError(error, 'Failed to update block statuses', { log: 'Update block statuses' })
  }
}
