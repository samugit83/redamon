import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { requireEffectiveUser } from '@/lib/access'
import { requirePermission } from '@/lib/authz/guards'

/**
 * A graph view is owned via its parent project: the session first (401), then the view's project,
 * 404 for a view that does not exist; the handler then asks its permission on that project.
 */
async function viewProject(id: string): Promise<string | NextResponse> {
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const v = await prisma.graphView.findUnique({ where: { id }, select: { projectId: true } })
  return v?.projectId || NextResponse.json({ error: 'Not found' }, { status: 404 })
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  try {
    const projectId = await viewProject(id)
    if (projectId instanceof NextResponse) return projectId
    const auth = await requirePermission(request, 'graph:views', { projectId })
    if (auth instanceof NextResponse) return auth

    const body = await request.json()
    const { name, description } = body

    const view = await prisma.graphView.update({
      where: { id },
      data: {
        ...(name !== undefined && { name }),
        ...(description !== undefined && { description }),
      },
    })

    return NextResponse.json(view)
  } catch (error) {
    return internalError(error, 'Failed to update graph view')
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params

  try {
    const projectId = await viewProject(id)
    if (projectId instanceof NextResponse) return projectId
    const auth = await requirePermission(request, 'graph:views', { projectId })
    if (auth instanceof NextResponse) return auth

    await prisma.graphView.delete({ where: { id } })
    return NextResponse.json({ success: true })
  } catch (error) {
    return internalError(error, 'Failed to delete graph view')
  }
}
