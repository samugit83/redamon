import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { requirePermission } from '@/lib/authz/guards'

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  try {
    const auth = await requirePermission(request, 'graph:read', { projectId })
    if (auth instanceof NextResponse) return auth

    const views = await prisma.graphView.findMany({
      where: { projectId },
      orderBy: { createdAt: 'desc' },
    })
    return NextResponse.json(views)
  } catch (error) {
    return internalError(error, 'Failed to fetch graph views')
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { projectId, name, description, cypherQuery } = body

    if (!projectId || !name?.trim() || !cypherQuery?.trim()) {
      return NextResponse.json(
        { error: 'projectId, name, and cypherQuery are required' },
        { status: 400 }
      )
    }

    const auth = await requirePermission(request, 'graph:views', { projectId })
    if (auth instanceof NextResponse) return auth

    const view = await prisma.graphView.create({
      data: {
        projectId,
        name: name.trim(),
        description: description || '',
        cypherQuery,
      },
    })

    return NextResponse.json(view, { status: 201 })
  } catch (error) {
    return internalError(error, 'Failed to create graph view')
  }
}
