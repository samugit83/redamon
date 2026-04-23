import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  try {
    const body = await request.json()
    const { projectId, name, description } = body

    // Verify view belongs to the specified project
    if (projectId) {
      const existing = await prisma.graphView.findUnique({ where: { id } })
      if (!existing || existing.projectId !== projectId) {
        return NextResponse.json({ error: 'View not found' }, { status: 404 })
      }
    }

    const view = await prisma.graphView.update({
      where: { id },
      data: {
        ...(name !== undefined && { name }),
        ...(description !== undefined && { description }),
      },
    })

    return NextResponse.json(view)
  } catch (error) {
    console.error('Failed to update graph view:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to update graph view' },
      { status: 500 }
    )
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  const projectId = request.nextUrl.searchParams.get('projectId')

  try {
    // Verify view belongs to the specified project
    if (projectId) {
      const existing = await prisma.graphView.findUnique({ where: { id } })
      if (!existing || existing.projectId !== projectId) {
        return NextResponse.json({ error: 'View not found' }, { status: 404 })
      }
    }

    await prisma.graphView.delete({ where: { id } })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Failed to delete graph view:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to delete graph view' },
      { status: 500 }
    )
  }
}
