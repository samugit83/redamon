import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  try {
    const views = await prisma.graphView.findMany({
      where: { projectId },
      orderBy: { createdAt: 'desc' },
    })
    return NextResponse.json(views)
  } catch (error) {
    console.error('Failed to fetch graph views:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to fetch graph views' },
      { status: 500 }
    )
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
    console.error('Failed to create graph view:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to create graph view' },
      { status: 500 }
    )
  }
}
