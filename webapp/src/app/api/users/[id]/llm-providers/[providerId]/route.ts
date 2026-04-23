import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string; providerId: string }>
}

function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

function maskProvider(provider: Record<string, unknown>): Record<string, unknown> {
  return {
    ...provider,
    apiKey: maskSecret(provider.apiKey as string),
    awsAccessKeyId: maskSecret(provider.awsAccessKeyId as string),
    awsSecretKey: maskSecret(provider.awsSecretKey as string),
  }
}

// GET /api/users/[id]/llm-providers/[providerId]
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, providerId } = await params
    const internal = request.nextUrl.searchParams.get('internal') === 'true'

    const provider = await prisma.userLlmProvider.findFirst({
      where: { id: providerId, userId: id },
    })

    if (!provider) {
      return NextResponse.json({ error: 'Provider not found' }, { status: 404 })
    }

    if (internal) {
      return NextResponse.json(provider)
    }

    return NextResponse.json(maskProvider(provider as unknown as Record<string, unknown>))
  } catch (error) {
    console.error('Failed to fetch LLM provider:', error)
    return NextResponse.json(
      { error: 'Failed to fetch LLM provider' },
      { status: 500 }
    )
  }
}

// PUT /api/users/[id]/llm-providers/[providerId]
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, providerId } = await params
    const body = await request.json()

    // Verify ownership
    const existing = await prisma.userLlmProvider.findFirst({
      where: { id: providerId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Provider not found' }, { status: 404 })
    }

    // Preserve masked secrets
    const secretFields = ['apiKey', 'awsAccessKeyId', 'awsSecretKey'] as const
    const updateData: Record<string, unknown> = { ...body }
    delete updateData.id
    delete updateData.userId
    delete updateData.createdAt
    delete updateData.updatedAt

    for (const field of secretFields) {
      if (field in updateData) {
        const val = updateData[field] as string
        if (val.startsWith('••••')) {
          updateData[field] = existing[field]
        }
      }
    }

    const provider = await prisma.userLlmProvider.update({
      where: { id: providerId },
      data: updateData,
    })

    return NextResponse.json(maskProvider(provider as unknown as Record<string, unknown>))
  } catch (error) {
    console.error('Failed to update LLM provider:', error)
    return NextResponse.json(
      { error: 'Failed to update LLM provider' },
      { status: 500 }
    )
  }
}

// DELETE /api/users/[id]/llm-providers/[providerId]
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, providerId } = await params

    const existing = await prisma.userLlmProvider.findFirst({
      where: { id: providerId, userId: id },
    })
    if (!existing) {
      return NextResponse.json({ error: 'Provider not found' }, { status: 404 })
    }

    await prisma.userLlmProvider.delete({
      where: { id: providerId },
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Failed to delete LLM provider:', error)
    return NextResponse.json(
      { error: 'Failed to delete LLM provider' },
      { status: 500 }
    )
  }
}
