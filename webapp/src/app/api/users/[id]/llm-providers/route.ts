import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
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

// GET /api/users/[id]/llm-providers
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const internal = request.nextUrl.searchParams.get('internal') === 'true'

    const providers = await prisma.userLlmProvider.findMany({
      where: { userId: id },
      orderBy: { createdAt: 'asc' },
    })

    if (internal) {
      return NextResponse.json(providers)
    }

    return NextResponse.json(providers.map(p => maskProvider(p as unknown as Record<string, unknown>)))
  } catch (error) {
    console.error('Failed to fetch LLM providers:', error)
    return NextResponse.json(
      { error: 'Failed to fetch LLM providers' },
      { status: 500 }
    )
  }
}

// POST /api/users/[id]/llm-providers
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()

    const { providerType, name } = body
    if (!providerType || !name) {
      return NextResponse.json(
        { error: 'providerType and name are required' },
        { status: 400 }
      )
    }

    // For openai_compatible, baseUrl and modelIdentifier are required
    if (providerType === 'openai_compatible') {
      if (!body.baseUrl || !body.modelIdentifier) {
        return NextResponse.json(
          { error: 'baseUrl and modelIdentifier are required for OpenAI-Compatible providers' },
          { status: 400 }
        )
      }
    }

    const provider = await prisma.userLlmProvider.create({
      data: {
        userId: id,
        providerType,
        name,
        apiKey: body.apiKey || '',
        baseUrl: body.baseUrl || '',
        modelIdentifier: body.modelIdentifier || '',
        defaultHeaders: body.defaultHeaders || {},
        timeout: body.timeout ?? 120,
        temperature: body.temperature ?? 0,
        maxTokens: body.maxTokens ?? 16384,
        sslVerify: body.sslVerify ?? true,
        awsRegion: body.awsRegion || 'us-east-1',
        awsAccessKeyId: body.awsAccessKeyId || '',
        awsSecretKey: body.awsSecretKey || '',
      },
    })

    return NextResponse.json(
      maskProvider(provider as unknown as Record<string, unknown>),
      { status: 201 }
    )
  } catch (error) {
    console.error('Failed to create LLM provider:', error)
    return NextResponse.json(
      { error: 'Failed to create LLM provider' },
      { status: 500 }
    )
  }
}
