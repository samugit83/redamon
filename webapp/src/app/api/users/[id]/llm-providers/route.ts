import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession, isInternalRequest } from '@/lib/session'
import { isReasoningEffort } from '@/lib/llmReasoning'
import { requireUserExists, isForeignKeyViolation } from '@/lib/userScopedWrite'
import { isJevProvider, jevPinnedConfig } from '@/lib/llmProviderKinds'
import { internalError } from '@/lib/routeErrors'

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
    awsBearerToken: maskSecret(provider.awsBearerToken as string),
  }
}

// GET /api/users/[id]/llm-providers
//
// STRIDE I1: unmasked provider secrets (apiKey / awsSecretKey / awsBearerToken)
// are returned ONLY to trusted internal callers that present a valid
// `X-Internal-Key` header (the agent) - never on the strength of the plaintext
// `?internal=true` query param alone. Browser/JWT callers always receive masked
// rows, and only for their OWN user id (or if admin), closing the cross-tenant
// IDOR where any logged-in user could read another user's cleartext keys.
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const internalReq = isInternalRequest(request)
    const wantUnmasked = request.nextUrl.searchParams.get('internal') === 'true'

    // Browser/JWT callers must own the account (or be admin); they never get
    // unmasked secrets even if they pass ?internal=true.
    if (!internalReq) {
      const session = await getSession()
      if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      }
      if (session.userId !== id && session.role !== 'admin') {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }
    }

    const providers = await prisma.userLlmProvider.findMany({
      where: { userId: id },
      orderBy: { createdAt: 'asc' },
    })

    // Unmasked only for internal-key callers that explicitly request it.
    if (internalReq && wantUnmasked) {
      return NextResponse.json(providers)
    }

    return NextResponse.json(providers.map(p => maskProvider(p as unknown as Record<string, unknown>)))
  } catch (error) {
    return internalError(error, 'Failed to fetch LLM providers')
  }
}

// POST /api/users/[id]/llm-providers
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    // Ownership: only the account owner (or admin) may create providers for
    // this user id. S2/E2: the internal-key bypass is removed -- no production
    // internal caller creates providers, and a leaked key must not be able to
    // add a provider (and thus a harvestable secret) to an arbitrary account.
    {
      const session = await getSession()
      if (!session) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      }
      if (session.userId !== id && session.role !== 'admin') {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }
    }

    // The admin bypass above lets a caller name any user id; a ghost id must
    // fail as a readable 404, not as a foreign-key 500 (issue #173).
    const missing = await requireUserExists(id)
    if (missing) return missing

    const body = await request.json()

    const { providerType, name } = body
    if (typeof providerType !== 'string' || !providerType || typeof name !== 'string' || !name.trim()) {
      return NextResponse.json(
        { error: 'providerType and name are required' },
        { status: 400 }
      )
    }

    const isJev = isJevProvider({ providerType })
    if (isJev) {
      if (typeof body.apiKey !== 'string' || !body.apiKey.trim()) {
        return NextResponse.json({ error: 'apiKey is required for Jev' }, { status: 400 })
      }
    }

    // For openai_compatible, baseUrl and modelIdentifier are required
    if (providerType === 'openai_compatible') {
      if (!body.baseUrl || !body.modelIdentifier) {
        return NextResponse.json(
          { error: 'baseUrl and modelIdentifier are required for OpenAI-Compatible providers' },
          { status: 400 }
        )
      }
      if (body.reasoningEnabled !== undefined && typeof body.reasoningEnabled !== 'boolean') {
        return NextResponse.json(
          { error: 'reasoningEnabled must be a boolean' },
          { status: 400 }
        )
      }
      if (body.reasoningEffort !== undefined && !isReasoningEffort(body.reasoningEffort)) {
        return NextResponse.json(
          { error: 'reasoningEffort must be one of: low, medium, high, max' },
          { status: 400 }
        )
      }
    }

    const data = {
        userId: id,
        providerType,
        name: name.trim(),
        apiKey: isJev ? body.apiKey.trim() : body.apiKey || '',
        baseUrl: body.baseUrl || '',
        modelIdentifier: body.modelIdentifier || '',
        defaultHeaders: isJev ? {} : body.defaultHeaders || {},
        timeout: body.timeout ?? 120,
        temperature: body.temperature ?? 0,
        maxTokens: body.maxTokens ?? 16384,
        sslVerify: body.sslVerify ?? true,
        reasoningEnabled: providerType === 'openai_compatible' ? body.reasoningEnabled ?? false : false,
        reasoningEffort: providerType === 'openai_compatible' ? body.reasoningEffort ?? 'high' : 'high',
        awsRegion: body.awsRegion || 'us-east-1',
        awsAccessKeyId: body.awsAccessKeyId || '',
        awsSecretKey: body.awsSecretKey || '',
        awsBearerToken: body.awsBearerToken || '',
        ...(isJev ? jevPinnedConfig(providerType as 'jev' | 'jev_openrouter') : {}),
    }

    const provider = await prisma.userLlmProvider.create({ data })

    return NextResponse.json(
      maskProvider(provider as unknown as Record<string, unknown>),
      { status: 201 }
    )
  } catch (error) {
    if (isForeignKeyViolation(error)) {
      return NextResponse.json(
        { error: 'User not found. Your session points at an account that no longer exists - log out and back in.' },
        { status: 404 }
      )
    }
    return internalError(error, 'Failed to create LLM provider')
  }
}
