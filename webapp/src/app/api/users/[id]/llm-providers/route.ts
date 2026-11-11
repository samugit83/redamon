import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession, isInternalRequest, requireAccountWrite } from '@/lib/session'
import { isReasoningEffort } from '@/lib/llmReasoning'
import { requireUserExists, isForeignKeyViolation } from '@/lib/userScopedWrite'
import { isJevProvider, jevPinnedConfig } from '@/lib/llmProviderKinds'
import { internalError } from '@/lib/routeErrors'
import { maskProvider } from '@/lib/llmProviderMask'

interface RouteParams {
  params: Promise<{ id: string }>
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

    // The read rule (requireUserAccess `read`): browser/JWT callers must own the
    // account or be an admin, and they never get unmasked secrets, even with
    // ?internal=true.
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

    // The account's write rule (HD-23): its own session, or an admin acting as a
    // passwordless managed account; an admin cannot add a provider to another
    // account. S2/E2: no internal-key bypass either -- no production internal
    // caller creates providers, and a leaked key must not be able to add a
    // provider (and thus a harvestable secret) to an arbitrary account.
    const denied = await requireAccountWrite(id)
    if (denied) return denied

    // An account deleted after the session check must fail as a readable 404,
    // not as a foreign-key 500 (issue #173).
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

    // A Jev row's model, URL and headers are pinned by its backend (jevPinnedConfig),
    // never the caller's to choose, so the key can only go to that backend's fixed
    // origin. A user may hold several named rows; each project selects one explicitly.
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
