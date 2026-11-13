import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getAuthzIdentity } from '@/lib/session'
import { requirePermission } from '@/lib/authz/guards'
import { isChatProvider } from '@/lib/llmProviderKinds'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'
import { entitledInstanceProviders, instanceProvidersInForce } from '@/lib/instanceProviders/entitlement'
import { instanceModelGroups, type ModelGroups } from '@/lib/instanceProviders/models'

// The agent asks every provider at once, each with its own 15-20 s budget; a slow
// Bedrock listing can outlast agentFetch's 30 s default.
const MODELS_TIMEOUT_MS = 60_000

class AgentModelsFailed extends Error {
  constructor(readonly response: NextResponse) {
    super('agent model listing failed')
  }
}

async function agentModels(providers: unknown[] | null): Promise<ModelGroups> {
  let res: Response
  try {
    res = await agentFetch('/models', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ providers }),
      cache: 'no-store',
    }, { timeoutMs: MODELS_TIMEOUT_MS })
  } catch (error) {
    if (error instanceof AgentUnreachableError) {
      throw new AgentModelsFailed(upstreamFailureResponse('agent', error.cause_, 'Failed to connect to agent API'))
    }
    throw error
  }
  if (!res.ok) {
    console.error('Failed to fetch models from agent API:', await res.clone().text().catch(() => ''))
    throw new AgentModelsFailed(await upstreamErrorResponse('agent', res, 'Failed to fetch models from agent API', { status: 503 }))
  }
  return await res.json() as ModelGroups
}

// POST /api/models { userId? } - Fetch available AI models from all configured providers.
// Body-based (not query-string) so plaintext apiKey values never appear in access logs.
//
// self:llm_providers lists the effective user's own providers. With RBAC_GOVERNANCE_ENABLED on the
// answer also holds the instance providers an administrator assigned to a set that user holds
// (step 6.11, GV-15), as `instance/<providerId>/<model>` ids, and a person WITHOUT self:llm_providers
// gets those alone (the Phase 6 kickoff's assumption (d)); with it off such a person is refused as
// before (DV-30).
export async function POST(request: NextRequest) {
  try {
    const auth = await requirePermission(request, 'self:llm_providers')
    let effectiveUserId: string
    let ownProviders: boolean
    if (auth instanceof NextResponse) {
      if (auth.status !== 403 || !instanceProvidersInForce()) return auth
      const identity = await getAuthzIdentity()
      if (!identity) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      effectiveUserId = (identity.actingAs ?? identity.principal).id
      ownProviders = false
    } else {
      effectiveUserId = auth.effective.userId
      ownProviders = true
    }

    const { userId } = await request.json().catch(() => ({ userId: null }))

    // Only ever load the EFFECTIVE user's providers; the body userId cannot be
    // used to enumerate another user's configured providers.
    let providers: unknown[] = []
    const instance = userId ? await entitledInstanceProviders(effectiveUserId) : []
    if (ownProviders && userId) {
      const rows = await prisma.userLlmProvider.findMany({ where: { userId: effectiveUserId } })
      // A non-chat key (Jev) lists no models, so it never leaves the webapp here.
      providers = rows.filter(isChatProvider)
    }

    try {
      const own = ownProviders ? await agentModels(providers.length > 0 ? providers : null) : {}
      const shared = await instanceModelGroups(instance, (rows) => agentModels(rows))
      return NextResponse.json({ ...own, ...shared })
    } catch (error) {
      if (error instanceof AgentModelsFailed) return error.response
      throw error
    }
  } catch (error) {
    return internalError(error, 'Failed to load the models')
  }
}
