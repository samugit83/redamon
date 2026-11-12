import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requirePermission } from '@/lib/authz/guards'
import { isChatProvider } from '@/lib/llmProviderKinds'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

// The agent asks every provider at once, each with its own 15-20 s budget; a slow
// Bedrock listing can outlast agentFetch's 30 s default.
const MODELS_TIMEOUT_MS = 60_000

// POST /api/models { userId? } - Fetch available AI models from all configured providers.
// Body-based (not query-string) so plaintext apiKey values never appear in access logs.
export async function POST(request: NextRequest) {
  try {
    const auth = await requirePermission(request, 'self:llm_providers')
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective

    const { userId } = await request.json().catch(() => ({ userId: null }))

    // Only ever load the EFFECTIVE user's providers; the body userId cannot be
    // used to enumerate another user's configured providers.
    let providers: unknown[] = []
    if (userId) {
      const rows = await prisma.userLlmProvider.findMany({ where: { userId: eff.userId } })
      // A non-chat key (Jev) lists no models, so it never leaves the webapp here.
      providers = rows.filter(isChatProvider)
    }

    let res: Response
    try {
      res = await agentFetch('/models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ providers: providers.length > 0 ? providers : null }),
        cache: 'no-store',
      }, { timeoutMs: MODELS_TIMEOUT_MS })
    } catch (error) {
      if (error instanceof AgentUnreachableError) {
        return upstreamFailureResponse('agent', error.cause_, 'Failed to connect to agent API')
      }
      throw error
    }

    if (!res.ok) {
      console.error('Failed to fetch models from agent API:', await res.clone().text().catch(() => ''))
      return upstreamErrorResponse('agent', res, 'Failed to fetch models from agent API', { status: 503 })
    }

    const data = await res.json()
    return NextResponse.json(data)
  } catch (error) {
    return internalError(error, 'Failed to load the models')
  }
}
