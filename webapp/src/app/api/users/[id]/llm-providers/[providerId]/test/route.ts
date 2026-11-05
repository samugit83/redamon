import { NextRequest, NextResponse } from 'next/server'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { requireUserAccess } from '@/lib/session'
import prisma from '@/lib/prisma'
import { isJevProvider, jevPinnedConfig } from '@/lib/llmProviderKinds'
import { internalError, readUpstreamBody, upstreamFailure } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string; providerId: string }>
}

/**
 * How long this hop waits on the agent.
 *
 * It must EXCEED the provider's own `timeout` (seconds, free integer, Prisma
 * default 120), which the agent hands straight to the LLM client. A fixed hop
 * budget shorter than that aborts a legitimately slow test - a cold local model
 * loading weights - and reports it as "the agent did not respond in time",
 * which is exactly the misattribution this route exists to prevent (#184).
 *
 * Floor keeps a nonsense `timeout: 1` usable; ceiling keeps a hostile or
 * fat-fingered value from pinning a route open for a day.
 */
const HOP_HEADROOM_MS = 30_000
const HOP_FLOOR_MS = 60_000
const HOP_CEILING_MS = 3_600_000
const PROVIDER_TIMEOUT_DEFAULT_S = 120  // mirrors the Prisma @default(120)

function hopBudgetMs(configuredSeconds: unknown): number {
  const secs = Number(configuredSeconds)
  const base = Number.isFinite(secs) && secs > 0 ? secs : PROVIDER_TIMEOUT_DEFAULT_S
  return Math.min(
    Math.max(base * 1000 + HOP_HEADROOM_MS, HOP_FLOOR_MS),
    HOP_CEILING_MS,
  )
}

// POST /api/users/[id]/llm-providers/[providerId]/test
// Also supports testing unsaved configs by passing full config in body
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, providerId } = await params
    const __denied = await requireUserAccess(request, id)
    if (__denied) return __denied
    const body = await request.json()

    let config: Record<string, unknown>

    if (providerId === 'unsaved') {
      // Testing an unsaved config - full config in body
      config = body
    } else {
      // Testing a saved config: start from DB (has full secrets), then
      // overlay any fields the operator has edited in the form. Secret
      // fields (apiKey, awsAccessKeyId, awsSecretKey) are returned masked
      // by GET; if the body still carries the mask, keep the DB value.
      // Otherwise the form-edited value wins (so a freshly typed key is
      // actually what gets tested).
      const provider = await prisma.userLlmProvider.findFirst({
        where: { id: providerId, userId: id },
      })
      if (!provider) {
        return NextResponse.json({ error: 'Provider not found' }, { status: 404 })
      }
      const isMasked = (v: unknown) => typeof v === 'string' && v.startsWith('••••')
      const SECRET_FIELDS = new Set(['apiKey', 'awsAccessKeyId', 'awsSecretKey', 'awsBearerToken'])
      // The stored type decides where the stored key may go. For a Jev row the
      // body can never redirect the token; for any other row it can never turn
      // the key into a Jev test.
      const LOCKED_FOR_JEV = new Set(['providerType', 'baseUrl', 'defaultHeaders', 'modelIdentifier'])
      const storedIsJev = isJevProvider(provider)
      if (body.providerType !== undefined && body.providerType !== provider.providerType
        && (storedIsJev || isJevProvider({ providerType: body.providerType }))) {
        return NextResponse.json({ success: false, error: 'The backend of a Jev provider cannot be changed' }, { status: 400 })
      }
      config = { ...(provider as unknown as Record<string, unknown>) }
      for (const [key, value] of Object.entries(body)) {
        if (SECRET_FIELDS.has(key) && isMasked(value)) {
          // Keep DB value - user did not retype the secret
          continue
        }
        if (storedIsJev && LOCKED_FOR_JEV.has(key)) continue
        config[key] = value
      }
    }

    if (isJevProvider({ providerType: String(config.providerType) })) {
      const type = config.providerType as 'jev' | 'jev_openrouter'
      config = { ...config, ...jevPinnedConfig(type), testMode: 'key' }
    }

    // Proxy to agent test endpoint. The AGENT does the live call to the
    // operator's endpoint, so the budget is derived from the provider's own
    // timeout rather than fixed here.
    const agentResp = await agentFetch(
      '/llm-provider/test',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      },
      { timeoutMs: hopBudgetMs(config.timeout) },
    )

    // A test the agent ran answers `{success, error}` (200, or 400 when the
    // provider refused), and is passed through as is. Any other body is the agent
    // itself failing (FastAPI `{detail}` on a bad key or body, a plain-text 500);
    // its text can quote an exception, so only its status and code go out.
    const answered = await readUpstreamBody(agentResp)
    if (answered.json && typeof answered.json.success === 'boolean') {
      return NextResponse.json(answered.json, { status: agentResp.status })
    }
    return NextResponse.json({
      success: false,
      error: 'The agent could not test this provider',
      code: answered.code ?? 'agent_error',
      upstreamStatus: agentResp.status,
    }, { status: 502 })
  } catch (error) {
    // The agent being down is an infrastructure outage, not a bad provider
    // config. Returning the raw `TypeError: fetch failed` here is what made
    // issue #184 read as "your Base URL is wrong" when the URL was fine.
    if (error instanceof AgentUnreachableError) {
      // Log the ACTIONABLE sentence, not just the cause: an operator reading
      // container logs would otherwise get the same bare 'TypeError: fetch
      // failed' stack that made #184 unreadable in the first place.
      console.error('LLM provider test: agent unreachable:', error.message, error.cause_)
      const failure = upstreamFailure('agent', error.cause_, error.message)
      return NextResponse.json({ success: false, ...failure.body }, { status: failure.status })
    }
    return internalError(error, 'Failed to test LLM provider', { extra: { success: false } })
  }
}
