import { NextRequest, NextResponse } from 'next/server'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { requireUserAccess } from '@/lib/session'
import prisma from '@/lib/prisma'

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
      config = { ...(provider as unknown as Record<string, unknown>) }
      for (const [key, value] of Object.entries(body)) {
        if (SECRET_FIELDS.has(key) && isMasked(value)) {
          // Keep DB value - user did not retype the secret
          continue
        }
        config[key] = value
      }
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

    const result = await agentResp.json()
    return NextResponse.json(result, { status: agentResp.status })
  } catch (error) {
    // The agent being down is an infrastructure outage, not a bad provider
    // config. Returning the raw `TypeError: fetch failed` here is what made
    // issue #184 read as "your Base URL is wrong" when the URL was fine.
    if (error instanceof AgentUnreachableError) {
      // Log the ACTIONABLE sentence, not just the cause: an operator reading
      // container logs would otherwise get the same bare 'TypeError: fetch
      // failed' stack that made #184 unreadable in the first place.
      console.error('LLM provider test: agent unreachable:', error.message, error.cause_)
      return NextResponse.json(
        { success: false, error: error.message },
        { status: 503 }
      )
    }
    console.error('Failed to test LLM provider:', error)
    return NextResponse.json(
      { success: false, error: String(error) },
      { status: 500 }
    )
  }
}
