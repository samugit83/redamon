import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { upstreamFailure } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

const UNAVAILABLE = 'The local judge model is unavailable'

/**
 * Every "no model" answer carries `reason` (also as `code`, which the browser's
 * error reader takes): `orchestrator_unreachable` / `orchestrator_timeout` (no
 * answer), `orchestrator_error` (it answered non-OK, see `upstreamStatus`) or
 * `no_model` (it answered without one). The page tells the three apart.
 */
const unavailable = (reason: string, status = 503, extra: Record<string, unknown> = {}) =>
  NextResponse.json({ model: null, error: UNAVAILABLE, code: reason, reason, ...extra }, { status })

// GET /api/ai-attack-surface/{projectId}/judge-model
// The judge model the orchestrator pulls and checks (LOCAL_LLM_MODEL, from
// /local-llm/status), so the page starts from the backend's model rather than
// a literal of its own. Only the model name is passed on: the status also
// carries the container id, the base URL and the pulled models.
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
  const auth = await requirePermission(request, 'recon:read', { projectId })
  if (auth instanceof NextResponse) return auth
  let response: Response
  try {
    response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/local-llm/status`,
      { headers: { 'Content-Type': 'application/json' }, cache: 'no-store' },
      { timeoutMs: 10_000 },
    )
  } catch (err) {
    const failure = upstreamFailure('orchestrator', err, UNAVAILABLE)
    console.error(`${UNAVAILABLE}:`, err)
    return unavailable(failure.body.code, failure.status, failure.body.cause ? { cause: failure.body.cause } : {})
  }
  if (!response.ok) return unavailable('orchestrator_error', 503, { upstreamStatus: response.status })
  const status = await response.json().catch(() => null) as { model?: unknown } | null
  const model = typeof status?.model === 'string' ? status.model.trim() : ''
  if (!model) return unavailable('no_model')
  return NextResponse.json({ model })
}
