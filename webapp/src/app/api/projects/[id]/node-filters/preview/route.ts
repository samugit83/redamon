/**
 * POST /api/projects/[id]/node-filters/preview — what draft rules would do, now.
 *
 * Body: { mode, rules, kinds? }. The draft need not be saved: the editor
 * previews as the operator types. A document that is not readable at all is a
 * 400; invalid individual rules are previewed the way the engine would run
 * them (skipped, or the kind deactivated in allowlist mode) and listed.
 *
 * One preview per project at a time: a second one while the first runs is a
 * 429, and the editor keeps its last counts and retries on its next debounce.
 * The agent stops at 20 s and marks the result partial; this call gives up at 25 s.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import { readJsonBody } from '@/lib/jsonBody'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { allErrors, validateNodeFilters } from '@/lib/nodeFilters/validate'
import { exemptionPairs, relatedRemediationCount } from '@/lib/nodeFilters/server'

const inFlight = new Set<string>()

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const auth = await requirePermission(request, 'node_filters:manage', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)

  const { mode, rules, kinds, withRemediations } = parsed.body as {
    mode?: unknown; rules?: unknown; kinds?: unknown; withRemediations?: unknown
  }
  const verdict = validateNodeFilters(mode, rules)
  if (!verdict.ok) {
    return NextResponse.json({ error: 'The rules are not readable.', errors: allErrors(verdict) }, { status: 400 })
  }
  const kindList = Array.isArray(kinds) ? kinds.filter((k): k is string => typeof k === 'string').slice(0, 50) : null

  if (inFlight.has(caller.projectId)) {
    return NextResponse.json({ error: 'A preview is already running for this project.' }, { status: 429 })
  }
  inFlight.add(caller.projectId)
  try {
    const res = await agentFetch('/graph/node-filters/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: caller.userId,
        project_id: caller.projectId,
        mode,
        rules,
        exemptions: await exemptionPairs(caller.projectId),
        ...(kindList ? { kinds: kindList } : {}),
      }),
    }, { timeoutMs: 25_000 })
    const body = await res.json().catch(() => ({ error: 'invalid response from the agent' }))
    if (!res.ok) return NextResponse.json(body, { status: res.status })
    const related = withRemediations === true
      ? await relatedRemediationCount(caller.projectId, body?.related).catch(() => null)
      : undefined
    return NextResponse.json({
      ...body,
      validation: allErrors(verdict),
      ...(related !== undefined ? { relatedRemediations: related } : {}),
    })
  } catch (err) {
    if (err instanceof AgentUnreachableError) {
      return NextResponse.json({ error: err.message }, { status: 503 })
    }
    return NextResponse.json({ error: err instanceof Error ? err.message : 'preview failed' }, { status: 500 })
  } finally {
    inFlight.delete(caller.projectId)
  }
}
