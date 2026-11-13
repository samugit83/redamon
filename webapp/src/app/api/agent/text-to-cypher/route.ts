/**
 * NL -> Cypher for the graph views.
 *
 * This route used to forward `user_id` and `project_id` straight from the
 * client body with no ownership check and no internal key. The agent endpoint
 * behind it spends the BODY-NAMED user's LLM provider key, so any logged-in
 * user could generate Cypher against any project and bill any other user's
 * key. The identity now comes from the session and the body's is ignored
 * (mcp_plan.md P0-3).
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { readUpstreamBody, upstreamFailureResponse } from '@/lib/routeErrors'

// Up to three generations, each with its own provider retries: as long as the
// raw fetch this replaced waited for headers.
const GENERATE_TIMEOUT_MS = 300_000
const PROVIDER_CLASS = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/
const GENERATE_FAILED = 'Could not generate a query for that question.'

/** The provider facts the agent adds to a failed model call: class name and integer status only. */
function providerFacts(json: Record<string, unknown> | null): Record<string, unknown> {
  if (!json) return {}
  const cls = json.error_class
  const status = json.provider_status
  return {
    ...(typeof cls === 'string' && PROVIDER_CLASS.test(cls) ? { errorClass: cls } : {}),
    ...(typeof status === 'number' && Number.isInteger(status) && status >= 100 && status <= 599
      ? { providerStatus: status } : {}),
  }
}

export async function POST(request: NextRequest) {
  let body: Record<string, unknown>
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  const projectId = typeof body.project_id === 'string' ? body.project_id : ''
  const auth = await requirePermission(request, 'agent:assistants', { projectId })
  if (auth instanceof NextResponse) return auth
  const access = auth.access!
  // The graph tenant is the project's owner, whose id its nodes carry. The key owner is the
  // owner too: agent:assistants is a write level, which only the owner reaches until Phase 5
  // decides whose key a collaborator's question spends.
  const owner = access.project.userId

  try {
    const resp = await agentFetch('/text-to-cypher', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...body,
        // The access check decides whose graph and whose LLM key are used, never
        // the caller's body.
        user_id: owner,
        tenant_user_id: owner,
        project_id: access.project.id,
      }),
    }, { timeoutMs: GENERATE_TIMEOUT_MS })

    if (!resp.ok) {
      // Only a JSON `error`/`detail` is forwarded: every one the agent writes on
      // this path is a literal sentence (agentic/tests/test_text_to_cypher_auth.py
      // pins it), such as "No LLM configured..." or the daily-cap 429. A plain-text
      // body can be a stack or a Cypher fragment, so it stays in the log.
      const upstream = await readUpstreamBody(resp)
      if (!upstream.text) console.error(`[text-to-cypher] agent returned ${resp.status} without a readable error`)
      return NextResponse.json(
        {
          error: upstream.text ?? GENERATE_FAILED,
          ...(upstream.code ? { code: upstream.code } : {}),
          upstreamStatus: resp.status,
          ...providerFacts(upstream.json),
        },
        { status: resp.status >= 500 ? 502 : resp.status }
      )
    }
    return NextResponse.json(await resp.json())
  } catch (error) {
    if (error instanceof AgentUnreachableError) {
      return upstreamFailureResponse('agent', error.cause_, 'Could not reach the query generator.')
    }
    console.error('Text-to-cypher proxy error:', error)
    return NextResponse.json({ error: 'Could not reach the query generator.' }, { status: 502 })
  }
}
