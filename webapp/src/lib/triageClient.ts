/**
 * Shared plumbing for the `/api/triage/*` routes.
 *
 * Two things every one of these routes must get right, so they live here once:
 *
 * 1. **Authorisation is hard-enforced.** `guardProject` honours the
 *    `ACCESS_ENFORCE=0` log-only escape hatch, which exists so an ownership fix
 *    can be rolled out in observe-mode first. Mute is not eligible for that:
 *    muting changes what the AGENT can see, project-wide, so a mis-scoped mute
 *    is a correctness failure and not just an information leak. These routes
 *    therefore re-check ownership themselves and 404 on a mismatch whatever the
 *    flag says.
 *
 * 2. **The tenant is never taken from the request body.** The caller sends a
 *    `projectId` and a `nodeId`; the user id is resolved server-side from the
 *    session, and the node is scoped by that pair inside the graph mixin. A
 *    guessed nodeId from another project matches nothing.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser } from '@/lib/access'
import { signedInActor } from '@/lib/auditActor'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { safeErrorCode, upstreamFailure } from '@/lib/routeErrors'

export interface TriageCaller {
  userId: string
  projectId: string
}

/**
 * Resolve the caller and prove they own the project, ignoring the log-only flag.
 *
 * Returns the resolved tenant, or the NextResponse to send back. A project that
 * does not exist and a project owned by somebody else both return 404, so this
 * cannot be used to enumerate project ids.
 */
export async function requireProjectOwner(
  projectId: string | null | undefined,
): Promise<TriageCaller | NextResponse> {
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { id: true, userId: true },
  })
  if (!project) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  // Deliberately NOT ownershipDenied(): that helper honours ACCESS_ENFORCE=0
  // and would let a mismatch through in log-only mode. There is no separate
  // admin bypass to reproduce -- an admin acts on another user's project by
  // simulating them, and getEffectiveUser has already resolved that, so the
  // strict comparison is the same rule requireProjectAccess applies.
  if (project.userId !== eff.userId) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  return { userId: project.userId, projectId: project.id }
}

/**
 * The person actually signed in, which differs from the effective user while an
 * admin acts as someone else. Audit rows record both, so "who really did this"
 * survives simulation.
 */
export async function realActorUserId(): Promise<string | null> {
  try {
    return (await signedInActor())?.id ?? null
  } catch {
    // No request scope (a unit test, a background caller): the audit row then
    // records the effective user alone, as every route did before.
    return null
  }
}

export type TriageOp =
  | 'mute' | 'unmute' | 'unmute_many' | 'list_muted' | 'muted_facets'
  | 'list_findings' | 'human_verdict' | 'preflight' | 'stop_run'
  | 'mute_batch'

/**
 * Call the agent's internal `/graph/triage`, where the graph writes live, and
 * hand back the status and parsed body for a route that post-processes them.
 */
export async function graphTriage(
  op: TriageOp,
  caller: TriageCaller,
  extra: Record<string, unknown> = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  try {
    const res = await agentFetch('/graph/triage', {
      method: 'POST',
      headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        op,
        user_id: caller.userId,
        project_id: caller.projectId,
        ...extra,
      }),
    })
    const parsed = await res.json().catch(() => null)
    const body: Record<string, unknown> = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : { error: 'invalid response from agent', code: 'non_json_response' }
    if (res.ok) return { status: res.status, body }
    return { status: res.status, body: failureBody(body, res.status) }
  } catch (err) {
    if (err instanceof AgentUnreachableError) {
      // Name the real service. Reporting this as a triage failure sends the
      // operator looking at the graph instead of at a stopped container.
      const { body } = upstreamFailure('agent', err.cause_, err.message)
      return { status: 503, body: { ...body, error: err.message } }
    }
    console.error(`[triage] ${op} failed:`, err)
    return {
      status: 500,
      body: { error: 'The triage request failed.', code: safeErrorCode(err) },
    }
  }
}

const AGENT_CODE = /^[a-z][a-z0-9_]{0,63}$/
const AGENT_CLASS = /^[A-Za-z_][A-Za-z0-9_.]{0,79}$/

/**
 * An agent refusal as the browser reads it: `error` is the agent's `error`, or
 * FastAPI's string `detail` (a refused key, a rate limit), and `upstreamStatus`
 * says what the agent answered. A 5xx's text is shown only when it carries a
 * code: every 5xx this agent writes does, while an older agent's catch-all
 * answered the raw Neo4j message, which can quote target data.
 */
function failureBody(body: Record<string, unknown>, status: number): Record<string, unknown> {
  const { code: rawCode, error_class: rawClass, ...rest } = body
  const code = typeof rawCode === 'string' && AGENT_CODE.test(rawCode) ? rawCode : undefined
  const errorClass = typeof rawClass === 'string' && AGENT_CLASS.test(rawClass) ? rawClass : undefined
  const text = [body.error, body.detail].find((v): v is string => typeof v === 'string' && v.trim() !== '')
  const trusted = status < 500 || code !== undefined
  return {
    ...rest,
    error: (trusted && text) || `The findings service answered ${status}.`,
    ...(code ? { code } : {}),
    ...(errorClass ? { errorClass } : {}),
    upstreamStatus: status,
  }
}

/** `graphTriage`, answered straight back to the browser. */
export async function callGraphTriage(
  op: TriageOp,
  caller: TriageCaller,
  extra: Record<string, unknown> = {},
): Promise<NextResponse> {
  const { status, body } = await graphTriage(op, caller, extra)
  return NextResponse.json(body, { status })
}
