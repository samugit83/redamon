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
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { internalKeyHeaders } from '@/lib/agentAuth'

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

export type TriageOp = 'mute' | 'unmute' | 'list_muted' | 'list_findings' | 'human_verdict'

/** Call the agent's internal `/graph/triage`, where the graph writes live. */
export async function callGraphTriage(
  op: TriageOp,
  caller: TriageCaller,
  extra: Record<string, unknown> = {},
): Promise<NextResponse> {
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
    const body = await res.json().catch(() => ({ error: 'invalid response from agent' }))
    return NextResponse.json(body, { status: res.status })
  } catch (err) {
    if (err instanceof AgentUnreachableError) {
      // Name the real service. Reporting this as a triage failure sends the
      // operator looking at the graph instead of at a stopped container.
      return NextResponse.json({ error: err.message }, { status: 503 })
    }
    return NextResponse.json(
      { error: err instanceof Error ? err.message : 'triage request failed' },
      { status: 500 },
    )
  }
}
