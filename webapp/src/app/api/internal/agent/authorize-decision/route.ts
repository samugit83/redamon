/**
 * POST /api/internal/agent/authorize-decision: may this person still take this decision, now
 * (step 5.4; SH-34, SH-41 mid-session part, IM-09)?
 *
 * The agent's `cap` claim is what the person held when their socket opened. Between the agent's
 * prompt and the answer the account can be disabled, the share revoked or narrowed, a toggle or a
 * permission taken away. So before it accepts an approval, a dangerous-tool confirmation, a Fireteam
 * member confirmation or an answer to its question, and before CodeFix pushes with the owner's token,
 * the agent asks here (agentic/decision_check.py), and anything but a 200
 * `{allowed: true}` is a refusal: an unreachable webapp too (`decision_check_unavailable`). It asks
 * the same for a decision the project's settings take without asking anyone (a phase transition with
 * approvals off, a dangerous call with confirmations off, a Fireteam wave start), for anyone but the
 * owner signed in as themself (`authorize_unasked`).
 *
 * The body names the decision's kind, and the permissions (and level) come from KINDS here, as the
 * audit route next door does: the agent cannot ask for less. The person is the ticket's `sub` and,
 * under act-as, the admin its `act`, so the check is the intersection can() gives, fresh. The internal
 * key is global, so this route trusts the ids only as the agent's verified ticket's; it is no oracle
 * for a token holder (a loop driver has no way to an answer: it reaches no ticket and no key).
 *
 * A refusal writes `agent.decision_refused` (the real person, the account acted as, the permission
 * and why); an accepted answer is audited by /api/internal/agent/decisions once the agent applies it.
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { writeAudit } from '@/lib/audit'
import { withRouteErrors } from '@/lib/routeErrors'
import { ActAsNotAllowedError, can } from '@/lib/authz/can'
import { rbacFlags } from '@/lib/authz/flags'
import { loadPrincipal, type Principal } from '@/lib/authz/principal'
import { meetsLevel } from '@/lib/authz/projectAccess'
import type { PermissionId, ProjectLevel } from '@/lib/authz/permissions'

export const runtime = 'nodejs'

interface DecisionKind {
  permissions: readonly PermissionId[]
  /** A level the decision needs beyond its permissions' (phase file 5.2: a CodeFix push is Manage's). */
  level?: ProjectLevel
}

const KINDS: Readonly<Record<string, DecisionKind>> = Object.freeze({
  approval: { permissions: ['agent:approve_phase'] },
  tool_confirmation: { permissions: ['agent:approve_dangerous'] },
  fireteam_member_confirmation: { permissions: ['agent:fireteam', 'agent:approve_dangerous'] },
  question: { permissions: ['agent:chat'] },
  // Pushing a branch and opening a PR with the owner's GitHub token.
  codefix_push: { permissions: ['codefix:run'], level: 'M' },
  // Nobody is asked before a wave starts; each member's dangerous call is decided on its own.
  fireteam_deploy: { permissions: ['agent:fireteam'] },
})

export type DecisionRefusalReason =
  | 'capability' | 'project_level' | 'project_not_visible' | 'account_inactive' | 'deleted' | 'act_as_refused'

const MAX_ID = 200

interface DecisionCheck {
  kind: string
  userId: string
  projectId: string
  sessionId: string
  actorId: string | null
}

const id = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= MAX_ID

function parse(body: unknown): DecisionCheck | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null
  const b = body as Record<string, unknown>
  if (typeof b.kind !== 'string' || !Object.hasOwn(KINDS, b.kind)) return null
  if (!id(b.userId) || !id(b.projectId) || !id(b.sessionId)) return null
  if (b.actorId !== undefined && b.actorId !== null && !id(b.actorId)) return null
  const actorId = (b.actorId as string | null | undefined) ?? null
  return { kind: b.kind, userId: b.userId, projectId: b.projectId, sessionId: b.sessionId, actorId: actorId === b.userId ? null : actorId }
}

/** As a session counts it (session.ts `tokenAccepted`): the status only with the identity switch on. */
const inactive = (p: Principal): boolean => rbacFlags().identity && p.status !== 'active'

type Verdict = { allowed: true } | { allowed: false; permission: PermissionId; reason: DecisionRefusalReason }

async function decide(check: DecisionCheck, person: Principal | null, actor: Principal | null): Promise<Verdict> {
  const { permissions, level } = KINDS[check.kind]
  const refuse = (reason: DecisionRefusalReason, permission: PermissionId = permissions[0]): Verdict =>
    ({ allowed: false, permission, reason })
  if (!person || (check.actorId && !actor)) return refuse('deleted')
  if (inactive(person) || (actor && inactive(actor))) return refuse('account_inactive')
  for (const permission of permissions) {
    let decision
    try {
      decision = actor
        ? await can(actor, permission, { projectId: check.projectId, actingAs: person, fresh: true })
        : await can(person, permission, { projectId: check.projectId, fresh: true })
    } catch (e) {
      // The admin may no longer act as this account (demoted, the account promoted or disabled).
      if (e instanceof ActAsNotAllowedError) return refuse('act_as_refused', permission)
      throw e
    }
    if (!decision.allowed) {
      if (decision.status === 400) throw new Error(`[rbac] authorize-decision lost its project (${permission})`)
      return refuse(decision.reason, permission)
    }
    if (level && (!decision.access || !meetsLevel(decision.access, level))) return refuse('project_level', permission)
  }
  return { allowed: true }
}

export const POST = withRouteErrors('Could not check the agent decision', async (request: NextRequest) => {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const check = parse(await request.json().catch(() => null))
  if (!check) {
    return NextResponse.json({ error: 'Not an agent decision check', code: 'invalid_decision_check' }, { status: 400 })
  }
  // Read now, never from the cache: a revocation must not wait out its bound.
  const person = await loadPrincipal(check.userId, { fresh: true })
  const actor = check.actorId ? await loadPrincipal(check.actorId, { fresh: true }) : null
  const verdict = await decide(check, person, actor)
  if (verdict.allowed) return NextResponse.json({ allowed: true })

  const realActor = check.actorId ?? check.userId
  console.warn(`[rbac] agent decision refused kind=${check.kind} permission=${verdict.permission} reason=${verdict.reason} session=${check.sessionId}`)
  // Best effort: the refusal stands whether or not its row is written.
  await writeAudit({
    actorId: realActor,
    onBehalfOfUserId: check.actorId ? check.userId : null,
    actorEmail: (check.actorId ? actor : person)?.email ?? null,
    projectId: check.projectId,
    permission: verdict.permission,
    action: 'agent.decision_refused',
    targetType: 'agent_session',
    targetId: check.sessionId,
    after: { kind: check.kind, reason: verdict.reason },
    source: 'ui',
  })
  return NextResponse.json({
    error: 'This decision is not allowed for this person on this project any more',
    code: 'forbidden',
    permission: verdict.permission,
    reason: verdict.reason,
  }, { status: 403 })
})
