/**
 * Who an audit row names (AU-01, AU-08). `actorId` is the person signed in (the login
 * cookie), never the account an admin acts as; under act-as that account goes in
 * `onBehalfOfUserId`; `actorEmail` snapshots the actor's address, so the row still
 * names a person after the account is deleted (OQ-31).
 *
 * This is the one reader of the real person behind a request. The per-feature helpers
 * (`realActorUserId`, `actingAdminId`, the workspace and plugin-action audits, the
 * change-set routes, `auditActorFor` and its callers) delegate to it.
 *
 * It lives apart from lib/audit.ts on purpose: most route tests replace that module with
 * a bare `writeAudit` double, which would take this reader away from the helpers too.
 */
import type { AuditEntry } from '@/lib/audit'
import { sessionPrincipal } from '@/lib/authz/sessionPrincipal'
import { getEffectiveUser, getSession, type EffectiveUser, type Session } from '@/lib/session'

export interface AuditActor {
  actorId: string | null
  onBehalfOfUserId: string | null
  actorEmail: string | null
}

/** The convention, from what a writer already holds: the real account and the effective user. */
export function auditActorOf(
  real: { id: string; email?: string | null } | null | undefined,
  effectiveUserId?: string | null,
): AuditActor {
  if (!real) return { actorId: null, onBehalfOfUserId: null, actorEmail: null }
  return {
    actorId: real.id,
    onBehalfOfUserId: effectiveUserId && effectiveUserId !== real.id ? effectiveUserId : null,
    actorEmail: real.email ?? null,
  }
}

/** The real account of a session a writer already read, with its email when getSession read it. */
export function sessionActor(session: Session): { id: string; email: string | null } {
  return { id: session.userId, email: sessionPrincipal(session)?.email ?? null }
}

/** The person signed in, with their email when the session read returned it. A failed read throws. */
export async function signedInActor(): Promise<{ id: string; email: string | null } | null> {
  const session = await getSession()
  return session ? sessionActor(session) : null
}

/**
 * The actor of the current request. Pass the effective user when the caller already
 * resolved it; otherwise it is read here (the act-as cookie, minted by this admin, naming
 * an account that still exists). A failed read throws, as the session helpers do.
 */
export async function auditActor(effective?: EffectiveUser | null): Promise<AuditActor> {
  const real = await signedInActor()
  if (!real) return auditActorOf(null)
  const eff = effective === undefined ? await getEffectiveUser() : effective
  return auditActorOf(real, eff?.userId)
}

/**
 * The actor as the fields of an audit entry. An empty column is left out, so an entry
 * without act-as and without a known email is exactly the entry written before.
 */
export function actorFields(actor: AuditActor): Pick<AuditEntry, 'actorId' | 'onBehalfOfUserId' | 'actorEmail'> {
  return {
    actorId: actor.actorId,
    ...(actor.onBehalfOfUserId ? { onBehalfOfUserId: actor.onBehalfOfUserId } : {}),
    ...(actor.actorEmail ? { actorEmail: actor.actorEmail } : {}),
  }
}
