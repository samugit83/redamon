/**
 * Audit rows of user administration (HD-14): creating, editing, promoting or
 * demoting, resetting and deleting an account. Best effort through `writeAudit`.
 *
 * Actor convention (lib/auditActor.ts): `actorId` is the REAL signed-in account (the
 * login cookie); the account an admin was acting as goes in `onBehalfOfUserId` and,
 * as before that column existed, in `after.actingAsUserId`. A row never carries a
 * password, a hash or a token.
 */
import { ACT_AS_COOKIE_NAME, verifyActAsToken } from '@/lib/auth'
import { writeAudit, type AuditEntry } from '@/lib/audit'
import { actorFields, auditActorOf } from '@/lib/auditActor'
import { actAsInForceFor } from '@/lib/session'
import { sessionPrincipal } from '@/lib/authz/sessionPrincipal'
import { actsAsOthers } from '@/lib/authz/actAs'
import { sessionHolds } from '@/lib/authz/adminPermission'
import { rbacFlags } from '@/lib/authz/flags'

interface Actor {
  userId: string
  role: string
}

/** Some route tests hand in a bare object, or a plain Request without NextRequest's cookie jar. */
type RequestLike = { headers?: Headers }

/**
 * The act-as token the request's cookie header carries, unverified. The header is read before
 * the cookie name, so a request without cookies never touches the auth module.
 */
export function presentedActAsToken(request: RequestLike): string | null {
  const header = request.headers?.get?.('cookie')
  if (!header) return null
  const prefix = `${ACT_AS_COOKIE_NAME}=`
  const pair = header.split(';').map(p => p.trim()).find(p => p.startsWith(prefix))
  return pair?.slice(prefix.length) || null
}

/**
 * The act-as cookie the request carries, when its signature holds. Whether it was
 * this admin's is the caller's decision.
 */
export async function presentedActAs(request: RequestLike): Promise<{ sub: string; act: string } | null> {
  const token = presentedActAsToken(request)
  return token ? verifyActAsToken(token) : null
}

/**
 * The account `actor` was acting as. Permissions switch on: the request's own decision (session.ts
 * `actAsInForceFor`), so a cookie that ended on this request (the admin's version moved, the account
 * disabled or promoted, its impersonation already stopped) names no one, as the request ran as the
 * admin. Off: an act-as cookie this admin minted, naming someone else, held by an admin; the target
 * is not re-read from the database, the row records what the request carried.
 */
export async function actingAsUserId(request: RequestLike, actor: Actor): Promise<string | null> {
  if (!actsAsOthers(actor)) return null
  if (rbacFlags().permissions) return (await actAsInForceFor(actor, presentedActAsToken(request)))?.target.id ?? null
  const claims = await presentedActAs(request)
  if (!claims || claims.sub !== actor.userId || claims.act === actor.userId) return null
  return (await sessionHolds(actor, 'users:impersonate')) ? claims.act : null
}

export interface UserAuditFields {
  action: string
  targetId: string
  before?: Record<string, unknown>
  after?: Record<string, unknown>
}

/** The row `writeUserAudit` writes, for a writer that must write it in its own transaction (`writeAuditTx`). */
export async function userAuditEntry(request: RequestLike, actor: Actor, entry: UserAuditFields): Promise<AuditEntry> {
  const actingAs = await actingAsUserId(request, actor)
  const real = { id: actor.userId, email: sessionPrincipal(actor)?.email }
  return {
    ...actorFields(auditActorOf(real, actingAs)),
    action: entry.action,
    targetType: 'user',
    targetId: entry.targetId,
    before: entry.before,
    after: actingAs ? { ...entry.after, actingAsUserId: actingAs } : entry.after,
    source: 'api',
  }
}

export async function writeUserAudit(request: RequestLike, actor: Actor, entry: UserAuditFields): Promise<void> {
  await writeAudit(await userAuditEntry(request, actor, entry))
}
