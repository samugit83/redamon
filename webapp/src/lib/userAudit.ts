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
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf } from '@/lib/auditActor'
import { sessionPrincipal } from '@/lib/authz/sessionPrincipal'

interface Actor {
  userId: string
  role: string
}

/** Some route tests hand in a bare object, or a plain Request without NextRequest's cookie jar. */
type RequestLike = { headers?: Headers }

/**
 * The act-as cookie the request carries, when its signature holds. Whether it was
 * this admin's is the caller's decision. The header is read before the cookie name,
 * so a request without cookies never touches the auth module.
 */
export async function presentedActAs(request: RequestLike): Promise<{ sub: string; act: string } | null> {
  const header = request.headers?.get?.('cookie')
  if (!header) return null
  const prefix = `${ACT_AS_COOKIE_NAME}=`
  const pair = header.split(';').map(p => p.trim()).find(p => p.startsWith(prefix))
  const token = pair?.slice(prefix.length)
  return token ? verifyActAsToken(token) : null
}

/**
 * The account `actor` was acting as: an act-as cookie this admin minted, naming
 * someone else. The target is not re-read from the database; the row records what
 * the request carried.
 */
export async function actingAsUserId(request: RequestLike, actor: Actor): Promise<string | null> {
  if (actor.role !== 'admin') return null
  const claims = await presentedActAs(request)
  if (!claims || claims.sub !== actor.userId || claims.act === actor.userId) return null
  return claims.act
}

export async function writeUserAudit(
  request: RequestLike,
  actor: Actor,
  entry: { action: string; targetId: string; before?: Record<string, unknown>; after?: Record<string, unknown> },
): Promise<void> {
  const actingAs = await actingAsUserId(request, actor)
  const real = { id: actor.userId, email: sessionPrincipal(actor)?.email }
  await writeAudit({
    ...actorFields(auditActorOf(real, actingAs)),
    action: entry.action,
    targetType: 'user',
    targetId: entry.targetId,
    before: entry.before,
    after: actingAs ? { ...entry.after, actingAsUserId: actingAs } : entry.after,
    source: 'api',
  })
}
