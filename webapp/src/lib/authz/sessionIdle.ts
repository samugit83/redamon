/**
 * The admin idle timeout (step 2.11, ID-24), judged by the Edge middleware from the login
 * token alone: an admin's token carries its idle limit `idl` (minutes) and its last activity
 * `lat` (seconds). Idle longer than the limit ends the session; activity moves `lat` forward at
 * most once a minute, so a busy admin is not handed a new cookie on every request. Pure, so the
 * middleware can import it.
 *
 * Any request the browser sends counts as activity, an open tab's polling included: the timeout
 * ends a session nobody has used, not one left open on a screen.
 */

/** `lat` moves forward at most this often. */
export const ACTIVITY_REFRESH_SECONDS = 60

export const SESSION_IDLE_CODE = 'session_ended'
export const SESSION_IDLE_MESSAGE = 'Your session ended after a period of inactivity. Sign in again.'

export type IdleVerdict = 'none' | 'active' | 'refresh' | 'idle'

const wholeFrom = (v: unknown, min: number) => typeof v === 'number' && Number.isSafeInteger(v) && v >= min

/**
 * The lifetime claims a login token may carry: `adm` is 1, and the idle pair is both or neither,
 * `idl` minutes from 1 and `lat` seconds. A token breaking this is invalid (lib/auth.ts
 * verifyToken and the middleware apply the same rule).
 */
export function lifetimeClaimsValid(payload: Record<string, unknown>): boolean {
  if (payload.adm !== undefined && payload.adm !== 1) return false
  if (payload.idl === undefined && payload.lat === undefined) return true
  return wholeFrom(payload.idl, 1) && wholeFrom(payload.lat, 0)
}

/**
 * What to do with a token at `nowSeconds`: `none` without idle claims (a member, or a token from
 * before the switch), `idle` past its limit, `refresh` when its `lat` is a minute old or more,
 * else `active`. A clock behind the token's (another copy, a skew) is `active`. The claims were
 * checked well-formed when the token was verified (lifetimeClaimsValid).
 */
export function idleVerdict(claims: Record<string, unknown>, nowSeconds: number): IdleVerdict {
  if (typeof claims.idl !== 'number' || typeof claims.lat !== 'number') return 'none'
  const quiet = nowSeconds - claims.lat
  if (quiet > claims.idl * 60) return 'idle'
  return quiet >= ACTIVITY_REFRESH_SECONDS ? 'refresh' : 'active'
}
