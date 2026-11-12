/**
 * The principal a session object was built from. `getSession()` answers `{userId, role}`
 * and many callers compare that shape exactly; the audit actor also needs the account's
 * email, which the same database read already returned. Keeping it beside the object
 * (weakly, so it dies with the request's session) saves a second read per audit row.
 *
 * A session object `getSession()` did not build (a test double, a hand-made one) has no
 * principal here: its rows record no email.
 */
import type { Principal } from './principal'

const principals = new WeakMap<object, Principal>()

export function rememberSessionPrincipal(session: object, principal: Principal): void {
  principals.set(session, principal)
}

export function sessionPrincipal(session: object): Principal | null {
  return principals.get(session) ?? null
}
