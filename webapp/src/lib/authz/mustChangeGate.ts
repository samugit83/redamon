/**
 * Where an account that must change its password may go (step 2.8, ID-17). The middleware
 * reads the login token's `pwc` claim (identity switch on) and lets through only the change
 * page and what it needs; every other page goes to MUST_CHANGE_PAGE and every other API
 * answers 403 MUST_CHANGE_CODE. Pure, so the Edge middleware can import it.
 */

export const MUST_CHANGE_PAGE = '/account?changePassword=1'
export const MUST_CHANGE_CODE = 'must_change_password'
export const MUST_CHANGE_MESSAGE = 'You must change your password before you continue.'

// The change page reads the signed-in account, the policy it must meet, and can sign out.
const ALLOWED_PATHS = new Set(['/account', '/api/auth/me', '/api/auth/logout', '/api/auth/password-policy'])

/** True when `userId`, holding a must-change token, may reach `method pathname`. */
export function mustChangeAllows(method: string, pathname: string, userId: string): boolean {
  if (ALLOWED_PATHS.has(pathname)) return true
  return method === 'PUT' && pathname === `/api/users/${userId}/password`
}
