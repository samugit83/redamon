import type { NextRequest, NextResponse } from 'next/server'
import { AUTH_COOKIE_NAME } from './auth'
import { isSecureRequest } from './cookieSecurity'

/** The Phase 1 login cookie lives as long as the Phase 1 login token (lib/auth.ts TOKEN_EXPIRY, 7 days). */
export const LOGIN_COOKIE_MAX_AGE = 7 * 24 * 60 * 60

/**
 * Hands the browser a login token: at sign-in, at an invite accept, and when a password change
 * re-issues it (step 2.8: the must-change claim dropped), with the same attributes each time.
 * `maxAge` is the token's own lifetime (lib/authz/sessionLifetime.ts issueLoginToken, step 2.11),
 * so the cookie never outlives the token nor drops it early.
 */
export function setLoginCookie(response: NextResponse, request: NextRequest, token: string, maxAge = LOGIN_COOKIE_MAX_AGE): void {
  response.cookies.set(AUTH_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isSecureRequest(request), // S12: Secure over HTTPS, else plain HTTP works
    path: '/',
    maxAge,
  })
}
