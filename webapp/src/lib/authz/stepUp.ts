/**
 * Step-up (T13): an action that a stolen session cookie must not be able to take on
 * its own asks again for the password of the REAL signed-in account, never the
 * account an admin is acting as, so this module reads the session itself.
 *
 * Every caller shares one lockout counter per person, the MCP mint's key: wrong
 * passwords count once across all step-up routes instead of five times per route,
 * which would multiply the guesses a stolen cookie gets. A locked check answers
 * before the KDF runs, so the step-up is neither an unlimited password oracle nor a
 * cheap way to burn CPU on a deliberately slow hash.
 *
 * The helper returns an outcome and each caller maps it. The MCP mint and the token
 * PATCH keep the answers their clients know (401 / 429); every other caller answers
 * through `stepUpRefusal`. No step-up cookie: each sensitive request carries the password.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { verifyPassword } from '@/lib/auth'
import { getSession } from '@/lib/session'
import { checkLockout, recordFailure, clearAttempts } from '@/lib/loginThrottle'

export type StepUpResult =
  | { outcome: 'ok' }
  | { outcome: 'missing' }
  | { outcome: 'wrong' }
  | { outcome: 'locked'; retryAfterSeconds: number }

export function stepUpThrottleKey(userId: string): string {
  return `mcp-token-mint:${userId}`
}

/** Some route tests hand in a bare object with only `json()`. */
function clientIp(request: { headers?: Headers }): string | null {
  return request.headers?.get?.('x-forwarded-for')?.split(',')[0]?.trim() || null
}

/**
 * Check `password` against the signed-in account. A missing password costs no
 * attempt (nothing was guessed); a wrong one counts. No signed-in account, or one
 * deleted since the caller read it, is `wrong`.
 */
export async function checkStepUp(request: { headers?: Headers }, password: unknown): Promise<StepUpResult> {
  const session = await getSession({ fresh: true })
  if (!session) return { outcome: 'wrong' }
  const key = stepUpThrottleKey(session.userId)
  const ip = clientIp(request)

  const lock = checkLockout(key, ip)
  if (lock.locked) return { outcome: 'locked', retryAfterSeconds: lock.retryAfterSeconds }
  if (typeof password !== 'string' || password === '') return { outcome: 'missing' }

  const account = await prisma.user.findUnique({ where: { id: session.userId }, select: { password: true } })
  if (!account || !(await verifyPassword(password, account.password))) {
    recordFailure(key, ip)
    return { outcome: 'wrong' }
  }
  clearAttempts(key, ip)
  return { outcome: 'ok' }
}

/** The answer of every step-up caller other than the MCP mint and token PATCH; null when ok. */
export function stepUpRefusal(result: StepUpResult): NextResponse | null {
  switch (result.outcome) {
    case 'ok':
      return null
    case 'missing':
      return NextResponse.json(
        { error: 'Enter your password to confirm this action.', code: 'step_up_required' },
        { status: 403 },
      )
    case 'wrong':
      return NextResponse.json({ error: 'Password is incorrect', code: 'step_up_failed' }, { status: 403 })
    case 'locked':
      return NextResponse.json(
        { error: `Too many incorrect passwords. Try again in ${result.retryAfterSeconds}s.`, code: 'step_up_locked' },
        { status: 429, headers: { 'Retry-After': String(result.retryAfterSeconds) } },
      )
  }
}

export async function requireStepUp(request: { headers?: Headers }, password: unknown): Promise<NextResponse | null> {
  return stepUpRefusal(await checkStepUp(request, password))
}
