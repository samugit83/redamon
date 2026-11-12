import { NextRequest, NextResponse } from 'next/server'
import { verifyPassword, createToken, AUTH_COOKIE_NAME, UNMATCHABLE_PASSWORD_HASH } from '@/lib/auth'
import { findSignInAccount, recordSignIn } from '@/lib/authz/accountEmail'
import { invalidatePrincipal } from '@/lib/authz/principal'
import { writeAudit } from '@/lib/audit'
import { getClientMeta } from '@/lib/requestMeta'
import { checkLockout, recordFailure, clearAttempts } from '@/lib/loginThrottle'
import { isSecureRequest } from '@/lib/cookieSecurity'
import { internalError } from '@/lib/routeErrors'

export async function POST(request: NextRequest) {
  try {
    const { email, password } = await request.json()
    const meta = getClientMeta(request)

    if (typeof email !== 'string' || typeof password !== 'string' || !email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      )
    }

    // S11: reject if this account or source IP is currently locked out. The
    // per-IP key is only used when the IP is TRUSTED (behind a proxy that sets a
    // real X-Forwarded-For). Untrusted (local) X-Forwarded-For is spoofable AND
    // collapses all host callers onto one docker-gateway IP, so keying on it
    // would let one client lock out others and let an attacker rotate XFF to
    // evade. Per-account lockout still protects every account either way.
    const lockIp = meta.ipTrusted ? meta.ip : null
    const lock = checkLockout(email, lockIp)
    if (lock.locked) {
      await writeAudit({
        action: 'auth.login.lockout', targetType: 'user',
        after: { email, ip: meta.ip, ipTrusted: meta.ipTrusted, retryAfter: lock.retryAfterSeconds },
      })
      return NextResponse.json(
        { error: 'Too many failed attempts. Try again later.' },
        { status: 429, headers: { 'Retry-After': String(lock.retryAfterSeconds) } }
      )
    }

    const user = await findSignInAccount(email)

    // One bcrypt compare on every path: with no account, or one without a
    // password, the compare runs against a hash nothing matches, so the answer
    // takes as long as a wrong password and its latency names no account.
    const valid = await verifyPassword(password, user?.password || UNMATCHABLE_PASSWORD_HASH)
    if (!user || !user.password || !valid) {
      // R5: log the failure. Record ONLY the attempted email + source IP; never
      // the password or hash. S11: increment the lockout counter.
      recordFailure(email, lockIp)
      await writeAudit({
        action: 'auth.login.failure', targetType: 'user',
        ...(user?.password ? { targetId: user.id } : {}),
        after: { email, ip: meta.ip, ipTrusted: meta.ipTrusted, userAgent: meta.userAgent },
      })
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      )
    }

    // S11: successful login clears the failure counters for this email + IP.
    clearAttempts(email, lockIp)
    await writeAudit({
      actorId: user.id, action: 'auth.login.success', targetType: 'user', targetId: user.id,
      after: { ip: meta.ip, ipTrusted: meta.ipTrusted, userAgent: meta.userAgent },
    })

    await recordSignIn(user.id)
    invalidatePrincipal(user.id)

    // The token carries the version the account holds now: raising it later signs this
    // browser out, together with every other one.
    const token = await createToken(user.id, user.role, user.sessionVersion)

    const response = NextResponse.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    })

    response.cookies.set(AUTH_COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: isSecureRequest(request), // S12: Secure over HTTPS, else plain HTTP works
      path: '/',
      maxAge: 7 * 24 * 60 * 60, // 7 days
    })

    return response
  } catch (error) {
    return internalError(error, 'Internal server error', { log: 'Login error' })
  }
}
