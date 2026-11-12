import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { BrowserContext } from '@playwright/test'

/**
 * A session cookie minted directly from AUTH_SECRET.
 *
 * Logging in through the form would mean holding a real password in the test
 * harness. The app's own token is an HS256 JWT over `{ sub, role, sv }`
 * (webapp/src/lib/auth.ts), so it can be signed here from the same secret the
 * server verifies with - no credentials, and no dependency on the login page's
 * markup staying put. Without `sv` the token is session version 0, which an
 * account holds until something signs it out everywhere (a revoke, a host
 * password reset): after that, sign in through the form.
 */

const AUTH_COOKIE_NAME = 'redamon-auth'

function repoRoot(): string {
  // tests/ -> e2e/ -> testing/ -> repo root. The harness moved under testing/
  // in the root reorg and this climb was left one level short, so every spec
  // died in beforeEach looking for testing/.env.
  return join(__dirname, '..', '..', '..')
}

export function authSecret(): string {
  const env = readFileSync(join(repoRoot(), '.env'), 'utf8')
  const line = env.split('\n').find(l => l.startsWith('AUTH_SECRET='))
  if (!line) throw new Error('AUTH_SECRET not found in .env')
  const value = line.slice('AUTH_SECRET='.length).trim().replace(/^["']|["']$/g, '')
  if (!value || value === 'changeme') throw new Error('AUTH_SECRET is unset or still the placeholder')
  return value
}

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

/**
 * `ttlSeconds` defaults to an hour, which is fine for a spec that finishes in
 * seconds and wrong for one that does not. A Secret Multiscanner
 * `github_experimental` scan runs 95-105 minutes, so a test driving one outlives
 * the default token: every `page.request` call starts answering 401 at the
 * 60-minute mark, `expect.poll` sees a guarded sentinel rather than a status,
 * and the test finally fails on a timeout that looks exactly like a scanner
 * that never finished. Pass a TTL that covers the whole run.
 */
export function mintToken(userId: string, role = 'admin', ttlSeconds = 3600): string {
  const now = Math.floor(Date.now() / 1000)
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = b64url(JSON.stringify({
    sub: userId, role, iat: now, exp: now + ttlSeconds,
  }))
  const data = `${header}.${payload}`
  const sig = b64url(createHmac('sha256', authSecret()).update(data).digest())
  return `${data}.${sig}`
}

export async function signIn(context: BrowserContext, userId: string, baseURL: string,
                             ttlSeconds = 3600) {
  const url = new URL(baseURL)
  await context.addCookies([{
    name: AUTH_COOKIE_NAME,
    value: mintToken(userId, 'admin', ttlSeconds),
    domain: url.hostname,
    path: '/',
    httpOnly: true,
    sameSite: 'Lax',
  }])
}
