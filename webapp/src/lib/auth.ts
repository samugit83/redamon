import { SignJWT, jwtVerify } from 'jose'
import bcrypt from 'bcryptjs'
import type { WsSocket } from './wsTicket'

export const AUTH_COOKIE_NAME = 'redamon-auth'
const BCRYPT_ROUNDS = 12
const TOKEN_EXPIRY = '7d'

function getSecret() {
  const secret = process.env.AUTH_SECRET
  if (!secret || secret === 'changeme') {
    throw new Error('AUTH_SECRET environment variable is not set')
  }
  return new TextEncoder().encode(secret)
}

export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, BCRYPT_ROUNDS)
}

/**
 * A cost-12 bcrypt hash of 32 random bytes that were thrown away, so no input
 * matches it. Sign-in compares against it when there is no account, or one
 * without a password, so those answers take as long as a wrong password.
 */
export const UNMATCHABLE_PASSWORD_HASH = '$2a$12$xYkdNROTApiw1WKvtx5wPOVpWYwmqFB1MZwWZbpNAiUIhZSfbAZbG'

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  if (!hash) return false
  return bcrypt.compare(plain, hash)
}

function isSessionVersion(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0
}

/**
 * The login token. `sv` is the account's session version when it signed in: the session
 * helpers refuse the token once the account's version moves on, which signs it out of
 * every browser at once.
 */
export async function createToken(userId: string, role: string, sv = 0): Promise<string> {
  if (!isSessionVersion(sv)) throw new Error('A session version is a whole number from 0')
  return new SignJWT({ sub: userId, role, sv })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(TOKEN_EXPIRY)
    .sign(getSecret())
}

/**
 * The claims of a valid login token. A token minted before the session version existed
 * (and the Playwright helper's `{sub, role}`) is version 0; a version that is present but
 * not a whole number from 0 makes the token invalid.
 */
export async function verifyToken(token: string): Promise<{ sub: string; role: string; sv: number } | null> {
  try {
    const { payload } = await jwtVerify(token, getSecret())
    if (!payload.sub || !payload.role) return null
    const sv = payload.sv === undefined ? 0 : payload.sv
    if (!isSessionVersion(sv)) return null
    return { sub: payload.sub, role: payload.role as string, sv }
  } catch {
    return null
  }
}

// --- Agent WebSocket ticket (STRIDE S6) ---------------------------------------
// Short-lived HS256 ticket that binds an authenticated operator identity to a
// (projectId, sessionId) and to the one socket it opens (`aud`, HD-25): the agent
// refuses it on any other socket, so a chat ticket never opens the terminal. Signed
// with a DEDICATED secret (never AUTH_SECRET) so an agent-side compromise cannot
// forge login cookies. Returns null when the secret is unset, and the agent then
// REFUSES the socket (it fails closed, see agentic/ws_ticket.py) - a stack whose
// .env predates this secret must run ./redamon.sh update.
const WS_TICKET_EXPIRY = '60s'

function getWsTicketSecret(): Uint8Array | null {
  const secret = process.env.AGENT_WS_TICKET_SECRET
  if (!secret || secret === 'changeme') return null
  return new TextEncoder().encode(secret)
}

export async function createWsTicket(
  userId: string,
  projectId: string,
  sessionId: string,
  socket: WsSocket,
  // The person actually signed in, when an admin is simulating `userId`. The
  // agent records it on the runs it starts, so an audit row names who really
  // pressed the button. Omitted when it is `userId` itself.
  realActorUserId?: string
): Promise<string | null> {
  const key = getWsTicketSecret()
  if (!key) return null
  // A plain string claim, not setAudience(), which may write a list: the agent
  // compares `aud` with its socket name and accepts exactly one string.
  return new SignJWT({
    sub: userId, pid: projectId, sid: sessionId, aud: socket,
    ...(realActorUserId && realActorUserId !== userId ? { act: realActorUserId } : {}),
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(WS_TICKET_EXPIRY)
    .sign(key)
}

// --- Admin impersonation "act-as" token (per-user access control) -------------
// Records which user an ADMIN is currently simulating, in a dedicated httpOnly
// cookie. Unlike the ws-ticket (which is sent to the agent), this token is minted
// AND verified only inside the webapp, so reusing AUTH_SECRET is safe. It is
// mutually non-substitutable with the login JWT by claim shape: a login token has
// `role` and no `act`; an act-as token has `act` and no `role`. getEffectiveUser
// only honors it when the signed-in caller (the untouched login JWT) is an admin
// in the database AND the token's `sub` equals that admin's id AND the target
// still exists - so a standard user forging
// this cookie is ignored, and a login cookie replayed here fails the `act` check.
export const ACT_AS_COOKIE_NAME = 'redamon-act-as'
const ACT_AS_EXPIRY = '12h'

export async function createActAsToken(adminUserId: string, targetUserId: string): Promise<string> {
  return new SignJWT({ sub: adminUserId, act: targetUserId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(ACT_AS_EXPIRY)
    .sign(getSecret())
}

export async function verifyActAsToken(token: string): Promise<{ sub: string; act: string } | null> {
  try {
    const { payload } = await jwtVerify(token, getSecret())
    if (!payload.sub || typeof payload.act !== 'string' || !payload.act) return null
    return { sub: payload.sub as string, act: payload.act }
  } catch {
    return null
  }
}
