import { SignJWT, jwtVerify, errors as joseErrors } from 'jose'
import bcrypt from 'bcryptjs'
import type { WsSocket } from './wsTicket'
import type { AgentTicketCap } from './authz/agentCap'
import { lifetimeClaimsValid } from './authz/sessionIdle'

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
 * How long a login token lives (identity switch on, step 2.11; lib/authz/sessionLifetime.ts
 * decides it). An admin's token says so (`adm: 1`) and, with `idleMinutes`, carries its idle
 * limit `idl` and its last activity `lat`, which the middleware checks and moves forward.
 */
export interface TokenLifetime {
  seconds: number
  admin?: boolean
  idleMinutes?: number | null
}

/**
 * The login token. `sv` is the account's session version when it signed in: the session
 * helpers refuse the token once the account's version moves on, which signs it out of
 * every browser at once. `pwc: 1` (identity switch on) says the account must change its
 * password: the middleware holds the browser on the change page without a database read.
 * Without `lifetime` the token is the Phase 1 one: 7 days, no lifetime claim.
 */
export async function createToken(
  userId: string,
  role: string,
  sv = 0,
  { pwc = false, lifetime }: { pwc?: boolean; lifetime?: TokenLifetime } = {},
): Promise<string> {
  if (!isSessionVersion(sv)) throw new Error('A session version is a whole number from 0')
  const claims = { sub: userId, role, sv, ...(pwc ? { pwc: 1 } : {}) }
  if (!lifetime) {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime(TOKEN_EXPIRY)
      .sign(getSecret())
  }
  // jose checks `exp` against the wall clock, so the token's times come from it too.
  const iat = Math.floor(Date.now() / 1000)
  const idle = lifetime.admin && lifetime.idleMinutes ? { idl: lifetime.idleMinutes, lat: iat } : {}
  return new SignJWT({ ...claims, ...(lifetime.admin ? { adm: 1 } : {}), ...idle })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(iat)
    .setExpirationTime(iat + lifetime.seconds)
    .sign(getSecret())
}

/**
 * The claims of a valid login token. A token minted before the session version existed
 * (and the Playwright helper's `{sub, role}`) is version 0; a version that is present but
 * not a whole number from 0 makes the token invalid, and so does a `pwc` other than 1 or a
 * malformed lifetime claim.
 */
export async function verifyToken(token: string): Promise<{ sub: string; role: string; sv: number; pwc?: true } | null> {
  try {
    const { payload } = await jwtVerify(token, getSecret())
    if (!payload.sub || !payload.role) return null
    const sv = payload.sv === undefined ? 0 : payload.sv
    if (!isSessionVersion(sv)) return null
    if (payload.pwc !== undefined && payload.pwc !== 1) return null
    if (!lifetimeClaimsValid(payload)) return null
    return { sub: payload.sub, role: payload.role as string, sv, ...(payload.pwc === 1 ? { pwc: true as const } : {}) }
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
  realActorUserId?: string,
  // An `agent` ticket's agent permissions (authz/agentCap.ts). The agent refuses the
  // approvals they do not cover; an empty list holds none, while no claim at all is
  // a ticket from before step 3.9b, which the agent treats as today's behaviour.
  cap?: readonly AgentTicketCap[]
): Promise<string | null> {
  const key = getWsTicketSecret()
  if (!key) return null
  // A plain string claim, not setAudience(), which may write a list: the agent
  // compares `aud` with its socket name and accepts exactly one string.
  return new SignJWT({
    sub: userId, pid: projectId, sid: sessionId, aud: socket,
    ...(realActorUserId && realActorUserId !== userId ? { act: realActorUserId } : {}),
    ...(cap ? { cap: [...cap] } : {}),
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

/**
 * `seconds`: the lifetime the identity switch gives act-as (step 2.11); without it, 12 h. `asv`: the
 * admin's session version when the impersonation started (step 3.14, permissions switch on): a later
 * change of the admin's version ends it.
 */
export async function createActAsToken(
  adminUserId: string,
  targetUserId: string,
  seconds?: number,
  { asv }: { asv?: number } = {},
): Promise<string> {
  if (asv !== undefined && !isSessionVersion(asv)) throw new Error('A session version is a whole number from 0')
  const claims = { sub: adminUserId, act: targetUserId, ...(asv !== undefined ? { asv } : {}) }
  const jwt = new SignJWT(claims).setProtectedHeader({ alg: 'HS256' })
  if (seconds === undefined) return jwt.setIssuedAt().setExpirationTime(ACT_AS_EXPIRY).sign(getSecret())
  const iat = Math.floor(Date.now() / 1000)
  return jwt.setIssuedAt(iat).setExpirationTime(iat + seconds).sign(getSecret())
}

/** The claims of an act-as token; `asv` only on a token minted with the permissions switch on. */
export interface ActAsClaims {
  sub: string
  act: string
  asv?: number
}

function actAsClaims(payload: Record<string, unknown>): ActAsClaims | null {
  if (typeof payload.sub !== 'string' || !payload.sub || typeof payload.act !== 'string' || !payload.act) return null
  if (payload.asv === undefined) return { sub: payload.sub, act: payload.act }
  return isSessionVersion(payload.asv) ? { sub: payload.sub, act: payload.act, asv: payload.asv } : null
}

export async function verifyActAsToken(token: string): Promise<ActAsClaims | null> {
  try {
    const { payload } = await jwtVerify(token, getSecret())
    return actAsClaims(payload)
  } catch {
    return null
  }
}

/**
 * An act-as token whose signature holds, expired or not (step 3.14): an expired one is how the
 * end of an impersonation by its time limit is noticed. `issuedAt` / `expiresAt` in seconds.
 */
export async function readActAsToken(
  token: string,
): Promise<{ claims: ActAsClaims; issuedAt: number | null; expiresAt: number | null; expired: boolean } | null> {
  let payload: Record<string, unknown>
  let expired = false
  try {
    payload = (await jwtVerify(token, getSecret())).payload
  } catch (err) {
    // jose checks the signature before the claims, so an expired token's payload is authentic.
    if (!(err instanceof joseErrors.JWTExpired)) return null
    payload = err.payload
    expired = true
  }
  const claims = actAsClaims(payload)
  if (!claims) return null
  const seconds = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null)
  return { claims, issuedAt: seconds(payload.iat), expiresAt: seconds(payload.exp), expired }
}
