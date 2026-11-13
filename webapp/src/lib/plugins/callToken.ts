import { randomUUID } from 'crypto'
import { SignJWT, jwtVerify } from 'jose'
import { now } from './clock'
import { isValidPluginId } from './ids'
import { actionMaxTimeoutSeconds } from './settings'

/**
 * Call tokens (README.PLUGINS.md §7.3, TD-07): the only credential plugin code ever
 * holds. The webapp mints one per action run and the worker sends it to the Gateway,
 * which re-checks everything it names on every call (gateway.ts); the token only says
 * who is asking (`sub`, and `act` under act-as) and for whose project (`ten`, its owner),
 * never what they may still do.
 *
 * Signed with PLUGIN_CALL_TOKEN_SECRET, never AUTH_SECRET, and the claims carry no
 * `role`: the middleware accepts any AUTH_SECRET-signed JWT with `sub` and `role` as a
 * login session, so either mistake would turn a token handed to third-party code into a
 * browser login. There is no `migration` kind: migration code is a per-row function the
 * platform runs, with no Gateway access (TD-28).
 */
export const CALL_TOKEN_AUDIENCE = 'redamon-plugin-gateway'
export const CALL_TOKEN_KINDS = ['action', 'job'] as const
export type CallTokenKind = (typeof CALL_TOKEN_KINDS)[number]

// The token outlives the action and its final jobs/complete (RV-20).
const TTL_MARGIN_SECONDS = 60
// openssl rand -hex 32 (redamon.sh) gives 64; HS256 wants at least 256 bits.
const SECRET_MIN_CHARS = 32
const OPTIONAL_STRING_CLAIMS = ['act', 'prj', 'ses', 'conv', 'jid'] as const

export class CallTokenConfigError extends Error {
  readonly code = 'plugins_not_configured'
  constructor(message: string) {
    super(message)
    this.name = 'CallTokenConfigError'
  }
}

export interface CallTokenClaims {
  pid: string
  ver: string
  /** The effective user the action runs for. */
  sub: string
  /**
   * The tenant (step 5.10): the owner of the token's project, whose model and keys a call spends,
   * else `sub`. A token minted before the claim existed reads as `sub`, the owner it was minted for.
   */
  ten: string
  /** The admin acting as `sub`, when one is. */
  act?: string
  prj?: string
  ses?: string
  conv?: string
  perms: string[]
  kind: CallTokenKind
  jid?: string
  jti: string
  aud: string
  iat: number
  exp: number
}

export interface MintCallTokenInput {
  pluginId: string
  version: string
  sub: string
  /** The project's owner; `sub` when absent. The Gateway refuses a token whose tenant no longer owns its project. */
  ten?: string
  act?: string
  prj?: string
  ses?: string
  conv?: string
  perms: string[]
  kind: CallTokenKind
  jid?: string
  /** The action's manifest timeout; the token lives min(it, PLUGIN_ACTION_MAX_TIMEOUT) + 60 s. */
  timeoutSeconds: number
}

// Keys the call-token secret must differ from. A leaked call token must never sign a
// login (AUTH_SECRET); the runner holds PLUGIN_RUNNER_KEY, and a runner escape must not
// yield the key that signs call tokens; the agent's keys must not double as it either.
const DISTINCT_FROM = ['AUTH_SECRET', 'PLUGIN_RUNNER_KEY', 'INTERNAL_API_KEY', 'AGENT_WS_TICKET_SECRET'] as const
const reportedSameAs = new Set<string>()

function secret(): Uint8Array {
  const value = (process.env.PLUGIN_CALL_TOKEN_SECRET || '').trim()
  if (!value || value === 'changeme' || value.length < SECRET_MIN_CHARS) {
    throw new CallTokenConfigError(
      `PLUGIN_CALL_TOKEN_SECRET is not configured (at least ${SECRET_MIN_CHARS} characters; ./redamon.sh up generates it)`,
    )
  }
  const same = DISTINCT_FROM.find((name) => value === (process.env[name] || '').trim())
  if (same) {
    if (!reportedSameAs.has(same)) {
      reportedSameAs.add(same)
      console.error(`[plugins] PLUGIN_CALL_TOKEN_SECRET equals ${same}; every plugin call is refused until it differs`)
    }
    throw new CallTokenConfigError(`PLUGIN_CALL_TOKEN_SECRET must differ from ${same}`)
  }
  return new TextEncoder().encode(value)
}

export function callTokenTtlSeconds(timeoutSeconds: number): number {
  if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 1) {
    throw new RangeError(`invalid action timeout ${timeoutSeconds}`)
  }
  return Math.min(timeoutSeconds, actionMaxTimeoutSeconds()) + TTL_MARGIN_SECONDS
}

const isKind = (k: unknown): k is CallTokenKind => (CALL_TOKEN_KINDS as readonly unknown[]).includes(k)
const nonEmpty = (v: unknown): v is string => typeof v === 'string' && v.length > 0

export async function mintCallToken(
  input: MintCallTokenInput,
): Promise<{ token: string; jti: string; expiresAt: Date }> {
  const key = secret()
  if (!isValidPluginId(input.pluginId)) throw new TypeError(`invalid plugin id ${JSON.stringify(input.pluginId)}`)
  if (!nonEmpty(input.version)) throw new TypeError('a call token needs the plugin version')
  if (!nonEmpty(input.sub)) throw new TypeError('a call token needs the user it acts for')
  if (input.ten !== undefined && !nonEmpty(input.ten)) throw new TypeError('a call token names its tenant, or leaves it out')
  if (!isKind(input.kind)) throw new TypeError(`invalid call token kind ${JSON.stringify(input.kind)}`)
  if ((input.kind === 'job') !== nonEmpty(input.jid)) {
    throw new TypeError('a job token needs its job id, and only a job token carries one')
  }
  const issuedAt = Math.floor(now().getTime() / 1000)
  const exp = issuedAt + callTokenTtlSeconds(input.timeoutSeconds)
  const jti = randomUUID()
  const claims: Record<string, unknown> = {
    pid: input.pluginId,
    ver: input.version,
    ten: input.ten ?? input.sub,
    perms: [...input.perms],
    kind: input.kind,
  }
  for (const k of OPTIONAL_STRING_CLAIMS) if (nonEmpty(input[k])) claims[k] = input[k]
  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(input.sub)
    .setAudience(CALL_TOKEN_AUDIENCE)
    .setJti(jti)
    .setIssuedAt(issuedAt)
    .setExpirationTime(exp)
    .sign(key)
  return { token, jti, expiresAt: new Date(exp * 1000) }
}

/**
 * The token's claims, or null when it is not a valid, unexpired call token of one of
 * `kinds`. Throws CallTokenConfigError when the platform cannot verify anything (no
 * usable secret), which the Gateway answers with 503 rather than blaming the caller.
 */
export async function verifyCallToken(
  token: string,
  opts: { kinds: readonly CallTokenKind[] },
): Promise<CallTokenClaims | null> {
  const key = secret()
  if (typeof token !== 'string' || token.length === 0 || token.length > 8192) return null
  let payload: Record<string, unknown>
  try {
    const verified = await jwtVerify(token, key, {
      algorithms: ['HS256'],
      audience: CALL_TOKEN_AUDIENCE,
      currentDate: now(),
      requiredClaims: ['sub', 'jti', 'iat', 'exp'],
    })
    payload = verified.payload as Record<string, unknown>
  } catch {
    return null
  }
  const { pid, ver, sub, ten, perms, kind, jti, iat, exp } = payload
  if (!isValidPluginId(pid) || !nonEmpty(ver) || !nonEmpty(sub) || !nonEmpty(jti)) return null
  if (ten !== undefined && !nonEmpty(ten)) return null
  if (!Array.isArray(perms) || !perms.every((p) => typeof p === 'string')) return null
  if (!isKind(kind) || !opts.kinds.includes(kind)) return null
  if (typeof iat !== 'number' || typeof exp !== 'number') return null
  for (const k of OPTIONAL_STRING_CLAIMS) {
    if (payload[k] !== undefined && !nonEmpty(payload[k])) return null
  }
  if ((kind === 'job') !== nonEmpty(payload.jid)) return null
  const claims: CallTokenClaims = {
    pid, ver, sub, ten: (ten as string | undefined) ?? sub, perms: perms as string[], kind, jti, aud: CALL_TOKEN_AUDIENCE, iat, exp,
  }
  for (const k of OPTIONAL_STRING_CLAIMS) if (nonEmpty(payload[k])) claims[k] = payload[k] as string
  return claims
}
