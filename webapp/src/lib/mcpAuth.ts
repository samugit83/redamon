/**
 * Personal access tokens for the INBOUND MCP server (/api/mcp-server).
 *
 * RedAmon is the *server* here and the caller is untrusted, so the one thing
 * this file exists to establish is WHICH USER a request is. Everything else -
 * ownership, scopes, budgets - hangs off that single resolved id.
 *
 * Deliberate choices, each because this surface is programmatic, credentialed
 * and internet-reachable:
 *
 *  - `assertMcpProjectAccess` takes the token (its user and its opt-in to shared
 *    projects), never a browser session or the act-as cookie, and refuses a project
 *    the token may not reach with a flat 404.
 *  - Scopes are checked on every call. A field that exists but is never read is
 *    fail-open by omission. The scopes a call sees are the minted ones its owner
 *    may still use (RBAC permissions, mcp/scopePermissions.ts), computed once here.
 *  - Expiry and revocation are re-checked on every call, not at connect, so both
 *    take effect mid-session.
 */
import { createHash, randomBytes } from 'crypto'
import prisma from '@/lib/prisma'
import { constantTimeEqual } from '@/lib/constantTimeEqual'
import { meetsLevel, projectAccess, type ProjectAccess } from '@/lib/authz/projectAccess'
import type { ProjectLevel } from '@/lib/authz/permissions'
import { usableScopes } from '@/lib/mcp/scopePermissions'

export const MCP_TOKEN_PREFIX = 'rdmn_mcp_'
/** 24 bytes -> 48 hex chars, comfortably past the 40 the format calls for. */
const TOKEN_RANDOM_BYTES = 24
const PREFIX_DISPLAY_LEN = 8
export const MCP_TOKEN_NAME_MAX = 64

// --- scopes ------------------------------------------------------------------

export const MCP_SCOPES = [
  'recon:read',
  'recon:scan',
  'recon:overwrite',
  'recon:settings',
  // Split from recon:read rather than folded into it. Suppressed findings and
  // the remediation corpus are data classes NO token has ever been able to
  // reach by any route, so adding them to an existing scope would silently
  // change what every already-minted credential can read, with no operator
  // action and no change to the chips an incident responder sees on it.
  'triage:read',
  // Queued work DISPATCHES LATER and outlives the credential that created it:
  // JobQueue carries no token id, and revoking a token writes only revokedAt.
  // That is a materially different grant from starting a scan now.
  'recon:queue',
  // A verdict on a finding. It is durable and suppresses future AI review of
  // that finding, but it only RANKS: the finding stays visible everywhere.
  'triage:write',
  // Split from triage:write because a verdict ranks and a mute HIDES: a muted
  // finding vanishes from every read on this surface, the graph, reports and
  // the in-app agent. An agent misled by target text could hide a real issue,
  // so this is opt-in, never auto-ticked, and bounded in code (see muteTools).
  'triage:mute',
  // A second reviewer's correction of the factors behind a finding's score,
  // every one quoted from the evidence and checked, with RedAmon recomputing
  // the score itself. Split from triage:write because a verdict is the
  // operator's decision and a review is a machine's reading: it is labelled as
  // an agent's, replaced by the next review or an evidence change, and can
  // never override a person's decision.
  'triage:review',
  // Starting and stopping a Priority Board run. Split because a run rewrites
  // the whole board and the fix list, spends the owner's model budget, and
  // holds up version switching, Recon Delta and Mute Rules while it works.
  // MCP starts are spaced and capped per project in code (triageRun.ts).
  'triage:run',
  'graph:cypher',
  // The act that binds the platform to a target. It gets its own checkbox so an
  // operator can mint a token that tunes existing engagements without being able
  // to open new ones. It also governs tightening an engagement afterwards, since
  // both write the engagement agreement.
  'project:create',
  // Split from project:create for the same reason triage:write is split from
  // recon:read: it is a DURABLE, NON-REVERSIBLE claim. Anyone holding it can
  // assert that a given document authorized a given engagement, and that
  // assertion outlives the token and appears in an audit. Writing the audit
  // trail is a different act from configuring the work.
  'engagement:authorize',
  // A preset is applied by a PERSON later, often without reading it, so writing
  // one is a stored instruction rather than a change to one project. Split from
  // recon:settings for that reason: tuning a project you are looking at is a
  // different grant from filling the library everyone applies from.
  'preset:write',
  // Apply REPLACES every preset field of a project in one call, resets what the
  // preset does not name, and bypasses the per-call key cap update_recon_settings
  // has. Held with preset:write it is recon:settings over the preset field set.
  'preset:apply',
  // Re-points the standalone scanners, edits a batch project's host list and an
  // IP project's hostname policy on a project that already exists. Scope was
  // create-only for every token; this reopens exactly the registry's rescopable
  // target lists, so it is never auto-ticked, a widening pauses the enabled
  // schedules, and widening a third-party engagement also needs engagement:authorize.
  'project:rescope',
  // Agent in the Loop: the token's client answers the model calls of the
  // owner's chat runs, so it decides what RedAmon's agent does next. Split
  // because it hands the agent's reasoning to an outside process; a token that
  // holds it must hold no other write or exec scope (loopTokenProblem), since
  // the driver reads target-controlled text at every step.
  'agent:loop',
  'kali:exec',
] as const

export type McpScope = (typeof MCP_SCOPES)[number]

// kali:exec is ticked on a new token so the sandbox works out of the box; the
// deployment switch and the project toggle still gate every command.
export const DEFAULT_MCP_SCOPES: McpScope[] = ['recon:read', 'kali:exec']

const SCOPE_SET: ReadonlySet<string> = new Set(MCP_SCOPES)

export function isKnownScope(value: string): value is McpScope {
  return SCOPE_SET.has(value)
}

/**
 * Validate a requested scope set at MINT time.
 *
 * An unknown scope rejects the whole token rather than being dropped: silently
 * storing a subset would hand back a credential that does less than the operator
 * asked for, and they would find out at the first failing call.
 */
export function validateScopes(raw: unknown): { scopes: McpScope[] } | { error: string } {
  if (!Array.isArray(raw) || raw.length === 0) {
    return { error: 'At least one scope is required.' }
  }
  const out: McpScope[] = []
  for (const s of raw) {
    if (typeof s !== 'string' || !isKnownScope(s)) {
      return { error: `Unknown scope: ${typeof s === 'string' ? s : typeof s}` }
    }
    if (!out.includes(s)) out.push(s)
  }
  return { scopes: out }
}

export class McpScopeError extends Error {
  constructor(public scope: McpScope) {
    super(`This token is missing the required scope: ${scope}`)
    this.name = 'McpScopeError'
  }
}

/** Throws a scope-naming error rather than a generic failure. */
export function requireScope(token: { scopes: string[] }, scope: McpScope): void {
  if (!token.scopes.includes(scope)) throw new McpScopeError(scope)
}

export function hasScope(token: { scopes: string[] }, scope: McpScope): boolean {
  return token.scopes.includes(scope)
}

// --- mint / hash / verify -----------------------------------------------------

export function hashToken(plaintext: string): string {
  return createHash('sha256').update(plaintext, 'utf8').digest('hex')
}

export function generateToken(): { plaintext: string; hash: string; prefix: string } {
  const plaintext = MCP_TOKEN_PREFIX + randomBytes(TOKEN_RANDOM_BYTES).toString('hex')
  return {
    plaintext,
    hash: hashToken(plaintext),
    prefix: plaintext.slice(0, MCP_TOKEN_PREFIX.length + PREFIX_DISPLAY_LEN),
  }
}

/** Strip control characters and cap the length before storing an operator label. */
export function sanitizeTokenName(raw: unknown): string {
  if (typeof raw !== 'string') return ''
  // eslint-disable-next-line no-control-regex
  return raw.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, MCP_TOKEN_NAME_MAX)
}

export const MCP_EXPIRY_PRESET_DAYS = [30, 60, 90, 365] as const
export const MCP_DEFAULT_EXPIRY_DAYS = 90

/**
 * `null` means "no expiry", which is a deliberate operator choice. Anything that
 * is neither null nor one of the presets is rejected rather than coerced.
 */
export function resolveExpiry(days: unknown): { expiresAt: Date | null } | { error: string } {
  if (days === null || days === 'never') return { expiresAt: null }
  const n = typeof days === 'number' ? days : Number(days)
  if (!Number.isFinite(n) || !(MCP_EXPIRY_PRESET_DAYS as readonly number[]).includes(n)) {
    return { error: 'Expiry must be 30, 60, 90 or 365 days, or "never".' }
  }
  return { expiresAt: new Date(Date.now() + n * 24 * 60 * 60 * 1000) }
}

/** A calendar date as far out as anyone plausibly means; past it, pick "never". */
export const MCP_EXPIRY_DATE_MAX_DAYS = 3650

/**
 * An expiry CHANGE on an existing token: everything the mint accepts, plus
 * `'now'` (end it immediately, and unlike a revoke it can be extended again)
 * and a `YYYY-MM-DD` date, which lasts to the END of that day in UTC.
 */
export function resolveExpiryChange(
  raw: unknown,
  now = Date.now()
): { expiresAt: Date | null } | { error: string } {
  if (raw === 'now') return { expiresAt: new Date(now) }
  if (typeof raw === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    const date = new Date(`${raw}T23:59:59.999Z`)
    // Round-trip, because `2026-02-31` parses to a real date in some engines.
    if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== raw) {
      return { error: `'${raw}' is not a valid date.` }
    }
    if (date.getTime() <= now) {
      return { error: 'The expiry date must be in the future. Use "Expire now" to end the token today.' }
    }
    if (date.getTime() > now + MCP_EXPIRY_DATE_MAX_DAYS * 24 * 60 * 60 * 1000) {
      return { error: 'The expiry date is too far out. Choose "never" instead.' }
    }
    return { expiresAt: date }
  }
  return resolveExpiry(raw)
}

/**
 * Does moving a token from `before` to `after` give it MORE power?
 *
 * Adding a scope, removing an expiry, or pushing it later all do, and a token
 * that has already expired is revived by any later date. Those changes get the
 * same step-up as minting: a stolen session cookie must not be able to upgrade
 * an existing token any more than it can mint a new one. Everything else
 * (dropping a scope, an earlier expiry) only narrows, and needs no step-up.
 */
export function isTokenWidening(
  before: TokenReach,
  after: TokenReach
): boolean {
  if (after.scopes.some(s => !before.scopes.includes(s))) return true
  if (sharedReachWidens(before, after)) return true
  if (after.expiresAt === null) return before.expiresAt !== null
  if (before.expiresAt === null) return false
  return after.expiresAt.getTime() > before.expiresAt.getTime()
}

/** What a token edit can widen: its scopes, its expiry and (step 4.10) the shared projects it reaches. */
export interface TokenReach {
  scopes: readonly string[]
  expiresAt: Date | null
  /** Absent: the edit does not touch the opt-in (and a token minted before sharing reaches none). */
  includeSharedProjects?: boolean
  projectAllowlist?: readonly string[]
}

/**
 * Opting in to shared projects widens a token; so does emptying its allowlist (empty reaches every
 * shared project) or naming a project it did not name. Opting out, or naming fewer, only narrows.
 */
function sharedReachWidens(before: TokenReach, after: TokenReach): boolean {
  if (after.includeSharedProjects !== true) return false
  if (before.includeSharedProjects !== true) return true
  const was = before.projectAllowlist ?? []
  const now = after.projectAllowlist ?? []
  if (was.length === 0) return false
  return now.length === 0 || now.some(id => !was.includes(id))
}

/** The most projects one token's allowlist may name. */
export const MCP_PROJECT_ALLOWLIST_MAX = 100

/**
 * Validate a token's shared-project opt-in from a mint or edit body. The allowlist holds plain
 * project ids, deduplicated; an id names no project the token's user could not already reach
 * (projectAccess decides on every call), so it is not checked against the shares here, which would
 * tell a caller which ids exist.
 */
export function validateSharedReach(
  include: unknown,
  allowlist: unknown
): { includeSharedProjects: boolean; projectAllowlist: string[] } | { error: string } {
  if (include !== undefined && typeof include !== 'boolean') {
    return { error: 'includeSharedProjects must be true or false.' }
  }
  if (allowlist !== undefined && !Array.isArray(allowlist)) {
    return { error: 'projectAllowlist must be a list of project ids.' }
  }
  const ids: string[] = []
  for (const raw of (allowlist as unknown[] | undefined) ?? []) {
    if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(raw)) {
      return { error: 'projectAllowlist holds project ids only.' }
    }
    if (!ids.includes(raw)) ids.push(raw)
  }
  if (ids.length > MCP_PROJECT_ALLOWLIST_MAX) {
    return { error: `projectAllowlist names at most ${MCP_PROJECT_ALLOWLIST_MAX} projects.` }
  }
  const includeSharedProjects = include === true
  // The allowlist narrows the shared projects only, so without the opt-in it would mean nothing.
  return { includeSharedProjects, projectAllowlist: includeSharedProjects ? ids : [] }
}

// --- resolution ----------------------------------------------------------------

export type McpAuthFailure =
  | 'missing'      // no bearer presented
  | 'malformed'    // not a rdmn_mcp_ token
  | 'invalid'      // no such token
  | 'revoked'
  | 'expired'
  | 'bad_scopes'   // the row carries a scope this build does not know

export interface ResolvedMcpToken {
  tokenId: string
  userId: string
  tokenPrefix: string
  name: string
  /**
   * What this call may use: the minted scopes its owner's permissions still allow. Every
   * requireScope / hasScope and the connect-time instructions read these, never the row's.
   */
  scopes: McpScope[]
  /**
   * The token opted in to projects shared with its user (step 4.10): the allowlist narrows them,
   * empty names none and reaches every one. Absent or null: the token reaches its user's own
   * projects only, as every token minted before sharing does.
   */
  sharedProjects?: McpSharedReach | null
}

export interface McpSharedReach {
  allowlist: readonly string[]
}

export interface McpAuthResult {
  ok: boolean
  token?: ResolvedMcpToken
  failure?: McpAuthFailure
  /** Present whenever it can be derived, so a failure can be audited by prefix. */
  prefix?: string
}

/** Extract the bearer value. The cookie and both service keys are ignored. */
export function bearerFrom(headers: Headers): string {
  const raw = headers.get('authorization') || ''
  const m = /^Bearer\s+(.+)$/i.exec(raw.trim())
  return m ? m[1].trim() : ''
}

/**
 * Resolve a presented bearer to a token row.
 *
 * "No such token" and "hash mismatch" are the same code path - one indexed
 * lookup on the unique hash - so they are indistinguishable in both message and
 * timing. The residual comparison is constant-time for the same reason.
 */
export async function resolveMcpToken(presented: string): Promise<McpAuthResult> {
  if (!presented) return { ok: false, failure: 'missing' }
  if (!presented.startsWith(MCP_TOKEN_PREFIX)) {
    return { ok: false, failure: 'malformed' }
  }
  const prefix = presented.slice(0, MCP_TOKEN_PREFIX.length + PREFIX_DISPLAY_LEN)

  const row = await prisma.mcpAccessToken.findUnique({
    where: { tokenHash: hashToken(presented) },
    select: {
      id: true, userId: true, name: true, tokenPrefix: true, tokenHash: true,
      scopes: true, revokedAt: true, expiresAt: true,
      includeSharedProjects: true, projectAllowlist: true,
    },
  })
  if (!row || !constantTimeEqual(row.tokenHash, hashToken(presented))) {
    return { ok: false, failure: 'invalid', prefix }
  }
  // Re-checked per call, so revoking or expiring takes effect mid-session
  // rather than at the client's next reconnect.
  if (row.revokedAt) return { ok: false, failure: 'revoked', prefix: row.tokenPrefix }
  if (row.expiresAt && row.expiresAt.getTime() <= Date.now()) {
    return { ok: false, failure: 'expired', prefix: row.tokenPrefix }
  }
  // A row carrying a scope this build does not know is a downgrade or a
  // tampered row: reject the TOKEN rather than ignore the scope.
  if (!row.scopes.every(isKnownScope)) {
    return { ok: false, failure: 'bad_scopes', prefix: row.tokenPrefix }
  }

  // A token never does more than its owner may do now (PE-20): a permission the owner lost
  // answers the scope error on this call. A failed read throws rather than grant the row's scopes.
  const scopes = await usableScopes(row.userId, row.scopes as McpScope[])

  return {
    ok: true,
    prefix: row.tokenPrefix,
    token: {
      tokenId: row.id,
      userId: row.userId,
      tokenPrefix: row.tokenPrefix,
      name: row.name,
      scopes,
      // Read whatever the switch: with sharing not in force projectAccess() never answers a
      // project of someone else, so the opt-in reaches nothing (DV-30).
      sharedProjects: row.includeSharedProjects === true
        ? { allowlist: Object.freeze([...(row.projectAllowlist ?? [])]) }
        : null,
    },
  }
}

/** Resolve straight from a request, so the route never handles the raw header. */
export async function resolveMcpUser(request: Request): Promise<McpAuthResult> {
  return resolveMcpToken(bearerFrom(request.headers))
}

// --- lastUsedAt, throttled -----------------------------------------------------

const LAST_USED_THROTTLE_MS = 60_000
const globalForLastUsed = globalThis as unknown as { __mcpLastUsed?: Map<string, number> }
const lastUsedAt: Map<string, number> = globalForLastUsed.__mcpLastUsed ?? new Map()
globalForLastUsed.__mcpLastUsed = lastUsedAt

/**
 * Best-effort and throttled to once per token per minute, so a busy agent does
 * not turn every tool call into a database write. Never awaited by the caller's
 * critical path and never throws.
 */
export function touchTokenUsage(tokenId: string): void {
  const now = Date.now()
  const prev = lastUsedAt.get(tokenId) ?? 0
  if (now - prev < LAST_USED_THROTTLE_MS) return
  lastUsedAt.set(tokenId, now)
  // Bound the map the way loginThrottle does: drop entries older than a window.
  if (lastUsedAt.size > 10_000) {
    for (const [k, t] of lastUsedAt) {
      if (now - t > LAST_USED_THROTTLE_MS) lastUsedAt.delete(k)
    }
  }
  prisma.mcpAccessToken
    .update({ where: { id: tokenId }, data: { lastUsedAt: new Date(now) } })
    .catch((err: unknown) => console.error('[mcp] could not record token usage:', err))
}

/** Test seam: the throttle map is process-global by design. */
export function __resetTokenUsageThrottle(): void {
  lastUsedAt.clear()
}

// --- ownership ------------------------------------------------------------------

export class McpAccessDenied extends Error {
  constructor(message = 'Project not found') {
    super(message)
    this.name = 'McpAccessDenied'
  }
}

/**
 * A project the token may reach, at a level its access does not meet (step 4.10): a project shared
 * with the token's user at Read, asked by a tool that writes. The token already reaches the project
 * (it lists it), so the answer says why rather than "not found", which would send an agent off to
 * retry with another id.
 */
export class McpLevelDenied extends McpAccessDenied {
  constructor(message: string) {
    super(message)
    this.name = 'McpLevelDenied'
  }
}

/** What a tool's access check needs of the token: its user and its opt-in to shared projects. */
export interface McpProjectToken {
  userId: string
  sharedProjects?: McpSharedReach | null
}

export interface McpProjectAccess {
  /** The project and its owner (`userId`): the tenant of every graph, finding and triage read (T9). */
  project: { id: string; userId: string }
  access: ProjectAccess
}

/** The words of a write share's toggles (§6.2), for a refusal that names the one a tool needs. */
const TOGGLE_WORDS: Readonly<Partial<Record<ProjectLevel, string>>> = {
  'W+S': 'Run scans', 'W+A': 'Use AI agent', 'W+X': 'Exploitation & shells', M: 'Manage',
}

function levelRefusal(access: ProjectAccess, needed: ProjectLevel): string {
  if (needed === 'R*') {
    return 'This project is shared with your account without Raw data & files, which this tool needs. ' +
      'Ask the owner to include raw data in the share.'
  }
  if (access.level === 'write') {
    // Step 5.2: a Read + Write share reaches the write tools at its toggles' levels, never the owner's.
    const toggle = TOGGLE_WORDS[needed]
    return toggle
      ? `This project is shared with your account at Read + Write without ${toggle}, which this tool ` +
        'needs. Ask the owner to include it in the share.'
      : "This tool is the project owner's alone: it is not available on a project shared with your account."
  }
  return 'This project is shared with your account at Read access, so this tool, which changes it or ' +
    "acts on it, is not available. Only the project's owner can use it."
}

/**
 * The token's access to a project, checked at the level the tool needs, with the same 404
 * anti-enumeration semantics as `requireProjectAccess`.
 *
 * A project that does not exist and a project the token may not reach are the same answer, so a
 * token holder cannot enumerate other users' project ids. The decision is `projectAccess()`'s,
 * asked for the token's user. The owner reaches every level. Anyone else's project reaches the token
 * only through a share (step 4.10; SH-42): never oversight or break-glass, which would turn an
 * admin's opted-in token into a reader of every project; only when the token opted in; and only
 * when its allowlist is empty or names the project. Then the share must meet `needed`, the level
 * of the permission behind the tool (`R` for a read, `R*` for raw data, `W` and the toggled levels
 * for a write at Read + Write, step 5.2), as the app's route asks it; `needed` defaults to the
 * owner, so a tool that names no level stays the owner's. A revoked or expired share fails the next
 * call: nothing is cached here.
 */
export async function mcpProjectAccess(
  token: McpProjectToken | string,
  projectId: unknown,
  needed: ProjectLevel = 'O'
): Promise<McpProjectAccess> {
  if (typeof projectId !== 'string' || !projectId) {
    throw new McpAccessDenied('projectId is required')
  }
  const holder: McpProjectToken = typeof token === 'string' ? { userId: token } : token
  const access = await projectAccess({ userId: holder.userId }, projectId)
  if (!access) throw new McpAccessDenied()
  if (access.level !== 'owner') {
    const reach = holder.sharedProjects
    if (access.via !== 'share' || !reach) throw new McpAccessDenied()
    if (reach.allowlist.length > 0 && !reach.allowlist.includes(projectId)) throw new McpAccessDenied()
    if (!meetsLevel(access, needed)) throw new McpLevelDenied(levelRefusal(access, needed))
  }
  return { project: { id: access.project.id, userId: access.project.userId }, access }
}

/**
 * `mcpProjectAccess` for a tool that needs only the project and its owner. `userId` is the owner,
 * the tenant every graph and triage read of the tool passes on, never the token's user.
 */
export async function assertMcpProjectAccess(
  token: McpProjectToken | string,
  projectId: unknown,
  needed: ProjectLevel = 'O'
): Promise<{ id: string; userId: string }> {
  return (await mcpProjectAccess(token, projectId, needed)).project
}

// --- per-token rate limiting ------------------------------------------------------
//
// Keyed on TOKEN ID, not IP: one agent behind one NAT is one caller, and IP
// keying would punish the wrong thing. In-memory and per-process (webapp is
// single-replica, so a shared store is not required; if ever scaled out, move to
// a Postgres counter - the audit trail is already durable). BOUNDED with a hard
// entry cap and lazy eviction so a flood of distinct tokens cannot turn a
// rate limiter into a memory-exhaustion vector. Thresholds come from env with
// SAFE DEFAULTS, so an unset value falls back to the documented limit and never
// to "no limit".

export type McpBucketName = 'read' | 'query' | 'write' | 'mute' | 'start' | 'exec' | 'compare' | 'loop'

interface BucketSpec {
  /** Max calls in the window. */
  limit: number
  windowMs: number
}

function envInt(name: string, fallback: number): number {
  const n = parseInt(process.env[name] || '', 10)
  return Number.isFinite(n) && n > 0 ? n : fallback
}

export function bucketSpec(bucket: McpBucketName): BucketSpec {
  switch (bucket) {
    // Cheap reads: generous, they cost a Postgres or bounded Neo4j read.
    case 'read':
      return { limit: envInt('MCP_RATE_READ_PER_MIN', 120), windowMs: 60_000 }
    // NL -> Cypher spends the owner's LLM key, so this is moderate.
    case 'query':
      return { limit: envInt('MCP_RATE_QUERY_PER_MIN', 20), windowMs: 60_000 }
    case 'write':
      return { limit: envInt('MCP_RATE_WRITE_PER_MIN', 10), windowMs: 60_000 }
    // Mutes and unmutes have their own bucket so a bulk clean-up neither starves
    // nor is starved by the settings and verdict writes above. One call can name
    // thousands of findings, so this is a runaway-loop ceiling, not a volume cap.
    case 'mute':
      return { limit: envInt('MCP_RATE_MUTE_PER_MIN', 200), windowMs: 60_000 }
    // Strict: one start per project per 5 minutes. A 'new' start consumes a
    // retention slot, so a looping agent must not be able to churn the timeline.
    case 'start':
      return { limit: envInt('MCP_RATE_START_PER_WINDOW', 1), windowMs: envInt('MCP_RATE_START_WINDOW_MS', 300_000) }
    // Each call reaches a live third-party target from RedAmon's own address,
    // so this is tighter than the read bucket. Polling a running command uses
    // the cheap `read` bucket instead, so a slow tool does not have to spend
    // this one to be watched.
    //
    // Not tighter still: one command is ONE tool invocation, and a recon pass
    // is naturally a few dozen of them. At 6/min a routine sequence spent most
    // of its time sleeping, which pushes callers toward heavier single
    // commands - the opposite of what this bucket is for. The containment here
    // is the allowlist and the scope check; this is a runaway-loop ceiling.
    case 'exec':
      return { limit: envInt('MCP_RATE_EXEC_PER_MIN', 20), windowMs: 60_000 }
    // Agent in the Loop: one step costs two to four calls (wait, a page or two,
    // submit), and a long poll returns early on every status change.
    case 'loop':
      return { limit: envInt('MCP_RATE_LOOP_PER_MIN', 120), windowMs: 60_000 }
    // Orders of magnitude heavier than any other read: a version comparison
    // gunzips and parses a whole stored graph, and a `current` side captures
    // the live one under the snapshot semaphore.
    //
    // It needs its OWN bucket name rather than a per-project `query` key,
    // because the key is `bucket|token|scopeKey` while `bucketSpec` switches on
    // the bucket NAME alone: a per-project `query` counter would be separate
    // but still allow 20 a minute, and twenty full-graph captures a minute per
    // project is not a limit.
    case 'compare':
      return {
        limit: envInt('MCP_RATE_COMPARE_PER_WINDOW', 2),
        windowMs: envInt('MCP_RATE_COMPARE_WINDOW_MS', 300_000),
      }
  }
}

interface Hits {
  count: number
  firstAt: number
}

const MAX_LIMITER_ENTRIES = 10_000
const globalForLimiter = globalThis as unknown as { __mcpLimiter?: Map<string, Hits> }
const limiter: Map<string, Hits> = globalForLimiter.__mcpLimiter ?? new Map()
globalForLimiter.__mcpLimiter = limiter

export interface RateDecision {
  allowed: boolean
  /** Seconds until the window resets. Always a number, so callers can say when. */
  retryAfterSeconds: number
}

/**
 * `scopeKey` lets a bucket be counted per project (the start bucket) rather than
 * per token, which is what "1 start per project per 5 minutes" means.
 */
export function checkRateLimit(
  bucket: McpBucketName,
  tokenId: string,
  scopeKey = ''
): RateDecision {
  const spec = bucketSpec(bucket)
  const key = `${bucket}|${tokenId}|${scopeKey}`
  const now = Date.now()

  if (limiter.size > MAX_LIMITER_ENTRIES) {
    // Lazy eviction: anything whose window has already closed is dead weight.
    for (const [k, h] of limiter) {
      if (now - h.firstAt >= bucketSpec(k.split('|')[0] as McpBucketName).windowMs) {
        limiter.delete(k)
      }
    }
    // Still over the cap: drop the oldest half rather than grow without bound.
    // Losing a live counter can only ever be generous to the caller, which is
    // the right direction for a memory bound to fail in.
    if (limiter.size > MAX_LIMITER_ENTRIES) {
      const oldest = [...limiter.entries()]
        .sort((a, b) => a[1].firstAt - b[1].firstAt)
        .slice(0, Math.floor(limiter.size / 2))
      for (const [k] of oldest) limiter.delete(k)
    }
  }

  const hit = limiter.get(key)
  if (!hit || now - hit.firstAt >= spec.windowMs) {
    limiter.set(key, { count: 1, firstAt: now })
    return { allowed: true, retryAfterSeconds: 0 }
  }
  if (hit.count >= spec.limit) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((hit.firstAt + spec.windowMs - now) / 1000)),
    }
  }
  hit.count += 1
  return { allowed: true, retryAfterSeconds: 0 }
}

/** Test seam: the limiter is process-global by design. */
export function __resetRateLimiter(): void {
  limiter.clear()
}

// --- per-token LLM budget ---------------------------------------------------------
//
// The `question` path spends the PROJECT OWNER's provider key, and one request
// can cost up to 9 provider calls. The agent's own daily cap keys on the
// user id, so a single user's several tokens share one pool there; this is the
// per-TOKEN layer, so one runaway agent cannot consume the user's whole budget.

const globalForBudget = globalThis as unknown as { __mcpLlmBudget?: Map<string, Hits> }
const llmBudget: Map<string, Hits> = globalForBudget.__mcpLlmBudget ?? new Map()
globalForBudget.__mcpLlmBudget = llmBudget

const DAY_MS = 24 * 60 * 60 * 1000

export interface BudgetDecision {
  allowed: boolean
  used: number
  limit: number
  /** ISO timestamp at which the daily window rolls over. */
  resetsAt: string
}

const MAX_BUDGET_ENTRIES = 10_000

/**
 * The daily cap, read WITHOUT spending any of it.
 *
 * `checkLlmBudget` is the only other way to learn the number and it consumes a
 * call to do so, which makes it useless to anything that merely documents the
 * limit.
 */
export function llmBudgetLimit(): number {
  return envInt('MCP_LLM_DAILY_BUDGET', 200)
}

export function checkLlmBudget(tokenId: string): BudgetDecision {
  const limit = llmBudgetLimit()
  const now = Date.now()

  // Bounded like `limiter` and `lastUsedAt`. Without this the map grew one
  // entry per token ever used on the question path and NEVER shrank - not even
  // for a window that had already rolled over - which is the memory-exhaustion
  // shape the other two carry explicit comments about avoiding.
  if (llmBudget.size >= MAX_BUDGET_ENTRIES) {
    for (const [k, h] of llmBudget) {
      if (now - h.firstAt >= DAY_MS) llmBudget.delete(k)
    }
    if (llmBudget.size >= MAX_BUDGET_ENTRIES) {
      const oldest = [...llmBudget.entries()].sort((a, b) => a[1].firstAt - b[1].firstAt)
      for (const [k] of oldest.slice(0, Math.floor(oldest.length / 2))) llmBudget.delete(k)
    }
  }

  const hit = llmBudget.get(tokenId)

  if (!hit || now - hit.firstAt >= DAY_MS) {
    llmBudget.set(tokenId, { count: 1, firstAt: now })
    return { allowed: true, used: 1, limit, resetsAt: new Date(now + DAY_MS).toISOString() }
  }
  const resetsAt = new Date(hit.firstAt + DAY_MS).toISOString()
  if (hit.count >= limit) {
    return { allowed: false, used: hit.count, limit, resetsAt }
  }
  hit.count += 1
  return { allowed: true, used: hit.count, limit, resetsAt }
}

/** Test seam: the budget map is process-global by design. */
export function __resetLlmBudget(): void {
  llmBudget.clear()
}
