import { NextRequest, NextResponse } from 'next/server'
import type { PluginInstall } from '@prisma/client'
import prisma from '@/lib/prisma'
import { meetsLevel, projectAccess } from '@/lib/authz/projectAccess'
import { ownsRow } from '@/lib/authz/rowOwner'
import { isJsonContentType } from '@/lib/jsonBody'
import { pluginAllowedFor } from './accessRules'
import { CallTokenConfigError, verifyCallToken, type CallTokenClaims, type CallTokenKind } from './callToken'
import { now } from './clock'
import { PluginDataError, type PluginOwner } from './dataStore'
import { completeJob, jobIsActive, type JobError } from './jobs'
import { PluginOverrideError } from './overrides'
import type { PluginPermission } from './permissions'
import { hasPermission, servesActions, showsContributions } from './registry'
import { gatewayCallsPerToken } from './settings'
import { SkillPartsRegistryError } from './skillPartsRegistry'
import { isStorableJson } from './storableText'

/**
 * The Gateway frame (README.PLUGINS.md §7.3, TD-06): every SDK call from plugin code
 * enters here, authenticated by its call token alone, and is re-authorised on every
 * call, because an admin may disable the plugin, revoke a permission or delete the user
 * while a 900 s action still holds a valid token.
 *
 * Per call: JSON only; the token; its call budget; for a job's token, the job
 * still active (a token outlives neither its job nor, for a sync action, its action);
 * the body (64 KB, up to 8 MB for the operations that carry data, bounded in depth and
 * containers, its text storable); the install row (enabled, ready, not revoked, at the
 * token's version); the permission, granted by the admin AND declared by the stored
 * manifest; the user; the project and session, asked for the token's user (`projectAccess()`
 * at the owner level, `ownsRow`); the plugin still available to that user (the per-plugin
 * allowlists, accessRules.ts). Strict on purpose: never through requireProjectAccess,
 * which reads the browser's effective user (RV-33). The frame never reads cookies, the
 * session, the effective user or X-Internal-Key: these routes are cookie-less in
 * middleware.ts and plugin code must not borrow a browser's identity.
 *
 * The budget is counted right after the token is verified, before any database read, so
 * a plugin that floods the Gateway with refused calls exhausts its token, not Postgres.
 */
export const GATEWAY_BODY_MAX_BYTES = 8 * 1024 * 1024
/** The body limit of an operation that names a key, a query or a short report. */
export const GATEWAY_SMALL_BODY_BYTES = 64 * 1024
// A body is parsed on the webapp's one thread and held while the handler runs. An empty
// container costs ~64 bytes of heap (8 MB of `{}` took 179 MB and 380 ms to parse), so
// containers are counted before parsing, and nesting too: no operation needs it deep,
// and JSON.stringify cannot write a value nested a few thousand levels back.
const BODY_MAX_DEPTH = 64
const BODY_MAX_CONTAINERS = 200_000
// jobs/complete is outside the call budget, so a job that used its calls still ends; it
// has this many reports of its own (the runner tries a report four times).
const JOB_END_REPORTS = 10
const DEFAULT_KINDS: readonly CallTokenKind[] = ['action', 'job']
const NO_STORE = { 'Cache-Control': 'no-store' }
const BUDGET_SWEEP_AT = 5_000

export class GatewayError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message)
    this.name = 'GatewayError'
  }
}

export interface GatewayConversation {
  id: string
  sessionId: string
  projectId: string
  userId: string
  title: string
  status: string
  currentPhase: string
  iterationCount: number
  agentRunning: boolean
  createdAt: Date
  updatedAt: Date
}

export interface GatewayContext {
  op: string
  claims: CallTokenClaims
  pluginId: string
  version: string
  plugin: PluginInstall
  manifest: Record<string, unknown>
  /** The effective user the action runs for. */
  userId: string
  /** The admin acting as `userId`, when one started the action. */
  actorId: string | null
  projectId: string | null
  sessionId: string | null
  conversation: GatewayConversation | null
  body: Record<string, unknown>
  /** jobs/complete only: why the job's result may no longer be kept, or null. */
  lapsed?: JobError | null
}

export interface GatewayOptions {
  op: string
  /**
   * The permission the call needs; a function when the body names it (the override
   * operations: `override:<point>`). It returns null for a point that does not exist.
   * `'in-handler'` when only the handler can know it (it reads a row first) and checks it
   * with assertPermission; said explicitly, so a route that forgot the option is not read
   * as one that needs none.
   */
  permission?: PluginPermission | ((body: Record<string, unknown>) => PluginPermission | null) | 'in-handler'
  kinds?: readonly CallTokenKind[]
  /**
   * The largest body the operation takes: GATEWAY_SMALL_BODY_BYTES unless it carries a
   * value, messages for a model, a proposal or a job's result.
   */
  maxBodyBytes?: number
  /**
   * jobs/complete only: the report of a job's end. It has its own small allowance instead
   * of the call budget. The plugin no longer serving, or the job's project or session gone,
   * reaches the handler as `ctx.lapsed` rather than refusing the report, which would leave
   * the job running until its deadline; text Postgres cannot store is the handler's too.
   */
  jobEnd?: boolean
}

type Handler = (ctx: GatewayContext) => Promise<Record<string, unknown> | NextResponse>

export function gatewayError(status: number, code: string, error: string, extra: Record<string, unknown> = {}) {
  return NextResponse.json({ error, code, ...extra }, { status, headers: NO_STORE })
}

// ---------------------------------------------------------------------------
// Call budget, per token id, in this process's memory (RV-39). Several webapp copies
// each count their own share; the bound is per copy, which is enough against a flood.
// On globalThis, like the other in-process limiters (mcpAuth.ts, loginThrottle.ts), so a
// dev reload or a route bundled with its own copy of this module cannot split the count.
// ---------------------------------------------------------------------------

interface CallLedger {
  budgets: Map<string, { count: number; expiresAt: number }>
  /** Tokens of sync actions that have returned, until they expire. */
  retired: Map<string, number>
}
const globalForLedger = globalThis as unknown as { __pluginCallLedger?: CallLedger }
const ledger: CallLedger = globalForLedger.__pluginCallLedger ?? { budgets: new Map(), retired: new Map() }
globalForLedger.__pluginCallLedger = ledger

function sweep(t: number) {
  if (ledger.budgets.size >= BUDGET_SWEEP_AT) {
    for (const [key, b] of ledger.budgets) if (b.expiresAt <= t) ledger.budgets.delete(key)
  }
  if (ledger.retired.size >= BUDGET_SWEEP_AT) {
    for (const [jti, expiresAt] of ledger.retired) if (expiresAt <= t) ledger.retired.delete(jti)
  }
}

function charge(key: string, claims: CallTokenClaims): number {
  sweep(now().getTime())
  const entry = ledger.budgets.get(key) ?? { count: 0, expiresAt: claims.exp * 1000 }
  entry.count += 1
  ledger.budgets.set(key, entry)
  return entry.count
}

/**
 * Ends a sync action's token when the action returns: plugin code that left a thread
 * running must not go on calling the Gateway with it. Job tokens end with their job row.
 */
export function retireCallToken(jti: string, expiresAt: Date): void {
  sweep(now().getTime())
  ledger.retired.set(jti, expiresAt.getTime())
}

/** Tests only: how many tokens are being counted. */
export function callBudgetEntries(): number {
  return ledger.budgets.size
}

/** Why a body is refused before it is parsed (too deep, too many containers), or null. */
function bodyShapeError(text: string): string | null {
  let depth = 0
  let containers = 0
  let inString = false
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (inString) {
      if (c === 0x5c) i++
      else if (c === 0x22) inString = false
    } else if (c === 0x22) {
      inString = true
    } else if (c === 0x7b || c === 0x5b) {
      if (++depth > BODY_MAX_DEPTH) return `The body is nested deeper than ${BODY_MAX_DEPTH} levels.`
      if (++containers > BODY_MAX_CONTAINERS) return `The body holds more than ${BODY_MAX_CONTAINERS} objects and arrays.`
    } else if (c === 0x7d || c === 0x5d) {
      depth--
    }
  }
  return null
}

// ---------------------------------------------------------------------------
// The body
// ---------------------------------------------------------------------------

async function readBounded(request: NextRequest, limit: number): Promise<string | null> {
  const declared = Number(request.headers.get('content-length') ?? '')
  if (Number.isFinite(declared) && declared > limit) return null
  const stream = request.body
  if (!stream) return ''
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > limit) {
        await reader.cancel().catch(() => {})
        return null
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  return Buffer.concat(chunks).toString('utf8')
}

function bearer(request: NextRequest): string | null {
  const m = /^Bearer ([A-Za-z0-9._~+/=-]+)$/.exec((request.headers.get('authorization') ?? '').trim())
  return m ? m[1] : null
}

// ---------------------------------------------------------------------------
// Error mapping: stable codes for every store refusal, the contract's messages where
// services/plugin_runner/sdk/contract_cases.json fixes one.
// ---------------------------------------------------------------------------

function dataErrorResponse(e: PluginDataError): NextResponse {
  switch (e.code) {
    case 'value_too_large':
      return gatewayError(413, e.code, e.message, { limit: e.limit })
    case 'rows_exceeded':
    case 'bytes_exceeded':
    case 'owner_rows_exceeded':
      return gatewayError(413, 'quota_exceeded', e.message, { quota: e.code.replace('_exceeded', ''), limit: e.limit })
    case 'reserved_collection':
      return gatewayError(400, e.code, 'collections starting with __ are reserved for the platform')
    default:
      return gatewayError(400, e.code, e.message)
  }
}

const OVERRIDE_STATUS: Record<string, number> = {
  not_found: 404,
  invalid_proposal: 422,
  invalid_target: 400,
  too_many_pending: 409,
  stale_proposal: 409,
  wrong_state: 409,
  active_not_deletable: 409,
}

function errorResponse(e: unknown, op: string, pluginId: string): NextResponse {
  if (e instanceof GatewayError) return gatewayError(e.status, e.code, e.message, e.extra)
  if (e instanceof SkillPartsRegistryError) {
    return e.code === 'unknown_skill' ? gatewayError(404, 'invalid_target', e.message) : gatewayError(503, e.code, e.message)
  }
  if (e instanceof PluginDataError) return dataErrorResponse(e)
  if (e instanceof PluginOverrideError) return gatewayError(OVERRIDE_STATUS[e.code] ?? 400, e.code, e.message)
  console.error(`[plugins] gateway ${op} plugin=${pluginId} failed:`, e)
  return gatewayError(500, 'internal_error', 'The Gateway failed; the webapp log has the details.')
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

function declaredPermissions(manifest: unknown): string[] {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return []
  const p = (manifest as Record<string, unknown>).permissions
  return Array.isArray(p) ? p.filter((x): x is string => typeof x === 'string') : []
}

async function checkPlugin(claims: CallTokenClaims): Promise<PluginInstall> {
  const plugin = await prisma.pluginInstall.findUnique({ where: { pluginId: claims.pid } })
  if (!plugin || !servesActions(plugin)) {
    throw new GatewayError(403, 'plugin_unavailable', `Plugin ${claims.pid} is not installed, enabled and ready.`)
  }
  if (plugin.activeVersion !== claims.ver) {
    throw new GatewayError(403, 'plugin_unavailable', `Plugin ${claims.pid} ${claims.ver} is no longer the active version.`)
  }
  return plugin
}

function checkPermission(plugin: PluginInstall, permission: PluginPermission) {
  if (!hasPermission(plugin, permission) || !declaredPermissions(plugin.manifest).includes(permission)) {
    throw new GatewayError(403, 'permission_denied', `This plugin was not granted ${permission}.`)
  }
}

/** The permission check of a route declared `permission: 'in-handler'`. */
export function assertPermission(ctx: Pick<GatewayContext, 'plugin'>, permission: PluginPermission): void {
  checkPermission(ctx.plugin, permission)
}

const NOT_FOUND = () => new GatewayError(404, 'not_found', 'Not found')

/**
 * Whose data the call may reach: the token's project at the owner level of `projectAccess()` for
 * the token's user (no route permission backs a Gateway call, so access below the owner's never
 * reaches one), and the session's conversation its author's (`ownsRow`) and in that project.
 */
async function checkTenancy(claims: CallTokenClaims): Promise<GatewayConversation | null> {
  const user = await prisma.user.findUnique({ where: { id: claims.sub }, select: { id: true } })
  if (!user) throw new GatewayError(401, 'invalid_token', 'The user this call token acts for no longer exists.')
  const subject = { userId: claims.sub }
  if (claims.prj) {
    const access = await projectAccess(subject, claims.prj)
    if (!access || !meetsLevel(access, 'O')) throw NOT_FOUND()
  }
  if (!claims.ses) return null
  if (!claims.prj) throw NOT_FOUND()
  const conversation = await prisma.conversation.findUnique({
    where: { sessionId: claims.ses },
    select: {
      id: true,
      sessionId: true,
      projectId: true,
      userId: true,
      title: true,
      status: true,
      currentPhase: true,
      iterationCount: true,
      agentRunning: true,
      createdAt: true,
      updatedAt: true,
    },
  })
  if (
    !conversation ||
    !ownsRow(subject, conversation.userId) ||
    conversation.projectId !== claims.prj ||
    (claims.conv !== undefined && conversation.id !== claims.conv)
  ) {
    throw NOT_FOUND()
  }
  return conversation
}

/** The owner of a data call: the token's user, or the token's project. Never the body's ids. */
export function dataOwner(ctx: GatewayContext): PluginOwner {
  const owner = ctx.body.owner
  if (owner === 'user') return { type: 'user', id: ctx.userId }
  if (owner === 'project') {
    if (!ctx.projectId) throw new GatewayError(400, 'invalid_owner', 'This action was not started from a project.')
    return { type: 'project', id: ctx.projectId }
  }
  throw new GatewayError(400, 'invalid_owner', 'owner is "user" or "project".')
}

// ---------------------------------------------------------------------------
// The frame
// ---------------------------------------------------------------------------

export async function withGateway(request: NextRequest, opts: GatewayOptions, handler: Handler): Promise<NextResponse> {
  const started = Date.now()
  let pluginId = '-'
  const seen: { claims: CallTokenClaims | null } = { claims: null }
  let res: NextResponse
  try {
    res = await run(request, opts, handler, (c) => {
      seen.claims = c
      pluginId = c.pid
    })
  } catch (e) {
    res = errorResponse(e, opts.op, pluginId)
  }
  const line = `[plugins] gateway ${opts.op} plugin=${pluginId} status=${res.status} ms=${Date.now() - started}`
  if (res.status >= 400) console.warn(line)
  else console.log(line)
  if (opts.jobEnd && seen.claims) await failRefusedReport(seen.claims, res)
  return res
}

// No job to fail (401: not this token's to say; 404: no such job), or a refusal the runner
// retries (429, 5xx), which a later report may still win.
const REPORT_NOT_FINAL = new Set([401, 404, 429])

/**
 * The runner does not retry a 4xx to jobs/complete, and records it only in the plugin's log,
 * so without this the job would wait out its deadline and read as timed out. It fails now,
 * with the refusal's code. The answer to the runner is left exactly as it was.
 */
async function failRefusedReport(claims: CallTokenClaims, res: NextResponse): Promise<void> {
  if (res.status < 400 || res.status >= 500 || REPORT_NOT_FINAL.has(res.status) || !claims.jid) return
  try {
    const body = (await res.clone().json().catch(() => null)) as { code?: unknown } | null
    const code = typeof body?.code === 'string' && /^[a-z][a-z0-9_]{0,47}$/.test(body.code) ? body.code : `http_${res.status}`
    await completeJob(claims.pid, claims.sub, claims.jid, {
      status: 'failed',
      error: {
        code: `report_refused:${code}`,
        message: `The plugin finished, but RedAmon refused its result report (${code}, HTTP ${res.status}); the plugin's log has the details.`,
      },
    })
  } catch (e) {
    console.error(`[plugins] job ${claims.jid}: its refused report could not fail it:`, e)
  }
}

async function run(
  request: NextRequest,
  opts: GatewayOptions,
  handler: Handler,
  identify: (claims: CallTokenClaims) => void,
): Promise<NextResponse> {
  if (!isJsonContentType(request.headers.get('content-type'))) {
    return gatewayError(415, 'unsupported_media_type', 'Content-Type must be application/json')
  }

  const raw = bearer(request)
  let claims: CallTokenClaims | null
  try {
    claims = raw ? await verifyCallToken(raw, { kinds: opts.kinds ?? DEFAULT_KINDS }) : null
  } catch (e) {
    if (e instanceof CallTokenConfigError) {
      console.error(`[plugins] gateway ${opts.op} refused: ${e.message}`)
      return gatewayError(503, e.code, 'The plugin platform is not configured on this deployment.')
    }
    throw e
  }
  if (!claims) return gatewayError(401, 'invalid_token', 'Invalid or expired call token.')
  identify(claims)

  if (ledger.retired.has(claims.jti)) {
    return gatewayError(403, 'action_ended', 'The action this call token was issued for has ended.')
  }
  if (opts.jobEnd) {
    if (charge(`${claims.jti}:end`, claims) > JOB_END_REPORTS) {
      return gatewayError(429, 'call_budget_exceeded', `This job has reported its end ${JOB_END_REPORTS} times.`)
    }
  } else {
    const limit = gatewayCallsPerToken()
    if (charge(claims.jti, claims) > limit) {
      return gatewayError(429, 'call_budget_exceeded', `This call token has made its ${limit} calls.`)
    }
    if (claims.kind === 'job' && !(await jobIsActive(claims.pid, claims.sub, claims.jid!))) {
      return gatewayError(403, 'job_ended', 'The job this call token was issued for has ended.')
    }
  }

  const maxBytes = opts.maxBodyBytes ?? GATEWAY_SMALL_BODY_BYTES
  const text = await readBounded(request, maxBytes)
  if (text === null) return gatewayError(413, 'body_too_large', `The body of ${opts.op} is limited to ${maxBytes} bytes.`, { limit: maxBytes })
  const shapeError = bodyShapeError(text)
  if (shapeError) return gatewayError(400, 'invalid_json', shapeError)
  let body: unknown
  try {
    body = JSON.parse(text)
  } catch {
    return gatewayError(400, 'invalid_json', 'The body is not valid JSON.')
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return gatewayError(400, 'invalid_json', 'The body must be a JSON object.')
  }
  if (!opts.jobEnd && !isStorableJson(body)) {
    return gatewayError(400, 'invalid_text', 'The body holds text that cannot be stored: U+0000 or an unpaired surrogate.')
  }

  let lapsed: JobError | null = null
  let plugin: PluginInstall
  if (opts.jobEnd) {
    const row = await prisma.pluginInstall.findUnique({ where: { pluginId: claims.pid } })
    if (!row) throw new GatewayError(404, 'not_found', 'No such job.')
    plugin = row
    // Still in service as a version that runs: an update keeps the active one running.
    if (!showsContributions(row) || row.activeVersion !== claims.ver) {
      lapsed = { code: 'plugin_unavailable', message: `Plugin ${claims.pid} ${claims.ver} stopped serving before the job ended.` }
    }
  } else {
    plugin = await checkPlugin(claims)
  }
  if (opts.permission && opts.permission !== 'in-handler') {
    const permission = typeof opts.permission === 'function' ? opts.permission(body as Record<string, unknown>) : opts.permission
    if (!permission) throw new GatewayError(400, 'invalid_target', `unknown extension point ${JSON.stringify((body as Record<string, unknown>).point)}`)
    checkPermission(plugin, permission)
  }
  let conversation: GatewayConversation | null = null
  try {
    conversation = await checkTenancy(claims)
  } catch (e) {
    if (!opts.jobEnd || !(e instanceof GatewayError) || e.code !== 'not_found') throw e
    lapsed ??= { code: 'context_gone', message: 'The project or chat session this job ran for no longer exists.' }
  }
  if (!(await pluginAllowedFor(claims.sub, claims.pid))) {
    const message = `Plugin ${claims.pid} is not available to the user this call acts for: an administrator limited it to permission sets that user holds none of.`
    if (!opts.jobEnd) throw new GatewayError(403, 'plugin_not_allowed', message)
    lapsed ??= { code: 'plugin_not_allowed', message }
  }

  const out = await handler({
    op: opts.op,
    claims,
    pluginId: claims.pid,
    version: claims.ver,
    plugin,
    manifest: plugin.manifest as Record<string, unknown>,
    userId: claims.sub,
    actorId: claims.act ?? null,
    projectId: claims.prj ?? null,
    sessionId: claims.ses ?? null,
    conversation,
    body: body as Record<string, unknown>,
    lapsed,
  })
  if (out instanceof NextResponse) {
    out.headers.set('Cache-Control', 'no-store')
    return out
  }
  return NextResponse.json(out, { headers: NO_STORE })
}
