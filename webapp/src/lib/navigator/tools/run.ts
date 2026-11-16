/**
 * One tool call of a live AI Navigator run (plan §7.7 steps 3-10). Every id comes from the run entry
 * the credential resolved to, never from the request. The checks are made fresh, on every call, the
 * way /api/internal/agent/authorize-decision makes them: a revoked person, a narrowed share, a
 * turned-off switch or policy, a transferred project or an ended login refuse the very next call,
 * so a missed abort is harmless.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { ActAsNotAllowedError, can } from '@/lib/authz/can'
import { rbacFlags } from '@/lib/authz/flags'
import { loadPrincipal, type Principal } from '@/lib/authz/principal'
import { meetsLevel, projectAccess, type ProjectAccess } from '@/lib/authz/projectAccess'
import { navigatorAllowedFor, sameNavigatorTenant } from '@/lib/authz/navigatorPolicy'
import { deviceSessionRefusal } from '@/lib/authz/deviceSessions'
import { actAsBindingInForce } from '@/lib/authz/actAs'
import { activationBusy } from '@/lib/activationLock'
import { McpToolError } from '@/lib/mcp/errors'
import { McpAccessDenied, McpLevelDenied, McpScopeError } from '@/lib/mcpAuth'
import { NAVIGATOR_ERRORS, TOOL_CALLS_PER_RUN, type DataRoute } from '../constants'
import type { NavigatorRun } from '../runRegistry'
import { navigatorEnabled } from '../switch'
import { navigatorTool, navigatorTools, type NavigatorTool } from './registry'
import { navigatorMcpContext } from './sessionContext'
import { shapeToolResult } from './output'
import { cypherSecretRefusal } from './secretGuard'
import { validateArgs } from './validate'

export type ToolAnswer =
  | { ok: true; result: unknown; truncated?: boolean }
  | { ok: false; code: string; message: string; status: number }

const refuse = (code: keyof typeof NAVIGATOR_ERRORS | string, status: number, message?: string): ToolAnswer => ({
  ok: false, code, status,
  message: message ?? (NAVIGATOR_ERRORS as Record<string, string>)[code] ?? NAVIGATOR_ERRORS.tool_failed,
})

const inactive = (p: Principal): boolean => rbacFlags().identity && p.status !== 'active'

export type FreshDecision =
  | { allowed: true; access: ProjectAccess; person: Principal; actor: Principal | null }
  | { allowed: false; code: string; permission?: string }

/**
 * The run's person, actor, project and login, judged again now. Does not check a tool's own
 * permissions; `toolAllowed` does, on the access this answers.
 */
export async function freshRunDecision(run: NavigatorRun): Promise<FreshDecision> {
  const person = await loadPrincipal(run.personId, { fresh: true })
  const actor = run.actorId ? await loadPrincipal(run.actorId, { fresh: true }) : null
  if (!person || (run.actorId && !actor)) return { allowed: false, code: 'account_gone' }
  if (inactive(person) || (actor && inactive(actor))) return { allowed: false, code: 'account_inactive' }

  const login = run.login
  if (!login) return { allowed: false, code: 'run_gone' }
  const signedIn = actor ?? person
  if (signedIn.id !== login.userId || signedIn.sessionVersion !== login.sessionVersion) {
    return { allowed: false, code: 'login_ended' }
  }
  if (login.deviceSessionId && (await deviceSessionRefusal(login.deviceSessionId, login.userId, { fresh: true }))) {
    return { allowed: false, code: 'login_ended' }
  }
  if (actor) {
    if (!login.actAsStartId) return { allowed: false, code: 'login_ended' }
    if (!(await actAsBindingInForce(actor.id, person.id, { startId: login.actAsStartId }))) {
      return { allowed: false, code: 'login_ended' }
    }
  }

  const access = await projectAccess({ userId: person.id }, run.projectId, { fresh: true, ...(actor ? { actingAs: true } : {}) })
  if (!access) return { allowed: false, code: 'project_not_visible' }
  if (access.via !== 'owner' && access.via !== 'share') return { allowed: false, code: 'navigator_not_available' }
  if (!sameNavigatorTenant(access, run.tenantId)) return { allowed: false, code: 'tenant_changed' }
  if (!(await navigatorEnabled())) return { allowed: false, code: 'navigator_disabled' }
  if (!(await navigatorAllowedFor(access))) return { allowed: false, code: 'owner_disallowed' }

  for (const permission of ['navigator:use'] as const) {
    const verdict = await canFor(person, actor, permission, run.projectId)
    if (verdict) return { allowed: false, code: verdict, permission }
  }
  return { allowed: true, access, person, actor }
}

async function canFor(person: Principal, actor: Principal | null, permission: Parameters<typeof can>[1], projectId: string): Promise<string | null> {
  try {
    const d = actor
      ? await can(actor, permission, { projectId, actingAs: person, fresh: true })
      : await can(person, permission, { projectId, fresh: true })
    return d.allowed ? null : d.reason
  } catch (err) {
    if (err instanceof ActAsNotAllowedError) return 'act_as_refused'
    throw err
  }
}

/** Null when the person may use the tool on the project now, else the refusal code and the permission. */
export async function toolRefusal(tool: NavigatorTool, d: Extract<FreshDecision, { allowed: true }>, projectId: string):
  Promise<{ code: string; permission: string } | null> {
  for (const permission of tool.permissions) {
    const verdict = await canFor(d.person, d.actor, permission, projectId)
    if (verdict) return { code: verdict, permission }
  }
  if (!meetsLevel(d.access, tool.level)) return { code: 'project_level', permission: tool.permissions[0] }
  return null
}

/** The tools this person may use on the project now: the manifest the agent binds. */
export async function allowedTools(d: Extract<FreshDecision, { allowed: true }>, projectId: string): Promise<NavigatorTool[]> {
  const out: NavigatorTool[] = []
  for (const tool of navigatorTools()) {
    if (!(await toolRefusal(tool, d, projectId))) out.push(tool)
  }
  return out
}

/**
 * The routes the person may use here, and why a data route is missing (`needs_raw_data` when only
 * the level is short, else `missing_permission`), for the agent's router and the status route.
 */
export async function routesFor(d: Extract<FreshDecision, { allowed: true }>, projectId: string):
  Promise<{ allowed: string[]; reasons: Record<string, string> }> {
  const tools = await allowedTools(d, projectId)
  const allowed = ['docs', 'direct']
  const reasons: Record<string, string> = {}
  for (const route of ['graph', 'records', 'workspace'] as DataRoute[]) {
    if (tools.some((t) => t.route === route)) {
      allowed.push(route)
      continue
    }
    const anyCapable = navigatorTools().filter((t) => t.route === route)
    let reason = 'missing_permission'
    for (const t of anyCapable) {
      const refusal = await toolRefusal(t, d, projectId)
      if (refusal?.code === 'project_level' && t.level === 'R*') reason = 'needs_raw_data'
    }
    reasons[route] = reason
  }
  return { allowed, reasons }
}

async function auditRefusal(run: NavigatorRun, tool: string, permission: string | undefined, code: string): Promise<void> {
  await writeAudit({
    actorId: run.actorId ?? run.personId,
    ...(run.actorId ? { onBehalfOfUserId: run.personId } : {}),
    projectId: run.projectId,
    action: 'navigator.refused',
    targetType: 'project',
    targetId: run.projectId,
    ...(permission ? { permission } : {}),
    after: { tool, ...(permission ? { permission } : {}), code },
    source: 'api',
  })
}

function withTimeout<T>(p: Promise<T>, seconds: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new McpToolError(NAVIGATOR_ERRORS.tool_timeout, 'tool_timeout')), seconds * 1000)
    p.then((v) => { clearTimeout(t); resolve(v) }, (e) => { clearTimeout(t); reject(e) })
  })
}

async function maskFor(projectId: string): Promise<boolean> {
  const row = await prisma.project.findUnique({ where: { id: projectId }, select: { roeSensitiveDataHandling: true } })
  return row?.roeSensitiveDataHandling !== 'full_access'
}

export async function runNavigatorTool(run: NavigatorRun, name: string, rawArgs: unknown): Promise<ToolAnswer> {
  if (run.toolCalls >= TOOL_CALLS_PER_RUN) return refuse('tool_budget', 429)
  run.toolCalls += 1
  const tool = navigatorTool(name)
  if (!tool) return refuse('tool_unknown', 404)

  const d = await freshRunDecision(run)
  if (!d.allowed) {
    await auditRefusal(run, name, d.permission, d.code)
    return refuse(d.code === 'navigator_disabled' || d.code === 'owner_disallowed' ? d.code : 'tool_refused', 403)
  }
  const refusal = await toolRefusal(tool, d, run.projectId)
  if (refusal) {
    await auditRefusal(run, name, refusal.permission, refusal.code)
    const message = refusal.code === 'project_level' && tool.level === 'R*'
      ? `This needs Raw data & files on this project (${refusal.permission}).`
      : `You do not hold the permission this needs on this project (${refusal.permission}).`
    return refuse('tool_refused', 403, message)
  }
  if (await activationBusy(run.projectId)) return refuse('project_busy', 409)

  const parsed = validateArgs(tool.parameters, rawArgs)
  if (!parsed.ok) return refuse('invalid_args', 400, parsed.message)
  const extra = tool.check?.(parsed.args)
  if (extra) return refuse('invalid_args', 400, extra)
  const mask = await maskFor(run.projectId)
  // A raw query could alias a secret value past the masking by name (RETURN s.matched_text AS x).
  if (tool.name === 'run_cypher' && mask) {
    const why = cypherSecretRefusal(String(parsed.args.cypher ?? ''))
    if (why) return refuse('invalid_args', 400, why)
  }

  const mcp = navigatorMcpContext({ personId: run.personId, projectId: run.projectId, actorId: run.actorId, scopes: tool.mcpScopes })
  let raw: unknown
  try {
    raw = await withTimeout(tool.handler({ mcp, projectId: run.projectId, tenantId: run.tenantId! }, parsed.args), tool.timeoutS)
  } catch (err) {
    // The MCP functions' own refusals are written for the caller ("label every node pattern"), so
    // they reach the model; anything else is a fixed sentence.
    if (err instanceof McpLevelDenied) return refuse('tool_refused', 403, err.message)
    if (err instanceof McpAccessDenied) return refuse('tool_refused', 403)
    if (err instanceof McpScopeError) return refuse('tool_refused', 403)
    if (err instanceof McpToolError) return refuse(err.code ?? 'tool_failed', err.code === 'tool_timeout' ? 504 : 400, err.message.slice(0, 500))
    console.error(`[navigator] tool failed tool=${name} run=${run.runId} class=${(err as Error)?.name ?? 'unknown'}`)
    return refuse('tool_failed', 500)
  }
  const shaped = shapeToolResult(raw, { access: d.access, mask })
  return { ok: true, result: shaped.result, ...(shaped.truncated ? { truncated: true } : {}) }
}
