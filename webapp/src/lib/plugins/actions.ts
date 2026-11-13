import { NextRequest, NextResponse } from 'next/server'
import type { PluginInstall } from '@prisma/client'
import prisma from '@/lib/prisma'
import { readFeatureModel } from '@/lib/featureModels'
import { readJsonBody } from '@/lib/jsonBody'
import { pluginFeatureId } from '@/lib/llmFeatures'
import { auditActor } from '@/lib/auditActor'
import { meetsLevel, projectAccess, type ProjectAccess } from '@/lib/authz/projectAccess'
import type { ProjectLevel } from '@/lib/authz/permissions'
import { getEffectiveUser } from '@/lib/session'
import { PLUGIN_NOT_ALLOWED_MESSAGE, pluginAllowedFor } from './accessRules'
import { CallTokenConfigError, mintCallToken } from './callToken'
import { now } from './clock'
import { isValidPluginId } from './ids'
import { conversationReachable, pluginLevels, retireCallToken, usablePermissions } from './gateway'
import { failJob, markRunning, startJob, type JobContext, type JobPick } from './jobs'
import { internalErrorResponse } from './lifecycleRoutes'
import * as ov from './overrides'
import { findInstall, servesActions } from './registry'
import { RunnerError, RunnerUnavailableError, cancelJob, runAction } from './runnerClient'
import { InvalidPickError, resolvePick } from './sessionPick'
import { crossOriginResponse, sameOrigin } from './sameOrigin'
import { ACTION_ID_RE } from './schemas/common'
import { actionMaxTimeoutSeconds } from './settings'

/**
 * A plugin action started from the UI (README.PLUGINS.md §7.7): POST
 * /api/plugins/[pluginId]/actions/[actionId] with `{context: {projectId?, sessionId?},
 * params}`. The webapp decides everything the plugin may reach before the runner sees the
 * call: the effective user, the plugin available to them (accessRules.ts), the project (theirs,
 * or shared with them at the levels the plugin's permissions need, step 5.10) and the session
 * (theirs), the permissions both granted and declared, the timeout; then it mints the call
 * token the plugin's code will hold, naming the project's owner as its tenant. A sync action answers its result;
 * an async one becomes a job (jobs.ts) and answers 202 `{jobId}`.
 *
 * A result naming a change set to review (`reviewProposal`) is kept only when that change
 * set exists, is this plugin's and is in the caller's scope: the worker could report any
 * id, and the UI would open the review modal on it (RV-21).
 */
const PARAMS_MAX_BYTES = 64 * 1024
/** A collaborator's model-calling run on a project whose owner chose no model for the plugin. */
export const OWNER_MODEL_REQUIRED = 'owner_model_required'
export const OWNER_MODEL_TEXT =
  "This project's owner has not chosen a model for this plugin in Models by feature; on a shared project the owner's choice is used. Ask the owner to choose one."
// A job's deadline: its timeout, plus time for the runner's own timeout answer and report.
const JOB_GRACE_SECONDS = 60

type Json = Record<string, unknown>

const refuse = (status: number, code: string, error: string, extra: Json = {}) =>
  NextResponse.json({ error, code, ...extra }, { status })

const isObj = (v: unknown): v is Json => !!v && typeof v === 'object' && !Array.isArray(v)

interface ManifestAction {
  id: string
  timeoutSeconds: number
  async?: boolean
  llm?: boolean
}

function declaredAction(plugin: PluginInstall, actionId: string): ManifestAction | null {
  const actions = isObj(plugin.manifest) ? plugin.manifest.actions : null
  if (!Array.isArray(actions)) return null
  const a = actions.find((x) => isObj(x) && x.id === actionId) as ManifestAction | undefined
  return a && Number.isInteger(a.timeoutSeconds) && a.timeoutSeconds > 0 ? a : null
}

export async function checkReviewProposal(
  result: Json,
  who: { pluginId: string; userId: string; projectId: string | null; access: ProjectAccess | null },
): Promise<Json> {
  if (!('reviewProposal' in result)) return result
  const rp = result.reviewProposal
  const rest = { ...result }
  delete rest.reviewProposal
  if (isObj(rp) && typeof rp.changeSetId === 'string' && typeof rp.extensionPoint === 'string') {
    const set = await ov.getChangeSet(rp.changeSetId)
    // A project's proposals are reviewed by whoever decides them (Manage, changeSetAccess.ts): the
    // window would open on a 404 for anyone else.
    const decidesProject = !!who.access && meetsLevel(who.access, 'M')
    const inScope = !!set && (set.scope.type === 'user' ? set.scope.id === who.userId : decidesProject && set.scope.id === who.projectId)
    if (set && inScope && set.pluginId === who.pluginId && set.point === rp.extensionPoint) {
      return { ...rest, reviewProposal: { extensionPoint: rp.extensionPoint, changeSetId: rp.changeSetId } }
    }
  }
  console.warn(`[plugins] dropped a reviewProposal from plugin=${who.pluginId}: not its change set in the caller's scope`)
  return rest
}

// The runner's own named failures: a busy or crashed worker, a timeout.
const RUNNER_NAMED_5XX = new Set([502, 503, 504])
// The runner's codes are its supervisor's; one in another shape is not shown.
const RUNNER_CODE_RE = /^[a-z][a-z0-9_]{0,63}$/

/** Why the runner was not reached, in words that say what to do: each reason has its own fix. */
function unavailableMessage(e: RunnerUnavailableError): string {
  if (e.reason === 'not_configured') {
    return 'The plugin runner is not configured on this deployment: PLUGIN_RUNNER_KEY is not set (./redamon.sh up generates it).'
  }
  if (e.proxyCode === 'proxy_busy') return 'The plugin-gateway proxy is busy (proxy_busy); try again shortly.'
  if (e.reason === 'timeout') {
    return `The plugin runner did not answer in time (${e.proxyCode ?? 'timeout'}); the action may still have run.`
  }
  if (e.reason === 'bad_response') {
    return `The plugin runner answered with something RedAmon cannot read (${e.proxyCode ?? 'bad_response'}); its log has the details.`
  }
  return `The plugin runner could not be reached (${e.proxyCode ?? 'unreachable'}); try again shortly.`
}

type Refusal = [number, string, string, Json]

/** A runner failure as the browser receives it, [status, code, message, extra]; null for any other error. */
function runnerRefusal(e: unknown): Refusal | null {
  if (e instanceof RunnerUnavailableError) {
    return [503, 'runner_unavailable', unavailableMessage(e), { reason: e.reason, ...(e.proxyCode ? { proxyCode: e.proxyCode } : {}) }]
  }
  if (!(e instanceof RunnerError)) return null
  const runnerCode = RUNNER_CODE_RE.test(e.code) ? e.code : 'runner_error'
  // The plugin is installed here but the runner has not started it yet (it reloads
  // within a minute of an install).
  if (e.status === 404 && e.code === 'unknown_plugin') {
    return [503, 'plugin_not_running', 'The plugin runner has not started this plugin yet; try again in a minute.', {}]
  }
  // The runner refusing the webapp's key, or its request, or failing without saying how,
  // is no fault of the user's: a 401 would also read as a lost login in the UI.
  if (e.status === 401) {
    return [502, 'runner_misconfigured', 'The plugin runner refused the webapp: PLUGIN_RUNNER_KEY differs between them.', { upstreamStatus: 401 }]
  }
  if (e.status === 400 || e.status === 403 || (e.status >= 500 && !RUNNER_NAMED_5XX.has(e.status))) {
    return [
      502,
      'runner_error',
      `The plugin runner could not run this action (${runnerCode}); its log has the details.`,
      { upstreamStatus: e.status, runnerCode },
    ]
  }
  return [e.status, e.code, e.message, {}]
}

function runnerFailure(e: unknown, extra: Json = {}): NextResponse | null {
  const refusal = runnerRefusal(e)
  if (!refusal) return null
  const [status, code, message, own] = refusal
  console.warn(`[plugins] action refused: ${code} (${e instanceof RunnerError ? `runner HTTP ${e.status} ${e.code}` : (e as RunnerUnavailableError).reason})`)
  return refuse(status, code, message, { ...own, ...extra })
}

export interface ContextOptions {
  /**
   * The project levels the plugin's run needs (gateway.ts `pluginLevels`, step 5.10). Absent, the
   * owner's alone, with every shortfall a 404; given, a project shared with the person below one of
   * them answers 403 naming the level.
   */
  levels?: readonly ProjectLevel[]
  /** The person is the account an admin acts as: a share reaches read and no further (D-22). */
  actingAs?: boolean
}

/** A checked context, the person's access to its project and its tenant: the project's owner, else the person. */
interface ResolvedContext {
  context: JobContext
  access: ProjectAccess | null
  tenantId: string
}

const OWNER_ONLY: readonly ProjectLevel[] = ['O']

async function resolveContext(raw: unknown, userId: string, opts: ContextOptions): Promise<ResolvedContext | NextResponse> {
  if (raw === undefined || raw === null) return { context: { projectId: null, sessionId: null, conversationId: null }, access: null, tenantId: userId }
  if (!isObj(raw)) return refuse(400, 'invalid_context', 'context must be an object')
  const { projectId, sessionId } = raw
  const optionalText = (v: unknown) => v === undefined || v === null || (typeof v === 'string' && v.length > 0 && v.length <= 128)
  if (!optionalText(projectId) || !optionalText(sessionId)) {
    return refuse(400, 'invalid_context', 'context.projectId and context.sessionId are ids')
  }
  const notFound = refuse(404, 'not_found', 'Not found')
  let conversationId: string | null = null
  let tenantId = userId
  let access: ProjectAccess | null = null
  if (projectId) {
    access = opts.actingAs === true
      ? await projectAccess({ userId }, projectId as string, { actingAs: true })
      : await projectAccess({ userId }, projectId as string)
    const reached = access
    if (!reached) return notFound
    const missing = (opts.levels ?? OWNER_ONLY).find((level) => !meetsLevel(reached, level))
    if (missing) {
      // A collaborator is told what the share lacks; oversight and break-glass never run a plugin.
      if (!opts.levels || reached.via !== 'share') return notFound
      return refuse(
        403,
        'forbidden',
        `Your access to this project does not reach this plugin (plugins:use, level ${missing}).`,
        { permission: 'plugins:use', level: missing },
      )
    }
    tenantId = reached.project.userId
  }
  if (sessionId) {
    if (!projectId) return notFound
    const conv = await prisma.conversation.findUnique({
      where: { sessionId: sessionId as string },
      select: { id: true, userId: true, projectId: true },
    })
    if (!conv || conv.projectId !== projectId || !(await conversationReachable({ userId }, conv, access))) return notFound
    conversationId = conv.id
  }
  return { context: { projectId: (projectId as string) ?? null, sessionId: (sessionId as string) ?? null, conversationId }, access, tenantId }
}

/**
 * The context of an action or a picker, for `userId`: the project through `projectAccess()` at the
 * levels `opts` names (the owner's alone unless it names others), the session's conversation one
 * the person may reach (`conversationReachable`: its author, or shared with the project) and in that project.
 */
export async function strictContext(raw: unknown, userId: string, opts: ContextOptions = {}): Promise<JobContext | NextResponse> {
  const resolved = await resolveContext(raw, userId, opts)
  return resolved instanceof NextResponse ? resolved : resolved.context
}

/** How far an action got, for the 500 of an unexpected failure: the step, and the job it created. */
interface ActionTrace {
  step: string
  jobId?: string
}

export async function handleAction(
  request: NextRequest,
  pluginId: string,
  actionId: string,
  opts: { actingAs?: boolean } = {},
): Promise<NextResponse> {
  const started = Date.now()
  const trace: ActionTrace = { step: 'checking the request' }
  let res: NextResponse
  try {
    res = await act(request, pluginId, actionId, trace, opts.actingAs === true)
  } catch (e) {
    res = internalErrorResponse(
      e,
      `action ${isValidPluginId(pluginId) ? pluginId : '-'}/${ACTION_ID_RE.test(actionId) ? actionId : '-'} at ${trace.step}`,
      `The plugin action failed while ${trace.step}; the webapp log has the details.`,
      { step: trace.step, ...(trace.jobId ? { jobId: trace.jobId } : {}) },
    )
  }
  console.log(`[plugins] action plugin=${isValidPluginId(pluginId) ? pluginId : '-'} action=${ACTION_ID_RE.test(actionId) ? actionId : '-'} status=${res.status} ms=${Date.now() - started}`)
  return res
}

async function act(request: NextRequest, pluginId: string, actionId: string, trace: ActionTrace, actingAs: boolean): Promise<NextResponse> {
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const body = parsed.body
  const eff = await getEffectiveUser()
  if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  if (!isValidPluginId(pluginId) || !ACTION_ID_RE.test(actionId)) return refuse(404, 'not_found', 'No such plugin action.')
  trace.step = 'reading the plugin'
  const plugin = await findInstall(pluginId)
  if (!plugin || ['available', 'installing', 'uninstalling'].includes(plugin.status)) {
    return refuse(404, 'not_found', 'No such plugin action.')
  }
  trace.step = 'checking who may use the plugin'
  if (!(await pluginAllowedFor(eff.userId, pluginId))) return refuse(403, 'plugin_not_allowed', PLUGIN_NOT_ALLOWED_MESSAGE)
  if (plugin.revokedReason == null && plugin.enabled && plugin.status === 'updating') {
    return refuse(409, 'plugin_updating', 'This plugin is being updated; try again in a moment.')
  }
  if (!servesActions(plugin) || !plugin.activeVersion) {
    return refuse(409, 'plugin_unavailable', 'This plugin is disabled or not ready.')
  }
  const action = declaredAction(plugin, actionId)
  if (!action) return refuse(404, 'unknown_action', `Plugin ${pluginId} declares no action ${actionId}.`)

  const params = body.params === undefined ? {} : body.params
  if (!isObj(params)) return refuse(400, 'invalid_params', 'params must be an object')
  if (Buffer.byteLength(JSON.stringify(params), 'utf8') > PARAMS_MAX_BYTES) {
    return refuse(413, 'params_too_large', `params are limited to ${PARAMS_MAX_BYTES} bytes of JSON`)
  }
  trace.step = 'checking the project and session'
  const resolved = await resolveContext(body.context, eff.userId, { levels: pluginLevels(plugin), actingAs })
  if (resolved instanceof NextResponse) return resolved
  const { context, access, tenantId } = resolved

  // A pick is re-derived from the session, never trusted: the plugin receives the
  // server's {kind, point, target, ref}, and the job records it.
  let pick: JobPick | null = null
  if (params.pick !== undefined) {
    trace.step = 'reading the picked skill'
    try {
      pick = await resolvePick(plugin, actionId, params.pick, context.conversationId, eff.userId)
    } catch (e) {
      if (e instanceof InvalidPickError) return refuse(400, 'invalid_pick', e.message)
      throw e
    }
    params.pick = { kind: pick.kind, point: pick.point, target: pick.target, ref: pick.ref }
  }

  trace.step = 'reading the chosen model'
  // On a shared project the run spends the owner's model choice and keys (C1), never the person's.
  if (action.llm && !(await readFeatureModel(tenantId, pluginFeatureId(pluginId)))) {
    if (tenantId !== eff.userId) return refuse(409, OWNER_MODEL_REQUIRED, OWNER_MODEL_TEXT, { featureId: pluginFeatureId(pluginId) })
    return refuse(409, 'model_required', 'Choose a model for this plugin in Models by feature.', { featureId: pluginFeatureId(pluginId) })
  }

  // The admin behind an act-as call, recorded in the call token as `act`.
  const real = await auditActor(eff)
  const actor = real.onBehalfOfUserId ? real.actorId ?? undefined : undefined
  const timeoutSeconds = Math.min(action.timeoutSeconds, actionMaxTimeoutSeconds())
  const tokenBase = {
    pluginId,
    version: plugin.activeVersion,
    sub: eff.userId,
    act: actor,
    ten: tenantId,
    prj: context.projectId ?? undefined,
    ses: context.sessionId ?? undefined,
    conv: context.conversationId ?? undefined,
    perms: usablePermissions(plugin),
    timeoutSeconds,
  }
  const ctx: Json = { pluginId, version: plugin.activeVersion, userId: eff.userId }
  if (context.projectId) ctx.projectId = context.projectId
  if (context.sessionId) ctx.sessionId = context.sessionId
  if (context.conversationId) ctx.conversationId = context.conversationId

  try {
    if (!action.async) {
      trace.step = 'running the action'
      const { token, jti, expiresAt } = await mintCallToken({ ...tokenBase, kind: 'action' })
      let out
      try {
        out = await runAction(pluginId, actionId, { token, params, ctx, timeoutSeconds })
      } finally {
        retireCallToken(jti, expiresAt)
      }
      if (out.kind !== 'result') return refuse(502, 'runner_bad_answer', 'The plugin runner answered a sync action as a job.')
      if (!out.ok) return NextResponse.json({ ok: false, error: out.error })
      trace.step = 'checking the result'
      const result = await checkReviewProposal(out.result, { pluginId, userId: eff.userId, projectId: context.projectId, access })
      return NextResponse.json({ ok: true, result })
    }

    const deadline = new Date(now().getTime() + (timeoutSeconds + JOB_GRACE_SECONDS) * 1000)
    trace.step = 'creating the job'
    const { job, created } = await startJob({ pluginId, userId: eff.userId, actionId, context, deadline, pick })
    // One job per session: the answer names the skill it works on, so a second pick is told
    // why its choice did not start a job of its own.
    if (!created) return NextResponse.json({ jobId: job.jobId, status: job.status, existing: true, pick: job.pick ?? null })
    trace.step = 'handing the job to the plugin runner'
    trace.jobId = job.jobId
    try {
      const { token } = await mintCallToken({ ...tokenBase, kind: 'job', jid: job.jobId })
      const out = await runAction(pluginId, actionId, {
        token,
        params,
        ctx: { ...ctx, jobId: job.jobId },
        timeoutSeconds,
        async: true,
        jobId: job.jobId,
      })
      if (out.kind !== 'accepted') throw new RunnerError(502, 'runner_bad_answer', 'The plugin runner answered an async action without a job.')
      const taken = await markRunning(job, out.bootId)
      // Cancelled while it was being handed over: the cancel found no job on the runner
      // then, so the runner is told now, or the run would go on with nobody able to stop it.
      if (taken.status === 'cancelled') {
        await cancelJob(pluginId, job.jobId).catch((e) =>
          console.warn(`[plugins] job ${job.jobId} cancelled during dispatch, but the runner could not be told:`, e instanceof Error ? e.message : e),
        )
      }
      return NextResponse.json({ jobId: job.jobId }, { status: 202 })
    } catch (e) {
      const refusal = runnerRefusal(e)
      await failJob(job, { code: refusal?.[1] ?? 'start_failed', message: 'The job could not be handed to the plugin runner.' })
      if (refusal) return runnerFailure(e, { jobId: job.jobId })!
      throw e
    }
  } catch (e) {
    if (e instanceof CallTokenConfigError) {
      console.error(`[plugins] action refused: ${e.message}`)
      // The message names the setting and its rule, never its value.
      return refuse(503, e.code, `The plugin platform is not configured on this deployment: ${e.message}.`)
    }
    const failure = runnerFailure(e)
    if (failure) return failure
    throw e
  }
}
