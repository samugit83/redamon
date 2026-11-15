/**
 * POST /api/navigator/projects/:projectId/messages `{threadId?, text, pageContext?}`: send a message
 * to AI Navigator and stream the answer back as `text/event-stream` (plan §7.3, Appendix B).
 *
 * In order: navigator:use on the project (oversight and break-glass refused inside the guard), the
 * person's share or ownership, Root's switch and the owner's policy; same origin and JSON; the text;
 * the rate buckets and the run reservation (one live answer per person and project); the thread
 * cap; a project being restored or transferred; the master key; the person's own model (D2), whose
 * absence answers `model_required` before anything is saved, so the browser's retry after the
 * model gate never duplicates the message. Then the message is saved (with its thread when none is
 * named: no route creates an empty thread), the history is read from the database (never from the
 * browser), the run is bound to the login it came from and handed its credential, and the agent's
 * NDJSON is relayed, validated, as SSE. The answer is saved once, when the stream ends.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { masterKeyIsWeak } from '@/lib/authz/machineCredential'
import { activationBusy } from '@/lib/activationLock'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { readFeatureModel, featureModelErrorResponse } from '@/lib/featureModels'
import { readJsonBody } from '@/lib/jsonBody'
import { checkRateLimit } from '@/lib/mcpAuth'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { navigatorContext } from '@/lib/navigator/access'
import { MAX_MESSAGE_CHARS, MAX_THREADS_PER_PERSON_PROJECT, RUN_TIMEOUT_S } from '@/lib/navigator/constants'
import { loadHistory } from '@/lib/navigator/history'
import { pageContextOf } from '@/lib/navigator/pageContext'
import { isNavigatorId, navigatorError } from '@/lib/navigator/responses'
import { navigatorRuns } from '@/lib/navigator/runRegistry'
import { relayStream } from '@/lib/navigator/stream'
import { countThreads, saveAnswer, startTurn, ThreadFull, ThreadMissing } from '@/lib/navigator/threads'
import { routesFor } from '@/lib/navigator/tools/run'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

type Ctx = { params: Promise<{ projectId: string }> }

/** Trimmed, with control characters other than newline and tab removed. */
function cleanText(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  // eslint-disable-next-line no-control-regex
  const text = raw.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim()
  return text.length >= 1 && text.length <= MAX_MESSAGE_CHARS ? text : null
}

export const POST = withRouteErrors('Could not send the message to AI Navigator', async (request: NextRequest, { params }: Ctx) => {
  const { projectId } = await params
  if (!isNavigatorId(projectId)) return navigatorError('not_found', 404)
  const nav = await navigatorContext(await requirePermission(request, 'navigator:use', { projectId, allowOversight: false }))
  if (nav instanceof NextResponse) return nav
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed

  const text = cleanText(parsed.body.text)
  if (!text) return navigatorError('invalid_message', 400)
  const rawThread = parsed.body.threadId
  if (rawThread !== undefined && rawThread !== null && !isNavigatorId(rawThread)) return navigatorError('not_found', 404)
  const threadId = (rawThread as string | null | undefined) ?? null
  const page = pageContextOf(parsed.body.pageContext)
  // An act-as token that names no start cannot be bound to its impersonation (§5.6).
  if (nav.actorId && !nav.login.actAsStartId) return navigatorError('navigator_not_available', 403)

  const personKey = `navigator:${nav.personId}`
  for (const bucket of ['navigator', 'navigator_day'] as const) {
    const rate = checkRateLimit(bucket, personKey)
    if (!rate.allowed) return navigatorError('rate_limited', 429, { retryAfterSeconds: rate.retryAfterSeconds })
  }

  const reservation = navigatorRuns().reserve({ personId: nav.personId, projectId: nav.projectId })
  if (!reservation.ok) {
    const running = [...navigatorRuns().liveThreadIds()]
      .map((id) => navigatorRuns().liveForThread(id))
      .find((r) => r && r.personId === nav.personId && r.projectId === nav.projectId)
    return navigatorError('busy', 409, running?.threadId ? { threadId: running.threadId } : {})
  }
  const runId = reservation.runId
  let handedOff = false
  try {
    if (!threadId && (await countThreads(nav.personId, nav.projectId)) >= MAX_THREADS_PER_PERSON_PROJECT) {
      return navigatorError('too_many_threads', 409)
    }
    if (await activationBusy(nav.projectId)) return navigatorError('project_busy', 409)
    if (masterKeyIsWeak()) return navigatorError('navigator_unavailable', 503)

    const model = await readFeatureModel(nav.personId, 'navigator')
    if (!model) return featureModelErrorResponse('model_required', 'navigator')

    let turn
    try {
      turn = await startTurn({ personId: nav.personId, projectId: nav.projectId, threadId, text, actorId: nav.actorId })
    } catch (err) {
      if (err instanceof ThreadMissing) return navigatorError('not_found', 404)
      if (err instanceof ThreadFull) return navigatorError('thread_full', 409)
      throw err
    }
    const history = await loadHistory(turn.threadId, turn.seq)
    const person = nav.auth.actingAs ?? nav.auth.principal
    const actor = nav.auth.actingAs ? nav.auth.principal : null
    const { allowed, reasons } = await routesFor({ allowed: true, access: nav.access, person, actor }, nav.projectId)

    const credential = navigatorRuns().complete(runId, {
      threadId: turn.threadId, tenantId: nav.tenantId, actorId: nav.actorId, login: nav.login,
    })
    const run = navigatorRuns().get(runId)
    if (!credential || !run) return navigatorError('run_gone', 409)

    const failEarly = async (code: string) => {
      await saveAnswer(turn.threadId, {
        content: '', status: 'failed', routes: [], citations: [], trace: [], modelUsed: model, actorId: nav.actorId, errorCode: code,
      }).catch(() => 'thread_gone')
    }
    // The browser closing aborts the run: an answer nobody waits for spends the person's budget.
    const onClientGone = () => run.abort.abort()
    request.signal.addEventListener('abort', onClientGone)
    const timer = setTimeout(() => run.abort.abort(), (RUN_TIMEOUT_S + 10) * 1000)

    let res: Response
    try {
      res = await agentFetch('/navigator/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: run.abort.signal,
        body: JSON.stringify({
          run_id: runId, credential, user_id: nav.personId, actor_id: nav.actorId, project_id: nav.projectId,
          tenant_id: nav.tenantId, model, history, message: text,
          page: page ? { path: page.path, wiki_hint: page.wiki_hint } : null,
          allowed_routes: allowed, route_reasons: reasons, language_hint: null,
        }),
      })
    } catch (err) {
      clearTimeout(timer)
      await failEarly('agent_unreachable')
      console.warn(`[navigator] agent unreachable run=${runId} class=${err instanceof AgentUnreachableError ? 'unreachable' : 'error'}`)
      return navigatorError('agent_unreachable', 502, { threadId: turn.threadId })
    }
    if (res.status === 404 || !res.ok || !res.body) {
      clearTimeout(timer)
      const code = res.status === 404 ? 'agent_outdated' : 'agent_unreachable'
      await failEarly(code)
      return navigatorError(code, 502, { threadId: turn.threadId })
    }

    handedOff = true
    const stream = relayStream({
      agentBody: res.body,
      runId,
      threadId: turn.threadId,
      userMessageId: turn.messageId,
      actorId: nav.actorId,
      abort: run.abort,
      save: (answer) => saveAnswer(turn.threadId, answer),
      end: () => {
        clearTimeout(timer)
        request.signal.removeEventListener('abort', onClientGone)
        navigatorRuns().end(runId)
      },
      clientGone: () => request.signal.aborted,
    })
    return new Response(stream, {
      headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store, no-transform', 'X-Accel-Buffering': 'no' },
    })
  } finally {
    if (!handedOff) navigatorRuns().release(runId)
  }
})
