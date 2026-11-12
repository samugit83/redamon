/**
 * GET  /api/users/[id]/settings/api-usage  - the saved API usage report + run state
 * POST /api/users/[id]/settings/api-usage  - check every saved key now, save the report
 *
 * The POST sends the user's PLAINTEXT keys to 25+ providers and spends their
 * rate limits, so it is stricter than the settings routes:
 * - internal and scanner principals are refused (neither has any business here,
 *   and the middleware's internal-key allowlist is log-only by default);
 * - the caller must be the EFFECTIVE user: the owner, or an admin while acting
 *   as that user. `requireUserAccess` is not used because its admin bypass is
 *   exactly what this refuses: an admin who is not acting as the user cannot
 *   read their report or send their keys anywhere;
 * - the POST body must be JSON, so a same-site HTML form cannot start a run with
 *   the user's cookie (lib/jsonBody.ts).
 * Only numbers, plan names and last-4 hints ever leave this route.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getEffectiveUser, getSession, isInternalRequest, isScannerRequest } from '@/lib/session'
import { visibleProjectsWhere } from '@/lib/authz/visibleProjects'
import { writeAudit } from '@/lib/audit'
import { readJsonBody } from '@/lib/jsonBody'
import { safeErrorCode } from '@/lib/routeErrors'
import { LLM_PROBES, PROBES } from '@/lib/apiUsage/registry'
import { buildJobs, trackedFields, type LlmProviderRow } from '@/lib/apiUsage/credentials'
import { runJobs } from '@/lib/apiUsage/runner'
import { COOLDOWN_MS, checksEnabled, lastFinishedAt, release, runningFor, setRunKeys, tryAcquire } from '@/lib/apiUsage/state'
import type { ApiUsageReportV1, UserActivity } from '@/lib/apiUsage/types'

export const dynamic = 'force-dynamic'

interface RouteParams {
  params: Promise<{ id: string }>
}

const NO_STORE = { 'Cache-Control': 'no-store' }

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return NextResponse.json(body, { status, headers: { ...NO_STORE, ...headers } })
}

async function authorize(request: NextRequest, id: string): Promise<NextResponse | { actorId: string }> {
  if (isInternalRequest(request) || isScannerRequest(request)) {
    return json({ error: 'Forbidden' }, 403)
  }
  const eff = await getEffectiveUser()
  if (!eff) return json({ error: 'Unauthorized' }, 401)
  if (eff.userId !== id) return json({ error: 'Forbidden' }, 403)
  const session = await getSession()
  return { actorId: session?.userId ?? eff.userId }
}

/**
 * Scans and agent runs in flight on the projects THIS user sees (visibleProjects.ts),
 * scoped server-side: never ids from the request, and never the kali
 * sandbox's session list (it spans every user and is the wrong kind of session).
 */
async function loadActivity(userId: string): Promise<UserActivity> {
  const [scans, convs] = await Promise.all([
    prisma.scanJob.findMany({
      where: { status: 'running', project: visibleProjectsWhere({ userId }) },
      select: { projectId: true, kind: true, startedAt: true, project: { select: { name: true } } },
      orderBy: { createdAt: 'asc' },
      take: 20,
    }),
    prisma.conversation.findMany({
      where: { agentRunning: true, project: visibleProjectsWhere({ userId }) },
      select: { projectId: true, project: { select: { name: true } } },
      distinct: ['projectId'],
      take: 20,
    }),
  ])
  return {
    runningScans: scans.map(s => ({
      projectId: s.projectId, projectName: s.project.name, kind: s.kind,
      startedAt: s.startedAt ? s.startedAt.toISOString() : null,
    })),
    agentRuns: convs.map(c => ({ projectId: c.projectId, projectName: c.project.name })),
  }
}

async function loadCredentials(userId: string) {
  const [settings, rotationRows, llmRows] = await Promise.all([
    prisma.userSettings.findUnique({ where: { userId } }),
    prisma.apiKeyRotationConfig.findMany({ where: { userId }, select: { toolName: true, extraKeys: true } }),
    prisma.userLlmProvider.findMany({
      where: { userId },
      orderBy: { createdAt: 'asc' },
      select: {
        id: true, providerType: true, name: true, apiKey: true, baseUrl: true,
        awsRegion: true, awsAccessKeyId: true, awsSecretKey: true, awsBearerToken: true,
      },
    }),
  ])
  return { settings: settings as unknown as Record<string, unknown> | null, rotationRows, llmRows: llmRows as LlmProviderRow[] }
}

// GET /api/users/[id]/settings/api-usage
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const auth = await authorize(request, id)
  if (auth instanceof NextResponse) return auth
  try {
    const row = await prisma.apiUsageReport.findUnique({ where: { userId: id } })
    let runBy: { id: string; name: string } | null = null
    if (row?.updatedById && row.updatedById !== id) {
      const actor = await prisma.user.findUnique({ where: { id: row.updatedById }, select: { id: true, name: true } })
      runBy = actor ? { id: actor.id, name: actor.name } : { id: row.updatedById, name: 'an administrator' }
    }
    let activity: UserActivity | null = null
    try {
      activity = await loadActivity(id)
    } catch (e) {
      // Unknown activity only matters to a POST, which fails closed on its own lookup.
      console.error('[api-usage] activity lookup failed:', e)
    }
    return json({
      enabled: checksEnabled(),
      report: row ? (row.report as unknown as ApiUsageReportV1) : null,
      running: runningFor(id),
      runBy,
      activity,
      tracked: trackedFields(PROBES),
    })
  } catch (error) {
    console.error('[api-usage] failed to load the report:', error)
    return json({ error: 'Failed to load the API usage report', code: safeErrorCode(error) }, 500)
  }
}

// POST /api/users/[id]/settings/api-usage  { overwrite?: boolean, ignoreRunningScans?: boolean }
export async function POST(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const auth = await authorize(request, id)
  if (auth instanceof NextResponse) return auth
  const { actorId } = auth

  if (!checksEnabled()) return json({ error: 'disabled' }, 409)

  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const overwrite = parsed.body.overwrite === true
  const ignoreRunningScans = parsed.body.ignoreRunningScans === true

  const lock = tryAcquire(id, new Date().toISOString())
  if (!lock.ok) {
    return lock.reason === 'busy'
      ? json({ error: 'busy', retryAfterSec: 30 }, 429, { 'Retry-After': '30' })
      : json({ error: 'run_in_progress', startedAt: lock.startedAt }, 409)
  }

  let finishedAtMs: number | undefined
  try {
    const existing = await prisma.apiUsageReport.findUnique({
      where: { userId: id },
      select: { finishedAt: true },
    })

    // Before the overwrite question, so nobody confirms and is then told to wait.
    const lastRun = Math.max(existing?.finishedAt.getTime() ?? 0, lastFinishedAt(id) ?? 0)
    const sinceLast = Date.now() - lastRun
    if (lastRun > 0 && sinceLast < COOLDOWN_MS) {
      const retryAfterSec = Math.max(1, Math.ceil((COOLDOWN_MS - sinceLast) / 1000))
      return json({ error: 'cooldown', retryAfterSec }, 429, { 'Retry-After': String(retryAfterSec) })
    }

    if (existing && !overwrite) {
      return json({ error: 'report_exists', finishedAt: existing.finishedAt.toISOString() }, 409)
    }

    let activity: UserActivity
    try {
      activity = await loadActivity(id)
    } catch (e) {
      console.error('[api-usage] activity lookup failed, refusing to run:', e)
      return json({ error: 'activity_unknown' }, 503)
    }
    if ((activity.runningScans.length || activity.agentRuns.length) && !ignoreRunningScans) {
      return json({ error: 'scans_running', scans: activity.runningScans, agentRuns: activity.agentRuns }, 409)
    }

    const creds = await loadCredentials(id)
    const plan = buildJobs({ ...creds, probes: PROBES, llmProbes: LLM_PROBES })
    if (plan.jobs.length === 0) return json({ error: 'no_keys' }, 400)
    setRunKeys(id, plan.jobs.length)

    console.info(`[api-usage] start user=${id} keys=${plan.jobs.length}`)
    let report: ApiUsageReportV1
    try {
      report = await runJobs(plan)
    } catch (e) {
      console.error(`[api-usage] run failed user=${id}:`, e instanceof Error ? e.message : 'unknown error')
      return json({ error: 'run_failed', code: 'run_failed' }, 500)
    }
    finishedAtMs = Date.now()
    console.info(`[api-usage] done user=${id} ms=${report.durationMs} usage=${report.counts.usage} errors=${report.counts.errors}`)

    let saved = true
    let saveError: string | undefined
    try {
      const data = {
        schemaVersion: report.schemaVersion,
        startedAt: new Date(report.startedAt),
        finishedAt: new Date(report.finishedAt),
        report: report as unknown as object,
        updatedById: actorId,
      }
      await prisma.apiUsageReport.upsert({
        where: { userId: id },
        create: { userId: id, ...data, createdById: actorId },
        update: data,
      })
    } catch (e) {
      // The user still sees the fresh results; the saved report stays the old one.
      saved = false
      saveError = 'the database refused the save'
      console.error(`[api-usage] save failed user=${id}:`, e instanceof Error ? e.message : 'unknown error')
    }

    // Counts only: never a key, a hint or a provider string. It outlives the
    // report row, so "who sent this user's keys to the providers" stays answerable.
    await writeAudit({
      actorId,
      action: 'api-usage.check',
      targetType: 'user',
      targetId: id,
      source: 'ui',
      after: { services: report.counts.services, keys: report.counts.keys, counts: report.counts, saved },
    })

    return json(saved ? { report, saved: true } : { report, saved: false, saveError })
  } catch (error) {
    console.error('[api-usage] check failed:', error instanceof Error ? error.message : 'unknown error')
    return json({ error: 'Failed to run the API usage check', code: safeErrorCode(error) }, 500)
  } finally {
    release(id, finishedAtMs)
  }
}
