import { randomUUID } from 'node:crypto'
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { auditActor } from '@/lib/auditActor'
import { SETTINGS_CONSTANTS } from '@/lib/tradecraft/settingsSpec'
import { jobActorOf, startBulkJobs, type JobView } from '@/lib/tradecraft/jobs'
import { hasStoredLogin } from '@/lib/tradecraft/masking'
import { tradecraftV2Enabled } from '@/lib/tradecraft/switch'

interface RouteParams {
  params: Promise<{ id: string }>
}

const MAX_IDS: number = SETTINGS_CONSTANTS.jobStartBatchMax

export type SkipReason = 'not_found' | 'disabled' | 'job_running' | 'use_site_logins' | 'use_github_token'

const bad = (error: string) => NextResponse.json({ error, code: 'bad_request', field: 'resourceIds' }, { status: 400 })

// POST /api/users/[id]/tradecraft-resources/refresh-all
//   Body: { resourceIds: [<id>, ...] }  (the enabled resources left ticked in the confirmation)
// Save & refresh all (§3.2, §4.7, T6.10): one `bulk` job per resource, one bulkId, started with
// one request to the agent, which runs them one at a time and stops the batch when the daily model
// budget is spent (R-027). Skipped, and listed with the reason: a resource not the account's, a
// disabled one, one already running, and, while an administrator acts as the account, one whose
// job would use its site login or the account's GitHub token (R-159; one `act_as.refused` row
// for each kind the batch was refused, as a single Refresh records one).
// Answers 202 { bulkId, started: [{ resourceId, name, job }], skipped: [{ resourceId, name, reason }] }.
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    const actor = jobActorOf(await auditActor())
    if (!actor) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    if (!(await tradecraftV2Enabled(id))) {
      return NextResponse.json({ error: 'Tradecraft 2.0 is off for this account', code: 'tradecraft_v2_off' }, { status: 404 })
    }
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const raw = parsed.body.resourceIds
    if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_IDS) return bad(`Send 1 to ${MAX_IDS} resource ids`)
    if (!raw.every(x => typeof x === 'string' && x.length > 0 && x.length <= 200)) return bad('A resource id is text')
    const ids = [...new Set(raw as string[])]

    const rows = await prisma.userTradecraftResource.findMany({
      where: { userId: id, id: { in: ids } },
      select: { id: true, name: true, enabled: true, hasLogin: true, credentials: true, githubTokenOverride: true },
    })
    const byId = new Map(rows.map(r => [r.id, r]))
    const skipped: { resourceId: string; name: string; reason: SkipReason }[] = []
    const skip = (resourceId: string, reason: SkipReason) => skipped.push({ resourceId, name: byId.get(resourceId)?.name ?? '', reason })
    let candidates = ids.filter(rid => {
      const r = byId.get(rid)
      if (!r) skip(rid, 'not_found')
      else if (!r.enabled) skip(rid, 'disabled')
      return !!r && r.enabled
    })

    // The jobs would log in with a site login, or send the account's GitHub token: neither while
    // an administrator acts as the account (§6.6, step 3.14). Asked once per kind, so a batch
    // records one refusal of each, as one Refresh does; the others still start.
    const withLogin = candidates.filter(rid => hasStoredLogin(byId.get(rid)!))
    if (withLogin.length > 0 && await refuseWhileActingAsOn(id, 'use_site_logins')) {
      for (const rid of withLogin) skip(rid, 'use_site_logins')
      candidates = candidates.filter(rid => !withLogin.includes(rid))
    }
    const account = candidates.some(rid => !byId.get(rid)!.githubTokenOverride)
      ? await prisma.userSettings.findUnique({ where: { userId: id }, select: { githubAccessToken: true } })
      : null
    const withToken = candidates.filter(rid => !!(byId.get(rid)!.githubTokenOverride || account?.githubAccessToken))
    if (withToken.length > 0 && await refuseWhileActingAsOn(id, 'use_github_token')) {
      for (const rid of withToken) skip(rid, 'use_github_token')
      candidates = candidates.filter(rid => !withToken.includes(rid))
    }

    const bulkId = `bulk-${randomUUID()}`
    const result = candidates.length > 0
      ? await startBulkJobs({ ownerId: id, resourceIds: candidates, actor, bulkId })
      : { started: [], skipped: [] }
    for (const s of result.skipped) skip(s.resourceId, s.reason)
    const started: { resourceId: string; name: string; job: JobView }[] = result.started.map(s => ({
      resourceId: s.resourceId, name: byId.get(s.resourceId)?.name ?? '', job: s.outcome.job,
    }))
    console.info(`[tradecraft] refresh_all user=${id} bulk=${bulkId} started=${started.length} skipped=${skipped.length}`)
    return NextResponse.json({ bulkId, started, skipped }, { status: 202 })
  } catch (error) {
    return internalError(error, 'Failed to start Save & refresh all')
  }
}
