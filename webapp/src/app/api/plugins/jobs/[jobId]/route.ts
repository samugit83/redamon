import { NextResponse, type NextRequest } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { pluginAllowedFor } from '@/lib/plugins/accessRules'
import { findUserJob, jobView, refreshJob } from '@/lib/plugins/jobs'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import { requirePermission } from '@/lib/authz/guards'

/**
 * GET /api/plugins/jobs/[jobId]: an async plugin action as the UI polls it (TD-22). Only
 * its owner sees it, while the plugin is available to them (404 otherwise; cancelling stays
 * theirs, jobs/[jobId]/cancel). A job past its deadline, or orphaned by a runner
 * restart, is turned into a failure here, on read.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const GET = pluginRoute('job read', 'The job could not be read; see the webapp log.', async (
  request: NextRequest,
  { params }: { params: Promise<{ jobId: string }> },
) => {
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const { jobId } = await params
  const job = await findUserJob(eff.userId, jobId)
  if (!job || !(await pluginAllowedFor(eff.userId, job.pluginId))) {
    return NextResponse.json({ error: 'Not found', code: 'not_found' }, { status: 404 })
  }
  return NextResponse.json(jobView(await refreshJob(job)), { headers: { 'Cache-Control': 'no-store' } })
})
