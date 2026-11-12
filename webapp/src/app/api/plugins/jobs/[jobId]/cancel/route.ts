import { NextResponse, type NextRequest } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { readJsonBody } from '@/lib/jsonBody'
import { cancelJobRow, findUserJob, isTerminal, jobView, refreshJob } from '@/lib/plugins/jobs'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'
import { cancelJob } from '@/lib/plugins/runnerClient'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { requirePermission } from '@/lib/authz/guards'

/**
 * POST /api/plugins/jobs/[jobId]/cancel: the owner stops an async plugin action. The job
 * is marked cancelled here first, so whatever the worker reports afterwards is ignored;
 * then the runner is asked to stop it (and kills the worker if it does not stop). A runner
 * that cannot be reached changes nothing for the user: the job is already cancelled.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const POST = pluginRoute('job cancel', 'The job could not be cancelled; see the webapp log.', async (
  request: NextRequest,
  { params }: { params: Promise<{ jobId: string }> },
) => {
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const auth = await requirePermission(request, 'plugins:use')
  if (auth instanceof NextResponse) return auth
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const { jobId } = await params
  const found = await findUserJob(eff.userId, jobId)
  if (!found) return NextResponse.json({ error: 'Not found', code: 'not_found' }, { status: 404 })
  const job = await refreshJob(found)
  if (isTerminal(job.status)) return NextResponse.json(jobView(job))
  const { job: cancelled, changed } = await cancelJobRow(job)
  if (changed) {
    try {
      await cancelJob(job.pluginId, job.jobId)
    } catch (e) {
      console.warn(`[plugins] job ${job.jobId} cancelled, but the runner could not be told:`, e instanceof Error ? e.message : e)
    }
  }
  return NextResponse.json(jobView(cancelled))
})
