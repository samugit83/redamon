import type { NextRequest } from 'next/server'
import { checkReviewProposal } from '@/lib/plugins/actions'
import { GATEWAY_BODY_MAX_BYTES, GatewayError, withGateway } from '@/lib/plugins/gateway'
import { JobReportError, checkedReport, completeJob } from '@/lib/plugins/jobs'

/**
 * POST /api/plugin-gateway/v1/jobs/complete: the runner reports a job's end with the job's
 * own token (`{status: succeeded, result} | {status: failed|cancelled, error}`). A job
 * already over keeps its state (a late or repeated report answers `ignored`). A result's
 * `reviewProposal` is checked as in a sync action (RV-21). Not counted against the token's
 * call budget: a job that used its calls must still be able to report its result. A plugin
 * that stopped serving, or a project or session deleted, while the job ran ends the job as
 * failed with that reason, its result dropped (see `jobEnd` in gateway.ts).
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export function POST(request: NextRequest) {
  const opts = { op: 'jobs/complete', kinds: ['job'] as const, jobEnd: true, maxBodyBytes: GATEWAY_BODY_MAX_BYTES }
  return withGateway(request, opts, async (ctx) => {
    let report
    try {
      report = checkedReport(ctx.body)
    } catch (e) {
      if (e instanceof JobReportError) throw new GatewayError(400, e.code, e.message)
      throw e
    }
    if (report.result && !ctx.lapsed) {
      report.result = await checkReviewProposal(report.result, { pluginId: ctx.pluginId, userId: ctx.userId, projectId: ctx.projectId, access: ctx.access })
    }
    const { found, changed } = await completeJob(ctx.pluginId, ctx.userId, ctx.claims.jid!, report, { lapsed: ctx.lapsed })
    if (!found) throw new GatewayError(404, 'not_found', 'No such job.')
    return changed ? { ok: true } : { ok: true, ignored: true }
  })
}
