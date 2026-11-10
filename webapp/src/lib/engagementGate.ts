/**
 * The third-party engagement gate for the manual start routes.
 *
 * `startFullScan` and the queue's `dispatchStart` refuse a third-party
 * engagement that lacks its rate ceiling or its authorization record. A manual
 * partial recon, GVM, AI Gauntlet or supply-chain start reaches the same
 * estate through its own route, so each route calls this before it hands the
 * run to the orchestrator; the orchestrator does not check engagements itself.
 */
import { NextResponse } from 'next/server'

import { loadEngagement } from '@/lib/engagement'

/**
 * A 422 refusal when the project's engagement is not startable, else null.
 *
 * The status and the message are the full start's, so a client (and the
 * queue, which reads 409 as "busy, retry") treats both refusals alike: only a
 * person adding the ceiling or the record can clear it. `loadEngagement`
 * fails closed, and a throw here reaches the route's catch, so an unreadable
 * project never starts either.
 */
export async function assertEngagementStartable(projectId: string): Promise<NextResponse | null> {
  const engagement = await loadEngagement(projectId)
  if (engagement.blockers.length === 0) return null
  return NextResponse.json(
    {
      error:
        'This is a third-party engagement and it is not startable: ' +
        engagement.blockers.join(' ') +
        ' Use preflight_scope_check to see the whole picture.',
    },
    { status: 422 },
  )
}
