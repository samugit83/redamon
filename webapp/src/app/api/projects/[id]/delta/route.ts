/**
 * Scan Timeline - Recon Delta (Section 6.1).
 *
 * GET /api/projects/[id]/delta?from=<versionId|current>&to=<versionId|current>
 *
 * Both sides are read in the SAME shape so the comparison is apples-to-apples:
 * a past version from its stored bytes, and `current` by capturing the live graph
 * through the identical query + session-label exclusion the snapshot uses. (The
 * plain /api/graph read pulls in extra enrichment nodes that snapshots never
 * carry, which would show up as a wall of phantom "removed" rows.)
 *
 * Read-only: nothing is written, and no snapshot content is logged.
 *
 * A reader below Raw data & files (`recon:read` is R) compares both sides as the graph read view
 * gives them (`stripStepContent`, the helper of every graph output): no chain-step content, nor what
 * OQ-R7 makes raw data, reaches the added, removed or changed nodes, a changed node's previous
 * properties or the overlay, and a change in such a property alone is no change.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { stripStepContent } from '@/lib/authz/stepContent'
import { internalError, withRouteErrors } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { SCOPE_SELECT, currentScanRoots } from '@/lib/scanCoverage'
import { resolveVersionSelector, isCurrentSelector } from '@/lib/scanVersionAccess'
import { captureGraphSnapshot, loadSnapshot, snapshotToGraphPayload } from '@/lib/scanSnapshot'
import { computeReconDelta, buildDeltaOverlay } from '@/lib/reconDelta'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import type { FormattedGraphData } from '@/app/api/graph/format'

interface RouteParams {
  params: Promise<{ id: string }>
}

interface SideDescriptor {
  versionId: string | 'current'
  label: string
  seq: number | null
  isCurrent: boolean
}

export const GET = withRouteErrors('Failed to compute the delta', async (request: NextRequest, { params }: RouteParams) => {
  const { id } = await params

  const auth = await requirePermission(request, 'recon:read', { projectId: id })
  if (auth instanceof NextResponse) return auth

  const sp = request.nextUrl.searchParams
  // Anti-IDOR: a version id in `from`/`to` must belong to THIS project.
  const fromSel = await resolveVersionSelector(id, sp.get('from'))
  if (fromSel instanceof NextResponse) return fromSel
  const toSel = await resolveVersionSelector(id, sp.get('to'))
  if (toSel instanceof NextResponse) return toSel

  const includeOverlay = sp.get('overlay') === '1'

  try {
    const load = async (
      sel: typeof fromSel
    ): Promise<
      | { data: FormattedGraphData; side: SideDescriptor; liveNodeIds?: ReadonlyMap<string, string> }
      | NextResponse
    > => {
      if (isCurrentSelector(sel)) {
        // Capturing the live graph while something is rewriting it produces a
        // comparison against a state that never existed. This route had no
        // guard at all (X15).
        const busy = await describeLiveGraphWriters(id)
        if (busy) {
          return NextResponse.json(
            {
              error: `The live graph cannot be compared right now: ${busy}.`,
              graphBusy: true,
            },
            { status: 409 }
          )
        }
        const captured = await captureGraphSnapshot(id)
        return {
          data: snapshotToGraphPayload(captured),
          side: { versionId: 'current', label: 'Current (live graph)', seq: null, isCurrent: true },
          // Only the live side can name a node's id; a stored version never does.
          liveNodeIds: captured.liveNodeIds,
        }
      }
      const snapshot = await loadSnapshot(sel.id)
      if (!snapshot) {
        return NextResponse.json(
          {
            error: `Version "${sel.label}" has no stored snapshot, so it cannot be compared.`,
            emptySnapshot: true,
            versionId: sel.id,
          },
          { status: 409 }
        )
      }
      return {
        data: snapshotToGraphPayload(snapshot),
        side: { versionId: sel.id, label: sel.label, seq: sel.seq, isCurrent: sel.isCurrent },
      }
    }

    const asRead = (data: FormattedGraphData): FormattedGraphData => ({ ...data, nodes: stripStepContent(data.nodes, auth.access) })
    const fromLoaded = await load(fromSel)
    if (fromLoaded instanceof NextResponse) return fromLoaded
    fromLoaded.data = asRead(fromLoaded.data)
    const toLoaded = await load(toSel)
    if (toLoaded instanceof NextResponse) return toLoaded
    toLoaded.data = asRead(toLoaded.data)

    // Coverage of a scan root removed since the run is not this scope's gap.
    const scope = await prisma.project.findUnique({ where: { id }, select: SCOPE_SELECT })
    const delta = computeReconDelta(fromLoaded.data, toLoaded.data, {
      from: fromLoaded.liveNodeIds,
      to: toLoaded.liveNodeIds,
    }, scope ? currentScanRoots(scope) : null)

    return NextResponse.json(
      {
        from: fromLoaded.side,
        to: toLoaded.side,
        ...delta,
        ...(includeOverlay
          ? { overlay: buildDeltaOverlay(fromLoaded.data, toLoaded.data, delta) }
          : {}),
      },
      { headers: { 'Cache-Control': 'private, no-cache' } }
    )
  } catch (error) {
    return internalError(error, 'Failed to compute the delta', { log: '[scanTimeline] delta failed' })
  }
})
