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
 */
import { NextRequest, NextResponse } from 'next/server'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
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

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params

  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, id)
  if (access instanceof NextResponse) return access

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
    ): Promise<{ data: FormattedGraphData; side: SideDescriptor } | NextResponse> => {
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

    const fromLoaded = await load(fromSel)
    if (fromLoaded instanceof NextResponse) return fromLoaded
    const toLoaded = await load(toSel)
    if (toLoaded instanceof NextResponse) return toLoaded

    const delta = computeReconDelta(fromLoaded.data, toLoaded.data)

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
    console.error('[scanTimeline] delta failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to compute the delta' },
      { status: 500 }
    )
  }
}
