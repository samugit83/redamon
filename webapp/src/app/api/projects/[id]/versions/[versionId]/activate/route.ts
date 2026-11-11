/**
 * Scan Timeline - ACTIVATE a version (Section 4A): make it the live graph.
 *
 * POST /api/projects/[id]/versions/[versionId]/activate
 *
 * Viewing a version only renders it. Activating SWAPS the live Neo4j graph, so it
 * is the deliberate, locked, destructive-then-restore operation:
 *
 *   1. freeze the OUTGOING current version from the LIVE graph (not from its old
 *      stored bytes - partial recon may have edited it since). If this fails we
 *      abort here: nothing has been deleted, nothing is lost (fail closed).
 *   2. clear the live recon graph (KEEPING agent session nodes, F1) and restore X
 *      through the shared import restore path.
 *   3. only then move the current pointer, in one Postgres transaction.
 *   4. invalidate the graph cache so the next read returns X.
 *
 * A crash inside step 2 leaves the live graph transiently inconsistent, but BOTH
 * endpoints are safe in Postgres (the outgoing version was frozen in step 1, X's
 * bytes are untouched), so re-running the activation simply rebuilds X.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { requireVersionInProject, type OwnedVersion } from '@/lib/scanVersionAccess'
import { writeAudit } from '@/lib/audit'
import {
  captureGraphSnapshot,
  storeSnapshot,
  loadSnapshot,
  ensureCurrentVersion,
  withSnapshotSlot,
  SESSION_LABELS,
} from '@/lib/scanSnapshot'
import { clearProjectGraph, restoreGraph, sweepOrphanReferenceNodes } from '@/lib/graphRestore'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { invalidateCache } from '@/app/api/graph/cache'
import { acquireActivationLock, releaseActivationLock } from '@/lib/activationLock'
import { GRAPH_LOCK_HOLDER_PHRASE, tryWithGraphLock } from '@/lib/projectGraphLock'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import { describeNodeFilterWriter } from '@/lib/nodeFilterRun'
import { internalError, withRouteErrors } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string; versionId: string }>
}

export const POST = withRouteErrors('Activation failed', async (_request: NextRequest, { params }: RouteParams) => {
  const { id, versionId } = await params

  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, id)
  if (access instanceof NextResponse) return access

  // Anti-IDOR: never activate a version that belongs to another project.
  const target = await requireVersionInProject(id, versionId)
  if (target instanceof NextResponse) return target

  if (target.isCurrent) {
    return NextResponse.json({ ok: true, alreadyCurrent: true, versionId })
  }

  // 4A.6: a version with no restorable bytes must never be activated - restoring
  // from the lossy render shape is not a thing we do.
  if (!target.hasSnapshot) {
    return NextResponse.json(
      {
        error: 'This version has no stored snapshot, so it cannot be activated. ' +
          'It predates the Scan Timeline or its capture failed.',
        notActivatable: true,
      },
      { status: 409 }
    )
  }

  // S-4: held from the writer check through the pointer move. A scan start that
  // passed its own activation check, or a version save, would otherwise freeze
  // the half-restored graph, and the start would spawn a scan into the swap.
  const held = await tryWithGraphLock(id, 'activation', () => activateUnderLock(id, versionId, target, eff.userId))
  if (held.acquired) return held.value
  const holder = GRAPH_LOCK_HOLDER_PHRASE[held.heldBy]
  return NextResponse.json(
    { error: `Cannot activate a version while ${holder} for this project. Try again once it finishes.`, busy: holder },
    { status: 409 }
  )
})

/** The narrowing marker for the project's current policy, on its owner's
 *  graph. Best-effort: the restore already committed, so a failure is only
 *  reported (every reader re-applies the current policy). */
async function markRestoredHostnames(projectId: string): Promise<boolean> {
  try {
    const row = await prisma.project.findUnique({
      where: { id: projectId },
      select: { userId: true, ipMode: true, ipHostnameMode: true, ipHostnameInclude: true, ipHostnameExclude: true },
    })
    if (!row) return false
    const { markOutOfPolicy } = await import('@/lib/ipHostnamePolicy')
    return await markOutOfPolicy(projectId, row.userId, row)
  } catch (e) {
    console.warn('[scanTimeline] hostname policy marker failed after activation:', e)
    return false
  }
}

async function activateUnderLock(
  id: string,
  versionId: string,
  target: OwnedVersion,
  actorId: string,
): Promise<NextResponse> {
  // 4A.3: mutually exclusive with anything else that touches the live graph.
  const busy = await describeLiveGraphWriters(id)
  if (busy) {
    return NextResponse.json(
      { error: `Cannot activate a version while ${busy} for this project. Stop it first.`, busy },
      { status: 409 }
    )
  }

  const lock = await acquireActivationLock(id, versionId)
  if (!lock.acquired) {
    return NextResponse.json({ error: lock.reason ?? 'Activation is already running' }, { status: 409 })
  }

  // A node-filter apply can start between the writer check above and the lock:
  // the apply route checks for an activation only before it creates its run.
  // Re-checked under the lock so the freeze below never captures a half-applied graph.
  let applying: Awaited<ReturnType<typeof describeNodeFilterWriter>>
  try {
    applying = await describeNodeFilterWriter(id)
  } catch (err) {
    // The try/finally below is not entered yet: without this the lock outlives the request.
    await releaseActivationLock(id)
    throw err
  }
  if (applying) {
    await releaseActivationLock(id)
    return NextResponse.json(
      { error: `Cannot activate a version while ${applying} for this project. Try again when it finishes.`, busy: applying },
      { status: 409 }
    )
  }

  const startedAt = Date.now()
  try {
    const current = await ensureCurrentVersion(id)

    // The target must not be the outgoing current. `requireVersionInProject` read
    // isCurrent BEFORE the lock, and ensureCurrentVersion can legitimately adopt
    // the highest-seq row when none is marked current (a crashed activation, an
    // imported archive with no current flag, or a concurrent list read). If that
    // row IS the target, freezing would overwrite the very bytes we are about to
    // restore with the live graph - silent loss of the version the user asked for.
    if (current.id === versionId) {
      return NextResponse.json({ ok: true, alreadyCurrent: true, versionId })
    }

    // --- 1. freeze the outgoing current FROM LIVE (Risk 10) -------------------
    let frozenNodeCount = 0
    try {
      const captured = await captureGraphSnapshot(id)
      frozenNodeCount = captured.nodeCount
      if (captured.nodeCount > 0) {
        await storeSnapshot(current.id, captured)
      }
    } catch (err) {
      return internalError(err, 'Could not save the current graph before switching, so nothing was changed.', {
        log: '[scanTimeline] activation aborted before any delete',
        extra: { freezeFailed: true },
      })
    }

    // --- 2. swap the live graph ----------------------------------------------
    const snapshot = await loadSnapshot(versionId)
    if (!snapshot) {
      // Defensive: hasSnapshot said there were bytes. Nothing has been deleted.
      return NextResponse.json(
        { error: 'This version has no stored snapshot, so it cannot be activated.', notActivatable: true },
        { status: 409 }
      )
    }

    try {
      await withSnapshotSlot(async () => {
        const session = getGraphSession()
        try {
          // F1: agent session nodes are NOT version state - they survive the swap.
          // The orphan sweep waits for the restore: run in between, it deletes a
          // CVE only this project linked, and the version's link to it is lost.
          await clearProjectGraph(session, id, SESSION_LABELS, { sweep: false })
          await restoreGraph(session, snapshot.nodes, snapshot.relationships, {
            projectId: id,
            ...(snapshot.referenceLinks ? { referenceLinks: snapshot.referenceLinks } : {}),
          })
          await sweepOrphanReferenceNodes(session)
        } finally {
          await session.close()
        }
      })
    } catch (err) {
      invalidateCache(id)
      return internalError(err, 'Activation failed while rebuilding the graph. No version data was lost - ' +
        'retry the activation to rebuild it.', {
        log: '[scanTimeline] activation failed mid-restore (retriable)',
        extra: { restoreFailed: true, retriable: true },
      })
    }

    // --- 3. move the pointer (only after the restore succeeded) --------------
    // The promoted version IS the live graph now, so it must shed its snapshot
    // bytes: the invariant is "the current version has snapshot=null" and it
    // renders from /api/graph. Keeping the bytes would leave a full duplicate of
    // the graph in Postgres and a stale copy a future reader could trust.
    await prisma.$transaction(async tx => {
      await tx.scanVersion.updateMany({
        where: { projectId: id, isCurrent: true },
        data: { isCurrent: false },
      })
      await tx.scanVersion.update({ where: { id: versionId }, data: { isCurrent: true, snapshot: null } })
    })

    // A version captured before a narrowing holds hostnames still marked
    // scanned that the current policy no longer admits (design §6.3). Readers
    // drop them anyway; the marker makes the graph agree before the cache
    // is refreshed.
    const hostnamePolicyMarked = await markRestoredHostnames(id)

    // --- 4. the next read must see X ----------------------------------------
    invalidateCache(id)

    await writeAudit({
      actorId,
      action: 'scan-version.activate',
      targetType: 'scanVersion',
      targetId: versionId,
      before: { currentVersionId: current.id, currentSeq: current.seq, frozenNodeCount },
      after: { currentVersionId: versionId, seq: target.seq, nodeCount: snapshot.nodes.length },
    })

    return NextResponse.json({
      ok: true,
      versionId,
      seq: target.seq,
      label: target.label,
      restoredNodes: snapshot.nodes.length,
      restoredRelationships: snapshot.relationships.length,
      frozenVersionId: frozenNodeCount > 0 ? current.id : null,
      frozenNodeCount,
      hostnamePolicyMarked,
      durationMs: Date.now() - startedAt,
      // F2: activation swaps ONLY the recon graph.
      notice: 'Derived artifacts (GVM/secret scan output, remediations, reports, captured traffic) ' +
        'are project-level and still reflect the latest scan.',
    })
  } catch (error) {
    return internalError(error, 'Activation failed', { log: '[scanTimeline] activation error' })
  } finally {
    await releaseActivationLock(id)
  }
}
