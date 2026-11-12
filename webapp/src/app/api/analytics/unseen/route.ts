/**
 * Unseen-row badge counts for every graph table tab, in one round trip.
 *
 * The alternative is the browser calling all twenty tab endpoints to see whether
 * any of them has anything new, which transfers the entire attack surface to
 * render twenty small numbers. This route does that fan-out server-side and
 * returns only the numbers.
 *
 * POST rather than GET because the request carries the caller's per-tab
 * watermark map; it is a read and performs no writes.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { internalError } from '@/lib/routeErrors'
import { BADGED_TABS } from '@/app/graph/unseen/registry'
import { barTotal, buildLabelCountQuery } from '@/app/graph/unseen/counts'
import { LABEL_TABS, ROUTE_TABS, countUnseenRows, labelsForTab } from './sources'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

const BADGED = new Set<string>(BADGED_TABS)

/**
 * How many tab sources may be in flight at once.
 *
 * Each one holds a Bolt session for the length of its query and the driver pool
 * is 50 across the whole webapp, so an unbounded fan-out of twenty per polling
 * browser tab would starve every other request on a busy page.
 */
const MAX_CONCURRENCY = 5

/**
 * Keep only watermarks that name a real tab and parse as an instant.
 *
 * Unparseable values are dropped rather than 400'd: they would otherwise reach
 * Cypher as `datetime($since)`, which THROWS on a malformed string, and one
 * stale value in a preferences blob would take every badge on the page down
 * with it. A dropped tab is re-seeded with the server clock on the next
 * response.
 */
function sanitiseMarks(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== 'object') return {}
  const out: Record<string, string> = {}
  for (const [tab, value] of Object.entries(raw as Record<string, unknown>)) {
    if (!BADGED.has(tab) || typeof value !== 'string') continue
    const ms = Date.parse(value)
    if (Number.isNaN(ms)) continue
    out[tab] = new Date(ms).toISOString()
  }
  return out
}

/** Run `tasks` with at most `limit` in flight, preserving order. */
async function pooled<T>(tasks: Array<() => Promise<T>>, limit: number): Promise<T[]> {
  const results = new Array<T>(tasks.length)
  let next = 0
  const workers = Array.from({ length: Math.min(limit, tasks.length) }, async () => {
    while (next < tasks.length) {
      const i = next++
      results[i] = await tasks[i]()
    }
  })
  await Promise.all(workers)
  return results
}

export async function POST(request: NextRequest) {
  let body: { projectId?: unknown; marks?: unknown }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  const projectId = typeof body.projectId === 'string' ? body.projectId : ''
  const auth = await requirePermission(request, 'graph:read', { projectId })
  if (auth instanceof NextResponse) return auth

  const marks = sanitiseMarks(body.marks)

  const session = getGraphSession()
  try {
    // The graph's own clock, not the browser's and not the webapp's. Watermarks
    // are compared against timestamps Neo4j stamped, so a client that is a
    // minute fast would write a watermark into the future and hide the next
    // scan's findings permanently.
    const nowResult = await session.run('RETURN toString(datetime()) AS now')
    const now = nowResult.records[0]?.get('now') as string

    // No watermarks yet (a first-ever visit) means nothing to count: the client
    // seeds every tab from `now` and starts at zero.
    if (Object.keys(marks).length === 0) {
      return NextResponse.json({ now, counts: {}, total: 0 })
    }

    const counts: Record<string, number> = {}

    // Whole-graph tabs: one label-count query each, since for them every node
    // with the label is a row.
    for (const tab of LABEL_TABS) {
      const since = marks[tab]
      if (!since) continue
      const query = buildLabelCountQuery(labelsForTab(tab))
      if (!query) continue
      const result = await session.run(query.cypher, { pid: projectId, since, ...query.params })
      counts[tab] = result.records.reduce((sum, r) => sum + toNum(r.get('c')), 0)
    }

    // Filtered tabs: ask the tab's own route what it would show.
    const routeTabs = ROUTE_TABS.filter(tab => marks[tab])
    const routeCounts = await pooled(
      routeTabs.map(tab => () => countUnseenRows(tab, projectId, Date.parse(marks[tab]))),
      MAX_CONCURRENCY,
    )
    routeTabs.forEach((tab, i) => { counts[tab] = routeCounts[i] })

    return NextResponse.json({ now, counts, total: barTotal(counts) })
  } catch (error) {
    return internalError(error, 'Failed to compute unseen counts')
  } finally {
    await session.close()
  }
}
