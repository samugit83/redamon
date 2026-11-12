/**
 * Hostnames on target IPs: the names the last run found on an IP-mode
 * project's addresses, and what a hostname policy would do with them.
 *
 * GET /api/projects/[id]/ip-hostnames
 *   ?limit=<1..500, default 100>&cursor=<last name>&reason=<code>&q=<substring>&name=<exact name>
 *   &mode=<ipHostnameMode>&include=..&include=..&exclude=..&cap=<n>
 *
 * `mode` (with the include/exclude/cap that go with it) judges an unsaved
 * policy, so the form preview counts what the edit would scan; without it the
 * saved policy is judged. Either way the totals cover every name and only one
 * page of rows comes back. Read-only: nothing is written.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { IP_HOSTNAME_MODES, type IpHostnameMode } from '@/lib/ipHostnameFilter'
import { IP_HOSTNAME_MAX_ENTRIES, IP_HOSTNAME_SELECT } from '@/lib/scopeGroups'
import {
  PREVIEW_PAGE_DEFAULT, PREVIEW_PAGE_MAX, type PreviewQuery, loadIpHostnamePreview,
} from '@/lib/ipHostnamePreview'

interface RouteParams {
  params: Promise<{ id: string }>
}

const bad = (error: string) => NextResponse.json({ error }, { status: 400 })

/** The query as PreviewQuery, or the sentence a 400 answers with. */
function parseQuery(sp: URLSearchParams): PreviewQuery | string {
  const query: PreviewQuery = { limit: PREVIEW_PAGE_DEFAULT }
  const rawLimit = sp.get('limit')
  if (rawLimit !== null) {
    const limit = Number(rawLimit)
    if (!Number.isInteger(limit) || limit < 1) return 'limit must be a whole number from 1'
    query.limit = Math.min(limit, PREVIEW_PAGE_MAX)
  }
  query.cursor = sp.get('cursor') || null
  query.reason = sp.get('reason') || null
  query.q = sp.get('q') || null
  query.name = sp.get('name')?.trim().toLowerCase() || null

  const mode = sp.get('mode')
  if (mode !== null) {
    if (!(IP_HOSTNAME_MODES as readonly string[]).includes(mode)) {
      return `mode must be one of ${IP_HOSTNAME_MODES.join(', ')}`
    }
    const include = sp.getAll('include')
    const exclude = sp.getAll('exclude')
    if (include.length > IP_HOSTNAME_MAX_ENTRIES || exclude.length > IP_HOSTNAME_MAX_ENTRIES) {
      return `include and exclude take at most ${IP_HOSTNAME_MAX_ENTRIES} entries each`
    }
    query.policy = { mode: mode as IpHostnameMode, include, exclude }
    const rawCap = sp.get('cap')
    if (rawCap !== null) {
      const cap = Number(rawCap)
      if (!Number.isInteger(cap) || cap < 1 || cap > 2000) return 'cap must be a whole number between 1 and 2000'
      query.policy.maxScanned = cap
    }
  }
  return query
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params

  const auth = await requirePermission(request, 'recon:read', { projectId: id })
  if (auth instanceof NextResponse) return auth

  const query = parseQuery(request.nextUrl.searchParams)
  if (typeof query === 'string') return bad(query)

  try {
    const row = await prisma.project.findUnique({
      where: { id },
      select: { id: true, userId: true, ipMode: true, roeExcludedHosts: true, ...IP_HOSTNAME_SELECT },
    })
    if (!row) return NextResponse.json({ error: 'Not found' }, { status: 404 })
    if (!row.ipMode) return bad('Hostnames on target IPs applies to IP-mode projects only.')

    // The graph is keyed by the project's owner, which is also who may read it.
    const session = getGraphSession()
    try {
      return NextResponse.json(await loadIpHostnamePreview(session, row, query))
    } finally {
      await session.close()
    }
  } catch (err) {
    return internalError(err, 'Failed to read the hostnames found on the target IPs')
  }
}
