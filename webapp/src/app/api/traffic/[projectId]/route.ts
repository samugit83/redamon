import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import { requirePermission } from '@/lib/authz/guards'
import { gcOrphanBodies } from '@/lib/captureBodies'
import type { Prisma } from '@prisma/client'
import { trafficRows, trafficTenant } from './trafficTenant'

// Summary columns only - bodies are fetched on demand via the [id] detail route,
// so a large history never materializes in the list response.
const LIST_SELECT = {
  id: true,
  startedAt: true,
  source: true,
  runId: true,
  sessionId: true,
  tool: true,
  phase: true,
  method: true,
  scheme: true,
  host: true,
  port: true,
  path: true,
  query: true,
  statusCode: true,
  respBodySize: true,
  respContentType: true,
  responseTimeMs: true,
  isTls: true,
  isReplay: true,
  hasSetCookie: true,
  hadAuth: true,
  reflectedParams: true,
  blocked: true,
  inScope: true,
  // A1: set by both ingest paths when the request's host or resolved IP appears
  // in the supply-chain incident catalog. Null means "no match OR never synced".
  iocIncidentId: true,
  iocIncidentUrl: true,
} satisfies Prisma.CapturedHttpTransactionSelect

// Whitelisted sortable columns (prevents arbitrary orderBy injection).
const SORTABLE = new Set([
  'startedAt', 'statusCode', 'host', 'tool', 'method', 'respBodySize', 'responseTimeMs', 'source',
])

const MAX_PAGE_SIZE = 200

function statusClassRange(cls: string | null): Prisma.IntFilter | undefined {
  switch (cls) {
    case '2xx': return { gte: 200, lt: 300 }
    case '3xx': return { gte: 300, lt: 400 }
    case '4xx': return { gte: 400, lt: 500 }
    case '5xx': return { gte: 500, lt: 600 }
    default: return undefined
  }
}

// The where clause shared by the list, the export and delete-all-matching: the project's rows
// under its owner (`tenantUserId`, trafficTenant.ts), then the filters. Both ids come from the
// route and the guard's access, never from client fields.
export function buildTrafficWhere(
  projectId: string,
  tenantUserId: string,
  sp: URLSearchParams,
): Prisma.CapturedHttpTransactionWhereInput {
  const where: Prisma.CapturedHttpTransactionWhereInput = { projectId, userId: tenantUserId }

  const source = sp.get('source')
  if (source && source !== 'both') where.source = source

  const tool = sp.get('tool')
  if (tool) where.tool = { in: tool.split(',').map(t => t.trim()).filter(Boolean) }

  const sessionId = sp.get('sessionId')
  if (sessionId) where.sessionId = sessionId

  const runId = sp.get('runId')
  if (runId) where.runId = runId

  const host = sp.get('host')
  if (host) where.host = host

  const method = sp.get('method')
  if (method) where.method = method

  const statusRange = statusClassRange(sp.get('statusClass'))
  if (statusRange) where.statusCode = statusRange

  // Date range over startedAt (native <input type=date> yields YYYY-MM-DD).
  // Ignore unparseable values rather than letting an Invalid Date reach Prisma
  // (which would 500 the request).
  const from = sp.get('from')
  const to = sp.get('to')
  const startedAt: Prisma.DateTimeFilter = {}
  if (from) {
    const d = new Date(from)
    if (!Number.isNaN(d.getTime())) startedAt.gte = d
  }
  if (to) {
    const end = new Date(to)
    if (!Number.isNaN(end.getTime())) {
      end.setUTCHours(23, 59, 59, 999) // inclusive end-of-day
      startedAt.lte = end
    }
  }
  if (startedAt.gte || startedAt.lte) where.startedAt = startedAt

  // Quick toggles
  if (sp.get('hasSetCookie') === 'true') where.hasSetCookie = true
  if (sp.get('reflected') === 'true') where.reflectedParams = true
  if (sp.get('only5xx') === 'true') where.statusCode = { gte: 500, lt: 600 }

  // Free-text over URL (host/path) - uses the pg_trgm indexes when FTS is on.
  const q = sp.get('q')
  if (q) {
    where.OR = [
      { host: { contains: q, mode: 'insensitive' } },
      { path: { contains: q, mode: 'insensitive' } },
    ]
  }

  // Body substring search (Phase 3). `resp_body ILIKE '%bodyq%'` - always correct;
  // becomes index-backed (fast) when the pg_trgm GIN index on resp_body exists
  // (built by the FTS migration when CAPTURE_PROXY_FTS is on). Covers secrets,
  // stack traces, code identifiers, and reflected input alike.
  const bodyq = sp.get('bodyq')
  if (bodyq) where.respBody = { contains: bodyq, mode: 'insensitive' }

  return where
}

// GET /api/traffic/[projectId] - paginated, filtered transaction list.
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  try {
    const { projectId } = await params

    const auth = await requirePermission(request, 'traffic:read', { projectId })
    if (auth instanceof NextResponse) return auth

    const sp = request.nextUrl.searchParams
    const where = buildTrafficWhere(projectId, trafficTenant(auth), sp)

    const page = Math.max(0, parseInt(sp.get('page') || '0', 10) || 0)
    const pageSize = Math.min(MAX_PAGE_SIZE, Math.max(1, parseInt(sp.get('pageSize') || '50', 10) || 50))

    const sortField = sp.get('sort') || 'startedAt'
    const orderBy: Prisma.CapturedHttpTransactionOrderByWithRelationInput = SORTABLE.has(sortField)
      ? { [sortField]: sp.get('dir') === 'asc' ? 'asc' : 'desc' }
      : { startedAt: 'desc' }

    const [rows, total] = await Promise.all([
      prisma.capturedHttpTransaction.findMany({
        where,
        select: LIST_SELECT,
        orderBy,
        skip: page * pageSize,
        take: pageSize,
      }),
      prisma.capturedHttpTransaction.count({ where }),
    ])

    return NextResponse.json({ rows, total, page, pageSize })
  } catch (error) {
    return internalError(error, 'Failed to list traffic', { log: 'Failed to list captured traffic' })
  }
}

// DELETE /api/traffic/[projectId] - batch delete (plan §12.2).
// Body: { ids: [...] } OR { filter: {<same query params as GET>} } (delete-all-matching).
// Tenant-enforced (the project's rows under its owner, trafficRows; a project the caller cannot
// see -> 404 from the guard), so a collaborator at traffic:delete (W) deletes the project's rows,
// not nothing (step 5.2), body-GC-aware (ref-counted blob cleanup), and audited. Client tenant
// fields are never trusted - projectId/userId come from the route + the guard's access.
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'traffic:delete', { projectId })
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective

    const body = await request.json().catch(() => ({}))
    const where: Prisma.CapturedHttpTransactionWhereInput = { ...trafficRows(projectId, auth) }

    let mode: string
    if (Array.isArray(body?.ids) && body.ids.length > 0) {
      where.id = { in: body.ids.filter((x: unknown) => typeof x === 'string') }
      mode = `ids(${body.ids.length})`
    } else if (body?.filter && typeof body.filter === 'object') {
      // Reuse the exact list filter predicate so "delete all matching" deletes
      // precisely what the current view shows.
      const sp = new URLSearchParams()
      for (const [k, v] of Object.entries(body.filter)) {
        if (v !== undefined && v !== null && v !== '') sp.set(k, String(v))
      }
      Object.assign(where, buildTrafficWhere(projectId, trafficTenant(auth), sp))
      mode = 'filter'
    } else {
      return NextResponse.json({ error: 'Provide { ids: [...] } or { filter: {...} }' }, { status: 400 })
    }

    // Collect the body refs of the doomed rows so we can GC their blobs after.
    const doomed = await prisma.capturedHttpTransaction.findMany({
      where, select: { reqBodyRef: true, respBodyRef: true },
    })
    const shas = doomed.flatMap(r => [r.reqBodyRef, r.respBodyRef])

    const res = await prisma.capturedHttpTransaction.deleteMany({ where })
    const gc = await gcOrphanBodies(shas)

    console.log(`[traffic-delete] user=${eff.userId} project=${projectId} mode=${mode} deleted=${res.count} blobsGC=${gc.deleted}`)
    return NextResponse.json({ deleted: res.count, blobsDeleted: gc.deleted })
  } catch (error) {
    return internalError(error, 'Failed to delete traffic', { log: 'Failed to delete captured traffic' })
  }
}
