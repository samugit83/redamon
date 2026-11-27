import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requirePermission } from '@/lib/authz/guards'
import { buildTrafficWhere } from '../route'
import { trafficTenant } from '../trafficTenant'
import { internalError } from '@/lib/routeErrors'

export const runtime = 'nodejs'

// Hard cap so a huge export can't exhaust memory; if hit, the response says so
// (no silent truncation, §12.2).
const MAX_EXPORT_ROWS = 50000
const PAGE = 1000

const CSV_COLS = [
  'id', 'startedAt', 'source', 'runId', 'sessionId', 'tool', 'phase',
  'method', 'scheme', 'host', 'port', 'path', 'query', 'statusCode',
  'respBodySize', 'respContentType', 'responseTimeMs', 'isTls', 'isReplay',
  'hasSetCookie', 'hadAuth', 'reflectedParams', 'blocked', 'inScope',
] as const

function csvCell(v: unknown): string {
  if (v === null || v === undefined) return ''
  let s = String(v)
  // Formula-injection guard: host/path/query come from the (attacker-controlled)
  // target, so neutralize leading =,+,-,@,tab,CR before a spreadsheet evals them.
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s
}

// GET /api/traffic/[projectId]/export?format=csv|json&<filters>
// Streams the CURRENT filtered result set (respecting every active filter).
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  const { projectId } = await params
  const auth = await requirePermission(request, 'traffic:export', { projectId })
  if (auth instanceof NextResponse) return auth

  const sp = request.nextUrl.searchParams
  const format = sp.get('format') === 'json' ? 'json' : 'csv'
  const where = buildTrafficWhere(projectId, trafficTenant(auth), sp)
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')

  const encoder = new TextEncoder()
  let sent = 0

  let cursor: string | undefined
  let first = true
  let opened = false
  let cancelled = false
  let done = false
  let truncated = false
  const csvSelect = Object.fromEntries(CSV_COLS.map(c => [c, true])) as {
    [K in typeof CSV_COLS[number]]: true
  }

  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (cancelled) return
      if (!opened) {
        opened = true
        controller.enqueue(encoder.encode(format === 'csv' ? CSV_COLS.join(',') + '\n' : '{"rows":[\n'))
        return
      }
      const finish = (errored = false) => {
        if (cancelled) return
        if (format === 'json') {
          controller.enqueue(encoder.encode(`\n],"count":${sent},"truncated":${truncated}${errored ? ',"error":"Failed to export traffic","code":"export_failed"' : ''}}\n`))
        } else {
          if (truncated) controller.enqueue(encoder.encode(`# TRUNCATED at ${MAX_EXPORT_ROWS} rows - narrow the filters to export the rest\n`))
          if (errored) controller.enqueue(encoder.encode('# export error: Failed to export traffic (export_failed)\n'))
        }
        controller.close()
      }
      if (done) { finish(); return }
      try {
        const take = Math.min(PAGE, MAX_EXPORT_ROWS - sent)
        const rows = await prisma.capturedHttpTransaction.findMany({
          where,
          orderBy: { id: 'asc' },
          take,
          ...(format === 'csv' ? { select: csvSelect } : {}),
          ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
        })
        // A query already in flight can finish after the consumer cancels.
        if (cancelled) return
        if (rows.length === 0) { finish(); return }
        const chunk = rows.map(r => {
          if (format === 'csv') {
            return CSV_COLS.map(c => csvCell(r[c])).join(',') + '\n'
          }
          const line = (first ? '' : ',\n') + JSON.stringify(r)
          first = false
          return line
        }).join('')
        sent += rows.length
        cursor = rows[rows.length - 1].id
        truncated = sent >= MAX_EXPORT_ROWS
        done = truncated || rows.length < take
        controller.enqueue(encoder.encode(chunk))
      } catch (e) {
        internalError(e, 'Failed to export traffic')
        finish(true)
      }
    },
    cancel() {
      cancelled = true
    },
  }, { highWaterMark: 0 })

  return new Response(stream, {
    headers: {
      'Content-Type': format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json',
      'Content-Disposition': `attachment; filename="traffic-${stamp}.${format}"`,
      'Cache-Control': 'no-store',
    },
  })
}
