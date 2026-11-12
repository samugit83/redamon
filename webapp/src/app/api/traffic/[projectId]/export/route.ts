import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requirePermission } from '@/lib/authz/guards'
import { buildTrafficWhere } from '../route'

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
  const eff = auth.effective

  const sp = request.nextUrl.searchParams
  const format = sp.get('format') === 'json' ? 'json' : 'csv'
  const where = buildTrafficWhere(projectId, eff.userId, sp)
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')

  const encoder = new TextEncoder()
  let sent = 0

  const stream = new ReadableStream({
    async start(controller) {
      // JSON is a wrapper object { rows: [...], truncated, error } so truncation
      // and mid-stream errors are represented as VALID JSON, not a silent partial
      // array or an illegal comment.
      let truncated = false
      let errored = ''
      try {
        if (format === 'csv') {
          controller.enqueue(encoder.encode(CSV_COLS.join(',') + '\n'))
        } else {
          controller.enqueue(encoder.encode('{"rows":[\n'))
        }
        let cursor: string | undefined
        let first = true
        for (;;) {
          if (sent >= MAX_EXPORT_ROWS) { truncated = true; break }
          const take = Math.min(PAGE, MAX_EXPORT_ROWS - sent)
          const rows = await prisma.capturedHttpTransaction.findMany({
            where,
            orderBy: { id: 'asc' },
            take,
            ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
          })
          if (rows.length === 0) break
          for (const r of rows) {
            if (format === 'csv') {
              controller.enqueue(encoder.encode(CSV_COLS.map(c => csvCell((r as Record<string, unknown>)[c])).join(',') + '\n'))
            } else {
              controller.enqueue(encoder.encode((first ? '' : ',\n') + JSON.stringify(r)))
              first = false
            }
          }
          sent += rows.length
          cursor = rows[rows.length - 1].id
          if (rows.length < take) break
        }
      } catch (e) {
        errored = String(e)
      } finally {
        if (format === 'json') {
          controller.enqueue(encoder.encode(`\n],"count":${sent},"truncated":${truncated}${errored ? `,"error":${JSON.stringify(errored)}` : ''}}\n`))
        } else {
          if (truncated) controller.enqueue(encoder.encode(`# TRUNCATED at ${MAX_EXPORT_ROWS} rows - narrow the filters to export the rest\n`))
          if (errored) controller.enqueue(encoder.encode(`# export error: ${errored}\n`))
        }
        controller.close()
      }
    },
  })

  return new Response(stream, {
    headers: {
      'Content-Type': format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json',
      'Content-Disposition': `attachment; filename="traffic-${stamp}.${format}"`,
      'Cache-Control': 'no-store',
    },
  })
}
