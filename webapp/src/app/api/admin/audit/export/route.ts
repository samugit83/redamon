import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { writeAuditTx, type AuditTx } from '@/lib/audit'
import { actorFields, auditActor } from '@/lib/auditActor'
import { rbacFlags } from '@/lib/authz/flags'
import { now } from '@/lib/authz/clock'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { AUDIT_FILTER_KEYS, countAuditRows, parseAuditQuery, type AuditFilters } from '@/lib/authz/auditReader'
import {
  AUDIT_EXPORT_FORMATS, AUDIT_EXPORT_MAX_ROWS, exportChunks, type AuditExportFormat, type ExportHead,
} from '@/lib/authz/auditExport'

export const runtime = 'nodejs'

const CONTENT_TYPE: Record<AuditExportFormat, string> = {
  csv: 'text/csv; charset=utf-8',
  json: 'application/json; charset=utf-8',
}

const invalid = (field: string, error: string) => NextResponse.json({ error, code: 'invalid_filter', field }, { status: 400 })

/** The filters the person set, as the audit row records them (strings, nothing empty). */
function recordedFilters(params: URLSearchParams): Record<string, string> {
  return Object.fromEntries(AUDIT_FILTER_KEYS.flatMap((k) => {
    const v = params.get(k)?.trim()
    return v ? [[k, v]] : []
  }))
}

function fileName(f: AuditFilters, format: AuditExportFormat, at: Date): string {
  const stamp = at.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z')
  return `redamon-audit-${f.table.replace('_', '-')}-${stamp}.${format}`
}

/**
 * The audit export (step 6.6; GV-07, AU-04). 404 with RBAC_GOVERNANCE_ENABLED off.
 *
 * GET `?table&<the viewer's filters>&format=csv|json` (audit:export; csv by default): every row the
 * filters select, newest first, at most AUDIT_EXPORT_MAX_ROWS (100 000), streamed a batch at a time
 * (lib/authz/auditExport.ts). `X-Audit-Export-Total` says how many matched and
 * `X-Audit-Export-Truncated` whether the file stops at the cap; a JSON file says both in its head.
 * `cursor` and `limit` are the viewer's paging and are refused here.
 *
 * The export is itself audited (`audit.exported`: the table, the format, the filters and the row
 * counts), before the first byte and fail-closed: a row that cannot be written refuses the export
 * (500), so no copy of the audit log leaves without its record. Personal data in the file: the
 * accounts' ids and emails and what the rows recorded, with credentials, tokens, hashes and step-up
 * fields withheld (master plan §9.8).
 */
export const GET = withRouteErrors('Could not export the audit log', async (request: NextRequest) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const refused = await requireSessionPermission(session, 'audit:export')
  if (refused) return refused

  const params = request.nextUrl.searchParams
  for (const field of ['cursor', 'limit']) {
    if (params.get(field)) return invalid(field, `${field} is not a filter of the export: it exports every row the filters select`)
  }
  const rawFormat = params.get('format')?.trim() || 'csv'
  if (!(AUDIT_EXPORT_FORMATS as readonly string[]).includes(rawFormat)) return invalid('format', 'format must be csv or json')
  const format = rawFormat as AuditExportFormat
  const asked = parseAuditQuery(params)
  if ('code' in asked) return NextResponse.json(asked, { status: 400 })

  // The file holds the rows written before the export started: neither its own audit row nor a row
  // written while it streams, so the counts in the headers and in the audit row are the file's.
  const at = now()
  const startedAt = new Date(at.getTime() - 1)
  const filters: AuditFilters = { ...asked, to: asked.to && asked.to < startedAt ? asked.to : startedAt }
  const total = await countAuditRows(filters)
  const head: ExportHead = {
    table: filters.table,
    exportedAt: at.toISOString(),
    total,
    rows: Math.min(total, AUDIT_EXPORT_MAX_ROWS),
    truncated: total > AUDIT_EXPORT_MAX_ROWS,
  }
  await writeAuditTx(prisma as unknown as AuditTx, {
    ...actorFields(await auditActor()),
    action: 'audit.exported',
    targetType: 'audit',
    targetId: filters.table,
    permission: 'audit:export',
    after: { table: filters.table, format, filters: recordedFilters(params), total, rows: head.rows, truncated: head.truncated },
    source: 'api',
  })

  const chunks = exportChunks(filters, format, head)
  const encoder = new TextEncoder()
  let sent = 0
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const next = await chunks.next()
        if (next.done) {
          controller.close()
          return
        }
        sent += 1
        controller.enqueue(encoder.encode(next.value))
      } catch (err) {
        console.error(`[rbac] audit export failed after ${sent} chunk(s) table=${filters.table} format=${format}:`, err)
        controller.error(err)
      }
    },
    async cancel() {
      await chunks.return(undefined)
    },
  })
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': CONTENT_TYPE[format],
      'Content-Disposition': `attachment; filename="${fileName(filters, format, at)}"`,
      'Cache-Control': 'no-store',
      'X-Audit-Export-Total': String(total),
      'X-Audit-Export-Rows': String(head.rows),
      'X-Audit-Export-Truncated': String(head.truncated),
    },
  })
})
