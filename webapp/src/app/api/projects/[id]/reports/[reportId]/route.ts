import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { existsSync, readFileSync, unlinkSync } from 'fs'
import { requirePermission } from '@/lib/authz/guards'
import { internalError } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string; reportId: string }>
}

/** GET /api/projects/{id}/reports/{reportId} - Download report HTML */
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, reportId } = await params

    const auth = await requirePermission(request, 'reports:read', { projectId: id })
    if (auth instanceof NextResponse) return auth

    const report = await prisma.report.findFirst({
      where: { id: reportId, projectId: id },
    })
    if (!report) {
      return NextResponse.json({ error: 'Report not found' }, { status: 404 })
    }

    if (!existsSync(report.filePath)) {
      return NextResponse.json({ error: 'Report file not found on disk' }, { status: 404 })
    }

    const fileBuffer = readFileSync(report.filePath)

    // Report HTML is template-generated but embeds target-influenced strings,
    // so serve it defensively: block MIME sniffing and neutralize any stored
    // XSS with a restrictive CSP (no scripts, no framing, no external loads).
    // Reports are static HTML + inline styles, so this does not affect
    // legitimate rendering.
    return new Response(fileBuffer, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `inline; filename="${report.filename}"`,
        'Content-Length': String(fileBuffer.length),
        'Cache-Control': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy':
          "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; font-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      },
    })
  } catch (error) {
    // An fs message names the report's path on the server; its errno (EACCES,
    // EISDIR) says the same thing without it.
    return internalError(error, 'Download failed', { log: 'Download report failed' })
  }
}

/** DELETE /api/projects/{id}/reports/{reportId} - Delete report (file + DB) */
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, reportId } = await params

    const auth = await requirePermission(request, 'reports:delete', { projectId: id })
    if (auth instanceof NextResponse) return auth

    const report = await prisma.report.findFirst({
      where: { id: reportId, projectId: id },
    })
    if (!report) {
      return NextResponse.json({ error: 'Report not found' }, { status: 404 })
    }

    // Delete file from disk
    if (existsSync(report.filePath)) {
      unlinkSync(report.filePath)
    }

    // Delete DB row
    await prisma.report.delete({ where: { id: reportId } })

    return new Response(null, { status: 204 })
  } catch (error) {
    return internalError(error, 'Delete failed', { log: 'Delete report failed' })
  }
}
