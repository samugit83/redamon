import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest, isScannerRequest } from '@/lib/session'
import { iocColumns } from '@/lib/scaIntel'
import type { Prisma } from '@prisma/client'

// POST /api/traffic/[projectId]/ingest
//
// Phase 0 write path for captured HTTP transactions. Called by the recon
// pipeline with `X-Internal-Key: SCANNER_API_KEY` (and, later, by the agent with
// INTERNAL_API_KEY). There is NO browser-session path here - this route is
// internal-only, gated in middleware to the internal/scanner allowlist.
//
// Trust model: tenant fields are NEVER taken from the request body. `projectId`
// comes from the route; `userId` is resolved to the project OWNER via a DB
// lookup. A compromised/rogue scanner therefore cannot forge cross-tenant rows,
// and the webapp remains the sole Prisma writer (per README.TM trust boundaries).

// Hard ceilings (defense-in-depth against DoS / Postgres bloat - §15.8).
const MAX_INLINE_BODY_BYTES = (parseInt(process.env.CAPTURE_PROXY_MAX_BODY_KB || '64', 10) || 64) * 1024
const MAX_TXNS_PER_REQUEST = 2000

const VALID_SOURCES = new Set(['recon', 'agent', 'operator'])

// Postgres text AND jsonb reject NUL (0x00) with error 22021: a single such byte
// in any captured (attacker-controlled) field makes the whole createMany batch fail
// and drops every httpx transaction in it. Strip NUL everywhere a captured string
// reaches the DB. (The proxy-path Python ingest worker strips it too.)
function stripNul(s: string): string {
  return s.indexOf('\u0000') === -1 ? s : s.replace(/\u0000/g, '')
}

function asString(v: unknown): string | null {
  if (v === null || v === undefined) return null
  return stripNul(typeof v === 'string' ? v : String(v))
}

// Recursively strip NUL from string keys/values so header JSON (respHeaders /
// reqHeaders) can't 22021 the jsonb insert either.
function stripNulDeep(v: unknown): unknown {
  if (typeof v === 'string') return stripNul(v)
  if (Array.isArray(v)) return v.map(stripNulDeep)
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[stripNul(k)] = stripNulDeep(val)
    return out
  }
  return v
}

function asInt(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null
  const n = typeof v === 'number' ? v : parseInt(String(v).replace(/[^\d-]/g, ''), 10)
  return Number.isFinite(n) ? n : null
}

// Postgres Int (int4) ceiling. A target-controlled Content-Length can exceed
// this; clamping keeps one poisoned row from failing the entire createMany batch.
const INT4_MAX = 2147483647
function clampInt4(v: number | null): number | null {
  if (v === null) return null
  if (v < 0) return 0
  return v > INT4_MAX ? INT4_MAX : v
}

function asJson(v: unknown): Prisma.InputJsonValue {
  if (v && typeof v === 'object') return stripNulDeep(v) as Prisma.InputJsonValue
  return {}
}

function asDate(v: unknown): Date {
  if (typeof v === 'string' || typeof v === 'number') {
    const d = new Date(v)
    if (!Number.isNaN(d.getTime())) return d
  }
  return new Date()
}

// Truncate an inline body to the ceiling; the full size/sha are recorded
// separately so the truncation is visible and later phases can disk-offload.
function capBody(body: unknown): { inline: string | null; truncated: boolean } {
  const s = asString(body)
  if (s === null) return { inline: null, truncated: false }
  if (Buffer.byteLength(s, 'utf8') <= MAX_INLINE_BODY_BYTES) return { inline: s, truncated: false }
  return { inline: Buffer.from(s, 'utf8').subarray(0, MAX_INLINE_BODY_BYTES).toString('utf8'), truncated: true }
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  try {
    const { projectId } = await params

    // Internal-only: recon (scanner key) or agent (internal key). No session path.
    if (!isScannerRequest(request) && !isInternalRequest(request)) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    // Resolve tenant from the trusted server side, never from the body.
    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { userId: true, captureProxyEnabled: true },
    })
    if (!project) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }
    // Defense in depth: silently no-op if capture is disabled for this project.
    if (!project.captureProxyEnabled) {
      return NextResponse.json({ stored: 0, reason: 'capture disabled' }, { status: 202 })
    }

    const body = await request.json().catch(() => null)
    if (!body || typeof body !== 'object') {
      return NextResponse.json({ error: 'Invalid body' }, { status: 400 })
    }

    const source = asString(body.source) || 'recon'
    if (!VALID_SOURCES.has(source)) {
      return NextResponse.json({ error: 'Invalid source' }, { status: 400 })
    }
    const runId = asString(body.runId)
    const sessionId = asString(body.sessionId)

    const txns: unknown[] = Array.isArray(body.transactions) ? body.transactions : []
    if (txns.length === 0) {
      return NextResponse.json({ stored: 0 }, { status: 200 })
    }
    if (txns.length > MAX_TXNS_PER_REQUEST) {
      return NextResponse.json(
        { error: `Too many transactions (max ${MAX_TXNS_PER_REQUEST})` },
        { status: 413 },
      )
    }

    const data: Prisma.CapturedHttpTransactionCreateManyInput[] = []
    for (const raw of txns) {
      if (!raw || typeof raw !== 'object') continue
      const t = raw as Record<string, unknown>

      const scheme = (asString(t.scheme) || 'http').toLowerCase()
      const host = asString(t.host)
      if (!host) continue // host is required; skip malformed rows
      const port = asInt(t.port) ?? (scheme === 'https' ? 443 : 80)

      const reqBody = capBody(t.reqBody)
      const respBody = capBody(t.respBody)

      // A1: the SECOND writer of this table. The Python spool worker sets the
      // same two columns for the same input; if only one path did, an operator
      // would see some requests flagged and conclude the rest were checked and
      // cleared. Local set lookup, no network, never throws.
      const ioc = iocColumns(host, asString(t.targetIp))

      data.push({
        projectId,
        userId: project.userId,
        source,
        runId: asString(t.runId) ?? runId,
        sessionId: asString(t.sessionId) ?? sessionId,
        memberId: asString(t.memberId),
        tool: asString(t.tool),
        phase: asString(t.phase),
        stepId: asString(t.stepId),

        method: (asString(t.method) || 'GET').toUpperCase(),
        scheme,
        host,
        port,
        path: asString(t.path) || '/',
        query: asString(t.query),
        reqHeaders: asJson(t.reqHeaders),
        reqBody: reqBody.inline,
        reqBodySize: clampInt4(asInt(t.reqBodySize) ?? (reqBody.inline ? Buffer.byteLength(reqBody.inline, 'utf8') : 0)) ?? 0,
        reqContentType: asString(t.reqContentType),
        reqBodySha: asString(t.reqBodySha),

        statusCode: clampInt4(asInt(t.statusCode)),
        respHeaders: asJson(t.respHeaders),
        respBody: respBody.inline,
        respBodySize: clampInt4(asInt(t.respBodySize) ?? (respBody.inline ? Buffer.byteLength(respBody.inline, 'utf8') : 0)) ?? 0,
        respContentType: asString(t.respContentType),
        respBodySha: asString(t.respBodySha),
        responseTimeMs: clampInt4(asInt(t.responseTimeMs)),

        targetIp: asString(t.targetIp),
        httpVersion: asString(t.httpVersion),
        isTls: scheme === 'https' || t.isTls === true,
        tlsVersion: asString(t.tlsVersion),

        inScope: t.inScope === false ? false : true,
        blocked: t.blocked === true,

        hasSetCookie: t.hasSetCookie === true,
        hadAuth: t.hadAuth === true,
        reflectedParams: t.reflectedParams === true,
        securityHeadersMissing: Array.isArray(t.securityHeadersMissing)
          ? (t.securityHeadersMissing as Prisma.InputJsonValue)
          : undefined,
        cookieFlagIssues: Array.isArray(t.cookieFlagIssues)
          ? (t.cookieFlagIssues as Prisma.InputJsonValue)
          : undefined,

        startedAt: asDate(t.startedAt),

        iocIncidentId: ioc.iocIncidentId,
        iocIncidentUrl: ioc.iocIncidentUrl,
      })
    }

    if (data.length === 0) {
      return NextResponse.json({ stored: 0 }, { status: 200 })
    }

    const created = await prisma.capturedHttpTransaction.createMany({ data })
    return NextResponse.json({ stored: created.count }, { status: 201 })
  } catch (error) {
    console.error('Failed to ingest captured traffic:', error)
    return NextResponse.json({ error: 'Failed to ingest traffic' }, { status: 500 })
  }
}
