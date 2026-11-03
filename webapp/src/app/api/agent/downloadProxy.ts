/**
 * Streaming download proxies for the agent's workspace files and archives.
 *
 * The body is passed through as a stream, never buffered: an imported file can
 * be gigabytes. Mirrored websites put attacker HTML and SVG in the workspace,
 * and these routes are served from the app's origin, so the proxy always sets
 * its own `attachment` Content-Disposition (never the agent's) and `nosniff`.
 *
 * Server-side only.
 */
import { NextResponse, type NextRequest } from 'next/server'
import { callAgent, type AgentCall } from './agentProxy'

/** A basename that is safe in a Content-Disposition header. */
export function safeDownloadName(raw: string | null | undefined, fallback = 'download'): string {
  const base = String(raw ?? '').split(/[\\/]/).pop() ?? ''
  const cleaned = base
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f"\\]/g, '')
    .replace(/^[.\s]+|[.\s]+$/g, '')
    .slice(0, 200)
  return cleaned || fallback
}

export function attachmentDisposition(name: string): string {
  const ascii = name.replace(/[^\x20-\x7e]/g, '_').replace(/[%;]/g, '_')
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`
}

/**
 * Call the agent for a download. `headerTimeoutMs` bounds only the wait for
 * the response headers (an archive is built before its first byte); once they
 * arrive the body streams for as long as the browser keeps the request open.
 */
export async function callAgentForDownload(
  request: NextRequest,
  path: string,
  init: RequestInit,
  message: string,
  headerTimeoutMs: number,
): Promise<AgentCall> {
  const headerTimer = new AbortController()
  const timer = setTimeout(
    () => headerTimer.abort(new DOMException('The agent did not answer in time', 'TimeoutError')),
    headerTimeoutMs,
  )
  try {
    return await callAgent(path, { ...init, signal: AbortSignal.any([request.signal, headerTimer.signal]) }, message)
  } finally {
    clearTimeout(timer)
  }
}

export function streamDownload(upstream: Response, filename: string): NextResponse {
  const headers = new Headers({
    'Content-Type': upstream.headers.get('Content-Type') || 'application/octet-stream',
    'Content-Disposition': attachmentDisposition(filename),
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-cache',
  })
  const length = upstream.headers.get('Content-Length')
  if (length && /^\d+$/.test(length)) headers.set('Content-Length', length)
  return new NextResponse(upstream.body, { status: 200, headers })
}
