/**
 * Error answers for API routes: a short fixed sentence saying WHAT failed, plus a
 * code saying WHY in a form that is safe to show.
 *
 * Never put an exception's own message in a response: a Prisma message can quote
 * the query's values, a Neo4j one the Cypher with target data, and an agent or
 * provider error a key. The code carries the cause instead (P2024, Neo.TransientError
 * .General.DatabaseUnavailable, ECONNREFUSED, PrismaClientValidationError), so a
 * screenshot of the error is enough to tell a DB timeout from a pool exhaustion.
 *
 * Server-side only. The browser reads these bodies with `lib/apiError.ts`.
 */
import { NextResponse } from 'next/server'

const PRISMA_CODE = /^P\d{4}$/
// Server codes (Neo.TransientError.General.DatabaseUnavailable) and the driver's own.
const NEO4J_CODE = /^(Neo\.[A-Za-z]+\.[A-Za-z]+\.[A-Za-z]+|ServiceUnavailable|SessionExpired|ProtocolError)$/
// Node errno (ECONNREFUSED, ENOSPC), undici's codes (UND_ERR_HEADERS_TIMEOUT) and
// OpenSSL's certificate codes (DEPTH_ZERO_SELF_SIGNED_CERT, CERT_HAS_EXPIRED).
const NODE_CODE = /^(E[A-Z0-9_]{2,40}|UND_ERR_[A-Z_]{2,40}|[A-Z]+(?:_[A-Z0-9]+){2,8})$/
const CLASS_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/

function codeOf(value: unknown): string | undefined {
  if (!value || typeof value !== 'object') return undefined
  const code = (value as { code?: unknown }).code
  if (typeof code !== 'string') return undefined
  return PRISMA_CODE.test(code) || NEO4J_CODE.test(code) || NODE_CODE.test(code) ? code : undefined
}

/**
 * The safe code of an error: a Prisma, Neo4j or Node code when it has one (undici
 * nests the errno in `.cause`), else its class name, else `internal_error`.
 */
export function safeErrorCode(err: unknown): string {
  const own = codeOf(err)
  if (own) return own
  const cause = err && typeof err === 'object' ? (err as { cause?: unknown }).cause : undefined
  const nested = codeOf(cause)
  if (nested) return nested
  const name = err && typeof err === 'object' ? (err as { name?: unknown }).name : undefined
  if (typeof name === 'string' && name !== 'Error' && CLASS_NAME.test(name)) return name
  return 'internal_error'
}

export interface InternalErrorOptions {
  status?: number
  /** The log line's prefix; defaults to the message. */
  log?: string
  /** Extra safe fields for the body, such as `committed: true`. */
  extra?: Record<string, unknown>
}

/**
 * Prisma's validation error renders the whole call, the values written included: a provider key, a
 * token or a password being saved. Only its class reaches the log.
 */
function loggable(err: unknown): unknown {
  const name = err && typeof err === 'object' ? (err as { name?: unknown }).name : undefined
  return name === 'PrismaClientValidationError' ? `${name} (its rendering of the call is not logged: it holds the values written)` : err
}

/** A 500 (or `status`) whose body is `{error: message, code}`; the full error goes to the log. */
export function internalError(err: unknown, message: string, opts: InternalErrorOptions = {}): NextResponse {
  const code = safeErrorCode(err)
  console.error(`${opts.log ?? message}:`, loggable(err))
  return NextResponse.json({ error: message, code, ...opts.extra }, { status: opts.status ?? 500 })
}

/**
 * Wrap a route handler so an uncaught throw answers `{error: message, code}`
 * instead of Next's empty-bodied 500, which no client can read.
 */
export function withRouteErrors<A extends unknown[]>(
  message: string,
  handler: (...args: A) => Promise<Response>,
): (...args: A) => Promise<Response> {
  return async (...args: A) => {
    try {
      return await handler(...args)
    } catch (err) {
      return internalError(err, message)
    }
  }
}

function isTimeout(err: unknown): boolean {
  const name = err && typeof err === 'object' ? (err as { name?: unknown }).name : undefined
  const code = safeErrorCode(err)
  return name === 'TimeoutError' || code === 'ETIMEDOUT' || (code.startsWith('UND_ERR_') && code.includes('TIMEOUT'))
}

export interface UpstreamFailure {
  status: 503 | 504
  body: { error: string; code: string; cause?: string }
}

/**
 * A service that never answered: 503 `<service>_unreachable` (refused, DNS, reset),
 * or 504 `<service>_timeout`, after which the outcome of a write is unknown.
 * `cause` is the errno when there is one.
 */
export function upstreamFailure(service: string, err: unknown, message: string): UpstreamFailure {
  const timeout = isTimeout(err)
  const code = safeErrorCode(err)
  const cause = NODE_CODE.test(code) ? code : undefined
  return {
    status: timeout ? 504 : 503,
    body: { error: message, code: `${service}_${timeout ? 'timeout' : 'unreachable'}`, ...(cause ? { cause } : {}) },
  }
}

export function upstreamFailureResponse(service: string, err: unknown, message: string): NextResponse {
  const failure = upstreamFailure(service, err, message)
  console.error(`${message}:`, err)
  return NextResponse.json(failure.body, { status: failure.status })
}

const SAFE_UPSTREAM_CODE = /^[a-z][a-z0-9_]{0,63}$/
const TEXT_MAX = 500

export interface UpstreamBody {
  /** The parsed JSON object, or null for an empty or non-JSON body. */
  json: Record<string, unknown> | null
  /** `error`, else a string `detail`, else an object detail's `detail` string. */
  text?: string
  /** A lowercase snake_case code the service sent (`code`, or `detail.code`). */
  code?: string
}

/** Read a service's error body without trusting its shape (FastAPI `detail` can be a string, an object or an array). */
export async function readUpstreamBody(res: Response): Promise<UpstreamBody> {
  const raw = await res.text().catch(() => '')
  let json: Record<string, unknown> | null = null
  try {
    const parsed = raw ? JSON.parse(raw) : null
    json = parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null
  } catch {
    json = null
  }
  if (!json) return { json: null }
  const detail = json.detail
  const nested = detail && typeof detail === 'object' && !Array.isArray(detail) ? detail as Record<string, unknown> : null
  const pick = [json.error, detail, nested?.detail].find((v): v is string => typeof v === 'string' && v.trim() !== '')
  const code = [json.code, nested?.code].find((v): v is string => typeof v === 'string' && SAFE_UPSTREAM_CODE.test(v))
  return {
    json,
    ...(pick ? { text: pick.replace(/\s+/g, ' ').trim().slice(0, TEXT_MAX) } : {}),
    ...(code ? { code } : {}),
  }
}

export interface UpstreamErrorOptions {
  /**
   * Show the service's own `error`/`detail` sentence instead of `message`. Only for
   * services whose error text is written by our code (the orchestrator's refusals),
   * never for one that can echo an exception or a provider error.
   */
  forwardText?: boolean
  /** The status to answer; default: the service's 4xx as is, a 5xx as 502. */
  status?: number
}

/**
 * A service that answered with an error: `{error, code, upstreamStatus}`. `code` is
 * the service's own when it sent one, else `<service>_error`.
 */
export async function upstreamErrorResponse(
  service: string,
  res: Response,
  message: string,
  opts: UpstreamErrorOptions = {},
): Promise<NextResponse> {
  const body = await readUpstreamBody(res)
  const status = opts.status ?? (res.status >= 500 ? 502 : res.status)
  return NextResponse.json({
    error: (opts.forwardText && body.text) || message,
    code: body.code ?? `${service}_error`,
    upstreamStatus: res.status,
  }, { status })
}
