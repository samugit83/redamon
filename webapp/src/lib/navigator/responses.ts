import { NextResponse } from 'next/server'
import { NAVIGATOR_ERRORS, type NavigatorErrorCode } from './constants'

export const NO_STORE = { 'Cache-Control': 'no-store' } as const

/** A Navigator route's refusal: `{error, code}` with the fixed sentence of the code, never a cause's text. */
export function navigatorError(code: NavigatorErrorCode, status: number, extra: Record<string, unknown> = {}): NextResponse {
  return NextResponse.json({ error: NAVIGATOR_ERRORS[code], code, ...extra }, { status, headers: NO_STORE })
}

export function navigatorJson(body: unknown, init: { status?: number } = {}): NextResponse {
  return NextResponse.json(body, { status: init.status ?? 200, headers: NO_STORE })
}

/** Project and thread ids are checked against the cuid shape before anything is read. */
const ID_RE = /^[A-Za-z0-9_-]{8,64}$/
export function isNavigatorId(value: unknown): value is string {
  return typeof value === 'string' && ID_RE.test(value)
}
