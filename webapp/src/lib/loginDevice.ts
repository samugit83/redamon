// D6: a browser that has signed in to an e-mail before keeps signing in to it while someone
// else holds that e-mail's lockout.
//
// The sign-in lockout (loginThrottle.ts) is keyed per e-mail, so a password guessed from any
// address counts against the account. The same key let anyone keep any account out, Root
// included, by sending a few wrong passwords for it every quarter hour. A successful sign-in
// now leaves an HMAC-signed entry in an httpOnly cookie, bound to the e-mail it signed in with.
// A request carrying a valid entry for the e-mail it names is throttled on that entry alone
// (the "device cookie" pattern from OWASP's brute-force guidance), so a stranger's failures do
// not reach it. An entry proves only that this browser signed in to that e-mail before: the
// password is still checked, and the entry has a lockout of its own.

import { createHmac, randomBytes } from 'node:crypto'
import type { NextRequest, NextResponse } from 'next/server'
import { constantTimeEqual } from './constantTimeEqual'
import { isSecureRequest } from './cookieSecurity'

export const LOGIN_DEVICE_COOKIE = 'redamon-login-device'
// The entries matter only to the sign-in route, so the browser sends them nowhere else.
export const LOGIN_DEVICE_COOKIE_PATH = '/api/auth/login'
export const LOGIN_DEVICE_MAX_AGE = 180 * 24 * 60 * 60
// A browser shared by several accounts keeps an entry for each of the most recent ones.
export const LOGIN_DEVICE_MAX_ENTRIES = 5

const VERSION = 'd1'
const ENTRY = /^d1\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{22})\.(\d{1,12})\.([A-Za-z0-9_-]{43})$/
const MAX_COOKIE_CHARS = 4096

interface Entry {
  deviceId: string
  emailTag: string
  exp: number
}

// Derived from AUTH_SECRET under its own label, so an entry can never pass for a login token
// or the reverse. Unset or left at the compose default, as lib/auth.ts refuses it: no entries.
function deviceKey(): Buffer | null {
  const secret = process.env.AUTH_SECRET
  if (!secret || secret === 'changeme') return null
  return createHmac('sha256', secret).update('redamon-login-device-v1').digest()
}

// The e-mail as the lockout keys it (lowercased), kept out of the cookie in clear.
function emailTag(key: Buffer, email: string): string {
  return createHmac('sha256', key).update(`email\0${email.toLowerCase()}`).digest().subarray(0, 16).toString('base64url')
}

function sign(key: Buffer, deviceId: string, tag: string, exp: number): string {
  return createHmac('sha256', key).update(`${VERSION}.${deviceId}.${tag}.${exp}`).digest('base64url')
}

function serialize(key: Buffer, e: Entry): string {
  return `${VERSION}.${e.deviceId}.${e.emailTag}.${e.exp}.${sign(key, e.deviceId, e.emailTag, e.exp)}`
}

function liveEntries(raw: string | undefined, key: Buffer, nowSeconds: number): Entry[] {
  if (!raw || raw.length > MAX_COOKIE_CHARS) return []
  const out: Entry[] = []
  for (const part of raw.split('~').slice(0, LOGIN_DEVICE_MAX_ENTRIES)) {
    const m = ENTRY.exec(part)
    if (!m) continue
    const [, deviceId, tag, expText, sig] = m
    const exp = Number(expText)
    if (!Number.isSafeInteger(exp) || exp <= nowSeconds) continue
    if (!constantTimeEqual(sig, sign(key, deviceId, tag, exp))) continue
    out.push({ deviceId, emailTag: tag, exp })
  }
  return out
}

/**
 * The id of this browser's known-device entry for `email`, or null when it has none (never
 * signed in to it here, an entry expired or forged, or no AUTH_SECRET).
 */
export function knownLoginDevice(request: NextRequest, email: string, now = Date.now()): string | null {
  const key = deviceKey()
  if (!key) return null
  const tag = emailTag(key, email)
  const raw = request.cookies.get(LOGIN_DEVICE_COOKIE)?.value
  return liveEntries(raw, key, Math.floor(now / 1000)).find((e) => e.emailTag === tag)?.deviceId ?? null
}

/**
 * After a successful sign-in: put `email`'s entry first (its id kept, its expiry renewed), keep
 * the browser's other live entries behind it, and drop the oldest beyond the cap.
 */
export function rememberLoginDevice(response: NextResponse, request: NextRequest, email: string, now = Date.now()): void {
  const key = deviceKey()
  if (!key) return
  const nowSeconds = Math.floor(now / 1000)
  const tag = emailTag(key, email)
  const entries = liveEntries(request.cookies.get(LOGIN_DEVICE_COOKIE)?.value, key, nowSeconds)
  const deviceId = entries.find((e) => e.emailTag === tag)?.deviceId ?? randomBytes(16).toString('base64url')
  const kept = [
    { deviceId, emailTag: tag, exp: nowSeconds + LOGIN_DEVICE_MAX_AGE },
    ...entries.filter((e) => e.emailTag !== tag),
  ].slice(0, LOGIN_DEVICE_MAX_ENTRIES)
  response.cookies.set(LOGIN_DEVICE_COOKIE, kept.map((e) => serialize(key, e)).join('~'), {
    httpOnly: true,
    sameSite: 'strict',
    secure: isSecureRequest(request),
    path: LOGIN_DEVICE_COOKIE_PATH,
    maxAge: LOGIN_DEVICE_MAX_AGE,
  })
}
