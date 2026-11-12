/**
 * Invite and reset links (step 2.9, ID-14, ID-15, DV-11; feature document §7.1).
 *
 * A link carries 32 random bytes (base64url) that are shown once, to the admin who made it,
 * and stored only as their SHA-256: a database read gives no working link. One open link per
 * account and kind: making a new one cancels the earlier one. A link works once, until it
 * expires (`inviteTtlHours` / `resetTtlHours` of the instance settings), while nobody cancelled
 * it, and while its account is still what the link was made for (an invite: `invited`; a reset:
 * `active`).
 *
 * The link is built from the instance's public address, never from a request's Host header
 * (which a client chooses): `publicBaseUrl`, else the deploy's public origin (E12: the
 * single-host deploy seeds PLUGINS_ALLOWED_ORIGIN and MCP_ALLOWED_ORIGIN with it), else
 * localhost, with a warning that nobody else can open it.
 *
 * Opening `/invite/<token>` trades the token for a 30-minute signed cookie naming the link, so
 * the token leaves the address bar and the history; the accept reads the link from the cookie.
 * The token is never logged and never written to an audit row, nor is its hash.
 */
import { createHash, randomBytes } from 'node:crypto'
import { SignJWT, jwtVerify } from 'jose'
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { now } from './clock'
import { INSTANCE_SETTINGS_ROW } from './root'

export type LinkKind = 'invite' | 'reset'

export const INVITE_COOKIE_NAME = 'redamon-invite'
/** Only the invite API reads the cookie, so only it receives it. */
export const INVITE_COOKIE_PATH = '/api/invite'
export const INVITE_COOKIE_MAX_AGE = 30 * 60

/** The one answer for an unknown, expired, used or cancelled link: it names no reason. */
export const INVALID_LINK = { error: 'This link is not valid or has expired', code: 'invite_invalid' } as const

/** The schema defaults (PLACEHOLDER(OQ-38)), used while the instance settings row is missing. */
const DEFAULT_TTL_HOURS: Record<LinkKind, number> = { invite: 168, reset: 4 }
/** The status an account must still have for its link to work. */
const ACCOUNT_STATUS_FOR: Record<LinkKind, string> = { invite: 'invited', reset: 'active' }

const COOKIE_AUDIENCE = 'redamon-invite'

type Tx = Pick<Prisma.TransactionClient, 'instanceSettings' | 'userInvite'>

export function newLinkToken(): string {
  return randomBytes(32).toString('base64url')
}

export function hashLinkToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

export interface LinkBase {
  /** Scheme, host, port and any path, without a trailing slash. */
  base: string
  /** Nobody but this computer can open a link to it. */
  localhostWarning: boolean
  source: 'instance' | 'deploy' | 'default'
}

function httpBase(raw: string | null | undefined): string | null {
  const text = (raw ?? '').trim()
  if (!text) return null
  try {
    const url = new URL(text)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
    return url.origin + url.pathname.replace(/\/+$/, '')
  } catch {
    return null
  }
}

function isLocalHost(base: string): boolean {
  const host = new URL(base).hostname.replace(/^\[|\]$/g, '')
  return host === 'localhost' || host.endsWith('.localhost') || host === '::1' || host === '0.0.0.0'
    || /^127\.\d+\.\d+\.\d+$/.test(host)
}

/** Where links point: the stored `publicBaseUrl`, else the deploy's public origin, else localhost. */
export function resolveLinkBase(stored: string | null | undefined): LinkBase {
  const instance = httpBase(stored)
  if (instance) return { base: instance, localhostWarning: isLocalHost(instance), source: 'instance' }
  const deploy = httpBase(process.env.PLUGINS_ALLOWED_ORIGIN) ?? httpBase(process.env.MCP_ALLOWED_ORIGIN)
  if (deploy) return { base: deploy, localhostWarning: isLocalHost(deploy), source: 'deploy' }
  return { base: `http://localhost:${process.env.WEBAPP_PORT || '3000'}`, localhostWarning: true, source: 'default' }
}

export interface CreatedLink {
  linkId: string
  /** The only place the token appears: shown once to the admin who made it. */
  link: string
  expiresAt: Date
  localhostWarning: boolean
  /** Earlier open links of the same account and kind this one cancelled. */
  cancelledLinks: number
}

/**
 * Makes a link inside the caller's transaction, so the account change, the link and the audit
 * row commit together. Cancels the account's earlier open link of the same kind.
 */
export async function createLink(
  tx: Tx,
  { userId, kind, createdById, reason }: { userId: string; kind: LinkKind; createdById: string; reason?: string | null },
): Promise<CreatedLink> {
  const settings = await tx.instanceSettings.findUnique({
    where: { id: INSTANCE_SETTINGS_ROW },
    select: { inviteTtlHours: true, resetTtlHours: true, publicBaseUrl: true },
  })
  const stored = kind === 'invite' ? settings?.inviteTtlHours : settings?.resetTtlHours
  const ttlHours = typeof stored === 'number' && Number.isInteger(stored) && stored > 0 ? stored : DEFAULT_TTL_HOURS[kind]
  const at = now()
  const { count: cancelledLinks } = await tx.userInvite.updateMany({
    where: { userId, kind, usedAt: null, cancelledAt: null },
    data: { cancelledAt: at },
  })
  const token = newLinkToken()
  const expiresAt = new Date(at.getTime() + ttlHours * 3600_000)
  const row = await tx.userInvite.create({
    data: { userId, kind, tokenHash: hashLinkToken(token), expiresAt, createdById, reason: reason ?? null },
    select: { id: true },
  })
  const base = resolveLinkBase(settings?.publicBaseUrl)
  return { linkId: row.id, link: `${base.base}/invite/${token}`, expiresAt, localhostWarning: base.localhostWarning, cancelledLinks }
}

const LINK_SELECT = {
  id: true,
  kind: true,
  userId: true,
  tokenHash: true,
  expiresAt: true,
  usedAt: true,
  cancelledAt: true,
  user: { select: { id: true, name: true, email: true, role: true, status: true, sessionVersion: true } },
} as const

export interface OpenLink {
  id: string
  kind: LinkKind
  userId: string
  tokenHash: string
  expiresAt: Date
  user: { id: string; name: string; email: string; role: string; status: string; sessionVersion: number }
}

type LinkRow = {
  id: string
  kind: string
  userId: string
  tokenHash: string
  expiresAt: Date
  usedAt: Date | null
  cancelledAt: Date | null
  user: OpenLink['user'] | null
}

function usable(row: LinkRow | null): OpenLink | null {
  if (!row || row.usedAt || row.cancelledAt || !row.user) return null
  if (row.kind !== 'invite' && row.kind !== 'reset') return null
  if (row.expiresAt.getTime() <= now().getTime()) return null
  if (row.user.status !== ACCOUNT_STATUS_FOR[row.kind]) return null
  return { id: row.id, kind: row.kind, userId: row.userId, tokenHash: row.tokenHash, expiresAt: row.expiresAt, user: row.user }
}

/**
 * The open link a token names, or null. The same work whatever the token: one hash and one
 * indexed read, so the answer's timing does not tell an unknown token from a stale one.
 */
export async function findLinkByToken(token: string): Promise<OpenLink | null> {
  const row = await prisma.userInvite.findUnique({ where: { tokenHash: hashLinkToken(token) }, select: LINK_SELECT })
  return usable(row as LinkRow | null)
}

export async function findLinkById(id: string): Promise<OpenLink | null> {
  const row = await prisma.userInvite.findUnique({ where: { id }, select: LINK_SELECT })
  return usable(row as LinkRow | null)
}

function cookieSecret(): Uint8Array {
  const secret = process.env.AUTH_SECRET
  if (!secret || secret === 'changeme') throw new Error('AUTH_SECRET environment variable is not set')
  return new TextEncoder().encode(secret)
}

/**
 * The cookie value naming a link for 30 minutes. Its claims (`lnk`, audience
 * `redamon-invite`, no `sub`, no `role`) make it useless as a login or act-as token.
 */
export async function signInviteCookie(linkId: string): Promise<string> {
  const issued = Math.floor(now().getTime() / 1000)
  return new SignJWT({ lnk: linkId })
    .setProtectedHeader({ alg: 'HS256' })
    .setAudience(COOKIE_AUDIENCE)
    .setIssuedAt(issued)
    .setExpirationTime(issued + INVITE_COOKIE_MAX_AGE)
    .sign(cookieSecret())
}

/** The link id an invite cookie names, or null for a missing, expired, tampered or foreign one. */
export async function readInviteCookie(value: string | null | undefined): Promise<string | null> {
  if (!value) return null
  try {
    const { payload } = await jwtVerify(value, cookieSecret(), { audience: COOKIE_AUDIENCE, currentDate: now() })
    return typeof payload.lnk === 'string' && payload.lnk ? payload.lnk : null
  } catch {
    return null
  }
}
