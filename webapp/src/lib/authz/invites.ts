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
import { NextResponse, type NextRequest } from 'next/server'
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { userAuditEntry } from '@/lib/userAudit'
import { isSecureRequest } from '@/lib/cookieSecurity'
import { safeErrorCode } from '@/lib/routeErrors'
import type { Session } from '@/lib/session'
import { emailTakenByAnother, normalizeEmail } from './accountEmail'
import { markShown, noticeView, pendingNotices, type NoticeView } from './accountNotices'
import { now } from './clock'
import { invalidatePrincipal } from './principal'
import { INSTANCE_SETTINGS_ROW } from './root'
import { checkInitialSets, InitialSetGone, initialSetGoneResponse, writeInitialSets } from './initialSets'

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

// --- The admin side (switch on): invite a member, resend its link, cancel the invite ---------

const NO_STORE_HEADERS = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' } as const

/** An answer that carries a link (or reads one): never cached, never sent on as a referrer. */
export function privateJson(body: unknown, status = 200): NextResponse {
  return NextResponse.json(body, { status, headers: NO_STORE_HEADERS })
}

/** `requireAdmin`'s 403, coded with the permission inviting needs (master §9.8); any other answer as is. */
export function forbiddenToInvite(res: NextResponse): NextResponse {
  if (res.status !== 403) return res
  return NextResponse.json(
    { error: 'Only an administrator can invite people or manage their invites.', code: 'forbidden', permission: 'users:create' },
    { status: 403 },
  )
}

export const ROOT_ONLY_INVITE = "Only Root can manage an admin account's invite."

const EMAIL_TAKEN = { error: 'A user with this email already exists', code: 'email_taken' } as const
const USER_NOT_FOUND = () => NextResponse.json({ error: 'User not found', code: 'user_not_found' }, { status: 404 })
const NOT_INVITED = () => NextResponse.json(
  { error: 'This account is not waiting for an invite: it was never invited, or it has already signed in.', code: 'not_invited' },
  { status: 409 },
)
const HAS_PROJECTS = () => NextResponse.json(
  { error: 'This invited account owns projects: delete the account instead, which also removes its projects.', code: 'has_projects' },
  { status: 409 },
)
const ACCOUNT_CHANGED = () => NextResponse.json(
  { error: 'The account changed while this request ran. Reload the list and try again.', code: 'account_changed' },
  { status: 409 },
)

const MAX_NAME = 200
const MAX_EMAIL = 320
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+$/

function invalidField(field: 'name' | 'email', error: string): NextResponse {
  return NextResponse.json({ error, code: 'invalid_field', field }, { status: 400 })
}

function isUniqueViolation(err: unknown): boolean {
  return Boolean(err && typeof err === 'object' && 'code' in err && (err as { code?: unknown }).code === 'P2002')
}

/**
 * POST /api/users/invite: a MEMBER account (whatever the body says: §7.1 "invited as member
 * only"), `invited`, with no password, and its link, answered once. With the permissions switch
 * on, `sets` names the member sets it starts with (step 3.13, ID-28; initialSets.ts: the
 * assignment rules, `stepUpPassword` when a set needs it); none, the instance default set. The
 * account, its sets, the link and `user.invite` commit together.
 */
export async function inviteMember(request: NextRequest, session: Session, body: Record<string, unknown>): Promise<NextResponse> {
  const name = typeof body.name === 'string' ? body.name.trim() : ''
  if (!name || name.length > MAX_NAME) return invalidField('name', `A name is required (at most ${MAX_NAME} characters).`)
  const typed = typeof body.email === 'string' ? body.email.trim() : ''
  if (!typed || typed.length > MAX_EMAIL || !EMAIL_SHAPE.test(typed)) return invalidField('email', 'A valid email address is required.')
  const initial = await checkInitialSets(request, session, body)
  if (initial instanceof NextResponse) return initial
  // Stored lowercase; an older account may hold the same address in other capitals.
  const email = normalizeEmail(typed)
  if (await emailTakenByAnother(email)) return NextResponse.json(EMAIL_TAKEN, { status: 409 })
  try {
    const { user, made } = await prisma.$transaction(async (tx) => {
      const user = await tx.user.create({
        data: { name, email, role: 'standard', status: 'invited', password: '' },
        select: { id: true, name: true, email: true, role: true, status: true },
      })
      if (initial) await writeInitialSets(tx, user.id, initial)
      const made = await createLink(tx, { userId: user.id, kind: 'invite', createdById: session.userId })
      await writeAuditTx(tx, await userAuditEntry(request, session, {
        action: 'user.invite',
        targetId: user.id,
        after: {
          email, role: 'standard', status: 'invited', expiresAt: made.expiresAt.toISOString(),
          ...(initial ? { sets: initial.sets } : {}),
        },
      }))
      return { user, made }
    })
    return privateJson({
      ...user, link: made.link, expiresAt: made.expiresAt.toISOString(), localhostWarning: made.localhostWarning,
    }, 201)
  } catch (err) {
    if (isUniqueViolation(err)) return NextResponse.json(EMAIL_TAKEN, { status: 409 })
    if (err instanceof InitialSetGone) return initialSetGoneResponse()
    throw err
  }
}

/** POST /api/users/[id]/invite/resend: a new link for an invited account; the open one is cancelled. */
export async function resendInvite(request: NextRequest, session: Session, userId: string): Promise<NextResponse> {
  return prisma.$transaction(async (tx) => {
    const user = await tx.user.findUnique({ where: { id: userId }, select: { status: true } })
    if (!user) return USER_NOT_FOUND()
    if (user.status !== 'invited') return NOT_INVITED()
    const made = await createLink(tx, { userId, kind: 'invite', createdById: session.userId })
    const expiresAt = made.expiresAt.toISOString()
    await writeAuditTx(tx, await userAuditEntry(request, session, {
      action: 'user.invite_resent', targetId: userId, after: { expiresAt, cancelledLinks: made.cancelledLinks },
    }))
    return privateJson({ id: userId, link: made.link, expiresAt, localhostWarning: made.localhostWarning })
  })
}

/**
 * POST /api/users/[id]/invite/cancel: removes an invited account that never signed in, with its
 * links. One that owns projects (an admin acting as it made them) is refused: the users DELETE
 * removes it with its projects' teardown.
 */
export async function cancelInvite(request: NextRequest, session: Session, userId: string): Promise<NextResponse> {
  const refused = await prisma.$transaction(async (tx) => {
    const user = await tx.user.findUnique({ where: { id: userId }, select: { email: true, status: true, lastLoginAt: true } })
    if (!user) return USER_NOT_FOUND()
    if (user.status !== 'invited' || user.lastLoginAt) return NOT_INVITED()
    if ((await tx.project.count({ where: { userId } })) > 0) return HAS_PROJECTS()
    const { count } = await tx.user.deleteMany({ where: { id: userId, status: 'invited', lastLoginAt: null } })
    if (count !== 1) return ACCOUNT_CHANGED()
    await writeAuditTx(tx, await userAuditEntry(request, session, {
      action: 'user.invite_cancelled', targetId: userId, before: { email: user.email, status: 'invited' },
    }))
    return null
  })
  if (refused) return refused
  invalidatePrincipal(userId)
  return NextResponse.json({ id: userId, cancelled: true })
}

// --- The public side (switch on): open a link, read its state, accept it ---------------------

/**
 * Wraps an invite route like `withRouteErrors` (`{error, code}` 500), but its log line carries
 * only the error's code: a Prisma error quotes its query's values, which here are a token hash or
 * a new password's hash.
 */
export function withInviteErrors<A extends unknown[]>(
  what: string,
  message: string,
  handler: (...args: A) => Promise<Response>,
): (...args: A) => Promise<Response> {
  return async (...args: A) => {
    try {
      return await handler(...args)
    } catch (err) {
      const code = safeErrorCode(err)
      console.error(`[rbac] ${what} failed code=${code}`)
      return privateJson({ error: message, code }, 500)
    }
  }
}

export function setInviteCookie(response: NextResponse, request: NextRequest, value: string): void {
  response.cookies.set(INVITE_COOKIE_NAME, value, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isSecureRequest(request),
    path: INVITE_COOKIE_PATH,
    maxAge: INVITE_COOKIE_MAX_AGE,
  })
}

export function clearInviteCookie(response: NextResponse, request: NextRequest): void {
  response.cookies.set(INVITE_COOKIE_NAME, '', {
    httpOnly: true,
    sameSite: 'lax',
    secure: isSecureRequest(request),
    path: INVITE_COOKIE_PATH,
    maxAge: 0,
  })
}

/** The open link the request's invite cookie names, or null. */
export async function linkFromCookie(request: NextRequest): Promise<OpenLink | null> {
  const id = await readInviteCookie(request.cookies.get(INVITE_COOKIE_NAME)?.value)
  return id ? findLinkById(id) : null
}

/** 410 `invite_invalid`, the cookie cleared: the one answer for every link that does not work. */
export function invalidLinkResponse(request: NextRequest): NextResponse {
  const res = privateJson(INVALID_LINK, 410)
  clearInviteCookie(res, request)
  return res
}

class LinkGone extends Error {
  constructor() {
    super('link gone')
    this.name = 'LinkGone'
  }
}

export interface AcceptedAccount {
  id: string
  name: string
  email: string
  role: string
  sessionVersion: number
  /** The account's pending notices (a reset's, step 2.10), handed over with this sign-in. */
  notices: NoticeView[]
  /** The stored notices list as it was before the hand-over. */
  storedNotices: unknown
}

/**
 * Uses the link and sets the password, in one transaction with the audit row: the link is
 * marked used only if it is still open, and the account changed only if it is still what the
 * link was made for, so two accepts of one link make one sign-in. A reset raises the session
 * version (every older cookie ends). The account's other open links are cancelled, and its
 * pending notices are handed over and marked shown (step 2.10). Null when the link stopped
 * working meanwhile.
 */
export async function acceptLink(link: OpenLink, passwordHash: string): Promise<AcceptedAccount | null> {
  const at = now()
  const reset = link.kind === 'reset'
  try {
    return await prisma.$transaction(async (tx) => {
      const used = await tx.userInvite.updateMany({
        where: { id: link.id, usedAt: null, cancelledAt: null, expiresAt: { gt: at } },
        data: { usedAt: at },
      })
      if (used.count !== 1) throw new LinkGone()
      const changed = await tx.user.updateMany({
        where: { id: link.userId, status: ACCOUNT_STATUS_FOR[link.kind] },
        data: {
          password: passwordHash,
          status: 'active',
          mustChangePassword: false,
          passwordOnHold: '',
          lastLoginAt: at,
          ...(reset ? { sessionVersion: { increment: 1 } } : {}),
        },
      })
      if (changed.count !== 1) throw new LinkGone()
      await tx.userInvite.updateMany({
        where: { userId: link.userId, usedAt: null, cancelledAt: null },
        data: { cancelledAt: at },
      })
      const row = await tx.user.findUnique({
        where: { id: link.userId },
        select: { id: true, name: true, email: true, role: true, sessionVersion: true, pendingNotices: true },
      })
      if (!row) throw new LinkGone()
      const { pendingNotices: storedNotices, ...user } = row
      const notices = pendingNotices(storedNotices).map(noticeView)
      if (notices.length) {
        await tx.user.update({
          where: { id: user.id },
          data: { pendingNotices: markShown(storedNotices) as unknown as Prisma.InputJsonValue },
        })
      }
      await writeAuditTx(tx, {
        actorId: user.id,
        actorEmail: user.email,
        action: reset ? 'user.reset_link_used' : 'user.invite_accepted',
        targetType: 'user',
        targetId: user.id,
        after: reset ? { kind: link.kind, sessionVersion: user.sessionVersion } : { kind: link.kind },
        source: 'api',
      })
      return { ...user, notices, storedNotices }
    })
  } catch (err) {
    if (err instanceof LinkGone) return null
    throw err
  }
}

/**
 * Cancels a link that took too many failed accepts, with `user.invite_locked` in the same
 * transaction; the operator learns it from that row and the `[rbac]` line.
 */
export async function lockLink(link: OpenLink, failedAccepts: number): Promise<void> {
  const locked = await prisma.$transaction(async (tx) => {
    const { count } = await tx.userInvite.updateMany({
      where: { id: link.id, usedAt: null, cancelledAt: null },
      data: { cancelledAt: now() },
    })
    if (count !== 1) return false
    await writeAuditTx(tx, {
      actorId: null,
      action: 'user.invite_locked',
      targetType: 'user',
      targetId: link.userId,
      after: { kind: link.kind, failedAccepts },
      source: 'api',
    })
    return true
  })
  if (locked) console.warn(`[rbac] invite link locked user=${link.userId} kind=${link.kind} after ${failedAccepts} failed accepts`)
}
