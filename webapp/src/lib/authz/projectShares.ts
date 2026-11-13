/**
 * Sharing a project at Read (step 4.4; feature document §6.1, §6.3-§6.5; SH-04, SH-06, SH-09,
 * SH-10, SH-11, SH-13, SH-19, SH-20, SH-21, DV-05, OQ-34): the writers behind
 * /api/projects/[id]/collaborators, .../collaborators/[userId] and .../leave.
 *
 * - Only with sharing in force (RBAC_SHARING_ENABLED and Root's `sharingPolicy.enabled`): otherwise
 *   every share route answers 404 having read no share, as before the feature (DV-30).
 * - A grant names the recipient by exact email, normalised (trimmed, lowercase) and compared ignoring
 *   case; it binds the account id the email resolves to now, and nothing is held for an email no
 *   account has (§6.4: members change their own email). The answer says whether an account exists
 *   (D-24 confirm mode), so each lookup is counted against the person's ceiling
 *   (`takeShareLookup`) and audited (`project.share.lookup`, the email as a hash only) before it is
 *   answered: no row, no answer. Two accounts whose emails differ only in case (accounts created
 *   before step 1.2) name nobody: 409, never a pick.
 * - Read + Write and its toggles only with write sharing in force (step 5.14: RBAC_SHARING_WRITE_ENABLED
 *   and Root's `maxLevel: 'write'`); otherwise a `write` level or a toggle is refused with 409
 *   (`write_sharing_off`, or `above_max_level` when Root's policy allows Read only) and every answer is
 *   Phase 4's. A toggle that spends the owner's credentials is refused first while the owner has not
 *   consented (409 `owner_consent_required`, step 5.6). Nobody grants more than they hold (§4.1 rule 5):
 *   a co-owner only the toggles of their own share (403 `grant_above_held`); a member grants
 *   Exploitation & shells only when Root's policy lets members (`membersMayGrantExploit`, 409
 *   `exploit_admins_only`), and whoever grants it confirms with their password (step-up, ID-25).
 * - Every change is written with its audit row in one transaction (`writeAuditTx`): no row, no
 *   change. A revoke, a leave or a change that narrows the share then stops the person's live work
 *   on the project (`onAccessReduced`, step 5.9), best effort: the change stands when the agent is
 *   down (`[rbac] socket-close failed`).
 */
import { createHash } from 'crypto'
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAuditTx, type AuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { auditActor, auditActorOf, sessionActor, type AuditActor } from '@/lib/auditActor'
import { safeErrorCode } from '@/lib/routeErrors'
import { getAuthzIdentity, type EffectiveUser } from '@/lib/session'
import { normalizeEmail } from './accountEmail'
import { can } from './can'
import { now } from './clock'
import { rbacFlags } from './flags'
import { forbiddenResponse, type PermissionContext } from './guards'
import { takeShareLookup } from './inviteLimits'
import { auditOversightRead } from './oversight'
import { projectAccess, type ProjectAccess } from './projectAccess'
import { ConsentStoreMissing, readOwnerConsent, SPEND_TOGGLES, spendToggleConsentRefusal } from './ownerConsent'
import { isAccessReduction, onAccessReduced, type ProjectReduction } from './revocation'
import { accountTypeOf, loadInstanceRoot, type AccountType } from './root'
import { DEFAULT_EXPIRY_DAYS_BOUNDS, maxShareLevel, sharingPolicyInForce, type SharingPolicy } from './sharingPolicy'
import { requireStepUp } from './stepUp'

export const SHARE_PERMISSION = 'project:share'
export const NOTE_MAX_LENGTH = 500
const EMAIL_MAX_LENGTH = 320
const DAY_MS = 86_400_000
const MAX_EXPIRY_MS = DEFAULT_EXPIRY_DAYS_BOUNDS[1] * DAY_MS
/** The toggles of Read + Write (§6.1), granted only with write sharing in force (step 5.14). */
const WRITE_TOGGLES = ['runScans', 'useAgent', 'exploit', 'manage'] as const
export type WriteToggle = (typeof WRITE_TOGGLES)[number]

const TOGGLE_LABELS: Record<WriteToggle, string> = {
  runScans: 'Run scans', useAgent: 'Use AI agent', exploit: 'Exploitation & shells', manage: 'Manage',
}
const EXPLOIT_ADMINS_ONLY = 'The instance sharing policy lets only administrators grant Exploitation & shells.'
const CONSENT_FIRST = "The project's owner must first allow collaborators to spend its credentials (keys and providers)."
const notHeld = (toggle: WriteToggle) => `You can grant only what you hold yourself: your share has no ${TOGGLE_LABELS[toggle]}.`

/** Why the asker may not grant a toggle (GET's `grantable`; the writers refuse with the same rule). */
export type GrantRefusalCode = 'not_held' | 'owner_consent_required' | 'exploit_admins_only'
export type GrantableToggle = { grantable: true } | { grantable: false; code: GrantRefusalCode; reason: string }

/** What the person asking may grant, for the share dialog (only with write sharing in force). */
export interface ShareGrantable {
  /** The owner, or a co-owner (a Read + Write share with Manage), who grants at most what they hold. */
  grantor: 'owner' | 'co_owner'
  toggles: Record<WriteToggle, GrantableToggle>
  /** The owner's consent to spend the project's credentials (step 5.6); only the owner gives it. */
  ownerConsent: boolean
}

/** The person who may change shares, as the list's guard decided (null for an oversight or break-glass reader). */
export interface ShareGrantor {
  access: ProjectAccess
  principal: { id: string; role: string }
}

/** An account a share names, as the share dialog shows it (ID-31): name, email and account type. */
export interface SharePerson {
  id: string
  name: string | null
  email: string | null
  accountType: AccountType
}

/** One share as its screens show it (the owner's list, the grant's answer). */
export interface ShareView {
  /** `accountType` null when the accounts could not be read after a change that committed. */
  user: { id: string; name: string | null; email: string | null; status: string | null; accountType: AccountType | null }
  access: string
  rawData: boolean
  expiresAt: string | null
  /** Past its expiry: it gives nothing (expiry is lazy) until the sweep removes it (step 4.15). */
  expired: boolean
  note: string | null
  grantedById: string
  /** Who granted it; null when that account is gone (or could not be read after a committed change). */
  grantedBy: SharePerson | null
  createdAt: string
  updatedAt: string
  /** The Read + Write toggles as stored: only with write sharing in force (Phase 4's answer otherwise, DV-30). */
  runScans?: boolean
  useAgent?: boolean
  exploit?: boolean
  manage?: boolean
}

interface ShareRecord {
  projectId: string
  userId: string
  access: string
  runScans: boolean
  useAgent: boolean
  exploit: boolean
  rawData: boolean
  manage: boolean
  expiresAt: Date | null
  note: string | null
  grantedById: string
  createdAt: Date
  updatedAt: Date
  user?: { id: string; name: string | null; email: string | null; status: string | null } | null
}

interface Recipient { id: string; name: string | null; email: string | null; status: string }

const iso = (d: Date | null) => (d ? d.toISOString() : null)

function refusal(status: number, code: string, error: string, extra: Record<string, unknown> = {}): NextResponse {
  return NextResponse.json({ error, code, ...extra }, { status })
}

function invalidField(field: string, error: string): NextResponse {
  return refusal(400, 'invalid_field', error, { field })
}

function noSuchShare(): NextResponse {
  return refusal(404, 'no_such_share', 'This person holds no share of the project.')
}

/** The share as the audit rows record it (the note stays out: free text, not a grant). */
function auditView(row: ShareRecord): Record<string, unknown> {
  return {
    access: row.access, rawData: row.rawData, runScans: row.runScans, useAgent: row.useAgent,
    exploit: row.exploit, manage: row.manage, expiresAt: iso(row.expiresAt), grantedById: row.grantedById,
  }
}

function shareView(row: ShareRecord, at: number, writeTerms = false): ShareView {
  const toggles = writeTerms ? { runScans: row.runScans, useAgent: row.useAgent, exploit: row.exploit, manage: row.manage } : {}
  return {
    user: {
      id: row.userId, name: row.user?.name ?? null, email: row.user?.email ?? null, status: row.user?.status ?? null,
      accountType: null,
    },
    access: row.access,
    rawData: row.rawData,
    expiresAt: iso(row.expiresAt),
    expired: row.expiresAt !== null && row.expiresAt.getTime() <= at,
    note: row.note,
    grantedById: row.grantedById,
    grantedBy: null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    ...toggles,
  }
}

/**
 * Each collaborator's account type and who granted each share (ID-31: a display name alone is not an
 * identity), from one read of the accounts both name and the Root. A failed read throws.
 */
async function withPeople(views: ShareView[]): Promise<ShareView[]> {
  if (views.length === 0) return views
  const ids = [...new Set(views.flatMap(v => [v.user.id, v.grantedById]))]
  const [accounts, root] = await Promise.all([
    prisma.user.findMany({ where: { id: { in: ids } }, select: { id: true, name: true, email: true, role: true } }),
    loadInstanceRoot(),
  ])
  const byId = new Map(accounts.map(a => [a.id, a]))
  const person = (id: string): SharePerson | null => {
    const a = byId.get(id)
    return a ? { id: a.id, name: a.name ?? null, email: a.email ?? null, accountType: accountTypeOf(a, root) } : null
  }
  return views.map(v => ({
    ...v,
    user: { ...v.user, accountType: person(v.user.id)?.accountType ?? null },
    grantedBy: person(v.grantedById),
  }))
}

/** withPeople for the answer to a change that already committed: a failed read leaves the names bare, never a 500. */
async function withPeopleAfterCommit(view: ShareView): Promise<ShareView> {
  try {
    return (await withPeople([view]))[0]
  } catch (err) {
    console.error(`[rbac] could not read the share's accounts: ${safeErrorCode(err)}`)
    return view
  }
}

const SHARE_SELECT = {
  projectId: true, userId: true, access: true, runScans: true, useAgent: true, exploit: true, rawData: true,
  manage: true, expiresAt: true, note: true, grantedById: true, createdAt: true, updatedAt: true,
  user: { select: { id: true, name: true, email: true, status: true } },
} as const

/** The policy the share routes act under, or null when sharing is not in force (they answer 404). */
export async function sharingPolicyForRoutes({ fresh = false }: { fresh?: boolean } = {}): Promise<Readonly<SharingPolicy> | null> {
  if (!rbacFlags().sharing) return null
  const policy = await sharingPolicyInForce({ fresh })
  return policy?.enabled === true ? policy : null
}

/** The hash an audit row keeps instead of the email a lookup named. */
export function emailSha256(email: string): string {
  return createHash('sha256').update(normalizeEmail(email.trim()), 'utf8').digest('hex')
}

/**
 * OQ-34: only the owner removes, narrows or otherwise changes a co-owner's share (Manage). A
 * co-owner reaches the share routes only from Phase 5; the check stands now so it cannot be missed.
 */
export function coOwnerRefusal(access: Pick<ProjectAccess, 'level'>, row: { manage: boolean }): NextResponse | null {
  if (!row.manage || access.level === 'owner') return null
  return refusal(403, 'owner_only', "Only the project's owner can change or remove a co-owner's share.", { permission: SHARE_PERMISSION })
}

/** Nobody shares a project with themselves, nor with its owner (a co-owner's grant, Phase 5). */
export function recipientRefusal(recipientId: string, { actorId, ownerId }: { actorId: string; ownerId: string }): NextResponse | null {
  if (recipientId === actorId) return refusal(400, 'share_with_self', 'You cannot share a project with yourself.')
  if (recipientId === ownerId) return refusal(400, 'share_with_owner', "The project's owner already has every access.")
  return null
}

/**
 * The level a body asks for. With write sharing in force any level and toggle passes here (the grantor
 * checks follow); otherwise a `write` level or a Read + Write toggle is refused (409), naming Root's
 * policy when the write switch is on and the policy allows Read only.
 */
function levelRefusal(body: Record<string, unknown>, policy: Readonly<SharingPolicy>, required: boolean): NextResponse | null {
  if (required || 'access' in body) {
    if (body.access !== 'read' && body.access !== 'write') return invalidField('access', 'access must be "read" (or "write" once write sharing is on)')
  }
  for (const toggle of WRITE_TOGGLES) {
    if (toggle in body && typeof body[toggle] !== 'boolean') return invalidField(toggle, `${toggle} must be true or false`)
  }
  const asksWrite = body.access === 'write' || WRITE_TOGGLES.some(t => body[t] === true)
  if (!asksWrite || maxShareLevel(policy) === 'write') return null
  if (rbacFlags().sharingWrite && policy.maxLevel === 'read') {
    return refusal(409, 'above_max_level', 'The instance sharing policy allows Read shares only.', { maxLevel: 'read' })
  }
  return refusal(409, 'write_sharing_off', 'Read + Write sharing is not available yet: share at Read.')
}

/**
 * Root's `membersMayGrantExploit` (§6.5): off, only an administrator grants Exploitation & shells. The
 * account type comes from the role alone: the Root's role is admin too (User.role follows the account
 * type), so no Root read is needed to tell a member apart.
 */
function exploitReservedToAdmins(principal: { id: string; role: string }, policy: Readonly<SharingPolicy>): boolean {
  return !policy.membersMayGrantExploit && accountTypeOf(principal, null) === 'member'
}

/** Whether `access` lets its holder change shares, and as whom: the owner, or a co-owner (write + Manage). */
function grantorKind(access: ProjectAccess): ShareGrantable['grantor'] | null {
  if (access.level === 'owner') return 'owner'
  return access.level === 'write' && access.toggles.manage === true ? 'co_owner' : null
}

/**
 * One toggle as the grantor may grant it. The owner grants every toggle (the spend toggles after their
 * consent, which the dialog asks for); a co-owner only what their own share holds now, so without the
 * owner's consent no spend toggle (projectAccess reads them off then).
 */
function toggleGrant(toggle: WriteToggle, grantor: ShareGrantor, policy: Readonly<SharingPolicy>, consent: boolean): GrantableToggle {
  const refused = (code: GrantRefusalCode, reason: string): GrantableToggle => ({ grantable: false, code, reason })
  if (toggle === 'exploit' && exploitReservedToAdmins(grantor.principal, policy)) return refused('exploit_admins_only', EXPLOIT_ADMINS_ONLY)
  if (grantor.access.level === 'owner') return { grantable: true }
  if ((SPEND_TOGGLES as readonly string[]).includes(toggle) && !consent) return refused('owner_consent_required', CONSENT_FIRST)
  return grantor.access.toggles[toggle] === true ? { grantable: true } : refused('not_held', notHeld(toggle))
}

/** What `grantor` may grant on the project, or null when write sharing is not in force or they change no share. */
export async function shareGrantable(grantor: ShareGrantor, policy: Readonly<SharingPolicy>): Promise<ShareGrantable | null> {
  if (maxShareLevel(policy) !== 'write') return null
  const kind = grantorKind(grantor.access)
  if (!kind) return null
  let consent = false
  try {
    consent = (await readOwnerConsent(grantor.access.project.id)) !== null
  } catch (err) {
    if (!(err instanceof ConsentStoreMissing)) throw err
  }
  const toggles = Object.fromEntries(WRITE_TOGGLES.map(t => [t, toggleGrant(t, grantor, policy, consent)])) as Record<WriteToggle, GrantableToggle>
  return { grantor: kind, toggles, ownerConsent: consent }
}

/**
 * The writers' grantor checks, on the toggles a body turns on (write sharing in force): Root's policy
 * on Exploitation first (409), then the co-owner's "never more than held" (403). The owner's consent
 * was asked already (`spendToggleConsentRefusal`).
 */
function grantorRefusal(auth: PermissionContext, policy: Readonly<SharingPolicy>, body: Record<string, unknown>): NextResponse | null {
  const access = auth.access
  if (!access || maxShareLevel(policy) !== 'write') return null
  for (const toggle of WRITE_TOGGLES) {
    if (body[toggle] !== true) continue
    if (toggle === 'exploit' && exploitReservedToAdmins(auth.principal, policy)) {
      return refusal(409, 'exploit_admins_only', EXPLOIT_ADMINS_ONLY)
    }
    if (access.level !== 'owner' && access.toggles[toggle] !== true) {
      return refusal(403, 'grant_above_held', notHeld(toggle), { toggle, permission: SHARE_PERMISSION })
    }
  }
  return null
}

/** Granting Exploitation & shells takes the granting person's password (ID-25); other grants do not. */
async function exploitStepUp(request: { headers?: Headers }, body: Record<string, unknown>): Promise<NextResponse | null> {
  return body.exploit === true ? requireStepUp(request, body.stepUpPassword) : null
}

/** A Read + Write toggle asked on a share that is (or stays) Read: 400 naming it. */
function toggleOnReadRefusal(asked: Partial<Record<WriteToggle, unknown>>): NextResponse | null {
  const toggle = WRITE_TOGGLES.find(t => asked[t] === true)
  return toggle ? invalidField(toggle, `${toggle} applies to Read + Write shares only: set access to "write"`) : null
}

type Parsed<T> = { value: T } | { response: NextResponse }

function parseRawData(value: unknown): Parsed<boolean> {
  return typeof value === 'boolean' ? { value } : { response: invalidField('rawData', 'rawData must be true or false') }
}

function parseExpiry(value: unknown, at: number): Parsed<Date | null> {
  if (value === null) return { value: null }
  const when = typeof value === 'string' ? new Date(value) : null
  if (!when || Number.isNaN(when.getTime())) return { response: invalidField('expiresAt', 'expiresAt must be a date and time (ISO 8601) or null') }
  if (when.getTime() <= at) return { response: invalidField('expiresAt', 'expiresAt must be in the future') }
  if (when.getTime() > at + MAX_EXPIRY_MS) {
    return { response: invalidField('expiresAt', `expiresAt must be within ${DEFAULT_EXPIRY_DAYS_BOUNDS[1]} days`) }
  }
  return { value: when }
}

function parseNote(value: unknown): Parsed<string | null> {
  if (value === null) return { value: null }
  if (typeof value !== 'string') return { response: invalidField('note', 'note must be text or null') }
  const note = value.trim()
  if (note.length > NOTE_MAX_LENGTH) return { response: invalidField('note', `note must be at most ${NOTE_MAX_LENGTH} characters`) }
  return { value: note || null }
}

function parseEmail(value: unknown): Parsed<string> {
  const email = typeof value === 'string' ? normalizeEmail(value.trim()) : ''
  if (!email || email.length > EMAIL_MAX_LENGTH || !/^[^\s@]+@[^\s@]+$/.test(email)) {
    return { response: invalidField('email', "email must be the recipient's exact sign-in email") }
  }
  return { value: email }
}

/**
 * The accounts an email names, compared ignoring case (lower() on both sides, the email bound as a
 * parameter: never ILIKE, where `_` and `%` match anything; accountEmail.ts).
 */
async function accountsByEmail(email: string): Promise<Recipient[]> {
  return prisma.$queryRaw<Recipient[]>`SELECT id, name, email, status FROM users WHERE lower(email) = lower(${email})`
}

/** The audit actor of a share change: the person signed in (act-as is refused before any change). */
function actorOf(auth: PermissionContext): AuditActor {
  return auditActorOf(sessionActor(auth.session), auth.effective.userId)
}

function ownerOf(auth: PermissionContext): string {
  if (!auth.access) throw new Error('[rbac] a share route checked no project')
  return auth.access.project.userId
}

/**
 * GET's guard: the owner and a co-owner through `project:share` at Manage (their `grantor`, for what
 * they may grant; null under act-as, where nothing can be changed); an admin reading the project by
 * oversight when Root's policy lets admins see every share (`adminsSeeAllShares`), which writes the
 * day's `project.oversee` row first (step 4.14); Root's break-glass (both `grantor: null`). A read
 * collaborator gets 403, a stranger 404. Under act-as the account acted as decides, so the acting
 * admin's oversight never applies (D-22).
 */
export async function requireShareListAccess(projectId: string, policy: Readonly<SharingPolicy>): Promise<{ grantor: ShareGrantor | null } | NextResponse> {
  const identity = await getAuthzIdentity()
  if (!identity) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const decision = await can(identity.principal, SHARE_PERMISSION, { projectId, actingAs: identity.actingAs })
  if (decision.allowed) {
    return { grantor: identity.actingAs || !decision.access ? null : { access: decision.access, principal: identity.principal } }
  }
  if (decision.status === 404) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  if (decision.status === 400) return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  if (!identity.actingAs) {
    const access = await projectAccess({ userId: identity.principal.id }, projectId, { principal: identity.principal })
    if (access?.via === 'break_glass') return { grantor: null }
    if (access?.via === 'oversight' && policy.adminsSeeAllShares) {
      await auditOversightRead(identity, access, SHARE_PERMISSION)
      return { grantor: null }
    }
  }
  return forbiddenResponse(SHARE_PERMISSION)
}

/**
 * Every share of the project, expired ones included (marked), oldest first; `writeTerms` adds each
 * share's Read + Write toggles (only with write sharing in force).
 */
export async function listShares(projectId: string, { writeTerms = false }: { writeTerms?: boolean } = {}): Promise<ShareView[]> {
  const rows = await prisma.projectCollaborator.findMany({
    where: { projectId },
    select: SHARE_SELECT,
    orderBy: { createdAt: 'asc' },
  }) as ShareRecord[]
  const at = now().getTime()
  return withPeople(rows.map(r => shareView(r, at, writeTerms)))
}

/**
 * GET .../collaborators' answer: Phase 4's `{collaborators}` unless write sharing is in force; then each
 * share's toggles and, for the owner or a co-owner, what they may grant (`grantable`).
 */
export async function shareListAnswer(projectId: string, policy: Readonly<SharingPolicy>, grantor: ShareGrantor | null): Promise<Record<string, unknown>> {
  if (maxShareLevel(policy) !== 'write') return { collaborators: await listShares(projectId) }
  const [collaborators, grantable] = await Promise.all([
    listShares(projectId, { writeTerms: true }),
    grantor ? shareGrantable(grantor, policy) : null,
  ])
  return { collaborators, grantable }
}

class AlreadyShared extends Error {}

const isUniqueViolation = (err: unknown) =>
  Boolean(err && typeof err === 'object' && (err as { code?: unknown }).code === 'P2002')

async function writeLookupRow(auth: PermissionContext, email: string, result: 'hit' | 'miss' | 'ambiguous', targetId: string | null): Promise<void> {
  await writeAuditTx(prisma as unknown as AuditTx, {
    ...actorOf(auth),
    projectId: auth.access?.project.id ?? null,
    permission: SHARE_PERMISSION,
    action: 'project.share.lookup',
    targetType: 'user',
    targetId,
    after: { result, emailSha256: emailSha256(email) },
    source: 'api',
  })
}

/**
 * POST .../collaborators: share the project with the account an email names, at Read, or with write
 * sharing in force at Read + Write with the toggles the granting person may grant. Exploitation &
 * shells takes their password, asked before any lookup.
 */
export async function grantShare(
  auth: PermissionContext,
  policy: Readonly<SharingPolicy>,
  body: Record<string, unknown>,
  request: { headers?: Headers },
): Promise<NextResponse> {
  const at = now().getTime()
  const email = parseEmail(body.email)
  if ('response' in email) return email.response
  const consent = await spendToggleConsentRefusal(auth.access!.project.id, policy, body)
  if (consent) return consent
  const level = levelRefusal(body, policy, true)
  if (level) return level
  const writeTerms = maxShareLevel(policy) === 'write'
  const access = writeTerms && body.access === 'write' ? 'write' : 'read'
  const onRead = access === 'read' ? toggleOnReadRefusal(body) : null
  if (onRead) return onRead
  const rawData = 'rawData' in body ? parseRawData(body.rawData) : { value: false }
  if ('response' in rawData) return rawData.response
  const defaultExpiry = policy.defaultExpiryDays ? new Date(at + policy.defaultExpiryDays * DAY_MS) : null
  const expiresAt = 'expiresAt' in body ? parseExpiry(body.expiresAt, at) : { value: defaultExpiry }
  if ('response' in expiresAt) return expiresAt.response
  const note = 'note' in body ? parseNote(body.note) : { value: null }
  if ('response' in note) return note.response
  const beyond = grantorRefusal(auth, policy, body)
  if (beyond) return beyond
  const stepUp = await exploitStepUp(request, body)
  if (stepUp) return stepUp
  const toggles = Object.fromEntries(WRITE_TOGGLES.map(t => [t, access === 'write' && body[t] === true])) as Record<WriteToggle, boolean>

  const limit = takeShareLookup(auth.session.userId)
  if (!limit.ok) {
    const res = refusal(429, 'rate_limited', 'Too many people looked up. Try again in a minute.', { retryAfterSeconds: limit.retryAfterSeconds })
    res.headers.set('Retry-After', String(limit.retryAfterSeconds))
    return res
  }
  const accounts = await accountsByEmail(email.value)
  if (accounts.length !== 1) {
    await writeLookupRow(auth, email.value, accounts.length ? 'ambiguous' : 'miss', null)
    return accounts.length
      ? refusal(409, 'ambiguous_account', 'More than one account has this email in different letter case. Ask an administrator to fix the accounts first.')
      : refusal(404, 'no_such_account', 'No account has this email.')
  }
  const recipient = accounts[0]
  await writeLookupRow(auth, email.value, 'hit', recipient.id)
  if (recipient.status !== 'active') {
    return refusal(409, 'account_not_active', 'This account is not active (invited or disabled): it cannot receive a share.')
  }
  const ownerId = ownerOf(auth)
  const self = recipientRefusal(recipient.id, { actorId: auth.effective.userId, ownerId })
  if (self) return self

  const projectId = auth.access!.project.id
  let created: ShareRecord
  try {
    created = await auditedTransaction(prisma, async (tx) => {
      const existing = await tx.projectCollaborator.findUnique({
        where: { projectId_userId: { projectId, userId: recipient.id } },
        select: SHARE_SELECT,
      }) as ShareRecord | null
      if (existing && (existing.expiresAt === null || existing.expiresAt.getTime() > at)) throw new AlreadyShared()
      // An expired share the sweep has not removed yet gives nothing: a new grant replaces it.
      if (existing) await tx.projectCollaborator.deleteMany({ where: { projectId, userId: recipient.id } })
      const row = await tx.projectCollaborator.create({
        data: {
          projectId, userId: recipient.id, access, ...toggles, rawData: rawData.value, expiresAt: expiresAt.value,
          note: note.value, grantedById: auth.effective.userId,
        },
        select: SHARE_SELECT,
      }) as ShareRecord
      await writeAuditTx(tx, {
        ...actorOf(auth),
        projectId,
        permission: SHARE_PERMISSION,
        action: 'project.share.grant',
        targetType: 'user',
        targetId: recipient.id,
        ...(existing ? { before: auditView(existing) } : {}),
        after: auditView(row),
        source: 'api',
      })
      return row
    })
  } catch (err) {
    if (err instanceof AlreadyShared || isUniqueViolation(err)) {
      return refusal(409, 'already_shared', 'This person already holds a share of the project: change it instead.')
    }
    throw err
  }
  const view = shareView({ ...created, user: { id: recipient.id, name: recipient.name, email: recipient.email, status: recipient.status } }, at, writeTerms)
  return NextResponse.json({ collaborator: await withPeopleAfterCommit(view) }, { status: 201 })
}

type SharePatchData = Partial<Record<WriteToggle, boolean>> & {
  access?: 'read' | 'write'
  rawData?: boolean
  expiresAt?: Date | null
  note?: string | null
}

/**
 * PATCH .../collaborators/[userId]: change a share's level, Raw data, expiry or note, and with write
 * sharing in force its toggles (within what the person changing it may grant; a share lowered to Read
 * loses its toggles). Turning Exploitation & shells on takes the password.
 */
export async function updateShare(
  auth: PermissionContext,
  policy: Readonly<SharingPolicy>,
  userId: string,
  body: Record<string, unknown>,
  request: { headers?: Headers },
): Promise<NextResponse> {
  const at = now().getTime()
  const consent = await spendToggleConsentRefusal(auth.access!.project.id, policy, body)
  if (consent) return consent
  const level = levelRefusal(body, policy, false)
  if (level) return level
  const writeTerms = maxShareLevel(policy) === 'write'
  const patch: SharePatchData = {}
  if (writeTerms) {
    if (body.access === 'read' || body.access === 'write') patch.access = body.access
    for (const t of WRITE_TOGGLES) if (t in body) patch[t] = body[t] === true
    const onRead = patch.access === 'read' ? toggleOnReadRefusal(patch) : null
    if (onRead) return onRead
  }
  if ('rawData' in body) {
    const v = parseRawData(body.rawData)
    if ('response' in v) return v.response
    patch.rawData = v.value
  }
  if ('expiresAt' in body) {
    const v = parseExpiry(body.expiresAt, at)
    if ('response' in v) return v.response
    patch.expiresAt = v.value
  }
  if ('note' in body) {
    const v = parseNote(body.note)
    if ('response' in v) return v.response
    patch.note = v.value
  }
  if (!('access' in body) && Object.keys(patch).length === 0) {
    return refusal(400, 'invalid_field', 'Name at least one of access, rawData, expiresAt and note.')
  }
  const beyond = grantorRefusal(auth, policy, body)
  if (beyond) return beyond
  const stepUp = await exploitStepUp(request, body)
  if (stepUp) return stepUp
  const access = auth.access
  if (!access) throw new Error('[rbac] a share route checked no project')
  const projectId = access.project.id
  const outcome = await auditedTransaction(prisma, async (tx) => {
    const where = { projectId_userId: { projectId, userId } }
    const before = await tx.projectCollaborator.findUnique({ where, select: SHARE_SELECT }) as ShareRecord | null
    if (!before) return { kind: 'missing' as const }
    const protectedRow = coOwnerRefusal(access, before)
    if (protectedRow) return { kind: 'refused' as const, response: protectedRow }
    const data: SharePatchData = { ...patch }
    if (writeTerms && (data.access ?? before.access) !== 'write') {
      const onRead = toggleOnReadRefusal(data)
      if (onRead) return { kind: 'refused' as const, response: onRead }
      // A Read share holds no Read + Write toggle: lowering the level drops them, so raising it later
      // never brings back toggles nobody granted again.
      for (const t of WRITE_TOGGLES) data[t] = false
    }
    const changed = (Object.keys(data) as Array<keyof SharePatchData>).filter((k) => {
      const next = data[k]
      const prev = before[k]
      return next instanceof Date || prev instanceof Date ? iso(next as Date | null) !== iso(prev as Date | null) : next !== prev
    })
    if (changed.length === 0) return { kind: 'done' as const, row: before }
    const { count } = await tx.projectCollaborator.updateMany({ where: { projectId, userId }, data })
    if (count !== 1) return { kind: 'missing' as const }
    const after = await tx.projectCollaborator.findUnique({ where, select: SHARE_SELECT }) as ShareRecord
    await writeAuditTx(tx, {
      ...actorOf(auth),
      projectId,
      permission: SHARE_PERMISSION,
      action: 'project.share.update',
      targetType: 'user',
      targetId: userId,
      before: auditView(before),
      after: { ...auditView(after), ...(changed.includes('note') ? { noteChanged: true } : {}) },
      source: 'api',
    })
    return { kind: 'done' as const, row: after, narrowed: isAccessReduction(before, after) }
  })
  if (outcome.kind === 'missing') return noSuchShare()
  if (outcome.kind === 'refused') return outcome.response
  if ('narrowed' in outcome && outcome.narrowed) await stopLiveWork(projectId, userId, 'share_reduced', access.project.userId)
  return NextResponse.json({ collaborator: await withPeopleAfterCommit(shareView(outcome.row, at, writeTerms)) })
}

/** Stops the person's live work on the project; false when the agent did not confirm the sockets closed (logged). */
async function stopLiveWork(projectId: string, userId: string, reason: ProjectReduction, ownerId?: string): Promise<boolean> {
  const stopped = await onAccessReduced(projectId, userId, reason, { ownerId })
  return !('error' in stopped.sockets)
}

/** Removes the share in one transaction with its audit row; false when there was none to remove. */
async function removeShare(
  projectId: string,
  userId: string,
  audit: { action: 'project.share.revoke' | 'project.share.leave'; actor: AuditActor; permission?: string },
  guard?: (row: ShareRecord) => NextResponse | null,
): Promise<'missing' | 'removed' | NextResponse> {
  return auditedTransaction(prisma, async (tx) => {
    const row = await tx.projectCollaborator.findUnique({
      where: { projectId_userId: { projectId, userId } },
      select: SHARE_SELECT,
    }) as ShareRecord | null
    if (!row) return 'missing' as const
    const refused = guard?.(row)
    if (refused) return refused
    // Conditional on the row being there: of two removals at once only one deletes it and audits.
    const { count } = await tx.projectCollaborator.deleteMany({ where: { projectId, userId } })
    if (count !== 1) return 'missing' as const
    await writeAuditTx(tx, {
      ...audit.actor,
      projectId,
      ...(audit.permission ? { permission: audit.permission } : {}),
      action: audit.action,
      targetType: 'user',
      targetId: userId,
      before: auditView(row),
      source: 'api',
    })
    return 'removed' as const
  })
}

/** DELETE .../collaborators/[userId]: the share ends now; the next request of that person gets 404. */
export async function revokeShare(auth: PermissionContext, userId: string): Promise<NextResponse> {
  const access = auth.access
  if (!access) throw new Error('[rbac] a share route checked no project')
  const projectId = access.project.id
  const outcome = await removeShare(projectId, userId, { action: 'project.share.revoke', actor: actorOf(auth), permission: SHARE_PERMISSION },
    (row) => coOwnerRefusal(access, row))
  if (outcome === 'missing') return noSuchShare()
  if (outcome instanceof NextResponse) return outcome
  return NextResponse.json({
    revoked: { projectId, userId }, socketsClosed: await stopLiveWork(projectId, userId, 'share_revoked', access.project.userId),
  })
}

/** POST .../leave: the person signed in gives up their own share of the project. */
export async function leaveShare(eff: EffectiveUser, projectId: string): Promise<NextResponse> {
  const outcome = await removeShare(projectId, eff.userId, { action: 'project.share.leave', actor: await auditActor(eff) })
  if (outcome === 'missing') return noSuchShare()
  if (outcome instanceof NextResponse) return outcome
  return NextResponse.json({ left: { projectId }, socketsClosed: await stopLiveWork(projectId, eff.userId, 'share_left') })
}
