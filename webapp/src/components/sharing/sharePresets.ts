/**
 * The share dialog's vocabulary as data (step 4.12; feature document §6.1, §6.2; SH-05, HD-22, SH-29):
 * the access levels, the toggles with their warnings, the presets that combine them, the body a
 * grant sends, and which share control a project row or the header offers. Data only (no React,
 * no request), so the switch-off test can import it.
 *
 * The four Read + Write presets and their toggles are offered only with write sharing in force (step
 * 5.14: the write switch and Root's policy at write, me's `sharing.maxLevel === 'write'`); otherwise
 * they are listed disabled with the reason (`writePresetsRefusal`). Within write sharing the share
 * list says what the person may grant (`grantable`: Root's policy on Exploitation, a co-owner's own
 * toggles), and `toggleOffer` / `presetOffer` turn that into offered, disabled (with why) or hidden.
 */
import type { MyAccess } from '@/lib/authz/projectAccess'
import type { ShareGrantable } from '@/lib/authz/projectShares'
import { PERMISSIONS } from '@/lib/authz/permissions'

export type ShareAccessLevel = 'read' | 'write'
export type ShareToggleId = 'rawData' | 'runScans' | 'useAgent' | 'exploit' | 'manage'
export type WriteToggleId = Exclude<ShareToggleId, 'rawData'>
export type SharePresetId = 'viewer' | 'analyst' | 'editor' | 'operator' | 'red_teamer' | 'co_owner' | 'custom'

export interface ShareTerms {
  access: ShareAccessLevel
  rawData: boolean
  runScans: boolean
  useAgent: boolean
  exploit: boolean
  manage: boolean
}

/**
 * A share as a list row carries it (`access` as stored); the Read + Write toggles are absent on a
 * Phase 4 row.
 */
export type ShareTermsLike = { access: string; rawData: boolean } & Partial<Omit<ShareTerms, 'access' | 'rawData'>>

export const RAW_DATA_WARNING =
  'Raw data includes captured traffic, workspace files and loot; grant it as you would hand over the files.'
/** HD-22 (F-18, OQ-46): what the agent runs, it runs in one sandbox every project shares, until D-21. */
export const SANDBOX_NOTICE = 'Use AI agent and Exploitation & shells reach a sandbox shared by every project on this server.'
/** SH-29: a scan or an agent run authenticates to the target with the project's auth profile. */
export const TARGET_CREDENTIALS_WARNING = "Run scans and Use AI agent carry the project's target credentials (its auth profile)."
/**
 * OQ-R7 is open and step 4.9 built its option (b): a Read share sees the graph as the owner does,
 * the full value of every secret recon found included, and reports carry them under either option.
 */
export const READ_SHOWS_FINDINGS_WARNING =
  'Every level shows what recon found as you see it, found secrets and reports included; the project settings never show your own keys and tokens.'

/** A collaborator who reads raw files or drives the agent can keep a copy of what they see. */
export const COPY_WARNING = 'A collaborator with Raw data or the agent can copy what they see: revoking ends the access, not the copies.'

export const WRITE_PRESETS_COMING = 'Coming when write sharing is on'

/**
 * The toggles that spend the owner's credentials, which need the owner's consent first (step 5.6;
 * lib/authz/ownerConsent.ts SPEND_TOGGLES, which this client module cannot import).
 */
export const SPEND_TOGGLE_IDS: readonly WriteToggleId[] = ['runScans', 'useAgent', 'exploit']

/** The consent prompt (step 5.6, C1): the owner allows collaborators to spend the project's credentials. */
export const CONSENT_PROMPT =
  "Run scans, Use AI agent and Exploitation & shells spend this project's credentials: your LLM providers and keys, " +
  "your scan keys and the target's credentials. Allow the collaborators you grant them to use them on this project? " +
  'You can withdraw it here at any time.'
/** The step-up's words when Exploitation & shells is granted (ID-25). */
export const EXPLOIT_STEP_UP =
  'Exploitation & shells lets them approve exploitation and dangerous tools and open shells on this project.'

/** A share's note, at most (lib/authz/projectShares.ts NOTE_MAX_LENGTH, which this module cannot import). */
export const NOTE_MAX_CHARS = 500

const sandboxShared = PERMISSIONS['agent:kali_exec'].sandboxShared

export interface ShareToggleInfo {
  id: ShareToggleId
  label: string
  description: string
  /** The base access it applies on: Raw data to Read (Read + Write already includes it), the rest to Read + Write. */
  level: ShareAccessLevel
  notices: readonly string[]
}

export const SHARE_TOGGLES: readonly ShareToggleInfo[] = [
  {
    id: 'rawData', label: 'Raw data & files', level: 'read',
    description: 'Captured traffic, workspace files and raw scan outputs.',
    notices: [RAW_DATA_WARNING],
  },
  {
    id: 'runScans', label: 'Run scans', level: 'write',
    description: 'Recon, partial recon, GVM, secrets, supply chain, AI attack, the queue and schedules.',
    notices: [TARGET_CREDENTIALS_WARNING],
  },
  {
    id: 'useAgent', label: 'Use AI agent', level: 'write',
    description: 'Chat, Fireteam, triage runs, CodeFix and assistants.',
    notices: [...(sandboxShared ? [SANDBOX_NOTICE] : []), TARGET_CREDENTIALS_WARNING],
  },
  {
    id: 'exploit', label: 'Exploitation & shells', level: 'write',
    description: 'Approve exploitation and dangerous tools, project shell sessions, Kali exec.',
    notices: sandboxShared ? [SANDBOX_NOTICE] : [],
  },
  {
    id: 'manage', label: 'Manage (co-owner)', level: 'write',
    description: 'Share with others, rescope, RoE and authorization, auth profile, delete versions, export.',
    notices: [],
  },
]

export interface SharePresetInfo {
  id: SharePresetId
  label: string
  /** What it grants, in the dialog's words. */
  summary: string
  level: ShareAccessLevel
  /** Null for Custom: the toggles chosen in the dialog. */
  terms: ShareTerms | null
}

const READ: ShareTerms = { access: 'read', rawData: false, runScans: false, useAgent: false, exploit: false, manage: false }
const WRITE: ShareTerms = { ...READ, access: 'write', rawData: true }

export const SHARE_PRESETS: readonly SharePresetInfo[] = [
  { id: 'viewer', label: 'Viewer', summary: 'Read', level: 'read', terms: READ },
  { id: 'analyst', label: 'Analyst', summary: 'Read + Raw data & files', level: 'read', terms: { ...READ, rawData: true } },
  { id: 'editor', label: 'Editor', summary: 'Read + Write', level: 'write', terms: WRITE },
  { id: 'operator', label: 'Operator', summary: 'Editor + Run scans + Use AI agent', level: 'write', terms: { ...WRITE, runScans: true, useAgent: true } },
  {
    id: 'red_teamer', label: 'Red-teamer', summary: 'Operator + Exploitation & shells', level: 'write',
    terms: { ...WRITE, runScans: true, useAgent: true, exploit: true },
  },
  {
    id: 'co_owner', label: 'Co-owner', summary: 'Everything but delete and transfer', level: 'write',
    terms: { ...WRITE, runScans: true, useAgent: true, exploit: true, manage: true },
  },
  { id: 'custom', label: 'Custom', summary: 'The level and each toggle you choose', level: 'read', terms: null },
]

export function presetById(id: SharePresetId): SharePresetInfo {
  const preset = SHARE_PRESETS.find(p => p.id === id)
  if (!preset) throw new Error(`unknown share preset ${id}`)
  return preset
}

export function fullTerms(terms: ShareTermsLike): ShareTerms {
  return {
    access: terms.access === 'write' ? 'write' : 'read', rawData: terms.rawData, runScans: terms.runScans === true, useAgent: terms.useAgent === true,
    exploit: terms.exploit === true, manage: terms.manage === true,
  }
}

const sameTerms = (a: ShareTerms, b: ShareTerms) =>
  a.access === b.access && a.rawData === b.rawData && a.runScans === b.runScans && a.useAgent === b.useAgent
  && a.exploit === b.exploit && a.manage === b.manage

/** The preset a share is, else Custom. */
export function presetOf(terms: ShareTermsLike): SharePresetId {
  const full = fullTerms(terms)
  return SHARE_PRESETS.find(p => p.terms && sameTerms(p.terms, full))?.id ?? 'custom'
}

/** "Viewer (Read)", "Analyst (Read + Raw data & files)", "Custom (Read + Write + Exploitation & shells)". */
export function shareTermsLabel(terms: ShareTermsLike): string {
  const id = presetOf(terms)
  if (id !== 'custom') {
    const preset = presetById(id)
    return `${preset.label} (${preset.summary})`
  }
  if (terms.access !== 'write') return `Custom (${terms.rawData ? 'Read + Raw data & files' : 'Read'})`
  const full = fullTerms(terms)
  const on = SHARE_TOGGLES.filter(t => t.level === 'write' && full[t.id]).map(t => t.label)
  return `Custom (${['Read + Write', ...on].join(' + ')})`
}

/** The labels of the toggles a share holds, Raw data included once Read + Write includes it. */
export function toggleLabels(terms: ShareTermsLike): string[] {
  const full = fullTerms(terms)
  return SHARE_TOGGLES.filter(t => full[t.id]).map(t => t.label)
}

/** POST .../collaborators' level fields: the Read + Write toggles only with a write level. */
export function termsToBody(terms: ShareTerms): Record<string, unknown> {
  const body: Record<string, unknown> = { access: terms.access, rawData: terms.rawData }
  if (terms.access === 'write') {
    body.runScans = terms.runScans
    body.useAgent = terms.useAgent
    body.exploit = terms.exploit
    body.manage = terms.manage
  }
  return body
}

/**
 * Why the Read + Write presets and toggles are offered disabled, or null once they may be granted:
 * write sharing in force (the write switch on and Root's policy at write; the routes refuse a write
 * body otherwise, 409 `write_sharing_off` or `above_max_level`).
 */
export function writePresetsRefusal(
  flags: { sharingWrite?: boolean } | null | undefined,
  sharing: { enabled?: boolean; maxLevel: ShareAccessLevel } | null | undefined,
): string | null {
  if (flags?.sharingWrite !== true) return WRITE_PRESETS_COMING
  if (sharing?.maxLevel !== 'write') return 'The instance sharing policy allows Read shares only'
  return null
}

/** How the dialog offers a toggle or preset: as is, disabled with the reason, or not at all (a co-owner's "only what they hold"). */
export type ShareOffer = { state: 'offered' } | { state: 'disabled'; reason: string } | { state: 'hidden' }

const OFFERED: ShareOffer = { state: 'offered' }

/**
 * A Read + Write toggle as the person may grant it. Without a `grantable` answer (none yet, or an
 * older server) every toggle is offered and the route decides.
 */
export function toggleOffer(id: WriteToggleId, writeRefusal: string | null, grantable: Pick<ShareGrantable, 'toggles'> | null | undefined): ShareOffer {
  if (writeRefusal) return { state: 'disabled', reason: writeRefusal }
  const grant = grantable?.toggles[id]
  if (!grant || grant.grantable) return OFFERED
  return grant.code === 'not_held' ? { state: 'hidden' } : { state: 'disabled', reason: grant.reason }
}

/** A preset as the person may grant it: hidden when it holds a toggle they cannot see, disabled when it holds one they cannot grant. */
export function presetOffer(preset: SharePresetInfo, writeRefusal: string | null, grantable: Pick<ShareGrantable, 'toggles'> | null | undefined): ShareOffer {
  if (preset.level === 'read' || !preset.terms) return OFFERED
  if (writeRefusal) return { state: 'disabled', reason: writeRefusal }
  const terms = preset.terms
  const offers = SHARE_TOGGLES.filter(t => t.level === 'write' && terms[t.id]).map(t => toggleOffer(t.id as WriteToggleId, null, grantable))
  return offers.find(o => o.state === 'hidden') ?? offers.find(o => o.state === 'disabled') ?? OFFERED
}

/**
 * Whether turning these toggles on needs the owner's consent first: a spend toggle while the owner has
 * not allowed it. Unknown without a `grantable` answer (the route then answers 409 `owner_consent_required`).
 */
export function consentNeeded(turnedOn: Partial<Record<WriteToggleId, boolean>>, grantable: Pick<ShareGrantable, 'ownerConsent'> | null | undefined): boolean {
  if (!grantable || grantable.ownerConsent) return false
  return SPEND_TOGGLE_IDS.some(t => turnedOn[t] === true)
}

/** Raw data, Read + Write (which includes it) or the agent: what the collaborator sees can be copied. */
export function copyWarningApplies(terms: ShareTerms): boolean {
  return terms.access === 'write' || terms.rawData || terms.useAgent
}

/**
 * The share control a project row or the header offers: Share on the person's own project and on one
 * they co-own (Read + Write with Manage: they grant what they hold), Leave on one shared with them;
 * nothing while sharing is not in force or the row was read without `myAccess` (DV-30). Oversight and
 * break-glass are no share, so they offer neither. The routes still decide.
 */
export function shareActions(
  row: { myAccess?: MyAccess | null } | null | undefined,
  sharingInForce: boolean,
): { share: boolean; leave: boolean } {
  const access = row?.myAccess
  if (!sharingInForce || !access) return { share: false, leave: false }
  const shared = access.level !== 'owner' && access.via === 'share'
  const coOwner = shared && access.level === 'write' && access.toggles.manage === true
  return { share: access.level === 'owner' || coOwner, leave: shared }
}

/** A date input's day as the end of that day in the browser's time zone, ISO (what POST/PATCH take). */
export function endOfDayIso(day: string): string {
  const [y, m, d] = day.split('-').map(Number)
  return new Date(y, m - 1, d, 23, 59, 59).toISOString()
}

/** The date input value (YYYY-MM-DD, local) of an ISO instant; '' for none. */
export function dateInputValue(iso: string | null | undefined): string {
  if (!iso) return ''
  const at = new Date(iso)
  if (Number.isNaN(at.getTime())) return ''
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`
}

/** Today as a date input's `min`. */
export function todayInputValue(now: Date = new Date()): string {
  return dateInputValue(now.toISOString())
}
