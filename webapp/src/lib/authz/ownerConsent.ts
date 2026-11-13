/**
 * The owner's consent that collaborators may spend the project's owner credentials (C1; step 5.6;
 * SH-32, OQ-06): the `ProjectAccessPolicy` row's `ownerCredentialConsentAt`. A collaborator's run,
 * scan or LLM feature on a shared project spends the owner's providers and keys, so the toggles that
 * reach them (Run scans, Use AI agent, Exploitation & shells) count only while this consent exists
 * (projectAccess's `effectiveToggles`).
 *
 * The one reader and writer of the table. Its Prisma delegate exists only once the model is in the
 * generated client: until then no consent can exist (every read answers none, a write throws
 * `ConsentStoreMissing`), so nothing a collaborator does spends the owner's keys. A failed read
 * throws: it never reads as consent.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { maxShareLevel, type SharingPolicy } from './sharingPolicy'

/**
 * The share toggles that spend the owner's credentials: a scan uses the owner's scan keys and AI
 * hooks, the agent and the LLM features the owner's providers, and a shell's `redagraph ask` the
 * owner's model through the terminal's run credential.
 */
export const SPEND_TOGGLES = ['runScans', 'useAgent', 'exploit'] as const

export interface OwnerConsent {
  at: Date
  /** Who consented: the owner (null once that account is gone). */
  byId: string | null
}

interface PolicyRow {
  ownerCredentialConsentAt: Date | null
  ownerCredentialConsentById: string | null
}

const CONSENT_SELECT = { ownerCredentialConsentAt: true, ownerCredentialConsentById: true } as const

interface PolicyTable {
  findUnique(args: { where: { projectId: string }; select: typeof CONSENT_SELECT }): Promise<PolicyRow | null>
  upsert(args: {
    where: { projectId: string }
    create: { projectId: string } & PolicyRow
    update: PolicyRow
    select: typeof CONSENT_SELECT
  }): Promise<PolicyRow>
}

/** The consent table's writes cannot run: its model is not in this build's database client yet. */
export class ConsentStoreMissing extends Error {
  constructor() {
    super('the project access policy table is not available in this build')
    this.name = 'ConsentStoreMissing'
  }
}

function policyTable(db: unknown): PolicyTable | null {
  return (db as { projectAccessPolicy?: PolicyTable } | null)?.projectAccessPolicy ?? null
}

const consentOf = (row: PolicyRow | null): OwnerConsent | null =>
  row?.ownerCredentialConsentAt ? { at: row.ownerCredentialConsentAt, byId: row.ownerCredentialConsentById } : null

/** The project's consent now, or null. Read on every call (never cached): a withdrawal counts at once. */
export async function readOwnerConsent(projectId: string, db: unknown = prisma): Promise<OwnerConsent | null> {
  const table = policyTable(db)
  if (!table || !projectId) return null
  return consentOf(await table.findUnique({ where: { projectId }, select: CONSENT_SELECT }))
}

/**
 * Records the consent (`by` the owner, now) or its withdrawal (null) through `tx`, the transaction of
 * its audit row. Answers the consent as stored.
 */
export async function writeOwnerConsent(
  tx: unknown,
  projectId: string,
  consent: { at: Date; byId: string } | null,
): Promise<OwnerConsent | null> {
  const table = policyTable(tx)
  if (!table) throw new ConsentStoreMissing()
  const row: PolicyRow = { ownerCredentialConsentAt: consent?.at ?? null, ownerCredentialConsentById: consent?.byId ?? null }
  return consentOf(await table.upsert({ where: { projectId }, create: { projectId, ...row }, update: row, select: CONSENT_SELECT }))
}

/**
 * The share routes' check (POST and PATCH .../collaborators): while write sharing is in force, granting
 * a toggle that spends the owner's credentials needs the owner's consent first, whoever grants it
 * (a co-owner only while it exists). 409 `owner_consent_required`; null when allowed or not asked.
 * With write sharing not in force nothing is read and the route's own refusal answers as before.
 */
export async function spendToggleConsentRefusal(
  projectId: string,
  policy: Readonly<SharingPolicy>,
  body: Record<string, unknown>,
): Promise<NextResponse | null> {
  if (maxShareLevel(policy) !== 'write') return null
  const asked = SPEND_TOGGLES.filter(t => body[t] === true)
  if (asked.length === 0 || (await readOwnerConsent(projectId)) !== null) return null
  return NextResponse.json({
    error: "Run scans, Use AI agent and Exploitation & shells spend the project owner's credentials: the owner must allow it for this project first.",
    code: 'owner_consent_required',
    toggles: asked,
  }, { status: 409 })
}
