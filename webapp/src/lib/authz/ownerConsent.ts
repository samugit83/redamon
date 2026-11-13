/**
 * The owner's consent that collaborators may spend the project's owner credentials (C1; step 5.6;
 * SH-32, OQ-06): the `ProjectAccessPolicy` row's `ownerCredentialConsentAt`. A collaborator's run,
 * scan or LLM feature on a shared project spends the owner's providers and keys, so the toggles that
 * reach them (Run scans, Use AI agent, Exploitation & shells) count only while this consent exists
 * (projectAccess's `effectiveToggles`).
 *
 * The one reader and writer of the table (`project_access_policies`, one row per project). No row,
 * or a row whose consent is null, is no consent: every project from before the table keeps its
 * collaborators off the owner's keys. A client without the model (one generated before this schema,
 * or a test double that leaves it out) has no delegate: no consent can exist then either. A failed
 * read throws, it never reads as consent; a missing table (a build ahead of its `db push`) throws
 * `ConsentStoreMissing`.
 */
import { NextResponse } from 'next/server'
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { maxShareLevel, type SharingPolicy } from './sharingPolicy'

/**
 * The share toggles that spend the owner's credentials: a scan uses the owner's scan keys and AI
 * hooks, the agent and the LLM features the owner's providers, and a shell's `redagraph ask` the
 * owner's model through the terminal's run credential.
 */
export const SPEND_TOGGLES = ['runScans', 'useAgent', 'exploit'] as const

/** A share holding one of them: only then can the consent open anything, so only then is it read. */
export const holdsSpendToggle = (row: Partial<Record<(typeof SPEND_TOGGLES)[number], unknown>>): boolean =>
  SPEND_TOGGLES.some(t => row[t] === true)

export interface OwnerConsent {
  at: Date
  /** Who consented: the owner (null once that account is gone). */
  byId: string | null
}

type PolicyDelegate = Prisma.TransactionClient['projectAccessPolicy']

/** The client or a transaction: the consent is read and written through either. */
export type ConsentDb = { projectAccessPolicy: PolicyDelegate }

const CONSENT_SELECT = { ownerCredentialConsentAt: true, ownerCredentialConsentById: true } as const

/** The consent table cannot be read or written: it is not in this database (yet), or not in this client. */
export class ConsentStoreMissing extends Error {
  constructor() {
    super('the project access policy table is not available')
    this.name = 'ConsentStoreMissing'
  }
}

function policyTable(db: ConsentDb | null | undefined): PolicyDelegate | null {
  return (db as Partial<ConsentDb> | null | undefined)?.projectAccessPolicy ?? null
}

/** Prisma's "table does not exist" (P2021) is the store missing, not a failure of this request. */
function missingTable(err: unknown): never {
  if ((err as { code?: unknown } | null)?.code === 'P2021') throw new ConsentStoreMissing()
  throw err
}

const consentOf = (row: { ownerCredentialConsentAt: Date | null; ownerCredentialConsentById: string | null } | null): OwnerConsent | null =>
  row?.ownerCredentialConsentAt ? { at: row.ownerCredentialConsentAt, byId: row.ownerCredentialConsentById } : null

/** The project's consent now, or null. Read on every call (never cached): a withdrawal counts at once. */
export async function readOwnerConsent(projectId: string, db: ConsentDb = prisma): Promise<OwnerConsent | null> {
  const table = policyTable(db)
  if (!table || !projectId) return null
  return consentOf(await table.findUnique({ where: { projectId }, select: CONSENT_SELECT }).catch(missingTable))
}

/**
 * Of `projectIds`, the projects whose owner consents now: a project list's one read for all its write
 * shares, never one per row. Read as readOwnerConsent reads (never cached; no delegate, no consent).
 */
export async function readOwnerConsents(projectIds: readonly string[], db: ConsentDb = prisma): Promise<ReadonlySet<string>> {
  const table = policyTable(db)
  const ids = [...new Set(projectIds.filter(id => typeof id === 'string' && id !== ''))]
  if (!table || ids.length === 0) return new Set()
  const rows = await table.findMany({
    where: { projectId: { in: ids }, ownerCredentialConsentAt: { not: null } },
    select: { projectId: true },
  }).catch(missingTable)
  return new Set(rows.map(r => r.projectId))
}

/**
 * Records the consent (`by` the owner, now) or its withdrawal (null) through `tx`, the transaction of
 * its audit row. Answers the consent as stored.
 */
export async function writeOwnerConsent(
  tx: ConsentDb,
  projectId: string,
  consent: { at: Date; byId: string } | null,
): Promise<OwnerConsent | null> {
  const table = policyTable(tx)
  if (!table) throw new ConsentStoreMissing()
  const row = { ownerCredentialConsentAt: consent?.at ?? null, ownerCredentialConsentById: consent?.byId ?? null }
  return consentOf(await table.upsert({ where: { projectId }, create: { projectId, ...row }, update: row, select: CONSENT_SELECT }).catch(missingTable))
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
