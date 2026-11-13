/**
 * What a project read returns to someone who is not the project's owner (HD-27, SH-28).
 *
 * The registry names the columns that stay the owner's (`share: secret` in
 * recon_settings/registry.yaml): the credentials, the client's contacts, the Rules of Engagement
 * document and what was parsed from it, and the custom request-header lists. Every read a
 * non-owner can reach removes them here, so a column marked later is withheld everywhere at once.
 * The owner, and an admin acting as the owner (the access is the owner's), keep the full row.
 * Service callers read for the owner and never pass through this view: the agent (master key)
 * reads the whole row, a scan container the row less what scanReadView leaves out.
 */
import { NextResponse } from 'next/server'
import { shareSecretFields } from '@/lib/reconSettings/registry'
import type { PermissionId } from './permissions'

/** The level of the access a read was granted; null when none was decided, which reads as not owner. */
export interface ReadViewAccess {
  level: string
}

export const SHARE_SECRET_FIELDS: readonly string[] = Object.freeze(shareSecretFields().map(f => f.key))

const isOwner = (access: ReadViewAccess | null | undefined): boolean => access?.level === 'owner'

/** The row as `access` may read it: whole for the owner, without every `share: secret` column for anyone else. */
export function projectReadView<T extends object>(row: T, access: ReadViewAccess | null | undefined): Partial<T> {
  if (isOwner(access)) return row
  const view = { ...row } as Record<string, unknown>
  for (const key of SHARE_SECRET_FIELDS) delete view[key]
  return view as Partial<T>
}

/**
 * The owner's secret columns no scan reads: those that are not a recon setting (no runtime key),
 * such as the CypherFix GitHub token, the phishing SMTP settings and the RoE contacts and
 * document. A scan container faces the target, so its project read leaves them out
 * (GHSA-8whg-rvcr-r88r); the header lists and every other recon setting it scans with stay.
 */
export const SCAN_UNREAD_SECRET_FIELDS: readonly string[] = Object.freeze(
  shareSecretFields().filter(f => f.runtime_key === null).map(f => f.key))

/** The row as a scan container reads it: without SCAN_UNREAD_SECRET_FIELDS. */
export function scanReadView<T extends object>(row: T): Partial<T> {
  const view = { ...row } as Record<string, unknown>
  for (const key of SCAN_UNREAD_SECRET_FIELDS) delete view[key]
  return view as Partial<T>
}

/** The RoE document stays the owner's on a shared project (OQ-53): both of its downloads refuse anyone else. */
export const ROE_DOCUMENT_OWNER_ONLY = "Only the project's owner can download the rules of engagement document."

/**
 * The 403 of a read that only the owner may make although its permission is a read (the RoE
 * document, OQ-53): null for the owner. The body is the permission refusal's, with its own code.
 */
export function ownerOnlyRefusal(access: ReadViewAccess | null | undefined, permission: PermissionId, error: string): NextResponse | null {
  if (isOwner(access)) return null
  return NextResponse.json({ error, code: 'owner_only', permission }, { status: 403 })
}
