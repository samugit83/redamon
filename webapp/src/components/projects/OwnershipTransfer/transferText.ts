/**
 * The words the ownership transfer screens share (step 5.12): who a person is, what a transfer does,
 * and what the new owner is told about the findings their own scans will create (OQ-R8, default).
 */
import type { ClearedSetting, TransferPerson } from '@/lib/authz/ownershipTransfer'

/** Fired after an offer is made, accepted, declined, cancelled or a re-pick list dismissed: screens read again. */
export const PROJECT_TRANSFER_CHANGED_EVENT = 'redamon:project-transfer-changed'

export function personName(p: TransferPerson | null | undefined): string {
  if (!p) return 'someone'
  return p.name && p.email ? `${p.name} (${p.email})` : p.name || p.email || 'an account that no longer exists'
}

/** What the old owner does after the transfer, said of them (the recipient's banner). */
export const ROLE_TEXT = {
  'co-owner': 'stays on as a co-owner (Read + Write with every toggle and Manage)',
  leave: 'leaves the project (their conversations there stay with it, read-only, naming them)',
} as const

/** The same, said to the owner offering it. */
export const OWN_ROLE_TEXT = {
  'co-owner': 'stay on as a co-owner (Read + Write with every toggle and Manage)',
  leave: 'leave the project (your conversations there stay with it, read-only, naming you)',
} as const

/**
 * OQ-R8 (default until answered): a finding node's id embeds the user id of the owner whose scan minted it,
 * and the transfer keeps every id (Postgres references them). A scan the new owner runs mints a new id for
 * a finding the old owner's scans had found, and the source's prune then removes the old-id node (unless a
 * person muted or judged it), taking the remediation and captured-traffic links to it along.
 */
export const FINDING_IDS_NOTE =
  'Some findings found before the transfer (GitHub, secret and JS findings among them) have ids that name the owner ' +
  'whose scan found them. A scan run after the transfer records such a finding again as a new entry, and the earlier entry is ' +
  'removed at that source\'s next run unless a person muted or judged it; fix items and captured requests linked to it ' +
  'lose that link. Mutes and verdicts do not carry over to the new entry.'

/** A transfer whose graph may be partly moved holds the project until it completes or is put back. */
export const SPLIT_NOTE = (undo: 'decline' | 'cancel') =>
  "The project's graph may be partly moved, so the project is held: nothing can scan or run on it until the transfer " +
  `is completed (accept again) or the graph is put back (${undo}).`

export function clearedLine(c: ClearedSetting): string {
  return c.values && c.values.length ? `${c.label}: ${c.values.join(', ')}` : c.label
}

export const untilDate = (iso: string) =>
  new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
