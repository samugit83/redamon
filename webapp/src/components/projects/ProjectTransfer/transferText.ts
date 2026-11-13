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
 * OQ-R8: a finding node's id embeds the user id of the owner whose scan minted it, and the transfer
 * keeps every id (Postgres references them), so a scan the new owner runs mints a new id for a finding
 * the old owner's scans had found.
 */
export const FINDING_IDS_NOTE =
  "Findings found before the transfer keep their history. A scan you run now records some findings it finds again " +
  "(GitHub, secret and JS findings among them) as new entries, since their ids name the owner whose scan found them: " +
  'a mute or verdict on the earlier entry does not carry over to the new one.'

export function clearedLine(c: ClearedSetting): string {
  return c.values && c.values.length ? `${c.label}: ${c.values.join(', ')}` : c.label
}

export const untilDate = (iso: string) =>
  new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
