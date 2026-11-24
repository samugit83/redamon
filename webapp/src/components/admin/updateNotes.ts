/**
 * The texts and answer shapes of the admin update cards and banners (step 1.18). Client
 * safe: no server import. The member lines are the upgrade preview's (`MEMBER_CHANGES` in
 * scripts/rbac-upgrade-preview.mjs, with no template file counted); a test keeps them equal,
 * so the operator's terminal and the admins' card say the same thing.
 */

export type LegacyGrant = 'kali_terminal' | 'shell_sessions' | 'tunnels'

export const LEGACY_GRANT_LABELS: Record<LegacyGrant, string> = {
  kali_terminal: 'Kali terminal',
  shell_sessions: 'All shell sessions',
  tunnels: 'Tunnel settings',
}

export interface LegacyHolderView {
  id: string
  name: string
  email: string
  /** `expiresAt`: with the permissions switch on, when the override keeping a grant ends (null: never). */
  grants: { grant: LegacyGrant; state: 'pending' | 'kept'; expiresAt?: string | null }[]
}

export interface LegacyGrantsAnswer {
  holders: LegacyHolderView[]
  pending: number
  /** The permissions switch is on: a Keep is an override that ends after `keepDays` days. */
  overrides?: boolean
  keepDays?: number
}

export interface LegacyDecisionAnswer {
  changed?: boolean | number
  terminal?: { closed?: number; error?: string }
  terminals?: { closed: number; failed: number }
}

export interface WhatsNewAnswer {
  dismissed: boolean
  applies: boolean
  stdioMembers: { id: string; name: string; email: string; servers: number }[]
}

/** Fired after a legacy grant decision, so the header's review banner reads the count again. */
export const LEGACY_GRANTS_CHANGED_EVENT = 'redamon:legacy-grants-changed'

export const LEGACY_REVIEW_ANCHOR = 'legacy-access'

export const ADMIN_CHANGE_LINES: readonly string[] = [
  'The Kali terminal and every shell session are now an admin\'s, and turning a tunnel on needs the tunnel grant: each person\'s tunnel runs in their own Kali sandbox, with their own credentials. Members who used them before the update keep them as legacy grants until you review them on this page.',
  'Acting as, resetting, demoting or deleting another admin asks for your own password, and the last admin with a password cannot be demoted or deleted.',
  'Other accounts\' settings, model providers, skills and MCP servers are shown masked and are no longer changed by an admin, except for passwordless managed accounts.',
]

export const MEMBER_CHANGE_LINES: readonly string[] = [
  "Emergency stop stops only their own agent runs; admins still stop everyone's.",
  'Nuclei templates: they upload and delete only their own.',
  'Tunnel: each person has their own, in their own Kali sandbox; turning it on needs the tunnel grant (admins, and members keeping it), and anyone can turn theirs off.',
  "Shell sessions: they see their own projects' sessions and their own sandbox's background jobs; the all-sessions console needs the sessions grant.",
  "Kali terminal: needs the terminal grant, and opens in their own Kali sandbox.",
  'MCP servers: only admins add, test or load stdio servers.',
]

export const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`
