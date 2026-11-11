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
  grants: { grant: LegacyGrant; state: 'pending' | 'kept' }[]
}

export interface LegacyGrantsAnswer {
  holders: LegacyHolderView[]
  pending: number
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
  'The Kali terminal, every shell session and the tunnel settings are now an admin\'s. Members who used them before the update keep them as legacy grants until you review them on this page.',
  'Acting as, resetting, demoting or deleting another admin asks for your own password, and the last admin with a password cannot be demoted or deleted.',
  'Other accounts\' settings, model providers, skills and MCP servers are shown masked and are no longer changed by an admin, except for passwordless managed accounts.',
]

export const MEMBER_CHANGE_LINES: readonly string[] = [
  "Emergency stop stops only their own agent runs; admins still stop everyone's.",
  'Nuclei templates: they upload and delete only their own.',
  'Tunnel: only admins and members keeping the tunnel grant change it; the others see its status.',
  "Shell sessions: they see their own projects' sessions; the all-sessions console needs the sessions grant.",
  "Kali terminal: needs the terminal grant, and warns that other projects' files are visible there.",
  'MCP servers: only admins add, test or load stdio servers.',
]

export const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`
