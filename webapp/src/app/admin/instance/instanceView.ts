import type { PermissionId } from '@/lib/authz/permissions'
import type { Holds } from '../consoleSections'

/**
 * The Instance page's logic (step 6.7, GV-08, UI-04), kept apart from the screens so it is tested
 * alone: which panels a person sees, the security policy's fields with the bounds the route
 * enforces (lib/instanceSecurityPolicy.ts; that module is not imported here so its rules reach the
 * browser only as this copy, pinned against it by instanceView.test.ts), and where each platform
 * tool without a panel here lives.
 *
 * The page only hides; each write goes to the route that decides it: the security policy, the
 * public base URL, the sharing policy, the audit retention, the tunnel and the TrafficMind settings to
 * /api/admin/instance-settings, the default member set to /api/admin/permission-sets/[id], the
 * Nuclei templates to /api/nuclei-templates.
 */

/** GET /api/admin/instance-settings as the page reads it; every group is absent for whoever does not hold it. */
export interface InstanceSettingsView {
  canManageTunnels?: boolean
  canManageCapture?: boolean
  securityPolicy?: Record<string, unknown>
  canManageSecurityPolicy?: boolean
  canManageSharingPolicy?: boolean
  [key: string]: unknown
}

export type IntegerField =
  | 'passwordMinLength' | 'memberSessionTtlHours' | 'adminSessionTtlHours' | 'adminIdleMinutes'
  | 'inviteTtlHours' | 'resetTtlHours' | 'impersonationMaxMinutes'
export type BooleanField = 'passwordAskChangeIfShort' | 'impersonationReasonRequired' | 'impersonationNotifyTarget'
export type PolicyField = IntegerField | BooleanField

interface IntegerSpec { field: IntegerField; label: string; unit: string; min: number; max: number; hint: string }
interface BooleanSpec { field: BooleanField; label: string; hint: string }

export interface PolicyGroup {
  title: string
  integers: readonly IntegerSpec[]
  booleans: readonly BooleanSpec[]
}

/** The security policy as the page shows it, in groups; the bounds are the route's. */
export const SECURITY_POLICY_GROUPS: readonly PolicyGroup[] = [
  {
    title: 'Passwords',
    integers: [
      { field: 'passwordMinLength', label: 'Minimum password length', unit: 'characters', min: 12, max: 72,
        hint: 'New and changed passwords must be at least this long.' },
    ],
    booleans: [
      { field: 'passwordAskChangeIfShort', label: 'Ask for a new password when the current one is too short',
        hint: 'At sign-in, an account whose password is shorter than the minimum must change it.' },
    ],
  },
  {
    title: 'Sessions and links',
    integers: [
      { field: 'memberSessionTtlHours', label: 'Member session lifetime', unit: 'hours', min: 1, max: 8760,
        hint: 'A member signs in again after this long.' },
      { field: 'adminSessionTtlHours', label: 'Administrator session lifetime', unit: 'hours', min: 1, max: 168,
        hint: 'An administrator signs in again after this long.' },
      { field: 'adminIdleMinutes', label: 'Administrator idle timeout', unit: 'minutes', min: 5, max: 1440,
        hint: 'An administrator session left idle this long ends.' },
      { field: 'inviteTtlHours', label: 'Invite link lifetime', unit: 'hours', min: 1, max: 720,
        hint: 'An invite link stops working after this long.' },
      { field: 'resetTtlHours', label: 'Reset link lifetime', unit: 'hours', min: 1, max: 168,
        hint: 'A credential reset link stops working after this long.' },
    ],
    booleans: [],
  },
  {
    title: 'Acting as another account',
    integers: [
      { field: 'impersonationMaxMinutes', label: 'Longest act-as session', unit: 'minutes', min: 5, max: 720,
        hint: 'Acting as another account ends after this long.' },
    ],
    booleans: [
      { field: 'impersonationReasonRequired', label: 'Ask for a reason before acting as someone',
        hint: 'The reason is kept in the audit trail.' },
      { field: 'impersonationNotifyTarget', label: 'Tell the person an administrator acted as them',
        hint: 'They see it in their account activity.' },
    ],
  },
]

export const INTEGER_FIELDS: readonly IntegerSpec[] = SECURITY_POLICY_GROUPS.flatMap((g) => g.integers)
export const BOOLEAN_FIELDS: readonly BooleanSpec[] = SECURITY_POLICY_GROUPS.flatMap((g) => g.booleans)

/** The form's values: integers as typed (text), booleans as they are. */
export type PolicyDraft = Record<IntegerField, string> & Record<BooleanField, boolean>

export function policyDraftOf(policy: Record<string, unknown> | undefined): PolicyDraft {
  const draft = {} as PolicyDraft
  for (const { field } of INTEGER_FIELDS) {
    const v = policy?.[field]
    draft[field] = typeof v === 'number' ? String(v) : ''
  }
  for (const { field } of BOOLEAN_FIELDS) draft[field] = policy?.[field] === true
  return draft
}

/** Why each typed integer is refused, by field; empty when the draft can be sent. */
export function policyDraftErrors(draft: PolicyDraft): Partial<Record<IntegerField, string>> {
  const errors: Partial<Record<IntegerField, string>> = {}
  for (const { field, min, max, unit } of INTEGER_FIELDS) {
    const text = draft[field].trim()
    const n = Number(text)
    if (!/^\d+$/.test(text) || n < min || n > max) errors[field] = `A whole number of ${unit} from ${min} to ${max}.`
  }
  return errors
}

/** The fields whose value differs from the saved draft, typed as the route takes them. */
export function policyPatch(saved: PolicyDraft, draft: PolicyDraft): Partial<Record<PolicyField, number | boolean>> {
  const patch: Partial<Record<PolicyField, number | boolean>> = {}
  for (const { field } of INTEGER_FIELDS) {
    if (draft[field].trim() !== saved[field]) patch[field] = Number(draft[field].trim())
  }
  for (const { field } of BOOLEAN_FIELDS) {
    if (draft[field] !== saved[field]) patch[field] = draft[field]
  }
  return patch
}

/** How the stored public base URL reads: the route stores it without a trailing slash, or null. */
export function baseUrlOf(policy: Record<string, unknown> | undefined): string {
  return typeof policy?.publicBaseUrl === 'string' ? policy.publicBaseUrl : ''
}

export type PanelId =
  | 'security' | 'public-url' | 'sharing' | 'retention' | 'default-set' | 'llm-providers' | 'quotas' | 'tunnels' | 'traffic' | 'nuclei' | 'plugins'
  | 'other-tools'

export interface PanelInput {
  holds: Holds
  /** The instance settings the person may read; null when the route refused them (403). */
  settings: InstanceSettingsView | null
  /** Whether the settings carry the sharing policy (only with RBAC_SHARING_ENABLED on, to admins). */
  sharingPolicyShown: boolean
}

/** The panels this person sees, in page order. */
export function visiblePanels({ holds, settings, sharingPolicyShown }: PanelInput): PanelId[] {
  const panels: PanelId[] = []
  const admin = !!settings?.securityPolicy
  if (admin) panels.push('security', 'public-url')
  if (admin && sharingPolicyShown) panels.push('sharing')
  // The audit retention: to administrators, with RBAC_GOVERNANCE_ENABLED on (the route carries it then only).
  if (admin && settings?.auditRetention) panels.push('retention')
  if (admin && (holds('roles:manage') || holds('users:assign_permissions'))) panels.push('default-set')
  // Root's alone: instance:settings is held only by the confirmed Root (rootOnly).
  if (holds('instance:settings')) panels.push('llm-providers')
  if (holds('instance:quotas')) panels.push('quotas')
  if (settings?.canManageTunnels === true) panels.push('tunnels')
  if (settings?.canManageCapture === true) panels.push('traffic')
  if (holds('platform:nuclei_templates')) panels.push('nuclei')
  if (holds('platform:plugins')) panels.push('plugins')
  if (otherPlatformTools(holds).length) panels.push('other-tools')
  return panels
}

export interface PlatformToolLine {
  permission: PermissionId
  where: string
  href: string
  linkLabel: string
}

/**
 * The platform permissions that open this page but are used elsewhere: the page says where, so
 * whoever holds only one of them (a member keeping `platform:kali_terminal` or
 * `platform:shell_sessions` as an override, for example from before the upgrade) learns why the
 * console showed them Instance and where the tool is.
 */
const ELSEWHERE: readonly PlatformToolLine[] = [
  { permission: 'platform:kali_terminal', where: "The raw Kali terminal is the RedAmon Terminal tab of a project's graph page.",
    href: '/projects', linkLabel: 'Open your projects' },
  { permission: 'platform:shell_sessions', where: "Every Metasploit and shell session on the instance is in the Reverse Shell tab of a project's graph page.",
    href: '/projects', linkLabel: 'Open your projects' },
  { permission: 'platform:emergency_stop', where: "Emergency Pause All on a project's graph page stops every user's running agent runs.",
    href: '/projects', linkLabel: 'Open your projects' },
  { permission: 'platform:agent_mcp', where: "The agent's MCP servers are reloaded and the system MCP servers managed in Global Settings, MCP Tool Plugins.",
    href: '/settings?tab=mcp', linkLabel: 'Open MCP Tool Plugins' },
  { permission: 'platform:operations', where: "Every user's running and queued scans, agent runs and triage runs are in the console's Operations section.",
    href: '/admin/operations', linkLabel: 'Open Operations' },
]

export function otherPlatformTools(holds: Holds): PlatformToolLine[] {
  return ELSEWHERE.filter((t) => holds(t.permission))
}
