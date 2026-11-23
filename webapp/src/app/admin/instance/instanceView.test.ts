/**
 * The Instance page's logic (step 6.7, GV-08): the panels each profile sees, the security policy's
 * bounds against the route's own parser, and the form diff the Save sends. The platform tools with
 * nothing to set here (TrafficMind, tunnels, plugins, the terminal and shells, the agent's MCP
 * servers, emergency stop, Operations) have no panel, and none of them opens the section.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/instance/instanceView.test.ts
 */
import { describe, test, expect } from 'vitest'
import { BUILTIN_ADMIN_PROFILES } from '@/lib/authz/builtinSets'
import type { PermissionId } from '@/lib/authz/permissions'
import { DEFAULT_EXPIRY_DAYS_BOUNDS } from '@/lib/authz/sharingPolicy'
import { SECURITY_POLICY_FIELDS, parseSecurityPolicyPatch } from '@/lib/instanceSecurityPolicy'
import { CONSOLE_SECTIONS } from '../consoleSections'
import {
  BOOLEAN_FIELDS, INTEGER_FIELDS, policyDraftErrors, policyDraftOf, policyPatch, visiblePanels,
  type InstanceSettingsView,
} from './instanceView'
import { EXPIRY_DAYS_BOUNDS } from './SharingPolicyPanel'
import { RETENTION_MAX_DAYS, retentionProblem } from './AuditRetentionPanel'
import { AUDIT_RETENTION_MAX_DAYS, AUDIT_RETENTION_MIN_DAYS, parseRetentionDays } from '@/lib/authz/auditRetention'

const profile = (slug: string) => BUILTIN_ADMIN_PROFILES.find((s) => s.id === `builtin:${slug}`)!.permissions
const holding = (held: readonly PermissionId[]) => (p: PermissionId) => held.includes(p)

const ADMIN_SETTINGS: InstanceSettingsView = {
  securityPolicy: { passwordMinLength: 12 }, canManageSecurityPolicy: false, canManageTunnels: true, canManageCapture: true,
}

const PLATFORM_USED_ELSEWHERE = [
  'platform:plugins', 'platform:traffic_capture', 'platform:tunnels', 'platform:agent_mcp', 'platform:emergency_stop',
  'platform:shell_sessions', 'platform:kali_terminal', 'platform:operations',
] as const

describe('the security policy fields', () => {
  test('the page edits every field of the route except the public base URL, which has its own panel', () => {
    const page = [...INTEGER_FIELDS.map((f) => f.field), ...BOOLEAN_FIELDS.map((f) => f.field), 'publicBaseUrl']
    expect(page.sort()).toEqual([...SECURITY_POLICY_FIELDS].sort())
  })

  test.each(INTEGER_FIELDS.map((f) => [f.field, f.min, f.max] as const))('%s: the page bounds are the route bounds (%i to %i)', (field, min, max) => {
    expect('patch' in parseSecurityPolicyPatch({ [field]: min })).toBe(true)
    expect('patch' in parseSecurityPolicyPatch({ [field]: max })).toBe(true)
    expect('error' in parseSecurityPolicyPatch({ [field]: min - 1 })).toBe(true)
    expect('error' in parseSecurityPolicyPatch({ [field]: max + 1 })).toBe(true)
  })

  test('the sharing panel expiry bound is the policy module bound', () => {
    expect([...EXPIRY_DAYS_BOUNDS]).toEqual([...DEFAULT_EXPIRY_DAYS_BOUNDS])
  })

  test('the Save sends only what changed, typed as the route takes it; an untouched form sends nothing', () => {
    const saved = policyDraftOf({ passwordMinLength: 12, adminIdleMinutes: 60, impersonationReasonRequired: false })
    expect(policyPatch(saved, saved)).toEqual({})
    const draft = { ...saved, passwordMinLength: ' 16 ', impersonationReasonRequired: true }
    expect(policyPatch(saved, draft)).toEqual({ passwordMinLength: 16, impersonationReasonRequired: true })
    expect('patch' in parseSecurityPolicyPatch(policyPatch(saved, draft))).toBe(true)
  })

  test('a value out of bounds or not a whole number is refused before anything is sent', () => {
    const saved = policyDraftOf({
      passwordMinLength: 12, memberSessionTtlHours: 168, adminSessionTtlHours: 12, adminIdleMinutes: 60,
      inviteTtlHours: 168, resetTtlHours: 4, impersonationMaxMinutes: 720,
    })
    expect(policyDraftErrors(saved)).toEqual({})
    const errors = policyDraftErrors({ ...saved, passwordMinLength: '8', adminIdleMinutes: '7.5', resetTtlHours: '' })
    expect(Object.keys(errors).sort()).toEqual(['adminIdleMinutes', 'passwordMinLength', 'resetTtlHours'])
    expect(errors.passwordMinLength).toBe('A whole number of characters from 12 to 72.')
  })
})

describe('the panels each profile sees', () => {
  test('Full admin: the Root-only panels to read, quotas and Nuclei; no tunnel, TrafficMind, Plugins or tools list', () => {
    const panels = visiblePanels({ holds: holding(profile('full-admin')), settings: ADMIN_SETTINGS, sharingPolicyShown: true })
    expect(panels).toEqual(['security', 'public-url', 'sharing', 'default-set', 'quotas', 'nuclei'])
  })

  // Step 6.11: the instance LLM providers are Root's alone (instance:settings is rootOnly).
  test('the confirmed Root (every permission): the instance LLM providers after the default set; Full admin: never', () => {
    const panels = visiblePanels({ holds: () => true, settings: ADMIN_SETTINGS, sharingPolicyShown: false })
    expect(panels.slice(0, 4)).toEqual(['security', 'public-url', 'default-set', 'llm-providers'])
    expect(visiblePanels({ holds: holding(profile('full-admin')), settings: ADMIN_SETTINGS, sharingPolicyShown: false })).not.toContain('llm-providers')
  })

  test('the sharing policy only when the route carries it (RBAC_SHARING_ENABLED on)', () => {
    const panels = visiblePanels({ holds: holding(profile('full-admin')), settings: ADMIN_SETTINGS, sharingPolicyShown: false })
    expect(panels).not.toContain('sharing')
  })

  test('a User manager: the policy panels to read and the default set, nothing of the platform', () => {
    const settings = { ...ADMIN_SETTINGS, canManageTunnels: false, canManageCapture: false }
    expect(visiblePanels({ holds: holding(profile('user-manager')), settings, sharingPolicyShown: false }))
      .toEqual(['security', 'public-url', 'default-set'])
  })

  test.each(PLATFORM_USED_ELSEWHERE)('a member holding %s alone: no panel, whatever the route answers', (permission) => {
    const holds = holding([permission])
    expect(visiblePanels({ holds, settings: null, sharingPolicyShown: false })).toEqual([])
    expect(visiblePanels({ holds, settings: { canManageTunnels: true, canManageCapture: true }, sharingPolicyShown: false })).toEqual([])
  })

  test('every permission that opens the Instance section has a panel here', () => {
    const instance = CONSOLE_SECTIONS.find((s) => s.id === 'instance')!
    const empty: PermissionId[] = []
    for (const p of instance.anyOf) {
      const settings: InstanceSettingsView | null = p === 'instance:settings' ? ADMIN_SETTINGS : null
      if (visiblePanels({ holds: holding([p]), settings, sharingPolicyShown: false }).length === 0) empty.push(p)
    }
    expect(empty).toEqual([])
  })
})

// Step 6.6: the audit retention panel, to administrators, only when the route carries it (governance on).
describe('the audit retention panel (step 6.6)', () => {
  const RETENTION = { days: null, pending: null, minDays: 90, delayDays: 7 }

  test('after the sharing policy, for every administrator, when the route carries it', () => {
    const settings = { ...ADMIN_SETTINGS, auditRetention: RETENTION }
    expect(visiblePanels({ holds: holding(profile('full-admin')), settings, sharingPolicyShown: true }).slice(0, 4))
      .toEqual(['security', 'public-url', 'sharing', 'retention'])
    const userManager = { ...settings, canManageTunnels: false, canManageCapture: false }
    expect(visiblePanels({ holds: holding(profile('user-manager')), settings: userManager, sharingPolicyShown: false }))
      .toEqual(['security', 'public-url', 'retention', 'default-set'])
  })

  test('not without it (RBAC_GOVERNANCE_ENABLED off), nor for a member', () => {
    expect(visiblePanels({ holds: holding(profile('full-admin')), settings: ADMIN_SETTINGS, sharingPolicyShown: false })).not.toContain('retention')
    const member: InstanceSettingsView = { canManageTunnels: true, canManageCapture: false, auditRetention: RETENTION }
    expect(visiblePanels({ holds: holding(['platform:nuclei_templates']), settings: member, sharingPolicyShown: false })).toEqual(['nuclei'])
  })

  test('the panel bound is the retention module bound, and its floor check refuses what the route refuses', () => {
    expect(RETENTION_MAX_DAYS).toBe(AUDIT_RETENTION_MAX_DAYS)
    for (const text of ['30', '89', '90.5', '', 'x', String(AUDIT_RETENTION_MAX_DAYS + 1)]) {
      expect(retentionProblem(text, AUDIT_RETENTION_MIN_DAYS), text).not.toBeNull()
      expect('error' in parseRetentionDays(Number(text) || text)).toBe(true)
    }
    for (const text of ['90', '120', String(AUDIT_RETENTION_MAX_DAYS)]) {
      expect(retentionProblem(text, AUDIT_RETENTION_MIN_DAYS), text).toBeNull()
      expect(parseRetentionDays(Number(text))).toEqual({ days: Number(text) })
    }
  })
})
