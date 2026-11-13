/**
 * The Instance page's logic (step 6.7, GV-08): the panels each profile sees, the security policy's
 * bounds against the route's own parser, the form diff the Save sends, and where each platform tool
 * without a panel lives.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/instance/instanceView.test.ts
 */
import { describe, test, expect } from 'vitest'
import { BUILTIN_ADMIN_PROFILES } from '@/lib/authz/builtinSets'
import { PERMISSION_IDS, type PermissionId } from '@/lib/authz/permissions'
import { DEFAULT_EXPIRY_DAYS_BOUNDS } from '@/lib/authz/sharingPolicy'
import { SECURITY_POLICY_FIELDS, parseSecurityPolicyPatch } from '@/lib/instanceSecurityPolicy'
import { CONSOLE_SECTIONS } from '../consoleSections'
import {
  BOOLEAN_FIELDS, INTEGER_FIELDS, otherPlatformTools, policyDraftErrors, policyDraftOf, policyPatch, visiblePanels,
  type InstanceSettingsView,
} from './instanceView'
import { EXPIRY_DAYS_BOUNDS } from './SharingPolicyPanel'

const profile = (slug: string) => BUILTIN_ADMIN_PROFILES.find((s) => s.id === `builtin:${slug}`)!.permissions
const holding = (held: readonly PermissionId[]) => (p: PermissionId) => held.includes(p)

const ADMIN_SETTINGS: InstanceSettingsView = {
  securityPolicy: { passwordMinLength: 12 }, canManageSecurityPolicy: false, canManageTunnels: true, canManageCapture: true,
}

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
  test('Full admin: the Root-only panels to read, quotas, tunnel, TrafficMind, Nuclei, Plugins, and Operations named', () => {
    const panels = visiblePanels({ holds: holding(profile('full-admin')), settings: ADMIN_SETTINGS, sharingPolicyShown: true })
    expect(panels).toEqual(['security', 'public-url', 'sharing', 'default-set', 'quotas', 'tunnels', 'traffic', 'nuclei', 'plugins', 'other-tools'])
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

  test('a member holding platform:tunnels as an override: only the tunnel (the route gives no policy to a member)', () => {
    const settings: InstanceSettingsView = { canManageTunnels: true, canManageCapture: false }
    expect(visiblePanels({ holds: holding(['platform:tunnels']), settings, sharingPolicyShown: false })).toEqual(['tunnels'])
  })

  test.each(['platform:kali_terminal', 'platform:shell_sessions'] as const)(
    'a member keeping %s from before the upgrade: the route refuses the settings, the page says where the tool is',
    (permission) => {
      const holds = holding([permission])
      expect(visiblePanels({ holds, settings: null, sharingPolicyShown: false })).toEqual(['other-tools'])
      expect(otherPlatformTools(holds).map((t) => t.permission)).toEqual([permission])
    },
  )

  test('every permission that opens the Instance section has a panel or a line here', () => {
    const instance = CONSOLE_SECTIONS.find((s) => s.id === 'instance')!
    const empty: PermissionId[] = []
    for (const p of instance.anyOf) {
      const settings: InstanceSettingsView | null = p === 'instance:settings'
        ? ADMIN_SETTINGS
        : p === 'platform:tunnels' ? { canManageTunnels: true } : p === 'platform:traffic_capture' ? { canManageCapture: true } : null
      if (visiblePanels({ holds: holding([p]), settings, sharingPolicyShown: false }).length === 0) empty.push(p)
    }
    expect(empty).toEqual([])
  })

  test('the lines name real permissions and link inside the app', () => {
    const lines = otherPlatformTools(() => true)
    for (const t of lines) {
      expect(PERMISSION_IDS).toContain(t.permission)
      expect(t.href.startsWith('/')).toBe(true)
    }
  })
})
