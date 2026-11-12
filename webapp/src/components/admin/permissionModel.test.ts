/**
 * The client mirror of the permission rules (step 3.13): what a person may give, the PUT body of a
 * change, what a change gives as the server counts it, and when it takes the person's password.
 * The server (userPermissionAdmin.ts, step 3.11) stays the authority; these keep the screens honest.
 *
 * Run: npx vitest run --no-file-parallelism src/components/admin/permissionModel.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { changeBody, draftOf, givableFrom, givingOf, reasonText, stepUpNeeded } from './permissionModel'
import { memberSetList, profileList, viewOf } from './__testing__/permissionViews'

const NOW = Date.parse('2026-11-12T10:00:00Z')
const LATER = '2026-12-01T00:00:00.000Z'
const EVEN_LATER = '2027-01-01T00:00:00.000Z'
const PAST = '2026-11-01T00:00:00.000Z'
const sets = memberSetList().sets
const profiles = profileList().sets

describe('permission model', () => {
  test('givable: what is held, and what only an instance cap removes (permissionAdmin.ts givable)', () => {
    const me = viewOf({ userId: 'a', sets: [{ id: 'builtin:read-only-analyst' }], capped: ['self:presets'] })
    const g = givableFrom(me.explain)
    expect(g.has('graph:read')).toBe(true)
    expect(g.has('self:presets')).toBe(true)
    expect(g.has('recon:scan')).toBe(false)
  })

  test('the draft leaves out expired overrides; the body sends only what changed', () => {
    const view = viewOf({
      userId: 'm', sets: [{ id: 'builtin:read-only-analyst' }],
      overrides: [
        { permission: 'recon:scan', effect: 'grant', expiresAt: LATER, reason: null },
        { permission: 'scan:gvm', effect: 'grant', expiresAt: PAST, reason: null },
      ],
    })
    const draft = draftOf(view, NOW)
    expect(draft.overrides.map((o) => o.permission)).toEqual(['recon:scan'])
    expect(changeBody(view, { ...draft })).toBeNull()
    expect(changeBody(view, { ...draft, sets: [] })).toEqual({ sets: [] })
    expect(changeBody(view, { ...draft, overrides: [] })).toEqual({ overrides: [] })
    expect(changeBody(view, { ...draft, profile: 'builtin:user-manager' })).toBeNull()
  })

  test('giving: added sets, new or lengthened grants, lifted denies; shortening gives nothing', () => {
    const view = viewOf({
      userId: 'm', sets: [{ id: 'builtin:read-only-analyst' }],
      overrides: [
        { permission: 'recon:scan', effect: 'grant', expiresAt: LATER, reason: null },
        { permission: 'agent:chat', effect: 'deny', expiresAt: null, reason: null },
      ],
    })
    const start = draftOf(view, NOW)
    expect(givingOf(view, { ...start, sets: [...start.sets, 'builtin:recon-operator'] }, sets, profiles, NOW))
      .toEqual(expect.arrayContaining(['recon:partial', 'agent:fireteam']))
    const lengthen = { ...start, overrides: [{ ...start.overrides[0], expiresAt: EVEN_LATER }, start.overrides[1]] }
    expect(givingOf(view, lengthen, sets, profiles, NOW)).toEqual(['recon:scan'])
    const shorten = { ...start, overrides: [{ ...start.overrides[0], expiresAt: '2026-11-20T00:00:00.000Z' }, start.overrides[1]] }
    expect(givingOf(view, shorten, sets, profiles, NOW)).toEqual([])
    expect(givingOf(view, { ...start, overrides: [start.overrides[0]] }, sets, profiles, NOW)).toEqual(['agent:chat'])
  })

  test('an admin\'s new profile gives its contents; every change to an admin takes the password', () => {
    const admin = viewOf({ userId: 'x', accountType: 'admin', profile: 'builtin:security-auditor', sets: [{ id: 'builtin:security-auditor' }] })
    const draft = { ...draftOf(admin, NOW), profile: 'builtin:user-manager' }
    expect(changeBody(admin, draft)).toEqual({ adminProfileId: 'builtin:user-manager' })
    expect(givingOf(admin, draft, sets, profiles, NOW)).toEqual(expect.arrayContaining(['users:create', 'users:assign_permissions']))
    expect(stepUpNeeded(admin, [])).toBe('admin')
  })

  test('a member: the password only for a cross-tenant tool or an exploitation right (ID-25)', () => {
    const m = viewOf({ userId: 'm' })
    expect(stepUpNeeded(m, ['recon:scan', 'graph:read'])).toBeNull()
    expect(stepUpNeeded(m, ['recon:scan', 'agent:kali_exec', 'platform:tunnels'])).toEqual(['platform:tunnels', 'agent:kali_exec'])
  })

  test('every reason has a line', () => {
    const set = { id: 'builtin:no-access', name: 'No access', kind: 'member' as const, via: 'dangling' as const }
    expect([
      reasonText({ effect: 'grant', kind: 'root' }),
      reasonText({ effect: 'deny', kind: 'root_unconfirmed' }),
      reasonText({ effect: 'grant', kind: 'set', set }),
      reasonText({ effect: 'grant', kind: 'legacy_grant', grant: 'tunnels' }),
      reasonText({ effect: 'grant', kind: 'phase1_admin' }),
      reasonText({ effect: 'deny', kind: 'inactive', status: 'disabled' }),
      reasonText({ effect: 'deny', kind: 'instance_cap', setting: 'AGENT_IN_THE_LOOP_ENABLED' }),
      reasonText({ effect: 'deny', kind: 'not_granted', sets: [] }),
    ]).toEqual([
      'Root holds every permission',
      "Root's own permission: Root must be confirmed first",
      'granted by the set No access (every set assigned is gone)',
      'granted by the legacy access tunnels, kept from before permission sets',
      'admins manage admins while the identity switch is off',
      'the account is disabled',
      'Agent in the Loop is switched off on this instance (AGENT_IN_THE_LOOP_ENABLED)',
      'no set in force holds it',
    ])
  })
})
