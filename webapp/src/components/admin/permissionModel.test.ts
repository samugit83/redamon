/**
 * The client mirror of the permission rules (step 3.13): what a person may give, the PUT body of a
 * change, what a change gives as the server counts it, and when it takes the person's password.
 * The server (userPermissionAdmin.ts, step 3.11) stays the authority; these keep the screens honest.
 *
 * Run: npx vitest run --no-file-parallelism src/components/admin/permissionModel.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  changeBody, draftChanges, draftOf, givableFrom, givingOf, heldDiff, offeredMemberSets, previewOf, reasonText, setRelations,
  stepUpNeeded,
  type SetOption,
} from './permissionModel'
import { memberSetList, profileList, setsOf, viewOf } from './__testing__/permissionViews'

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

describe('the preview of a draft (capabilities.ts, client side)', () => {
  const source = { sets: memberSetList(), profiles: profileList() }
  const marco = () => viewOf({
    userId: 'm', sets: [{ id: 'builtin:read-only-analyst' }],
    overrides: [{ permission: 'scan:gvm', effect: 'grant', expiresAt: LATER, reason: null }],
  })
  const heldIn = (explain: { permission: string; held: boolean }[]) => explain.filter((e) => e.held).map((e) => e.permission)

  test('an unchanged draft previews exactly what is saved', () => {
    const view = marco()
    const preview = previewOf(view, draftOf(view, NOW), source, NOW)!
    expect(heldIn(preview.explain)).toEqual(view.held)
    expect(heldDiff(view.explain, preview.explain)).toEqual({ gained: [], lost: [] })
  })

  test('sets only add: ticking Recon operator gains what Read-only analyst lacks, loses nothing', () => {
    const view = marco()
    const draft = { ...draftOf(view, NOW), sets: ['builtin:read-only-analyst', 'builtin:recon-operator'] }
    const preview = previewOf(view, draft, source, NOW)!
    const diff = heldDiff(view.explain, preview.explain)
    expect(diff.lost).toEqual([])
    expect(new Set(diff.gained)).toEqual(new Set(setsOf('builtin:recon-operator').filter((p) => !view.held.includes(p))))
    expect(preview.sets.map((s) => `${s.name}/${s.via}`)).toEqual(['Read-only analyst/assigned', 'Recon operator/assigned'])
  })

  test('no set ticked: a member follows the instance default, else Default member', () => {
    const view = marco()
    const none = { ...draftOf(view, NOW), sets: [] }
    expect(previewOf(view, none, source, NOW)!.sets.map((s) => `${s.name}/${s.via}`)).toEqual(['Default member/default'])
    const recon = { sets: memberSetList([], 'builtin:recon-operator'), profiles: null }
    expect(previewOf(view, none, recon, NOW)!.sets.map((s) => `${s.name}/${s.via}`)).toEqual(['Recon operator/instance_default'])
    expect(previewOf(view, none, { sets: null, profiles: null }, NOW)).toBeNull()
  })

  test('a deny wins over every set; an expired override counts for nothing; an admin permission is never granted by override', () => {
    const view = marco()
    const draft = {
      ...draftOf(view, NOW),
      overrides: [
        { permission: 'graph:read' as const, effect: 'deny' as const, expiresAt: null, reason: null },
        { permission: 'recon:scan' as const, effect: 'grant' as const, expiresAt: PAST, reason: null },
        { permission: 'users:read' as const, effect: 'grant' as const, expiresAt: null, reason: null },
      ],
    }
    const diff = heldDiff(view.explain, previewOf(view, draft, source, NOW)!.explain)
    // Registry order.
    expect(diff.lost).toEqual(['scan:gvm', 'graph:read'])
    expect(diff.gained).toEqual([])
  })

  test('what the form cannot change is carried over: an instance switch still denies', () => {
    const view = viewOf({ userId: 'm', sets: [{ id: 'builtin:automation' }], capped: ['self:mcp_tokens'] })
    const preview = previewOf(view, { ...draftOf(view, NOW), sets: ['builtin:default-member'] }, source, NOW)!
    const mcp = preview.explain.find((e) => e.permission === 'self:mcp_tokens')!
    expect(mcp.held).toBe(false)
    expect(mcp.reasons.map((r) => r.kind)).toEqual(['set', 'instance_cap'])
  })

  test('a custom set: read from the list, gone means No access, unread means no preview', () => {
    const view = marco()
    const custom: SetOption = {
      id: 'set-1', kind: 'member', name: 'Reports', description: null, permissions: ['reports:read', 'users:read'],
      builtin: false, holders: 0, instanceDefault: false,
    }
    const draft = { ...draftOf(view, NOW), sets: ['set-1'], overrides: [] }
    const withCustom = previewOf(view, draft, { sets: memberSetList([custom]), profiles: null }, NOW)!
    expect(heldIn(withCustom.explain)).toEqual(['reports:read'])
    const gone = previewOf(view, draft, { sets: memberSetList(), profiles: null }, NOW)!
    expect(gone.sets.map((s) => `${s.name}/${s.via}`)).toEqual(['No access/dangling'])
    expect(heldIn(gone.explain)).toEqual([])
    expect(previewOf(view, draft, { sets: null, profiles: null }, NOW)).toBeNull()
  })

  test('an admin: no profile is Full admin; a narrower profile loses the platform tools', () => {
    const view = viewOf({
      userId: 'a', accountType: 'admin',
      sets: [{ id: 'builtin:full-admin', via: 'default' }, { id: 'builtin:default-member', via: 'default' }],
    })
    expect(heldDiff(view.explain, previewOf(view, draftOf(view, NOW), source, NOW)!.explain)).toEqual({ gained: [], lost: [] })
    const diff = heldDiff(view.explain, previewOf(view, { ...draftOf(view, NOW), profile: 'builtin:user-manager' }, source, NOW)!.explain)
    expect(diff.gained).toEqual([])
    expect(diff.lost).toContain('platform:plugins')
    expect(diff.lost).not.toContain('users:read')
  })

  test('the edits, item by item', () => {
    const view = marco()
    const edits = draftChanges(view, {
      sets: ['builtin:recon-operator'],
      overrides: [{ permission: 'scan:gvm', effect: 'grant', expiresAt: EVEN_LATER, reason: null }, { permission: 'recon:scan', effect: 'deny', expiresAt: null, reason: 'x' }],
      profile: null,
    })
    expect(edits.setsAdded).toEqual(['builtin:recon-operator'])
    expect(edits.setsRemoved).toEqual(['builtin:read-only-analyst'])
    expect(edits.overridesAdded.map((o) => o.permission)).toEqual(['recon:scan'])
    expect(edits.overridesChanged.map((o) => o.permission)).toEqual(['scan:gvm'])
    expect(edits.overridesRemoved).toEqual([])
    expect(edits.profile).toBeNull()
    expect(edits.count).toBe(4)
    expect(draftChanges(view, draftOf(view, NOW)).count).toBe(0)
  })

  test('how the built-in sets overlap', () => {
    const byName = (n: string) => sets.find((s) => s.name === n)!
    const names = (list: SetOption[]) => list.map((s) => s.name)
    expect(names(setRelations(byName('Default member'), sets).same)).toEqual(['Red-team operator'])
    const recon = setRelations(byName('Recon operator'), sets)
    expect(names(recon.includes)).toEqual(['Read-only analyst', 'Automation'])
    expect(names(recon.within)).toEqual(['Default member', 'Red-team operator'])
    expect(setRelations(byName('No access'), sets)).toEqual({ same: [], includes: [], within: [] })
  })
})

test('the sets offered when giving one: Default member only where the account already holds it', () => {
  const ids = (list: SetOption[]) => list.map((s) => s.id)
  expect(ids(offeredMemberSets(sets))).not.toContain('builtin:default-member')
  expect(ids(offeredMemberSets(sets))).toContain('builtin:red-team-operator')
  expect(ids(offeredMemberSets(sets, ['builtin:default-member']))).toContain('builtin:default-member')
  expect(ids(offeredMemberSets(profiles))).toEqual([])
})
