/**
 * The instance sharing policy (step 4.2, SH-21; feature document §6.5): the shape of
 * `InstanceSettings.sharingPolicy`, its defaults, how a stored value is read and how a change is
 * checked, and the reader the share routes, `projectAccess()` and /api/auth/me use.
 *
 *   - The stored `{}` (the column default, what every instance holds after the upgrade) reads as
 *     the defaults: sharing off, Read + Write allowed later, Exploitation not grantable by members,
 *     no default expiry, admins see every share. A missing setting reads as its default.
 *   - Anything invalid (not an object, a setting of the wrong type or out of bounds) reads as the
 *     defaults as a whole, so sharing stays off, with a warning naming the setting, never the value.
 *     An unknown setting (a later release's) is ignored, and kept when Root saves.
 *   - A change names known settings only, each with a valid value; the first refused one is named.
 *   - The reader reads nothing with RBAC_SHARING_ENABLED off; on, one instance row, cached for
 *     RBAC_AUTHZ_CACHE_MS like the Root, dropped by a write in this process.
 *   - "Sharing in force" (what the screens ask) is the switch AND `enabled`; the level a share may
 *     be granted at is Read unless the write switch is on and the policy allows Read + Write.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/sharingPolicy.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({
  instance: null as Record<string, unknown> | null,
  reads: 0,
  fail: false,
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    instanceSettings: {
      findUnique: async (args: unknown) => {
        // One indexed read of the one column: nothing else of the row (its secrets) is loaded.
        expect(args).toEqual({ where: { id: 'instance' }, select: { sharingPolicy: true } })
        h.reads++
        if (h.fail) throw Object.assign(new Error('connection refused'), { code: 'P1001' })
        return h.instance && structuredClone(h.instance)
      },
    },
  },
}))

import {
  SHARING_POLICY_DEFAULTS, SHARING_POLICY_FIELDS, changedSharingPolicyFields, clearSharingPolicyCacheForTests,
  invalidateSharingPolicy, parseSharingPolicy, parseSharingPolicyPatch, sharingInForce, sharingPolicyInForce,
  sharingPolicyToStore,
} from './sharingPolicy'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'

const DEFAULTS = {
  enabled: false, maxLevel: 'write', membersMayGrantExploit: false, defaultExpiryDays: null, adminsSeeAllShares: true,
}
const ON = { identity: true, permissions: true, sharing: true }
let clock = new Date('2026-11-13T10:00:00.000Z')
let warn: { mock: { calls: unknown[][] } }

beforeEach(() => {
  h.instance = { id: 'instance', sharingPolicy: {} }
  h.reads = 0
  h.fail = false
  clock = new Date('2026-11-13T10:00:00.000Z')
  setNowForTests(() => clock)
  setFlagsForTests(ON)
  clearSharingPolicyCacheForTests()
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const warnings = () => warn.mock.calls.map((c) => String(c[0]))

describe('the defaults', () => {
  test('the stored {} reads as the defaults: sharing off', () => {
    expect(SHARING_POLICY_DEFAULTS).toEqual(DEFAULTS)
    expect(Object.isFrozen(SHARING_POLICY_DEFAULTS)).toBe(true)
    expect(parseSharingPolicy({})).toEqual(DEFAULTS)
    expect(warnings()).toEqual([])
  })

  test('the five settings, in the order the views list them', () => {
    expect(SHARING_POLICY_FIELDS).toEqual(['enabled', 'maxLevel', 'membersMayGrantExploit', 'defaultExpiryDays', 'adminsSeeAllShares'])
  })

  test('a missing setting reads as its default; the stored ones are kept', () => {
    expect(parseSharingPolicy({ enabled: true, maxLevel: 'read' })).toEqual({ ...DEFAULTS, enabled: true, maxLevel: 'read' })
    expect(parseSharingPolicy({ defaultExpiryDays: 30, adminsSeeAllShares: false, membersMayGrantExploit: true }))
      .toEqual({ ...DEFAULTS, defaultExpiryDays: 30, adminsSeeAllShares: false, membersMayGrantExploit: true })
    expect(warnings()).toEqual([])
  })

  test('a whole valid policy reads as stored', () => {
    const full = { enabled: true, maxLevel: 'read', membersMayGrantExploit: true, defaultExpiryDays: 3650, adminsSeeAllShares: false }
    expect(parseSharingPolicy(full)).toEqual(full)
    expect(parseSharingPolicy({ ...full, defaultExpiryDays: 1 }).defaultExpiryDays).toBe(1)
  })

  test('an unknown setting (a later release) is ignored without a warning', () => {
    expect(parseSharingPolicy({ enabled: true, laterSetting: 'x' })).toEqual({ ...DEFAULTS, enabled: true })
    expect(warnings()).toEqual([])
  })
})

describe('invalid JSON -> defaults with a warning', () => {
  test.each([
    ['null', null],
    ['an array', [{ enabled: true }]],
    ['a string', '{"enabled":true}'],
    ['a number', 1],
    ['a boolean', true],
    ['undefined (no row value)', undefined],
  ])('not an object (%s): the defaults, sharing off', (_what, stored) => {
    expect(parseSharingPolicy(stored)).toEqual(DEFAULTS)
    expect(warnings()).toEqual([expect.stringMatching(/^\[rbac\] the stored sharing policy is invalid \(not an object\)/)])
  })

  test.each([
    ['enabled', 'yes'],
    ['enabled', 1],
    ['maxLevel', 'Read'],
    ['maxLevel', 'owner'],
    ['maxLevel', null],
    ['membersMayGrantExploit', 'false'],
    ['adminsSeeAllShares', null],
    ['defaultExpiryDays', 0],
    ['defaultExpiryDays', -5],
    ['defaultExpiryDays', 3651],
    ['defaultExpiryDays', 7.5],
    ['defaultExpiryDays', '30'],
  ])('%s = %j: the whole policy reads as the defaults (enabled stays false), the setting named', (field, value) => {
    const policy = parseSharingPolicy({ enabled: true, maxLevel: 'read', [field]: value })
    expect(policy).toEqual(DEFAULTS)
    const lines = warnings()
    expect(lines).toHaveLength(1)
    expect(lines[0]).toContain(`(${field})`)
    expect(lines[0]).toMatch(/sharing stays off/)
    expect(lines[0]).not.toContain(JSON.stringify(value))
  })

  test('the same problem is logged once per process, a different one again', () => {
    parseSharingPolicy({ enabled: 'on' })
    parseSharingPolicy({ enabled: 'on' })
    parseSharingPolicy({ maxLevel: 'none' })
    expect(warnings()).toHaveLength(2)
  })

  test('a parsed policy is a new object each time: a caller changing it changes no other read', () => {
    const a = parseSharingPolicy({})
    a.enabled = true
    expect(parseSharingPolicy({}).enabled).toBe(false)
    expect(SHARING_POLICY_DEFAULTS.enabled).toBe(false)
  })
})

describe('a change (the instance settings PUT)', () => {
  test('known settings with valid values make the patch', () => {
    expect(parseSharingPolicyPatch({ enabled: true, defaultExpiryDays: 90 })).toEqual({ patch: { enabled: true, defaultExpiryDays: 90 } })
    expect(parseSharingPolicyPatch({ defaultExpiryDays: null, maxLevel: 'read' })).toEqual({ patch: { defaultExpiryDays: null, maxLevel: 'read' } })
    expect(parseSharingPolicyPatch({})).toEqual({ patch: {} })
  })

  test.each([
    [null, 'sharingPolicy'],
    [[], 'sharingPolicy'],
    ['{}', 'sharingPolicy'],
    [{ enabled: 'true' }, 'sharingPolicy.enabled'],
    [{ maxLevel: 'admin' }, 'sharingPolicy.maxLevel'],
    [{ membersMayGrantExploit: 0 }, 'sharingPolicy.membersMayGrantExploit'],
    [{ adminsSeeAllShares: 'no' }, 'sharingPolicy.adminsSeeAllShares'],
    [{ defaultExpiryDays: 0 }, 'sharingPolicy.defaultExpiryDays'],
    [{ defaultExpiryDays: 3651 }, 'sharingPolicy.defaultExpiryDays'],
    [{ defaultExpiryDays: 1.5 }, 'sharingPolicy.defaultExpiryDays'],
    [{ directoryVisible: true }, 'sharingPolicy.directoryVisible'],
    [{ enabled: true, unknown: 1 }, 'sharingPolicy.unknown'],
  ])('%j is refused, naming %s', (raw, field) => {
    const parsed = parseSharingPolicyPatch(raw)
    expect(parsed).toEqual({ error: { field, message: expect.any(String) } })
  })

  test('the settings whose value differs from the policy in force', () => {
    const current = parseSharingPolicy({ enabled: true, defaultExpiryDays: 30 })
    expect(changedSharingPolicyFields(current, { enabled: true, defaultExpiryDays: 30 })).toEqual([])
    expect(changedSharingPolicyFields(current, { enabled: false, defaultExpiryDays: 30, maxLevel: 'write' })).toEqual(['enabled'])
    expect(changedSharingPolicyFields(current, { defaultExpiryDays: null, adminsSeeAllShares: false }))
      .toEqual(['defaultExpiryDays', 'adminsSeeAllShares'])
  })

  test('what is stored: every setting written out, the change applied, a later release\'s setting kept', () => {
    expect(sharingPolicyToStore({}, { enabled: true })).toEqual({ ...DEFAULTS, enabled: true })
    expect(sharingPolicyToStore({ enabled: true, laterSetting: { a: 1 } }, { defaultExpiryDays: 7 }))
      .toEqual({ ...DEFAULTS, enabled: true, defaultExpiryDays: 7, laterSetting: { a: 1 } })
  })

  test('an invalid stored value is replaced by the defaults plus the change (the save repairs it)', () => {
    expect(sharingPolicyToStore('garbage', { enabled: true })).toEqual({ ...DEFAULTS, enabled: true })
    expect(sharingPolicyToStore({ enabled: 'on', maxLevel: 'read' }, { adminsSeeAllShares: false }))
      .toEqual({ ...DEFAULTS, adminsSeeAllShares: false })
  })
})

describe('the reader', () => {
  test('switch off: nothing is read, no policy', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    h.instance = { id: 'instance', sharingPolicy: { enabled: true } }
    expect(await sharingPolicyInForce()).toBeNull()
    expect(await sharingInForce()).toEqual({ enabled: false, maxLevel: 'read' })
    expect(h.reads).toBe(0)
  })

  test('switch on: the instance row, parsed', async () => {
    h.instance = { id: 'instance', sharingPolicy: { enabled: true, maxLevel: 'read', defaultExpiryDays: 14 } }
    expect(await sharingPolicyInForce()).toEqual({ ...DEFAULTS, enabled: true, maxLevel: 'read', defaultExpiryDays: 14 })
    expect(h.reads).toBe(1)
  })

  test('a missing instance row (the boot backfill has not filled it) reads as the defaults: sharing off', async () => {
    h.instance = null
    expect(await sharingPolicyInForce()).toEqual(DEFAULTS)
    expect(await sharingInForce()).toEqual({ enabled: false, maxLevel: 'read' })
  })

  test('cached for RBAC_AUTHZ_CACHE_MS: one read per bound, then read again', async () => {
    vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '5000')
    await sharingPolicyInForce()
    h.instance = { id: 'instance', sharingPolicy: { enabled: true } }
    clock = new Date(clock.getTime() + 4999)
    expect((await sharingPolicyInForce())!.enabled).toBe(false)
    expect(h.reads).toBe(1)
    clock = new Date(clock.getTime() + 2)
    expect((await sharingPolicyInForce())!.enabled).toBe(true)
    expect(h.reads).toBe(2)
  })

  test('fresh reads the row; a write in this process drops the cached policy', async () => {
    await sharingPolicyInForce()
    h.instance = { id: 'instance', sharingPolicy: { enabled: true } }
    expect((await sharingPolicyInForce({ fresh: true }))!.enabled).toBe(true)
    h.instance = { id: 'instance', sharingPolicy: { enabled: false } }
    expect((await sharingPolicyInForce())!.enabled).toBe(true)
    invalidateSharingPolicy()
    expect((await sharingPolicyInForce())!.enabled).toBe(false)
    expect(h.reads).toBe(3)
  })

  test('RBAC_AUTHZ_CACHE_MS=0: every call reads', async () => {
    vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '0')
    await sharingPolicyInForce()
    await sharingPolicyInForce()
    expect(h.reads).toBe(2)
  })

  test('a cached policy is frozen: no caller can change what the next one reads', async () => {
    const policy = await sharingPolicyInForce()
    expect(Object.isFrozen(policy)).toBe(true)
  })

  test('a failed read throws and caches nothing (the caller decides; /api/auth/me logs it)', async () => {
    h.fail = true
    await expect(sharingPolicyInForce()).rejects.toThrow()
    h.fail = false
    expect(await sharingPolicyInForce()).toEqual(DEFAULTS)
    expect(h.reads).toBe(2)
  })
})

describe('sharing in force (switch AND policy)', () => {
  test('the switch on and the policy enabled: in force; Read while the write switch is off', async () => {
    h.instance = { id: 'instance', sharingPolicy: { enabled: true } }
    expect(await sharingInForce()).toEqual({ enabled: true, maxLevel: 'read' })
  })

  test('the write switch on: the policy\'s level', async () => {
    setFlagsForTests({ ...ON, sharingWrite: true })
    h.instance = { id: 'instance', sharingPolicy: { enabled: true } }
    expect(await sharingInForce()).toEqual({ enabled: true, maxLevel: 'write' })
    clearSharingPolicyCacheForTests()
    h.instance = { id: 'instance', sharingPolicy: { enabled: true, maxLevel: 'read' } }
    expect(await sharingInForce()).toEqual({ enabled: true, maxLevel: 'read' })
  })

  test('the policy disabled (the stored {}): not in force', async () => {
    expect(await sharingInForce()).toEqual({ enabled: false, maxLevel: 'read' })
  })

  test('the switch on but its requirement off reads off (flags chain): nothing read', async () => {
    setFlagsForTests({ identity: true, sharing: true })
    expect(await sharingInForce()).toEqual({ enabled: false, maxLevel: 'read' })
    expect(h.reads).toBe(0)
  })
})
