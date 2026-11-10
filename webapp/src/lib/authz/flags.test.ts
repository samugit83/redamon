/**
 * The RBAC feature switches (T10, DV-01): parsing, the dependency chain and the
 * test hook. Each test imports a fresh module, because "warns once" is per process.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const NAMES = [
  'REDAMON_SHARED_TOOLS_COMPAT',
  'RBAC_IDENTITY_ENABLED',
  'RBAC_PERMISSIONS_ENABLED',
  'RBAC_SHARING_ENABLED',
  'RBAC_SHARING_WRITE_ENABLED',
  'RBAC_GOVERNANCE_ENABLED',
] as const

const ALL_OFF = {
  sharedToolsCompat: false,
  identity: false,
  permissions: false,
  sharing: false,
  sharingWrite: false,
  governance: false,
}

async function freshFlags() {
  vi.resetModules()
  return import('./flags')
}

function rbacWarnings(spy: ReturnType<typeof vi.spyOn>): string[] {
  return spy.mock.calls.map((c: unknown[]) => String(c[0])).filter((m: string) => m.startsWith('[rbac]'))
}

let warn: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  // The developer's shell or a CI job may export a switch; every test starts from unset.
  for (const name of NAMES) vi.stubEnv(name, undefined)
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
})

afterEach(() => {
  vi.unstubAllEnvs()
  warn.mockRestore()
})

describe('rbacFlags()', () => {
  test('every switch is off when unset', async () => {
    const { rbacFlags } = await freshFlags()
    expect(rbacFlags()).toEqual(ALL_OFF)
    expect(rbacWarnings(warn)).toEqual([])
  })

  test('the recognised off values are off and do not warn', async () => {
    const { rbacFlags } = await freshFlags()
    for (const value of ['', 'false', '0', 'no', ' FALSE ']) {
      vi.stubEnv('RBAC_IDENTITY_ENABLED', value)
      expect(rbacFlags().identity).toBe(false)
    }
    expect(rbacWarnings(warn)).toEqual([])
  })

  test('true, 1 and yes turn a switch on', async () => {
    const { rbacFlags } = await freshFlags()
    for (const value of ['true', '1', 'yes', 'TRUE', ' Yes ']) {
      vi.stubEnv('RBAC_IDENTITY_ENABLED', value)
      expect(rbacFlags().identity).toBe(true)
    }
    expect(rbacWarnings(warn)).toEqual([])
  })

  test('every switch reads its own variable', async () => {
    const { rbacFlags } = await freshFlags()
    // Turned on one at a time, in chain order, so a swapped variable shows.
    const steps: Array<[string, keyof typeof ALL_OFF]> = [
      ['REDAMON_SHARED_TOOLS_COMPAT', 'sharedToolsCompat'],
      ['RBAC_IDENTITY_ENABLED', 'identity'],
      ['RBAC_PERMISSIONS_ENABLED', 'permissions'],
      ['RBAC_GOVERNANCE_ENABLED', 'governance'],
      ['RBAC_SHARING_ENABLED', 'sharing'],
      ['RBAC_SHARING_WRITE_ENABLED', 'sharingWrite'],
    ]
    const expected = { ...ALL_OFF }
    for (const [name, flag] of steps) {
      vi.stubEnv(name, 'true')
      expected[flag] = true
      expect(rbacFlags()).toEqual(expected)
    }
    expect(rbacWarnings(warn)).toEqual([])
  })

  test('an unrecognised value is off and warns once', async () => {
    const { rbacFlags } = await freshFlags()
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'enabled')
    expect(rbacFlags().identity).toBe(false)
    expect(rbacFlags().identity).toBe(false)
    expect(rbacFlags().identity).toBe(false)
    const lines = rbacWarnings(warn)
    expect(lines).toHaveLength(1)
    expect(lines[0]).toMatch(/^\[rbac\] unrecognised value for RBAC_IDENTITY_ENABLED\b/)
    // The value itself is never logged: an operator may paste anything into .env.
    expect(lines[0]).not.toContain('enabled')
  })

  test('permissions without identity reads off', async () => {
    const { rbacFlags } = await freshFlags()
    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', 'true')
    expect(rbacFlags().permissions).toBe(false)
    expect(rbacFlags().permissions).toBe(false)
    const lines = rbacWarnings(warn)
    expect(lines).toHaveLength(1)
    expect(lines[0]).toMatch(/RBAC_PERMISSIONS_ENABLED/)
    expect(lines[0]).toMatch(/RBAC_IDENTITY_ENABLED/)

    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    expect(rbacFlags()).toMatchObject({ identity: true, permissions: true })
  })

  test('sharing without permissions reads off, and so does everything after it', async () => {
    const { rbacFlags } = await freshFlags()
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    vi.stubEnv('RBAC_SHARING_ENABLED', 'true')
    vi.stubEnv('RBAC_SHARING_WRITE_ENABLED', 'true')
    expect(rbacFlags()).toEqual({ ...ALL_OFF, identity: true })
  })

  test('sharing write without sharing reads off', async () => {
    const { rbacFlags } = await freshFlags()
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', 'true')
    vi.stubEnv('RBAC_SHARING_WRITE_ENABLED', 'yes')
    expect(rbacFlags()).toEqual({ ...ALL_OFF, identity: true, permissions: true })
    const lines = rbacWarnings(warn)
    expect(lines).toHaveLength(1)
    expect(lines[0]).toMatch(/RBAC_SHARING_WRITE_ENABLED.*RBAC_SHARING_ENABLED/)
  })

  test('governance without permissions reads off', async () => {
    const { rbacFlags } = await freshFlags()
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    vi.stubEnv('RBAC_GOVERNANCE_ENABLED', '1')
    expect(rbacFlags()).toEqual({ ...ALL_OFF, identity: true })
    expect(rbacWarnings(warn)).toHaveLength(1)

    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', '1')
    expect(rbacFlags()).toMatchObject({ permissions: true, governance: true, sharing: false })
  })

  test('compat is independent', async () => {
    const { rbacFlags } = await freshFlags()
    vi.stubEnv('REDAMON_SHARED_TOOLS_COMPAT', 'true')
    expect(rbacFlags()).toEqual({ ...ALL_OFF, sharedToolsCompat: true })

    for (const name of NAMES) vi.stubEnv(name, 'true')
    vi.stubEnv('REDAMON_SHARED_TOOLS_COMPAT', 'false')
    expect(rbacFlags()).toEqual({
      sharedToolsCompat: false,
      identity: true,
      permissions: true,
      sharing: true,
      sharingWrite: true,
      governance: true,
    })
    expect(rbacWarnings(warn)).toEqual([])
  })

  test('the result is a copy a caller cannot use to change the switches', async () => {
    const { rbacFlags } = await freshFlags()
    const flags = rbacFlags()
    expect(Object.isFrozen(flags)).toBe(true)
    expect(rbacFlags()).not.toBe(flags)
  })
})

describe('setFlagsForTests', () => {
  test('overrides the environment, missing switches read off', async () => {
    const { rbacFlags, setFlagsForTests } = await freshFlags()
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    vi.stubEnv('REDAMON_SHARED_TOOLS_COMPAT', 'true')
    setFlagsForTests({ governance: false })
    expect(rbacFlags()).toEqual(ALL_OFF)
    setFlagsForTests({ identity: true, permissions: true, governance: true })
    expect(rbacFlags()).toEqual({ ...ALL_OFF, identity: true, permissions: true, governance: true })
  })

  test('the dependency chain still applies to an override', async () => {
    const { rbacFlags, setFlagsForTests } = await freshFlags()
    setFlagsForTests({ sharing: true, sharingWrite: true })
    expect(rbacFlags()).toEqual(ALL_OFF)
  })

  test('null restores the environment', async () => {
    const { rbacFlags, setFlagsForTests } = await freshFlags()
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    setFlagsForTests({})
    expect(rbacFlags().identity).toBe(false)
    setFlagsForTests(null)
    expect(rbacFlags().identity).toBe(true)
  })

  test('setFlagsForTests throws in production', async () => {
    const { rbacFlags, setFlagsForTests } = await freshFlags()
    vi.stubEnv('NODE_ENV', 'production')
    expect(() => setFlagsForTests({ identity: true })).toThrow(/tests only/)
    vi.stubEnv('NODE_ENV', 'test')
    expect(rbacFlags().identity).toBe(false)
  })
})
