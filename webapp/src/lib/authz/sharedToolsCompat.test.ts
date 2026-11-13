/**
 * The escape hatch REDAMON_SHARED_TOOLS_COMPAT (HD-30, T27): it restores the five shared
 * tools only for accounts that existed when the hardened code first started (the
 * backfill's cutoff row), warns on every use and audits `rbac.compat_used` at most once per
 * account, tool and hour; it is never reachable from any other path. That F-02, F-04,
 * F-14, F-18, F-19 and F-20 call sites never consult it is asserted by their own tests
 * (steps 1.9-1.16); here, that nothing but sharedToolAccess reads the switch.
 *
 * @vitest-environment node
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const findFirst = vi.fn()
const create = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: { auditLog: { findFirst: (...a: unknown[]) => findFirst(...a), create: (...a: unknown[]) => create(...a) } },
}))

import {
  COMPAT_USED_ACTION, LEGACY_GRANTS_CUTOFF_ACTION, SHARED_TOOLS, legacyCutoff, resetSharedToolsForTests,
  sharedToolAccess, type SharedTool,
} from './sharedTools'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'

const CUTOFF = new Date('2026-11-11T08:00:00.000Z')
const HOUR = 3_600_000
let t = CUTOFF.getTime() + 10 * HOUR
const member = (id: string, createdAt: Date, legacyGrants: string[] = []) => ({ id, role: 'standard', legacyGrants, createdAt })
const PRE = member('pre', new Date(CUTOFF.getTime() - 86_400_000))
const POST = member('post', new Date(CUTOFF.getTime() + 1))
let warn: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  findFirst.mockReset().mockResolvedValue({ createdAt: CUTOFF })
  create.mockReset().mockResolvedValue({})
  resetSharedToolsForTests()
  setFlagsForTests({ sharedToolsCompat: true })
  t = CUTOFF.getTime() + 10 * HOUR
  setNowForTests(() => new Date(t))
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

const compatRows = () => create.mock.calls.map((c) => (c[0] as { data: Record<string, unknown> }).data)
  .filter((d) => d.action === COMPAT_USED_ACTION)

describe('the escape hatch', () => {
  test('compat off → no, and neither the cutoff nor the audit is touched', async () => {
    setFlagsForTests({})
    for (const tool of SHARED_TOOLS) {
      expect(await sharedToolAccess(PRE, tool)).toEqual({ allowed: false, via: null })
    }
    expect(findFirst).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()
    expect(warn).not.toHaveBeenCalled()
  })

  test('compat on and pre-cutoff → yes for the five tools', async () => {
    for (const tool of SHARED_TOOLS) {
      expect(await sharedToolAccess(PRE, tool), tool).toEqual({ allowed: true, via: 'compat' })
    }
  })

  test('post-cutoff → no', async () => {
    for (const tool of SHARED_TOOLS) {
      expect(await sharedToolAccess(POST, tool)).toEqual({ allowed: false, via: null })
    }
    expect(create).not.toHaveBeenCalled()
  })

  test('an account created at the cutoff instant counts as pre-upgrade', async () => {
    expect(await sharedToolAccess(member('edge', CUTOFF), 'tunnels')).toEqual({ allowed: true, via: 'compat' })
  })

  test('no cutoff row (the backfill never ran) → no, and it is read again next time', async () => {
    findFirst.mockResolvedValueOnce(null)
    expect(await sharedToolAccess(PRE, 'kali_terminal')).toEqual({ allowed: false, via: null })
    expect(await sharedToolAccess(PRE, 'kali_terminal')).toEqual({ allowed: true, via: 'compat' })
    expect(findFirst).toHaveBeenCalledTimes(2)
  })

  test('the cutoff row is read once per process, by its action', async () => {
    await sharedToolAccess(PRE, 'kali_terminal')
    await sharedToolAccess(PRE, 'tunnels')
    await sharedToolAccess(POST, 'tunnels')
    expect(await legacyCutoff()).toEqual(CUTOFF)
    expect(findFirst).toHaveBeenCalledTimes(1)
    expect(findFirst).toHaveBeenCalledWith({
      where: { action: LEGACY_GRANTS_CUTOFF_ACTION }, orderBy: { createdAt: 'asc' }, select: { createdAt: true },
    })
  })

  test('a failed cutoff read throws: it never reads as allowed', async () => {
    findFirst.mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1001' }))
    await expect(sharedToolAccess(PRE, 'kali_terminal')).rejects.toThrow('db down')
  })

  test('an admin or a legacy holder is never counted as a compat use', async () => {
    expect(await sharedToolAccess({ ...PRE, role: 'admin' }, 'tunnels')).toEqual({ allowed: true, via: 'admin' })
    expect(await sharedToolAccess(member('kept', PRE.createdAt, ['tunnels']), 'tunnels')).toEqual({ allowed: true, via: 'legacy' })
    expect(compatRows()).toEqual([])
    expect(warn).not.toHaveBeenCalled()
  })
})

describe('every compat use is visible', () => {
  test('a warning on every use, naming the account and the tool', async () => {
    await sharedToolAccess(PRE, 'emergency_stop_all')
    await sharedToolAccess(PRE, 'emergency_stop_all')
    expect(warn.mock.calls.map((c: unknown[]) => c[0])).toEqual([
      '[rbac] shared-tools compat used user=pre tool=emergency_stop_all',
      '[rbac] shared-tools compat used user=pre tool=emergency_stop_all',
    ])
  })

  test('an rbac.compat_used row naming the account and the tool', async () => {
    await sharedToolAccess(PRE, 'nuclei_templates_all')
    expect(compatRows()).toEqual([expect.objectContaining({
      actorId: 'pre', action: 'rbac.compat_used', targetType: 'shared_tool', targetId: 'nuclei_templates_all',
    })])
  })

  test('at most one row per account, tool and hour', async () => {
    const other = member('pre2', PRE.createdAt)
    await sharedToolAccess(PRE, 'kali_terminal')
    t += HOUR - 1
    await sharedToolAccess(PRE, 'kali_terminal')
    await sharedToolAccess(PRE, 'shell_sessions_all')
    await sharedToolAccess(other, 'kali_terminal')
    expect(compatRows().map((d) => `${d.actorId}:${d.targetId}`)).toEqual(['pre:kali_terminal', 'pre:shell_sessions_all', 'pre2:kali_terminal'])
    t += 1
    await sharedToolAccess(PRE, 'kali_terminal')
    expect(compatRows()).toHaveLength(4)
  })

  test('two uses at once write one row', async () => {
    await Promise.all([sharedToolAccess(PRE, 'tunnels'), sharedToolAccess(PRE, 'tunnels')])
    expect(compatRows()).toHaveLength(1)
  })

  test('a failed audit write never takes the tool away', async () => {
    create.mockRejectedValue(new Error('audit down'))
    vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(await sharedToolAccess(PRE, 'tunnels')).toEqual({ allowed: true, via: 'compat' })
  })

  test('a screen asking whether to offer the tool (record: false) is not a use: no warning, no row', async () => {
    expect(await sharedToolAccess(PRE, 'tunnels', { record: false })).toEqual({ allowed: true, via: 'compat' })
    expect(await sharedToolAccess(POST, 'tunnels', { record: false })).toEqual({ allowed: false, via: null })
    expect(warn).not.toHaveBeenCalled()
    expect(compatRows()).toEqual([])
    // The next real use is still recorded.
    await sharedToolAccess(PRE, 'tunnels')
    expect(compatRows()).toHaveLength(1)
  })
})

describe('F-02/F-04/F-14/F-18/F-19/F-20 paths never consult compat', () => {
  test('a name that is not one of the five shared tools is refused before the switch is read', async () => {
    for (const name of ['mcp_reload', 'mcp_manifest', 'tunnel_credentials', 'service_credentials', 'other_account_settings', 'ws_ticket']) {
      expect(await sharedToolAccess(PRE, name as SharedTool), name).toEqual({ allowed: false, via: null })
    }
    expect(findFirst).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()
  })

  test('only flags.ts, sharedTools.ts, the admin banner and the terminal tab read the switch in the webapp source', () => {
    const src = path.resolve(__dirname, '..', '..')
    const readers: string[] = []
    // Test code is out of scope, as the .test.ts(x) files are: a `__testing__/` double (such as
    // providers/__testing__/fakeAuth.ts, which fakes an RbacFlags value) never ships, because
    // lib/plugins/__testing__/noProductionImports.test.ts keeps every production module from
    // importing one, and Next does not route a `_` folder.
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const full = path.join(dir, name)
        if (statSync(full).isDirectory()) { if (name !== '__testing__') walk(full); continue }
        if (!/\.(ts|tsx|mjs|js)$/.test(name) || /\.test\.(ts|tsx)$/.test(name)) continue
        const text = readFileSync(full, 'utf8')
        if (text.includes('sharedToolsCompat') || text.includes('REDAMON_SHARED_TOOLS_COMPAT')) readers.push(path.relative(src, full))
      }
    }
    walk(src)
    // Step 1.18's admin banner: /api/auth/me tells admins whether the switch is on, and the banner
    // names it; neither opens a tool. Step 2.4's instance settings route names the switch in its
    // doc comment only: the tunnel holder of OQ-R3 (a) is admitted through sharedToolAccess('tunnels').
    // Step 3.12's terminal tab is shown while the switch is on, because an older account may still
    // open the terminal through it; the tab opens nothing: the ticket route decides, through
    // sharedToolAccess('kali_terminal').
    expect(readers.sort()).toEqual([
      'app/api/admin/instance-settings/route.ts', 'app/api/auth/me/route.ts', 'app/graph/components/ViewTabs/ViewTabs.tsx',
      'components/admin/CompatBanner.tsx', 'lib/authz/flags.ts', 'lib/authz/sharedTools.ts',
    ])
    // A screen learns the switch from /api/auth/me's flags (useRbacFlags), never from the environment.
    for (const screen of ['app/graph/components/ViewTabs/ViewTabs.tsx', 'components/admin/CompatBanner.tsx']) {
      expect(readFileSync(path.join(src, screen), 'utf8'), screen).not.toMatch(/process\.env/)
    }
  })
})
