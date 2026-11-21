/**
 * PUT /api/users/[id]/settings, the `featureModels` branch (Models by feature).
 *
 * A feature's model decides whose provider keys that feature spends, so the
 * branch is stricter than the rest of the PUT: only a browser session may set
 * it, only for the user it is acting as (never through the admin bypass of
 * requireUserAccess, never with a service key). A refused or invalid change
 * stops the whole PUT before anything is written. The merge is one tagged
 * `$executeRaw`, so two tabs saving different features cannot drop each
 * other's key.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpsert = vi.fn()
const mockExecuteRaw = vi.fn()
const mockExecuteRawUnsafe = vi.fn()
const mockRotationFindMany = vi.fn()
const mockRequireUserAccess = vi.fn()
const mockIsInternal = vi.fn()
const mockIsScanner = vi.fn()
const mockGetSession = vi.fn()
const mockRequireEff = vi.fn()
const mockWriteAudit = vi.fn()
const mockOrchestratorFetch = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      upsert: (...a: unknown[]) => mockUpsert(...a),
    },
    apiKeyRotationConfig: { findMany: (...a: unknown[]) => mockRotationFindMany(...a) },
    // No plugin installed: featureModels.plugins.test.ts owns the plugin keys.
    pluginInstall: { findMany: async () => [] },
    $executeRaw: (...a: unknown[]) => mockExecuteRaw(...a),
    $executeRawUnsafe: (...a: unknown[]) => mockExecuteRawUnsafe(...a),
  },
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => mockRequireUserAccess(...a),
  isInternalRequest: (...a: unknown[]) => mockIsInternal(...a),
  isScannerRequest: (...a: unknown[]) => mockIsScanner(...a),
  getSession: () => mockGetSession(),
}))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: () => mockRequireEff() }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => mockWriteAudit(...a) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => mockOrchestratorFetch(...a) }))

import { GET, PUT } from './route'

type Row = Record<string, unknown> & { featureModels: Record<string, string> }

const USER = 'alice'
let row: Row | null

function baseRow(featureModels: Record<string, string> = {}): Row {
  return {
    userId: USER,
    shodanApiKey: 'STORED-SHODAN-KEY-9999',
    tunnelsEnabled: false,
    captureProxyEnabled: true,
    featureModels,
  }
}

function put(body: unknown, id = USER) {
  return PUT(
    new NextRequest(`http://x/api/users/${id}/settings`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
    { params: Promise.resolve({ id }) },
  )
}

/** Every write the route can make. */
function writes() {
  return {
    upsert: mockUpsert.mock.calls.length,
    raw: mockExecuteRaw.mock.calls.length,
    unsafe: mockExecuteRawUnsafe.mock.calls.length,
    audit: mockWriteAudit.mock.calls.length,
  }
}
const NO_WRITES = { upsert: 0, raw: 0, unsafe: 0, audit: 0 }

beforeEach(() => {
  vi.clearAllMocks()
  row = baseRow({ codefix: 'claude-opus-4-6' })
  // A tiny stand-in for the table: the selects the route makes, the upserts,
  // and the jsonb merge the raw UPDATE performs in Postgres.
  mockFindUnique.mockImplementation(async (args: { select?: Record<string, boolean> }) => {
    if (!row) return null
    return args.select ? { featureModels: { ...row.featureModels } } : { ...row }
  })
  mockUpsert.mockImplementation(async ({ update, create }: { update: Record<string, unknown>; create: Record<string, unknown> }) => {
    row = row ? { ...row, ...update } : { ...baseRow(), shodanApiKey: '', ...create }
    return { ...row }
  })
  mockExecuteRaw.mockImplementation(async (_strings: TemplateStringsArray, set: string, removed: string[]) => {
    const merged = { ...row!.featureModels, ...JSON.parse(set) }
    for (const k of removed) delete merged[k]
    row!.featureModels = merged
    return 1
  })
  mockRotationFindMany.mockResolvedValue([])
  mockRequireUserAccess.mockResolvedValue(null)
  mockIsInternal.mockReturnValue(false)
  mockIsScanner.mockReturnValue(false)
  mockGetSession.mockResolvedValue({ userId: USER, role: 'standard' })
  mockRequireEff.mockResolvedValue({ userId: USER })
})

describe('validation: 400 and nothing written', () => {
  const invalid: Array<[string, unknown]> = [
    ['a string', 'claude-opus-4-6'],
    ['an array', ['triage']],
    ['null', null],
    ['a number', 5],
    ['an unknown feature', { graph_query: 'gpt-5' }],
    ['a non-string model', { triage: 42 }],
    ['a null model', { triage: null }],
    ['a model over 200 characters', { triage: 'm'.repeat(201) }],
    ['Bedrock for the preset generator', { preset_generator: 'bedrock/anthropic.claude-3-5-sonnet' }],
    ['one bad key among good ones', { triage: 'claude-haiku-4-5', nope: 'x' }],
  ]
  for (const [name, featureModels] of invalid) {
    test(name, async () => {
      const res = await put({ featureModels, shodanApiKey: 'NEW-KEY-SHOULD-NOT-LAND' })
      expect(res.status).toBe(400)
      expect(typeof (await res.json()).error).toBe('string')
      expect(writes()).toEqual(NO_WRITES)
      expect(row!.shodanApiKey).toBe('STORED-SHODAN-KEY-9999')
    })
  }
})

describe('who may write it', () => {
  test('an admin not acting as the target is refused (403), even though requireUserAccess lets admins through', async () => {
    mockGetSession.mockResolvedValue({ userId: 'root', role: 'admin' })
    mockRequireEff.mockResolvedValue({ userId: 'root' })
    const res = await put({ featureModels: { triage: 'gpt-5' }, shodanApiKey: 'NEW' })
    expect(res.status).toBe(403)
    expect(writes()).toEqual(NO_WRITES)
    expect(row!.shodanApiKey).toBe('STORED-SHODAN-KEY-9999')
  })

  test('an internal-key request is refused (403)', async () => {
    mockIsInternal.mockReturnValue(true)
    mockGetSession.mockResolvedValue(null)
    const res = await put({ featureModels: { triage: 'gpt-5' } })
    expect(res.status).toBe(403)
    expect(writes()).toEqual(NO_WRITES)
  })

  test('a scanner-key request is refused (403)', async () => {
    mockIsScanner.mockReturnValue(true)
    const res = await put({ featureModels: { triage: 'gpt-5' } })
    expect(res.status).toBe(403)
    expect(writes()).toEqual(NO_WRITES)
  })

  test('no effective user is 401', async () => {
    mockRequireEff.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    const res = await put({ featureModels: { triage: 'gpt-5' } })
    expect(res.status).toBe(401)
    expect(writes()).toEqual(NO_WRITES)
  })

  test('the ordinary ownership gate still runs first', async () => {
    mockRequireUserAccess.mockResolvedValue(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))
    const res = await put({ featureModels: { triage: 'gpt-5' } }, 'bob')
    expect(res.status).toBe(403)
    expect(mockRequireEff).not.toHaveBeenCalled()
    expect(writes()).toEqual(NO_WRITES)
  })

  test('an admin acting as the target may write it', async () => {
    mockGetSession.mockResolvedValue({ userId: 'root', role: 'admin' })
    mockRequireEff.mockResolvedValue({ userId: USER })
    const res = await put({ featureModels: { triage: 'gpt-5' } })
    expect(res.status).toBe(200)
    expect(row!.featureModels).toEqual({ codefix: 'claude-opus-4-6', triage: 'gpt-5' })
  })
})

describe('the write', () => {
  test('one TAGGED $executeRaw with the jsonb merge, the key removal and updated_at; never $executeRawUnsafe', async () => {
    const res = await put({ featureModels: { triage: 'claude-haiku-4-5', codefix: '' } })
    expect(res.status).toBe(200)

    expect(mockExecuteRaw).toHaveBeenCalledTimes(1)
    expect(mockExecuteRawUnsafe).not.toHaveBeenCalled()
    const [strings, set, removed, userId] = mockExecuteRaw.mock.calls[0]
    // Called as a template tag: the first argument is a TemplateStringsArray,
    // so every value travels as a bound parameter, not spliced SQL.
    expect(Array.isArray(strings)).toBe(true)
    expect(Object.prototype.hasOwnProperty.call(strings, 'raw')).toBe(true)
    const sql = (strings as TemplateStringsArray).join('$')
    expect(sql).toContain('UPDATE user_settings')
    expect(sql).toContain('::jsonb')
    expect(sql).toContain('::text[]')
    expect(sql).toContain('updated_at = now()')
    expect(sql).toContain('WHERE user_id =')
    expect(sql).not.toContain('claude-haiku')
    expect(JSON.parse(set)).toEqual({ triage: 'claude-haiku-4-5' })
    expect(removed).toEqual(['codefix'])
    expect(userId).toBe(USER)
  })

  test("'' removes the key", async () => {
    const res = await put({ featureModels: { codefix: '' } })
    expect(res.status).toBe(200)
    const [, set, removed] = mockExecuteRaw.mock.calls[0]
    expect(JSON.parse(set)).toEqual({})
    expect(removed).toEqual(['codefix'])
    expect(row!.featureModels).toEqual({})
    expect((await res.json()).featureModels).toEqual({})
  })

  test('a missing row is created before the UPDATE', async () => {
    row = null
    const res = await put({ featureModels: { triage: 'gpt-5' } })
    expect(res.status).toBe(200)
    expect(mockUpsert).toHaveBeenCalledWith({ where: { userId: USER }, update: {}, create: { userId: USER } })
    const upsertOrder = mockUpsert.mock.invocationCallOrder[0]
    const rawOrder = mockExecuteRaw.mock.invocationCallOrder[0]
    expect(upsertOrder).toBeLessThan(rawOrder)
    expect(row!.featureModels).toEqual({ triage: 'gpt-5' })
  })

  test('an existing row is not upserted just for the merge', async () => {
    await put({ featureModels: { triage: 'gpt-5' } })
    const createOnly = mockUpsert.mock.calls.filter(([a]) => JSON.stringify(a) === JSON.stringify({ where: { userId: USER }, update: {}, create: { userId: USER } }))
    expect(createOnly).toHaveLength(0)
  })

  test('the response is the masked row with the merged map', async () => {
    const res = await put({ featureModels: { triage: 'gpt-5' } })
    const body = await res.json()
    expect(body.featureModels).toEqual({ codefix: 'claude-opus-4-6', triage: 'gpt-5' })
    expect(body.shodanApiKey).toBe('••••••••9999')
    expect(body.rotationConfigs).toEqual({})
  })

  test('a body with only featureModels changes no other column and triggers no side effect', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    await put({ featureModels: { triage: 'gpt-5' } })
    const [mainUpsert] = mockUpsert.mock.calls.map(([a]) => a as { update: Record<string, unknown> })
    expect(mainUpsert.update).toEqual({})
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(row!.shodanApiKey).toBe('STORED-SHODAN-KEY-9999')
    fetchSpy.mockRestore()
  })

  test('an empty object writes and audits nothing', async () => {
    const res = await put({ featureModels: {} })
    expect(res.status).toBe(200)
    expect(mockExecuteRaw).not.toHaveBeenCalled()
    expect(mockWriteAudit).not.toHaveBeenCalled()
  })

  test('the rest of the PUT is unchanged when featureModels is absent', async () => {
    const res = await put({ shodanApiKey: 'NEW-KEY-1234' })
    expect(res.status).toBe(200)
    expect(mockRequireEff).not.toHaveBeenCalled()
    expect(mockExecuteRaw).not.toHaveBeenCalled()
    expect(row!.shodanApiKey).toBe('NEW-KEY-1234')
  })
})

describe('audit', () => {
  test('one row with the real actor, the target and model ids only', async () => {
    mockGetSession.mockResolvedValue({ userId: 'root', role: 'admin' })
    mockRequireEff.mockResolvedValue({ userId: USER })
    await put({ featureModels: { triage: 'claude-haiku-4-5', codefix: '' } })
    expect(mockWriteAudit).toHaveBeenCalledTimes(1)
    expect(mockWriteAudit).toHaveBeenCalledWith({
      actorId: 'root',
      action: 'user_settings.feature_models',
      targetType: 'user',
      targetId: USER,
      before: { featureModels: { codefix: 'claude-opus-4-6' } },
      after: { featureModels: { triage: 'claude-haiku-4-5' }, effectiveUserId: USER },
    })
    expect(JSON.stringify(mockWriteAudit.mock.calls[0][0])).not.toContain('STORED-SHODAN')
  })
})

describe('GET', () => {
  test('the no-row default carries an empty featureModels', async () => {
    row = null
    const res = await GET(new NextRequest(`http://x/api/users/${USER}/settings`), { params: Promise.resolve({ id: USER }) })
    expect(res.status).toBe(200)
    expect((await res.json()).featureModels).toEqual({})
  })

  test('a saved map comes back as stored', async () => {
    const res = await GET(new NextRequest(`http://x/api/users/${USER}/settings`), { params: Promise.resolve({ id: USER }) })
    expect((await res.json()).featureModels).toEqual({ codefix: 'claude-opus-4-6' })
  })
})
