/**
 * The readers of the shared tunnel and capture settings (step 2.4, ID-32): with the
 * identity switch on they read the instance settings row, with it off (and until the boot
 * backfill fills that row) the user row each reader picked before. Retention stays per
 * owner either way.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/sharedInstanceSettings.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const db = {
  instanceFindUnique: vi.fn(),
  settingsFindFirst: vi.fn(),
  settingsFindMany: vi.fn(),
  userFindMany: vi.fn(),
  trafficFindMany: vi.fn(),
  trafficDeleteMany: vi.fn(),
  trafficGroupBy: vi.fn(),
}

vi.mock('@/lib/prisma', () => ({
  default: {
    instanceSettings: { findUnique: (...a: unknown[]) => db.instanceFindUnique(...a) },
    userSettings: {
      findFirst: (...a: unknown[]) => db.settingsFindFirst(...a),
      findMany: (...a: unknown[]) => db.settingsFindMany(...a),
    },
    user: { findMany: (...a: unknown[]) => db.userFindMany(...a) },
    capturedHttpTransaction: {
      findMany: (...a: unknown[]) => db.trafficFindMany(...a),
      deleteMany: (...a: unknown[]) => db.trafficDeleteMany(...a),
      groupBy: (...a: unknown[]) => db.trafficGroupBy(...a),
    },
  },
}))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => true }))
vi.mock('@/lib/recordingConfig', () => ({ activeRecordingBlock: async () => null }))
vi.mock('@/lib/captureBodies', () => ({ gcOrphanBodies: async () => 0 }))

import { setFlagsForTests } from '@/lib/authz/flags'
import { INSTANCE_SETTINGS_ID, instanceSettingsInForce } from './sharedInstanceSettings'
import { isCaptureGloballyEnabled } from './captureStatus'
import { GET as captureConfig } from '@/app/api/internal/capture-config/route'
import { GET as tunnelConfig } from '@/app/api/global/tunnel-config/route'
import { POST as maintenance } from '@/app/api/traffic/maintenance/route'

const EGRESS = [
  'captureEgressBlockEmptyHost', 'captureEgressBlockHardGuardrail', 'captureEgressFailClosed',
  'captureEgressBlockUnresolvable', 'captureEgressBlockPrivate', 'captureEgressBlockLoopback',
  'captureEgressBlockLinkLocal', 'captureEgressBlockCgnat', 'captureEgressBlockReserved',
  'captureEgressBlockMulticast', 'captureEgressBlockUnspecified',
]

// The admin row in force before the switch: capture on, private IPs blocked, an ngrok tunnel.
const ADMIN_ROW = {
  ...Object.fromEntries(EGRESS.map((f) => [f, true])),
  captureProxyEnabled: true, captureProxyStoreBodies: true, captureProxyStoreReqBodies: true,
  captureProxyStoreRespBodies: true, captureProxyMaxBodyKb: 64, captureProxyMaxStoreMb: 5,
  captureProxyBodyRules: {}, scaIntelIgnoreSuffixes: 'user-row.test',
  ngrokAuthtoken: 'fake-user-row-ngrok', chiselServerUrl: '', chiselAuth: '',
}

// The instance row: every value different from the user row.
const INSTANCE_ROW = {
  id: 'instance',
  ...Object.fromEntries(EGRESS.map((f) => [f, true])),
  captureEgressBlockPrivate: false,
  captureProxyEnabled: false, captureProxyStoreBodies: false, captureProxyStoreReqBodies: false,
  captureProxyStoreRespBodies: false, captureProxyMaxBodyKb: 256, captureProxyMaxStoreMb: 0,
  captureProxyBodyRules: { image: 'disk' }, scaIntelIgnoreSuffixes: 'instance.test',
  tunnelsEnabled: true, ngrokAuthtoken: '', chiselServerUrl: 'https://chisel.instance.test', chiselAuth: 'u:fake-pass',
}

const internalGet = (url: string) => new NextRequest(`http://webapp${url}`, { headers: { 'x-internal-key': 'k' } })

beforeEach(() => {
  for (const fn of Object.values(db)) fn.mockReset()
  db.instanceFindUnique.mockResolvedValue({ ...INSTANCE_ROW })
  db.settingsFindFirst.mockResolvedValue({ ...ADMIN_ROW })
  db.userFindMany.mockResolvedValue([{ id: 'admin-1' }])
})
afterEach(() => setFlagsForTests(null))

describe('switch off reads the user rows', () => {
  beforeEach(() => setFlagsForTests({ identity: false }))

  test('nothing reads the instance settings row', async () => {
    expect(await instanceSettingsInForce()).toBeNull()
    await captureConfig(internalGet('/api/internal/capture-config'))
    await tunnelConfig(internalGet('/api/global/tunnel-config'))
    await isCaptureGloballyEnabled()
    expect(db.instanceFindUnique).not.toHaveBeenCalled()
  })

  test('capture-config answers the admin row saved last, as before', async () => {
    const body = await (await captureConfig(internalGet('/api/internal/capture-config'))).json()
    expect(body).toMatchObject({ enabled: true, source: 'db', sca_intel_ignore_suffixes: 'user-row.test' })
    expect(body.egress.block_private).toBe(true)
    expect(db.settingsFindFirst).toHaveBeenCalledWith({ where: { userId: { in: ['admin-1'] } }, orderBy: { updatedAt: 'desc' } })
  })

  test('the tunnel credentials come from the user row', async () => {
    const body = await (await tunnelConfig(internalGet('/api/global/tunnel-config'))).json()
    expect(body.ngrokAuthtoken).toBe('fake-user-row-ngrok')
  })

  test('the capture status reads the admin row', async () => {
    expect(await isCaptureGloballyEnabled()).toBe(true)
  })
})

describe('switch on reads the singleton', () => {
  beforeEach(() => setFlagsForTests({ identity: true }))

  test('capture-config answers the instance row, never a user row', async () => {
    const body = await (await captureConfig(internalGet('/api/internal/capture-config'))).json()
    expect(db.instanceFindUnique).toHaveBeenCalledWith({ where: { id: INSTANCE_SETTINGS_ID } })
    expect(body).toMatchObject({
      enabled: false, source: 'instance', sca_intel_ignore_suffixes: 'instance.test',
      body: { store_bodies: false, store_req_bodies: false, store_resp_bodies: false, max_body_kb: 256, max_store_mb: 0, body_rules: { image: 'disk' } },
    })
    expect(body.egress.block_private).toBe(false)
    expect(body.egress.block_loopback).toBe(true)
    expect(db.settingsFindFirst).not.toHaveBeenCalled()
    expect(db.userFindMany).not.toHaveBeenCalled()
  })

  test('the tunnel credentials come from the instance row', async () => {
    const body = await (await tunnelConfig(internalGet('/api/global/tunnel-config'))).json()
    expect(body).toEqual({ ngrokAuthtoken: '', chiselServerUrl: 'https://chisel.instance.test', chiselAuth: 'u:fake-pass' })
    expect(db.settingsFindFirst).not.toHaveBeenCalled()
  })

  test('the capture status reads the instance row', async () => {
    expect(await isCaptureGloballyEnabled()).toBe(false)
    expect(db.userFindMany).not.toHaveBeenCalled()
  })

  test('before the backfill filled the row, every reader keeps the user rows', async () => {
    db.instanceFindUnique.mockResolvedValue(null)
    expect((await (await captureConfig(internalGet('/api/internal/capture-config'))).json()).source).toBe('db')
    expect((await (await tunnelConfig(internalGet('/api/global/tunnel-config'))).json()).ngrokAuthtoken).toBe('fake-user-row-ngrok')
    expect(await isCaptureGloballyEnabled()).toBe(true)
  })

  test('a failed read of the instance row never relaxes the egress guard: 503, capture reads off', async () => {
    db.instanceFindUnique.mockRejectedValue(new Error('connection reset'))
    expect((await captureConfig(internalGet('/api/internal/capture-config'))).status).toBe(503)
    expect(await isCaptureGloballyEnabled()).toBe(false)
  })

  test('retention still per owner: maintenance applies each owner\'s days from their own row', async () => {
    const NOW = Date.parse('2026-11-12T00:00:00Z')
    vi.spyOn(Date, 'now').mockReturnValue(NOW)
    db.settingsFindMany.mockResolvedValue([
      { userId: 'owner-a', captureProxyRetentionDays: 3 },
      { userId: 'owner-b', captureProxyRetentionDays: 30 },
    ])
    db.trafficFindMany.mockResolvedValue([{ userId: 'owner-a' }, { userId: 'owner-b' }, { userId: 'owner-c' }])
    db.trafficDeleteMany.mockResolvedValue({ count: 0 })
    db.trafficGroupBy.mockResolvedValue([])
    const res = await maintenance(new NextRequest('http://webapp/api/traffic/maintenance', { method: 'POST' }))
    expect(res.status).toBe(200)
    const cutoffs = db.trafficDeleteMany.mock.calls.map(([a]) => [a.where.userId, (NOW - a.where.startedAt.lt.getTime()) / 86_400_000])
    expect(cutoffs).toEqual([['owner-a', 3], ['owner-b', 30], ['owner-c', 14]])
    expect(db.instanceFindUnique).not.toHaveBeenCalled()
    vi.restoreAllMocks()
  })
})
