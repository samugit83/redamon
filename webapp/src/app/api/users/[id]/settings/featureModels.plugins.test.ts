/**
 * Models by feature for plugins (TD-10, F-19, R-39, R-66): the PUT saves a `plugin:<id>`
 * key only for a plugin that is installed, enabled and holds `llm:invoke`; clearing one
 * ('') is always accepted, so a key left by an uninstalled plugin can be removed. Plugin
 * keys never reach getLlmFeature or modelAllowedForFeature, which know only core features
 * and throw for others. Every existing refusal of the branch is unchanged.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const m = vi.hoisted(() => ({
  findUnique: vi.fn(),
  upsert: vi.fn(),
  executeRaw: vi.fn(),
  pluginRows: [] as Record<string, unknown>[],
  requireUserAccess: vi.fn(),
  isInternal: vi.fn(),
  isScanner: vi.fn(),
  getSession: vi.fn(),
  requireEff: vi.fn(),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: { findUnique: (...a: unknown[]) => m.findUnique(...a), upsert: (...a: unknown[]) => m.upsert(...a) },
    apiKeyRotationConfig: { findMany: async () => [] },
    pluginInstall: { findMany: async () => m.pluginRows },
    $executeRaw: (...a: unknown[]) => m.executeRaw(...a),
    $executeRawUnsafe: vi.fn(),
  },
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => m.requireUserAccess(...a),
  isInternalRequest: (...a: unknown[]) => m.isInternal(...a),
  isScannerRequest: (...a: unknown[]) => m.isScanner(...a),
  getSession: () => m.getSession(),
}))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: () => m.requireEff() }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { PUT } from './route'
import { parseFeatureModelsPatch } from '@/lib/featureModels'

const USER = 'alice'

function plugin(pluginId: string, over: Record<string, unknown> = {}, manifest: Record<string, unknown> = {}) {
  return {
    pluginId,
    enabled: true,
    status: 'ready',
    revokedReason: null,
    activeVersion: '1.0.0',
    grantedPermissions: ['llm:invoke'],
    manifest: { id: pluginId, displayName: pluginId, permissions: ['llm:invoke'], llmFeature: { description: 'd' }, ...manifest },
    ...over,
  }
}

function put(featureModels: unknown) {
  return PUT(new NextRequest(`http://x/api/users/${USER}/settings`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ featureModels }) }), {
    params: Promise.resolve({ id: USER }),
  })
}

/** The patch the one raw UPDATE received: the merged keys and the removed ones. */
function applied() {
  const call = m.executeRaw.mock.calls[0]
  if (!call) return null
  const values = call.slice(1)
  return { set: JSON.parse(values[0] as string), removed: values[1] }
}

beforeEach(() => {
  m.pluginRows = [plugin('skiller')]
  m.findUnique.mockReset().mockResolvedValue({ userId: USER, featureModels: {} })
  m.upsert.mockReset().mockResolvedValue({})
  m.executeRaw.mockReset().mockResolvedValue(1)
  m.requireUserAccess.mockReset().mockResolvedValue(null)
  m.isInternal.mockReset().mockReturnValue(false)
  m.isScanner.mockReset().mockReturnValue(false)
  m.getSession.mockReset().mockResolvedValue({ userId: USER, role: 'standard' })
  m.requireEff.mockReset().mockResolvedValue({ userId: USER })
})

describe('PUT featureModels with plugin keys', () => {
  test('a qualifying plugin: saved under plugin:<id> on the user', async () => {
    const res = await put({ 'plugin:skiller': 'claude-haiku-4-5' })
    expect(res.status).toBe(200)
    expect(applied()).toEqual({ set: { 'plugin:skiller': 'claude-haiku-4-5' }, removed: [] })
  })

  test('a plugin has no excluded model prefixes (they belong to core features)', async () => {
    expect((await put({ 'plugin:skiller': 'bedrock/anthropic.claude-3-5-sonnet' })).status).toBe(200)
    expect((await put({ preset_generator: 'bedrock/anthropic.claude-3-5-sonnet' })).status).toBe(400)
  })

  test.each<[string, Record<string, unknown>[]]>([
    ['not installed', []],
    ['disabled', [plugin('skiller', { enabled: false })]],
    ['revoked', [plugin('skiller', { revokedReason: 'revoked' })]],
    ['failed', [plugin('skiller', { status: 'failed' })]],
    ['llm:invoke not granted', [plugin('skiller', { grantedPermissions: [] })]],
    ['llm:invoke not in the manifest', [plugin('skiller', {}, { permissions: [] })]],
    ['no llmFeature in the manifest', [plugin('skiller', {}, { llmFeature: undefined })]],
  ])('a plugin %s: 400, nothing written', async (_n, rows) => {
    m.pluginRows = rows
    const res = await put({ 'plugin:skiller': 'claude-haiku-4-5' })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe('Unknown feature: plugin:skiller')
    expect(m.executeRaw).not.toHaveBeenCalled()
  })

  test('clearing the key of a plugin that does not qualify is accepted', async () => {
    m.pluginRows = []
    const res = await put({ 'plugin:gone': '' })
    expect(res.status).toBe(200)
    expect(applied()).toEqual({ set: {}, removed: ['plugin:gone'] })
  })

  test.each([['plugin:'], ['plugin:Skiller'], ['plugin:x'], ['plugin:../a'], ['plugins:skiller']])(
    'a malformed key %s: 400, never 500',
    async (key) => {
      const res = await put({ [key]: 'claude-haiku-4-5' })
      expect(res.status).toBe(400)
    },
  )

  test('a core key and a plugin key in one PUT; one bad key refuses both', async () => {
    expect((await put({ triage: 'claude-haiku-4-5', 'plugin:skiller': 'claude-opus-4-6' })).status).toBe(200)
    expect(applied()!.set).toEqual({ triage: 'claude-haiku-4-5', 'plugin:skiller': 'claude-opus-4-6' })
    m.executeRaw.mockClear()
    expect((await put({ triage: 'claude-haiku-4-5', 'plugin:unknown': 'x' })).status).toBe(400)
    expect(m.executeRaw).not.toHaveBeenCalled()
  })

  test('the existing refusals hold for plugin keys: an admin acting for someone else, a service key', async () => {
    m.requireEff.mockResolvedValue({ userId: 'bob' })
    expect((await put({ 'plugin:skiller': 'claude-haiku-4-5' })).status).toBe(403)
    m.requireEff.mockResolvedValue({ userId: USER })
    m.isInternal.mockReturnValue(true)
    expect((await put({ 'plugin:skiller': 'claude-haiku-4-5' })).status).toBe(403)
    m.isInternal.mockReturnValue(false)
    m.requireEff.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    expect((await put({ 'plugin:skiller': 'claude-haiku-4-5' })).status).toBe(401)
    expect(m.executeRaw).not.toHaveBeenCalled()
  })
})

describe('parseFeatureModelsPatch', () => {
  const ids = new Set(['plugin:skiller'])

  test('a plugin key only with the qualifying set, the same length and control-character rules', () => {
    expect(parseFeatureModelsPatch({ 'plugin:skiller': ' m ' }, { pluginFeatureIds: ids })).toEqual({ set: { 'plugin:skiller': 'm' }, removed: [] })
    expect(parseFeatureModelsPatch({ 'plugin:skiller': 'm' })).toEqual({ error: 'Unknown feature: plugin:skiller' })
    expect(parseFeatureModelsPatch({ 'plugin:skiller': 'x'.repeat(201) }, { pluginFeatureIds: ids })).toHaveProperty('error')
    expect(parseFeatureModelsPatch({ 'plugin:skiller': 'a\u0000b' }, { pluginFeatureIds: ids })).toHaveProperty('error')
    expect(parseFeatureModelsPatch({ 'plugin:skiller': 7 }, { pluginFeatureIds: ids })).toHaveProperty('error')
    expect(parseFeatureModelsPatch({ 'plugin:other': '' })).toEqual({ set: {}, removed: ['plugin:other'] })
  })

  test('core keys behave exactly as before', () => {
    expect(parseFeatureModelsPatch({ triage: 'm' })).toEqual({ set: { triage: 'm' }, removed: [] })
    expect(parseFeatureModelsPatch({ nope: 'm' })).toEqual({ error: 'Unknown feature: nope' })
    expect(parseFeatureModelsPatch({ preset_generator: 'bedrock/x' })).toEqual({ error: 'Recon preset generator cannot run on bedrock/x' })
  })
})
