/**
 * Scan Queue - enqueueJob (Phase 3). It writes a queued JobQueue row with a
 * settings fingerprint computed at enqueue (C-4), refuses an unknown kind, and
 * refuses an ai_attack that carries an inline api_key (the secret must never be
 * stored in a row).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  projectFindUnique: vi.fn(),
  jqCreate: vi.fn(),
  authProfileFindUnique: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) },
    jobQueue: { create: (...a: unknown[]) => h.jqCreate(...a) },
    projectAuthProfile: { findUnique: (...a: unknown[]) => h.authProfileFindUnique(...a) },
  },
}))

import { enqueueJob } from './enqueueJob'
import { settingsFingerprint } from './jobQueue'

const PROJECT = {
  id: 'p1', targetDomain: 'example.com', ipMode: false, targetIps: [],
  scanModules: ['port_scan'], targetGuardrailEnabled: true, stealthMode: false,
}

beforeEach(() => {
  vi.clearAllMocks()
  h.projectFindUnique.mockResolvedValue(PROJECT)
  h.jqCreate.mockResolvedValue({ id: 'jq1' })
  // clearAllMocks clears CALLS, not implementations, so without an explicit
  // default a profile set by one test leaks into the fingerprint of the next.
  h.authProfileFindUnique.mockResolvedValue(null)
})

// The auth profile is a RELATION, so settingsFingerprint (Project-row fields
// only) cannot see it. Without folding it in, editing the recorded session
// between enqueue and dispatch left the queued scan running the old identity
// with no drift detected.
const AUTH_PROFILE = {
  authType: 'cookie', authHeaderName: '', authValue: 'sid=one',
  extraHeaders: {}, scopeHosts: ['example.com'],
}

test('settingsHash changes when the auth profile value changes', async () => {
  h.authProfileFindUnique.mockResolvedValue(AUTH_PROFILE)
  await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'full_recon' })
  const first = h.jqCreate.mock.calls[0][0].data.settingsHash

  h.jqCreate.mockClear()
  h.authProfileFindUnique.mockResolvedValue({ ...AUTH_PROFILE, authValue: 'sid=two' })
  await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'full_recon' })
  const second = h.jqCreate.mock.calls[0][0].data.settingsHash

  expect(first).not.toBe(second)
  expect(first).not.toContain('sid=')   // the secret never enters the hash input
})

test('settingsHash is stable when the profile is unchanged', async () => {
  h.authProfileFindUnique.mockResolvedValue(AUTH_PROFILE)
  await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'full_recon' })
  const a = h.jqCreate.mock.calls[0][0].data.settingsHash
  h.jqCreate.mockClear()
  await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'full_recon' })
  expect(h.jqCreate.mock.calls[0][0].data.settingsHash).toBe(a)
})

test('an unknown kind is refused with 400 and writes nothing', async () => {
  const r = await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'nope' })
  expect(r).toMatchObject({ ok: false, status: 400 })
  expect(h.jqCreate).not.toHaveBeenCalled()
})

test('a missing project is a 404', async () => {
  h.projectFindUnique.mockResolvedValue(null)
  const r = await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'full_recon' })
  expect(r).toMatchObject({ ok: false, status: 404 })
})

test('ai_attack with an inline api_key is not queueable', async () => {
  const r = await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'ai_attack', payload: { api_key: 'sk-123' } })
  expect(r).toMatchObject({ ok: false, status: 400 })
  expect(h.jqCreate).not.toHaveBeenCalled()
})

test('ai_attack without an api_key is queueable', async () => {
  const r = await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'ai_attack', payload: { api_key: '' } })
  expect(r.ok).toBe(true)
})

test('a valid enqueue stores the fingerprint + envelope + queued status', async () => {
  const r = await enqueueJob({ projectId: 'p1', userId: 'u1', kind: 'full_recon', payload: { mode: 'new' } })
  expect(r).toMatchObject({ ok: true, status: 201, id: 'jq1' })
  const arg = h.jqCreate.mock.calls[0][0]
  expect(arg.data.status).toBe('queued')
  // full_recon is auth-aware, so the fingerprint folds in the auth-profile
  // contribution ('none' when the project has no profile).
  expect(arg.data.settingsHash).toBe(
    settingsFingerprint('full_recon', PROJECT as unknown as Record<string, unknown>, { authProfileFp: 'none' }))
  expect(arg.data.envelopeBytes).toBe(BigInt(2147483648))
  expect(arg.data.priority).toBe(10)
})
