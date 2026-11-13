/**
 * Scan Timeline — project activation lock (Section 4A.3).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const prismaMock = vi.hoisted(() => ({
  project: { findUnique: vi.fn(), findMany: vi.fn(), update: vi.fn(), updateMany: vi.fn() },
}))
vi.mock('@/lib/prisma', () => ({ default: prismaMock }))

import {
  isActivationInProgress,
  assertGraphNotActivating,
  activationBusy,
  acquireActivationLock,
  releaseActivationLock,
  activationLockTtlMs,
  ACTIVATION_STATE_ACTIVATING,
  ACTIVATION_STATE_IDLE,
  ACTIVATION_STATE_TRANSFERRING,
  acquireTransferLock,
  activationStates,
  graphHold,
  refreshTransferLock,
  releaseTransferLock,
  holdOf,
} from './activationLock'

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.ACTIVATION_LOCK_TTL_MS
})
afterEach(() => { delete process.env.ACTIVATION_LOCK_TTL_MS })

describe('isActivationInProgress', () => {
  test('idle project → false', async () => {
    prismaMock.project.findUnique.mockResolvedValue({ activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null })
    expect(await isActivationInProgress('p1')).toBe(false)
  })

  test('freshly activating project → true', async () => {
    prismaMock.project.findUnique.mockResolvedValue({
      activationState: ACTIVATION_STATE_ACTIVATING, activationStartedAt: new Date(),
    })
    expect(await isActivationInProgress('p1')).toBe(true)
  })

  test('a lock older than the TTL is stale, so the project is not wedged forever', async () => {
    prismaMock.project.findUnique.mockResolvedValue({
      activationState: ACTIVATION_STATE_ACTIVATING,
      activationStartedAt: new Date(Date.now() - activationLockTtlMs() - 1000),
    })
    expect(await isActivationInProgress('p1')).toBe(false)
  })

  test('missing project → false', async () => {
    prismaMock.project.findUnique.mockResolvedValue(null)
    expect(await isActivationInProgress('p1')).toBe(false)
  })

  test('TTL is configurable and falls back on garbage', () => {
    process.env.ACTIVATION_LOCK_TTL_MS = '60000'
    expect(activationLockTtlMs()).toBe(60000)
    process.env.ACTIVATION_LOCK_TTL_MS = 'nope'
    expect(activationLockTtlMs()).toBe(15 * 60 * 1000)
  })
})

describe('assertGraphNotActivating', () => {
  test('returns null when the graph is free', async () => {
    prismaMock.project.findUnique.mockResolvedValue({ activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null })
    expect(await assertGraphNotActivating('p1')).toBeNull()
  })

  test('returns a 409 the caller must return', async () => {
    prismaMock.project.findUnique.mockResolvedValue({
      activationState: ACTIVATION_STATE_ACTIVATING, activationStartedAt: new Date(),
    })
    const res = await assertGraphNotActivating('p1')
    expect(res).toBeInstanceOf(NextResponse)
    expect(res!.status).toBe(409)
    expect((await res!.json()).activationInProgress).toBe(true)
  })

  test('a failed lock read allows the operation rather than blocking all work', async () => {
    prismaMock.project.findUnique.mockRejectedValue(new Error('db down'))
    expect(await assertGraphNotActivating('p1')).toBeNull()
  })
})

describe('activationBusy (the fail-closed form, for mutes and unmutes)', () => {
  test('false when the graph is free, true while activating', async () => {
    prismaMock.project.findUnique.mockResolvedValue({ activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null })
    expect(await activationBusy('p1')).toBe(false)
    prismaMock.project.findUnique.mockResolvedValue({
      activationState: ACTIVATION_STATE_ACTIVATING, activationStartedAt: new Date(),
    })
    expect(await activationBusy('p1')).toBe(true)
  })

  test('a failed lock read is BUSY: activation would swallow a mute written now', async () => {
    // The opposite of assertGraphNotActivating, deliberately.
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    prismaMock.project.findUnique.mockRejectedValue(new Error('db down'))
    expect(await activationBusy('p1')).toBe(true)
  })
})

describe('acquireActivationLock', () => {
  test('takes the lock with a conditional update on idle-or-stale', async () => {
    prismaMock.project.updateMany.mockResolvedValue({ count: 1 })
    const handle = await acquireActivationLock('p1', 'v2')
    expect(handle.acquired).toBe(true)
    const arg = prismaMock.project.updateMany.mock.calls[0][0]
    expect(arg.where.id).toBe('p1')
    // Only an idle (or expired) project matches — that is what makes it atomic.
    expect(arg.where.OR).toEqual([
      { activationState: ACTIVATION_STATE_IDLE },
      { activationStartedAt: null },
      { activationStartedAt: { lt: expect.any(Date) } },
    ])
    expect(arg.data).toMatchObject({
      activationState: ACTIVATION_STATE_ACTIVATING, activationVersionId: 'v2',
    })
  })

  test('a second concurrent activation loses (no rows matched)', async () => {
    prismaMock.project.updateMany.mockResolvedValue({ count: 0 })
    const handle = await acquireActivationLock('p1', 'v2')
    expect(handle.acquired).toBe(false)
    expect(handle.reason).toMatch(/already in progress/i)
  })
})

describe('releaseActivationLock', () => {
  test('clears the flag', async () => {
    prismaMock.project.update.mockResolvedValue({})
    await releaseActivationLock('p1')
    expect(prismaMock.project.update).toHaveBeenCalledWith({
      where: { id: 'p1' },
      data: { activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null, activationVersionId: null },
    })
  })

  test('never throws — the TTL is the backstop', async () => {
    prismaMock.project.update.mockRejectedValue(new Error('db down'))
    await expect(releaseActivationLock('p1')).resolves.toBeUndefined()
  })
})

// Step 5.12 (SH-15, DV-15): an ownership transfer holds the same row lock with the value `transferring`, so
// every writer that already asks the lock (scan starts, tickets, partial recon, the scheduler, mutes) waits
// for it; the callers that build the 409 here name `project_transfer_in_progress`.
describe('the ownership transfer holds the project lock (step 5.12)', () => {
  const transferring = (startedAt: Date | null = new Date()) =>
    prismaMock.project.findUnique.mockResolvedValue({ activationState: ACTIVATION_STATE_TRANSFERRING, activationStartedAt: startedAt })

  test('a transfer in progress holds the graph: the scan starts, tickets and mutes wait', async () => {
    transferring()
    expect(await graphHold('p1')).toBe('transferring')
    expect(await isActivationInProgress('p1')).toBe(true)
    expect(await activationBusy('p1')).toBe(true)
    prismaMock.project.findMany.mockResolvedValue([
      { id: 'p1', activationState: ACTIVATION_STATE_TRANSFERRING, activationStartedAt: new Date() },
      { id: 'p2', activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null },
    ])
    const states = await activationStates(['p1', 'p2'])
    expect(Object.fromEntries(states)).toEqual({ p1: true, p2: false })
  })

  test("the 409 names project_transfer_in_progress for a transfer, and keeps the activation's answer otherwise", async () => {
    transferring()
    const res = await assertGraphNotActivating('p1')
    expect(res!.status).toBe(409)
    expect(await res!.json()).toMatchObject({ code: 'project_transfer_in_progress', transferInProgress: true })
    prismaMock.project.findUnique.mockResolvedValue({ activationState: ACTIVATION_STATE_ACTIVATING, activationStartedAt: new Date() })
    const activating = await (await assertGraphNotActivating('p1'))!.json()
    expect(activating.activationInProgress).toBe(true)
    expect(activating.code).toBeUndefined()
  })

  test('holdOf reads the hold from a row a writer already read (the settings save): only a fresh transfer or activation', () => {
    expect(holdOf({ activationState: ACTIVATION_STATE_TRANSFERRING, activationStartedAt: new Date() })).toBe('transferring')
    expect(holdOf({ activationState: ACTIVATION_STATE_ACTIVATING, activationStartedAt: new Date() })).toBe('activating')
    expect(holdOf({ activationState: ACTIVATION_STATE_TRANSFERRING, activationStartedAt: new Date(Date.now() - activationLockTtlMs() - 1) })).toBeNull()
    expect(holdOf({ activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null })).toBeNull()
    // A test double or an older select without the columns reads as free.
    expect(holdOf({})).toBeNull()
    expect(holdOf(null)).toBeNull()
  })

  test('a transfer older than the TTL is stale, like an activation (a crashed copy never wedges the project)', async () => {
    transferring(new Date(Date.now() - activationLockTtlMs() - 1000))
    expect(await graphHold('p1')).toBeNull()
    expect(await assertGraphNotActivating('p1')).toBeNull()
  })

  test('the transfer takes the lock only from the owner it read and an idle (or stale) project', async () => {
    prismaMock.project.updateMany.mockResolvedValue({ count: 1 })
    expect(await acquireTransferLock('p1', 't1', 'owner-1')).toBe(true)
    const arg = prismaMock.project.updateMany.mock.calls[0][0]
    expect(arg.where).toMatchObject({ id: 'p1', userId: 'owner-1' })
    expect(arg.where.OR).toEqual([
      { activationState: ACTIVATION_STATE_IDLE },
      { activationStartedAt: null },
      { activationStartedAt: { lt: expect.any(Date) } },
    ])
    expect(arg.data).toMatchObject({ activationState: ACTIVATION_STATE_TRANSFERRING, activationVersionId: 'transfer:t1' })
    prismaMock.project.updateMany.mockResolvedValue({ count: 0 })
    expect(await acquireTransferLock('p1', 't1', 'owner-1')).toBe(false)
  })

  test('an activation cannot take a transfer\'s lock, and the transfer releases only its own', async () => {
    prismaMock.project.updateMany.mockResolvedValue({ count: 0 })
    expect((await acquireActivationLock('p1', 'v2')).acquired).toBe(false)
    prismaMock.project.updateMany.mockReset()
    prismaMock.project.updateMany.mockResolvedValue({ count: 1 })
    await refreshTransferLock('p1')
    expect(prismaMock.project.updateMany.mock.calls[0][0]).toMatchObject({
      where: { id: 'p1', activationState: ACTIVATION_STATE_TRANSFERRING }, data: { activationStartedAt: expect.any(Date) },
    })
    await releaseTransferLock('p1')
    expect(prismaMock.project.updateMany.mock.calls[1][0]).toEqual({
      where: { id: 'p1', activationState: ACTIVATION_STATE_TRANSFERRING },
      data: { activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null, activationVersionId: null },
    })
  })

  test('a failed release is logged, never thrown: the TTL frees the project', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    prismaMock.project.updateMany.mockRejectedValue(new Error('db down'))
    await expect(releaseTransferLock('p1')).resolves.toBeUndefined()
    expect(err.mock.calls[0][0]).toMatch(/\[rbac\] transfer lock release failed/)
  })
})
