/**
 * Scan Timeline — project activation lock (Section 4A.3).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const prismaMock = vi.hoisted(() => ({
  project: { findUnique: vi.fn(), findMany: vi.fn(), update: vi.fn(), updateMany: vi.fn() },
  $executeRaw: vi.fn(async (..._args: unknown[]) => 1),
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
  ACTIVATION_STATE_TRANSFER_SPLIT,
  acquireTransferLock,
  clearTransferSplit,
  markTransferSplit,
  parkTransferSplit,
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

  test('the transfer takes the lock only from the owner it read and an idle (or stale) project, never a split one', async () => {
    prismaMock.project.updateMany.mockResolvedValueOnce({ count: 0 }).mockResolvedValueOnce({ count: 1 })
    expect(await acquireTransferLock('p1', 't1', 'owner-1')).toEqual({ acquired: true, split: false })
    // First its own split hold (a retry of a transfer that may have split the graph), then a free lock.
    expect(prismaMock.project.updateMany.mock.calls[0][0].where).toMatchObject({
      id: 'p1', userId: 'owner-1', activationState: ACTIVATION_STATE_TRANSFER_SPLIT, activationVersionId: 'transfer:t1',
    })
    const arg = prismaMock.project.updateMany.mock.calls[1][0]
    expect(arg.where).toMatchObject({ id: 'p1', userId: 'owner-1', activationState: { not: ACTIVATION_STATE_TRANSFER_SPLIT } })
    expect(arg.where.OR).toEqual([
      { activationState: ACTIVATION_STATE_IDLE },
      { activationStartedAt: null },
      { activationStartedAt: { lt: expect.any(Date) } },
    ])
    expect(arg.data).toMatchObject({ activationState: ACTIVATION_STATE_TRANSFERRING, activationVersionId: 'transfer:t1' })
    prismaMock.project.updateMany.mockReset()
    prismaMock.project.updateMany.mockResolvedValue({ count: 0 })
    expect(await acquireTransferLock('p1', 't1', 'owner-1')).toEqual({ acquired: false, split: false })
  })

  test('a retry of the transfer that split the graph resumes its own split hold, keeping it split', async () => {
    prismaMock.project.updateMany.mockResolvedValueOnce({ count: 1 })
    expect(await acquireTransferLock('p1', 't1', 'owner-1')).toEqual({ acquired: true, split: true })
    expect(prismaMock.project.updateMany).toHaveBeenCalledTimes(1)
    // Only when no attempt is live on it: parked (null) or a heartbeat a TTL old.
    expect(prismaMock.project.updateMany.mock.calls[0][0].where.OR).toEqual([
      { activationStartedAt: null }, { activationStartedAt: { lt: expect.any(Date) } },
    ])
    expect(prismaMock.project.updateMany.mock.calls[0][0].data).toEqual({ activationStartedAt: expect.any(Date) })
  })

  test('an activation cannot take a transfer\'s lock, and the transfer releases only its own', async () => {
    prismaMock.project.updateMany.mockResolvedValue({ count: 0 })
    expect((await acquireActivationLock('p1', 'v2')).acquired).toBe(false)
    prismaMock.project.updateMany.mockReset()
    prismaMock.project.updateMany.mockResolvedValue({ count: 1 })
    // The heartbeat is raw SQL: the project's updatedAt (which the Postgres move compares) does not move.
    await refreshTransferLock('p1', 't1')
    expect(prismaMock.project.updateMany).not.toHaveBeenCalled()
    expect(String((prismaMock.$executeRaw.mock.calls[0][0] as string[]).join('?'))).toMatch(/UPDATE projects SET activation_started_at/)
    expect(prismaMock.$executeRaw.mock.calls[0].slice(1)).toEqual([expect.any(Date), 'p1', 'transfer:t1', 'transferring', 'transfer_split'])
    await releaseTransferLock('p1')
    expect(prismaMock.project.updateMany.mock.calls[0][0]).toEqual({
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

// Review of 5.12 (findings 1, 2): from the graph move until it completed or was run back the project may sit partly
// under each owner. The hold is then `transfer_split`: it never goes stale, no activation or other transfer takes
// it, every writer keeps refusing (409 project_transfer_in_progress), and only its own transfer clears it.
describe('a transfer that may have split the graph keeps the project (review of 5.12)', () => {
  const split = (startedAt: Date) => ({ activationState: ACTIVATION_STATE_TRANSFER_SPLIT, activationStartedAt: startedAt })

  test('held as a transfer whatever its age: writers refuse with project_transfer_in_progress', async () => {
    const day = new Date(Date.now() - 24 * 3600 * 1000)
    expect(holdOf(split(day))).toBe('transferring')
    prismaMock.project.findUnique.mockResolvedValue(split(day))
    expect(await isActivationInProgress('p1')).toBe(true)
    expect(await activationBusy('p1')).toBe(true)
    expect((await (await assertGraphNotActivating('p1'))!.json()).code).toBe('project_transfer_in_progress')
    prismaMock.project.findMany.mockResolvedValue([{ id: 'p1', ...split(day) }])
    expect(Object.fromEntries(await activationStates(['p1']))).toEqual({ p1: true })
  })

  test('an activation never takes a split hold, however old', async () => {
    prismaMock.project.updateMany.mockResolvedValue({ count: 0 })
    await acquireActivationLock('p1', 'v2')
    expect(prismaMock.project.updateMany.mock.calls[0][0].where).toMatchObject({ activationState: { not: ACTIVATION_STATE_TRANSFER_SPLIT } })
  })

  test('marked split just before the graph moves; cleared only by its own transfer; a plain release leaves it', async () => {
    prismaMock.project.updateMany.mockResolvedValue({ count: 1 })
    await markTransferSplit('p1', 't1')
    expect(prismaMock.project.updateMany.mock.calls[0][0]).toEqual({
      where: { id: 'p1', activationState: ACTIVATION_STATE_TRANSFERRING, activationVersionId: 'transfer:t1' },
      data: { activationState: ACTIVATION_STATE_TRANSFER_SPLIT },
    })
    await clearTransferSplit('p1', 't1')
    expect(prismaMock.project.updateMany.mock.calls[1][0]).toEqual({
      where: { id: 'p1', activationState: ACTIVATION_STATE_TRANSFER_SPLIT, activationVersionId: 'transfer:t1' },
      data: { activationState: ACTIVATION_STATE_IDLE, activationStartedAt: null, activationVersionId: null },
    })
    await releaseTransferLock('p1')
    expect(prismaMock.project.updateMany.mock.calls[2][0].where).toEqual({ id: 'p1', activationState: ACTIVATION_STATE_TRANSFERRING })
  })

  test('an attempt that ends split parks the hold (raw, still held), so the same transfer resumes it at once', async () => {
    await parkTransferSplit('p1', 't1')
    expect(String((prismaMock.$executeRaw.mock.calls[0][0] as string[]).join('?'))).toMatch(/SET activation_started_at = NULL/)
    expect(prismaMock.$executeRaw.mock.calls[0].slice(1)).toEqual(['p1', 'transfer_split', 'transfer:t1'])
    expect(holdOf({ activationState: ACTIVATION_STATE_TRANSFER_SPLIT, activationStartedAt: null })).toBe('transferring')
    const err = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    prismaMock.$executeRaw.mockRejectedValueOnce(new Error('db down'))
    await expect(parkTransferSplit('p1', 't1')).resolves.toBeUndefined()
    expect(err).toHaveBeenCalled()
  })
})
