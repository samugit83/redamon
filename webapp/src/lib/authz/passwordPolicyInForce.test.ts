/**
 * The password policy in force (step 2.8, ID-20, ID-29): with the identity switch on, the
 * instance settings row's minimum (never below the floor), the deny list and the two rules,
 * and whether a short password at sign-in asks for a change; with it off, the Phase 1 policy
 * and nothing read.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const findUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({ default: { instanceSettings: { findUnique: (a: unknown) => findUnique(a) } } }))

import { setFlagsForTests } from './flags'
import { passwordPolicyInForce } from './passwordPolicyInForce'

beforeEach(() => {
  findUnique.mockReset()
  setFlagsForTests({ identity: true })
})
afterEach(() => setFlagsForTests(null))

describe('passwordPolicyInForce', () => {
  test('policy reads the instance minimum (switch on)', async () => {
    findUnique.mockResolvedValue({ passwordMinLength: 16, passwordAskChangeIfShort: true })
    expect(await passwordPolicyInForce()).toEqual({ minLength: 16, rules: true, askChangeIfShort: true })
    expect(findUnique).toHaveBeenCalledWith({
      where: { id: 'instance' },
      select: { passwordMinLength: true, passwordAskChangeIfShort: true },
    })
  })

  test('never below 12: a lower stored minimum reads as the floor', async () => {
    findUnique.mockResolvedValue({ passwordMinLength: 8, passwordAskChangeIfShort: false })
    expect(await passwordPolicyInForce()).toEqual({ minLength: 12, rules: true, askChangeIfShort: false })
  })

  test('a missing row (the boot backfill has not filled it yet) reads as the floor, rules on', async () => {
    findUnique.mockResolvedValue(null)
    expect(await passwordPolicyInForce()).toEqual({ minLength: 12, rules: true, askChangeIfShort: false })
  })

  test('a failed read throws: no caller takes it for a weaker policy', async () => {
    findUnique.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    await expect(passwordPolicyInForce()).rejects.toThrow('db down')
  })

  test('with the switch off it is the Phase 1 policy and nothing is read', async () => {
    setFlagsForTests({ identity: false })
    expect(await passwordPolicyInForce()).toEqual({ minLength: 12, rules: false, askChangeIfShort: false })
    expect(findUnique).not.toHaveBeenCalled()
  })
})
