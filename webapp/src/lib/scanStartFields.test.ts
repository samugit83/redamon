/**
 * scanStartFields (step 6.8): every start's fields are scanJobCredential's plus the actor's
 * maxConcurrentScans quota, asked of the actor (the owner when the start names nobody). With no
 * credential minted there is no actor and nothing is read; with the switch off nothing is read.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/scanStartFields.test.ts
 * @vitest-environment node
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

const h = vi.hoisted(() => ({ cap: vi.fn() }))
vi.mock('@/lib/authz/quotas', () => ({ actorScanCap: (id: string) => h.cap(id) }))

import { scanJobCredential, scanStartFields } from './scanJobCredential'

const saved = process.env.INTERNAL_API_KEY
beforeEach(() => {
  h.cap.mockReset()
  process.env.INTERNAL_API_KEY = 'scan-start-fields-test-master'
})
afterEach(() => {
  if (saved === undefined) delete process.env.INTERNAL_API_KEY
  else process.env.INTERNAL_API_KEY = saved
})

describe('scanStartFields', () => {
  test("the actor's quota is asked of the actor and added beside the credential", async () => {
    h.cap.mockResolvedValue({ actor_max_concurrent: 3 })
    const fields = await scanStartFields('p1', 'owner-1', 'collab-1')
    expect(h.cap).toHaveBeenCalledWith('collab-1')
    expect(fields).toMatchObject({ actor_user_id: 'collab-1', actor_max_concurrent: 3 })
    expect(typeof fields.job_credential).toBe('string')
  })

  test('no actor named: the owner is the actor and is asked', async () => {
    h.cap.mockResolvedValue({})
    const fields = await scanStartFields('p1', 'owner-1', null)
    expect(h.cap).toHaveBeenCalledWith('owner-1')
    expect(Object.keys(fields).sort()).toEqual(Object.keys(scanJobCredential('p1', 'owner-1', null)).sort())
  })

  test('no credential minted (no master key): no actor, nothing read', async () => {
    delete process.env.INTERNAL_API_KEY
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(await scanStartFields('p1', 'owner-1', 'collab-1')).toEqual({})
    expect(h.cap).not.toHaveBeenCalled()
  })

  test('a failed quota read throws (the start is never sent)', async () => {
    h.cap.mockRejectedValue(new Error('db down'))
    await expect(scanStartFields('p1', 'owner-1', 'collab-1')).rejects.toThrow('db down')
  })
})
