/**
 * scanStartFields (step 6.8): every start's fields are scanJobCredential's plus the actor's
 * maxConcurrentScans quota, asked of the actor (the owner when the start names nobody). With no
 * credential minted there is no actor and nothing is read; with the switch off nothing is read.
 * A collaborator's start writes its credits.used row first (step 5.6): the write is mocked here,
 * and ownerCredentials.test.ts proves the row itself.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/scanStartFields.test.ts
 * @vitest-environment node
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

const h = vi.hoisted(() => ({ cap: vi.fn(), spend: vi.fn() }))
vi.mock('@/lib/authz/quotas', () => ({ actorScanCap: (id: string) => h.cap(id) }))
vi.mock('@/lib/authz/ownerSpend', () => ({ recordOwnerCredentialSpend: (spend: unknown) => h.spend(spend) }))

import { scanJobCredential, scanStartFields } from './scanJobCredential'

const saved = process.env.INTERNAL_API_KEY
beforeEach(() => {
  h.cap.mockReset()
  h.spend.mockReset().mockResolvedValue(true)
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
    expect(h.spend).toHaveBeenCalledWith({
      projectId: 'p1', ownerId: 'owner-1', userId: 'collab-1', feature: 'scan', source: 'system',
    })
    expect(h.spend.mock.invocationCallOrder[0]).toBeLessThan(h.cap.mock.invocationCallOrder[0])
  })

  test('no actor named: the owner is the actor and is asked', async () => {
    h.cap.mockResolvedValue({})
    const fields = await scanStartFields('p1', 'owner-1', null)
    expect(h.cap).toHaveBeenCalledWith('owner-1')
    expect(Object.keys(fields).sort()).toEqual(Object.keys(scanJobCredential('p1', 'owner-1', null)).sort())
    expect(h.spend).not.toHaveBeenCalled()
  })

  test('the owner named as actor spends their own credentials: no row', async () => {
    h.cap.mockResolvedValue({})
    await scanStartFields('p1', 'owner-1', 'owner-1')
    expect(h.spend).not.toHaveBeenCalled()
  })

  test('no row, no start: a failed credits.used write throws before the quota or the credential', async () => {
    h.spend.mockRejectedValue(new Error('audit down'))
    await expect(scanStartFields('p1', 'owner-1', 'collab-1')).rejects.toThrow('audit down')
    expect(h.cap).not.toHaveBeenCalled()
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
