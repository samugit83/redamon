/**
 * The one helper every scan start calls before its orchestrator call (step 1.16):
 * the body field carrying the start's job credential.
 *
 * @vitest-environment node
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { verifyJobCredential } from '@/lib/authz/machineCredential'
import { scanJobCredential } from './scanJobCredential'

const saved = process.env.INTERNAL_API_KEY

beforeEach(() => {
  process.env.INTERNAL_API_KEY = 'scan-job-credential-test-master'
})
afterEach(() => {
  if (saved === undefined) delete process.env.INTERNAL_API_KEY
  else process.env.INTERNAL_API_KEY = saved
  vi.restoreAllMocks()
})

describe('scanJobCredential', () => {
  test('the field verifies as a job credential for the owner and the project', () => {
    const field = scanJobCredential('proj-1', 'owner-1')
    expect(Object.keys(field)).toEqual(['job_credential'])
    expect(verifyJobCredential(field.job_credential)).toMatchObject({ aud: 'scan', ten: 'owner-1', pid: 'proj-1' })
  })

  test('each start gets its own job', () => {
    const a = verifyJobCredential(scanJobCredential('proj-1', 'owner-1').job_credential)
    const b = verifyJobCredential(scanJobCredential('proj-1', 'owner-1').job_credential)
    expect(a.job).not.toBe(b.job)
  })

  test('with no configured master key nothing is sent and the reason is logged', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    for (const weak of ['', 'changeme']) {
      process.env.INTERNAL_API_KEY = weak
      expect(scanJobCredential('proj-1', 'owner-1')).toEqual({})
    }
    expect(warn).toHaveBeenCalledWith('[rbac] job credential not minted reason=weak_master_key project=proj-1')
  })
})
