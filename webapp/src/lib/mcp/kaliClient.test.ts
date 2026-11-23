/**
 * The MCP server's Kali transport.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ fetch: vi.fn() }))

vi.mock('@/lib/agentFetch', () => ({ agentBaseUrl: () => 'http://agent:8080' }))
vi.mock('@/lib/agentAuth', () => ({ internalKeyHeaders: (x?: object) => ({ ...(x ?? {}) }) }))

import { MODAL_RAM_BODY, SANDBOX_REFUSED } from '@/lib/sandbox/contract'
import { McpToolError } from './errors'
import { kaliExec, kaliJobCancel, kaliJobStatus } from './kaliClient'

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
  vi.stubGlobal('fetch', h.fetch)
})

const agentAnswers = (body: Record<string, unknown>) => {
  h.fetch.mockResolvedValue({ ok: true, status: 200, json: async () => body })
}
const sentBody = () => JSON.parse(String(h.fetch.mock.calls[0][1].body)) as Record<string, unknown>
const jobId = 'a'.repeat(32)

describe('kali_exec names the person whose sandbox runs the command', () => {
  // Per-user sandboxes route by the token's owner (contract B.12). The project's
  // owner is the tenant, and sending it would run a collaborator's command in the
  // owner's sandbox, beside the owner's keys and files.
  test('the body carries user_id, the argument it is given', async () => {
    agentAnswers({ job_id: jobId, status: 'done', exit_code: 0, output: '', next_cursor: 0 })
    await kaliExec('p1', 'id', undefined, 'person-7')
    expect(h.fetch.mock.calls[0][0]).toBe('http://agent:8080/kali/exec')
    expect(sentBody()).toEqual({ project_id: 'p1', user_id: 'person-7', command: 'id' })
  })

  test('alongside the inline wait when one is given', async () => {
    agentAnswers({ job_id: jobId, status: 'done', exit_code: 0, output: '', next_cursor: 0 })
    await kaliExec('p1', 'id', 5, 'person-7')
    expect(sentBody()).toEqual({ project_id: 'p1', user_id: 'person-7', command: 'id', wait_seconds: 5 })
  })

  // The agent refuses a job recorded for another person (S11 F2): the poll and the cancel name the
  // token's owner too, so a co-member of the project cannot read or stop someone else's command.
  test('the poll and the cancel carry user_id, the argument they are given', async () => {
    agentAnswers({ job_id: jobId, status: 'running', next_cursor: 0 })
    await kaliJobStatus('p1', jobId, 0, 'person-7')
    await kaliJobCancel('p1', jobId, 'person-7')
    const [poll, cancel] = h.fetch.mock.calls.map(([url]) => new URL(String(url)))
    expect([poll.pathname, Object.fromEntries(poll.searchParams)]).toEqual([`/kali/exec/${jobId}`, { project_id: 'p1', cursor: '0', user_id: 'person-7' }])
    expect([cancel.pathname, Object.fromEntries(cancel.searchParams)]).toEqual([`/kali/exec/${jobId}/cancel`, { project_id: 'p1', user_id: 'person-7' }])
  })
})

describe('a per-user sandbox that is starting or could not be used', () => {
  test('starting is parsed as its own status, with no failure', async () => {
    agentAnswers({ job_id: jobId, status: 'starting', exit_code: null, output: '', next_cursor: 0 })
    const job = await kaliExec('p1', 'id', undefined, 'person-7')
    expect(job.status).toBe('starting')
    expect(job.failure).toBeUndefined()
    expect(job.errorCode).toBeUndefined()
  })

  test('ram carries its code and the governor\'s sentence', async () => {
    agentAnswers({
      job_id: jobId, status: 'failed', error_code: 'ram',
      error: 'not enough free memory to start this sandbox now',
    })
    const job = await kaliJobStatus('p1', jobId, 0, 'person-7')
    expect(job.errorCode).toBe('ram')
    expect(job.failure).toBe('not enough free memory to start this sandbox now')
  })

  test('ram without a sentence still says why', async () => {
    agentAnswers({ job_id: jobId, status: 'failed', error_code: 'ram' })
    expect((await kaliJobStatus('p1', jobId, 0, 'person-7')).failure).toBe(MODAL_RAM_BODY)
  })

  test('sandbox_refused always reads as the contract\'s text, never the upstream one', async () => {
    agentAnswers({ job_id: jobId, status: 'failed', error_code: 'sandbox_refused', error: 'user cm0abc refused on p1' })
    const job = await kaliJobStatus('p1', jobId, 0, 'person-7')
    expect(job.errorCode).toBe('sandbox_refused')
    expect(job.failure).toBe(SANDBOX_REFUSED)
  })

  test('sandbox_error and sandbox_stopped are fixed lines', async () => {
    for (const code of ['sandbox_error', 'sandbox_stopped']) {
      agentAnswers({ job_id: jobId, status: 'failed', error_code: code, error: 'Traceback: /opt/x.py' })
      const job = await kaliJobStatus('p1', jobId, 0, 'person-7')
      expect(job.errorCode).toBe(code)
      expect(job.failure).toMatch(/^The Kali sandbox /)
    }
  })

  test('a code outside the contract is not passed on as one', async () => {
    agentAnswers({ job_id: jobId, status: 'failed', error_code: 'disk_full', error: 'boom' })
    const job = await kaliJobStatus('p1', jobId, 0, 'person-7')
    expect(job.errorCode).toBeUndefined()
    expect(job.failure).toBe('boom')
  })

  test('a refusal answered as an HTTP error keeps its code and names it to the caller', async () => {
    // The code reaches the audit row; only the message reaches the MCP caller.
    h.fetch.mockResolvedValue({
      ok: false, status: 409,
      json: async () => ({ error: 'not enough free memory to start this sandbox now', error_code: 'ram' }),
    })
    const err = await kaliExec('p1', 'id', undefined, 'person-7').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(McpToolError)
    expect((err as McpToolError).code).toBe('ram')
    expect((err as Error).message).toMatch(/not enough free memory/)
    expect((err as Error).message).toMatch(/errorCode: ram/)

    h.fetch.mockResolvedValue({
      ok: false, status: 403,
      json: async () => ({ error: 'user cm0abc refused', error_code: 'sandbox_refused' }),
    })
    const refused = await kaliExec('p1', 'id', undefined, 'person-7').catch((e: unknown) => e)
    expect((refused as McpToolError).code).toBe('sandbox_refused')
    expect((refused as Error).message).toContain(SANDBOX_REFUSED)
    expect((refused as Error).message).not.toMatch(/cm0abc/)
  })
})

describe('an agent 4xx reaches the caller', () => {
  // A sibling session found this class in graphClient.ts: a refusal the caller
  // could have acted on was collapsed into a flat generic message. The same
  // shape was here - the agent answers 409 from kali_cancel with the reason a
  // job could not be stopped, and only 400/404/429/503 were enumerated.
  const agentSays = (status: number, error: string) => {
    h.fetch.mockResolvedValue({
      ok: false, status,
      json: async () => ({ error }),
    })
  }

  test('a 409 conflict carries its reason instead of a generic message', async () => {
    agentSays(409, 'the job already finished and cannot be cancelled')
    await expect(kaliJobCancel('p1', 'a'.repeat(32), 'person-7'))
      .rejects.toThrow(/already finished and cannot be cancelled/)
  })

  test('an unenumerated 4xx carries its reason too', async () => {
    agentSays(422, 'cursor must be a whole number of bytes')
    await expect(kaliJobStatus('p1', 'a'.repeat(32), 0, 'person-7'))
      .rejects.toThrow(/whole number of bytes/)
  })

  test('a 5xx still degrades to a fixed line', async () => {
    // Those bodies are raw exception text: host paths and image names.
    agentSays(500, "FileNotFoundError: /opt/redamon/agentic/api.py line 42")
    await expect(kaliJobStatus('p1', 'a'.repeat(32), 0, 'person-7'))
      .rejects.toThrow(/The command could not be run\./)
    await expect(kaliJobStatus('p1', 'a'.repeat(32), 0, 'person-7'))
      .rejects.not.toThrow(/api\.py/)
  })

  test('404 stays deliberately uniform, for anti-enumeration', async () => {
    // A missing job and another project's job must read identically.
    agentSays(404, 'no such command')
    await expect(kaliJobStatus('p1', 'a'.repeat(32), 0, 'person-7'))
      .rejects.toThrow(/^No such command\.$/)
  })
})
