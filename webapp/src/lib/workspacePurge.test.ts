/**
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { purgeProjectWorkspace } from './workspacePurge'

let warn: ReturnType<typeof vi.spyOn>
let calls: { url: string; init?: RequestInit }[]

beforeEach(() => {
  calls = []
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.stubEnv('INTERNAL_API_KEY', 'k-test')
})

afterEach(() => {
  warn.mockRestore()
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

describe('purgeProjectWorkspace', () => {
  test('asks the agent with the master key', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: unknown, init?: RequestInit) => {
      calls.push({ url: String(url), init })
      return new Response(JSON.stringify({ cancelledJobs: 0, removed: ['workspace'] }), { status: 200 })
    }))
    await purgeProjectWorkspace('p1')
    expect(calls[0].url).toMatch(/\/workspace\/project-purge$/)
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ projectId: 'p1' })
    expect((calls[0].init?.headers as Record<string, string>)['x-internal-key']).toBe('k-test')
    expect(warn).not.toHaveBeenCalled()
  })

  test('never throws, and logs the code on failure', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: 'The project still exists; its workspace was not purged.', code: 'project_exists' }),
      { status: 409 })))
    await expect(purgeProjectWorkspace('p1')).resolves.toBeUndefined()
    expect(String(warn.mock.calls[0][0])).toContain('project_exists')

    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('fetch failed') }))
    await expect(purgeProjectWorkspace('p1')).resolves.toBeUndefined()
    expect(warn).toHaveBeenCalledTimes(2)
  })
})
