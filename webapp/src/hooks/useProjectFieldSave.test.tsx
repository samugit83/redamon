/**
 * The graph page's stealth and model switches (step 5.2, SH-40): each saves one field with the
 * header's version; a stale 409 says "Someone else changed this project" and the header takes the row
 * as it is now; a saved field moves the header's version forward; another failure is shown as before.
 *
 * Run: npx vitest run --no-file-parallelism src/hooks/useProjectFieldSave.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'
import type { ProjectSummary } from '@/lib/projectSummary'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }))
vi.mock('@/components/ui', async (orig) => ({ ...(await orig<typeof import('@/components/ui')>()), useToast: () => toast }))

import { useProjectFieldSave } from './useProjectFieldSave'

const V1 = '2026-11-13T10:00:00.000Z'
const V2 = '2026-11-13T11:00:00.000Z'
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const CURRENT = { id: 'p1', name: 'ACME', stealthMode: false, agentOpenaiModel: 'm-1', updatedAt: V1 } as unknown as ProjectSummary

const h = vi.hoisted(() => ({ calls: [] as Array<{ method: string; body?: Record<string, unknown> }>, put: null as null | (() => Response) }))

beforeEach(() => {
  h.calls = []
  h.put = null
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    h.calls.push({ method, body: init?.body ? JSON.parse(String(init.body)) : undefined })
    if (method === 'PUT') return h.put ? h.put() : json(200, { id: 'p1', updatedAt: V2 })
    return json(200, { id: 'p1', name: 'ACME', targetDomain: 'acme.test', stealthMode: true, agentOpenaiModel: 'm-9', updatedAt: V2 })
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

function hook() {
  const setCurrentProject = vi.fn()
  const { result } = renderHook(() => useProjectFieldSave('p1', CURRENT, setCurrentProject))
  return { save: result.current, setCurrentProject }
}

describe('the stealth and model switches of the graph page (step 5.2)', () => {
  test.each([
    ['stealth mode', 'stealthMode', true],
    ['the agent model', 'agentOpenaiModel', 'm-2'],
  ] as const)('%s: sends the header version, then takes the saved version', async (_what, field, value) => {
    const { save, setCurrentProject } = hook()
    await act(() => save(field, value, 'Could not save'))
    expect(h.calls).toEqual([{ method: 'PUT', body: { [field]: value, updatedAt: V1 } }])
    expect(setCurrentProject).toHaveBeenCalledWith({ ...CURRENT, [field]: value, updatedAt: V2 })
  })

  test.each([['stealthMode', true], ['agentOpenaiModel', 'm-2']] as const)('auto-save stale -> 409 and reload (%s)', async (field, value) => {
    h.put = () => json(409, { error: 'changed', code: 'stale_save' })
    const { save, setCurrentProject } = hook()
    await act(() => save(field, value, 'Could not save'))
    expect(toast.warning).toHaveBeenCalledWith(expect.stringMatching(/Someone else changed this project/))
    expect(h.calls.map(c => c.method)).toEqual(['PUT', 'GET'])
    expect(setCurrentProject).toHaveBeenCalledWith(expect.objectContaining({ id: 'p1', stealthMode: true, agentOpenaiModel: 'm-9', updatedAt: V2 }))
    expect(toast.error).not.toHaveBeenCalled()
  })

  test('another failure is shown as before and changes nothing', async () => {
    h.put = () => json(403, { error: 'Refused.', code: 'forbidden', permission: 'project:settings' })
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const { save, setCurrentProject } = hook()
    await act(() => save('stealthMode', true, 'Could not change Stealth Mode'))
    expect(toast.error).toHaveBeenCalledWith(expect.stringMatching(/Refused/))
    expect(setCurrentProject).not.toHaveBeenCalled()
  })
})
