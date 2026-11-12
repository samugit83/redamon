/**
 * The plugin facts of the project Agent Skills section. A failed read still resolves to
 * "nothing", so the core section never breaks (RV-52), but `error` says what failed, with its
 * code and status, for a hint with Retry instead of items that silently vanish.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { usePluginSkillOverrides } from './usePluginSkillOverrides'

afterEach(() => vi.unstubAllGlobals())

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

function stub(summary: () => Response, contributions: () => Response) {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => (url.includes('/overrides/summary') ? summary() : contributions())))
}

describe('usePluginSkillOverrides', () => {
  test('both reads answer: the facts, no error', async () => {
    stub(
      () => json(200, { skills: [{ skillId: 'ssrf' }] }),
      () => json(200, [{ pluginId: 'skiller', displayName: 'Skiller', projectSkillsRow: [{ action: 'improve', label: 'Improve' }] }]),
    )
    const { result } = renderHook(() => usePluginSkillOverrides('p1'))
    await waitFor(() => expect(result.current.ready).toBe(true))
    expect(result.current.error).toBeNull()
    expect(result.current.bySkill.has('ssrf')).toBe(true)
    expect(result.current.rowActions).toEqual([{ action: 'improve', label: 'Improve', pluginId: 'skiller', pluginDisplayName: 'Skiller' }])
  })

  test('a failed read: nothing shown, and why; Retry (reload) reads again', async () => {
    stub(() => json(500, { error: 'The plugin skill versions could not be read; see the webapp log.', code: 'P2024' }), () => json(200, []))
    const { result } = renderHook(() => usePluginSkillOverrides('p1'))
    await waitFor(() => expect(result.current.ready).toBe(true))
    expect(result.current.bySkill.size).toBe(0)
    expect(result.current.error).toBe('The plugin skill versions could not be read; see the webapp log. (P2024 · HTTP 500)')

    stub(() => json(200, { skills: [] }), () => json(200, []))
    act(() => result.current.reload())
    await waitFor(() => expect(result.current.error).toBeNull())
  })

  test('refused for plugins:use: nothing shown and no error, a 403 for anything else still is one (step 3.9)', async () => {
    const refused = (permission: string) => () => json(403, { error: `You do not hold the permission this action needs (${permission}).`, code: 'forbidden', permission })
    stub(refused('plugins:use'), refused('plugins:use'))
    const { result } = renderHook(() => usePluginSkillOverrides('p1'))
    await waitFor(() => expect(result.current.ready).toBe(true))
    expect(result.current.error).toBeNull()
    expect(result.current.bySkill.size).toBe(0)
    expect(result.current.rowActions).toEqual([])

    stub(refused('project:settings'), () => json(200, []))
    act(() => result.current.reload())
    await waitFor(() => expect(result.current.error).toMatch(/project:settings/))
  })

  test('the contributions failing with no answer at all is named too', async () => {
    stub(() => json(200, { skills: [] }), () => {
      throw new TypeError('Failed to fetch')
    })
    const { result } = renderHook(() => usePluginSkillOverrides('p1'))
    await waitFor(() => expect(result.current.error).toBe('Plugin items could not be loaded (network_error)'))
  })
})
