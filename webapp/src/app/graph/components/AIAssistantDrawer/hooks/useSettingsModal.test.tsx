/**
 * The chat drawer's settings modals autosave (plan Phase 0.B.4): the debounced PUT sends ONLY
 * the fields changed since the modal opened (never the whole row), so it cannot overwrite a
 * toggle another window switched meanwhile. A refused or failed PUT says so in a toast and its
 * keys are sent again with the next change; switching or closing the modal flushes a pending
 * save at once. Step 5.2 (SH-40): each PUT also carries the row's `updatedAt` as the modal last
 * read or saved it (recorded apart from the fields, `h.versions`), and a stale 409 reloads the row.
 */
import { test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }))
vi.mock('@/components/ui', async (orig) => ({ ...(await orig<typeof import('@/components/ui')>()), useToast: () => toast }))

import { useSettingsModal, type ProjectFormData } from './useSettingsModal'
import { postUserSkillsChanged } from '@/lib/userSkillsChannel'

const ROW = {
  id: 'p1', userId: 'alice', createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-12T10:00:00.000Z', user: { id: 'alice' },
  name: 'ACME lab', agentMaxIterations: 30, stealthMode: false,
  attackSkillConfig: { builtIn: { xss: true }, user: { sk1: true } },
}

const h = vi.hoisted(() => ({
  puts: [] as { url: string; body: Record<string, unknown> }[],
  /** The `updatedAt` each PUT carried (the fields are in `puts`). */
  versions: [] as unknown[],
  gets: [] as string[],
  putAnswer: null as null | (() => Response | Promise<Response>),
  row: null as Record<string, unknown> | null,
}))

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    if (init?.method === 'PUT') {
      const { updatedAt, ...fields } = JSON.parse(String(init.body)) as Record<string, unknown>
      h.puts.push({ url, body: fields })
      h.versions.push(updatedAt)
      return h.putAnswer ? h.putAnswer() : json(200, { ok: true })
    }
    h.gets.push(url)
    return json(200, h.row ?? ROW)
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
  h.puts = []
  h.versions = []
  h.gets = []
  h.putAnswer = null
  h.row = null
})

async function open(modal: 'agent' | 'toolmatrix' | 'attack' = 'agent') {
  const hook = renderHook(() => useSettingsModal('p1'))
  act(() => hook.result.current.setSettingsModal(modal))
  await waitFor(() => expect(hook.result.current.projectFormData).not.toBeNull())
  return hook
}

const set = <K extends keyof ProjectFormData>(hook: Awaited<ReturnType<typeof open>>, k: K, v: ProjectFormData[K]) =>
  act(() => hook.result.current.updateProjectField(k, v))

test('opening a modal loads the project without its identity and timestamps', async () => {
  const hook = await open()
  expect(h.gets).toEqual(['/api/projects/p1'])
  const data = hook.result.current.projectFormData as unknown as Record<string, unknown>
  expect(data.name).toBe('ACME lab')
  for (const k of ['id', 'userId', 'createdAt', 'updatedAt', 'user']) expect(k in data).toBe(false)
})

test('a change PUTs only that field, after the debounce, with the version the modal read (step 5.2)', async () => {
  const hook = await open()
  set(hook, 'agentMaxIterations' as keyof ProjectFormData, 50 as never)
  expect(h.puts).toHaveLength(0)
  await waitFor(() => expect(h.puts).toHaveLength(1))
  expect(h.puts[0].url).toBe('/api/projects/p1')
  expect(h.puts[0].body).toEqual({ agentMaxIterations: 50 })
  expect(h.versions[0]).toBe(ROW.updatedAt)
})

test('auto-save stale -> 409 and reload: the modal says so and takes the row as it is now (step 5.2)', async () => {
  const hook = await open()
  h.putAnswer = () => json(409, { error: 'This project changed since you opened it.', code: 'stale_save' })
  h.row = { ...ROW, agentMaxIterations: 70, updatedAt: '2026-10-12T11:00:00.000Z' }
  set(hook, 'agentMaxIterations' as keyof ProjectFormData, 50 as never)
  await waitFor(() => expect(toast.warning).toHaveBeenCalledWith(expect.stringMatching(/Someone else changed this project/)))
  await waitFor(() => expect((hook.result.current.projectFormData as unknown as Record<string, unknown>)?.agentMaxIterations).toBe(70))
  expect(h.gets).toEqual(['/api/projects/p1', '/api/projects/p1'])
  expect(toast.error).not.toHaveBeenCalled()
  // The next change carries the reloaded row's version, and the refused field is not sent again.
  h.putAnswer = null
  set(hook, 'stealthMode' as keyof ProjectFormData, true as never)
  await waitFor(() => expect(h.puts).toHaveLength(2))
  expect(h.puts[1].body).toEqual({ stealthMode: true })
  expect(h.versions[1]).toBe('2026-10-12T11:00:00.000Z')
})

test('changing a skill toggle sends attackSkillConfig alone', async () => {
  const hook = await open('attack')
  const next = { builtIn: { xss: true }, user: { sk1: true, sk2: true } }
  set(hook, 'attackSkillConfig', next as never)
  await waitFor(() => expect(h.puts).toHaveLength(1))
  expect(h.puts[0].body).toEqual({ attackSkillConfig: next })
})

test('rapid changes are debounced into one PUT carrying every changed field, with the last values', async () => {
  const hook = await open()
  set(hook, 'agentMaxIterations' as keyof ProjectFormData, 40 as never)
  set(hook, 'stealthMode' as keyof ProjectFormData, true as never)
  set(hook, 'agentMaxIterations' as keyof ProjectFormData, 45 as never)
  await waitFor(() => expect(h.puts).toHaveLength(1))
  await new Promise((r) => setTimeout(r, 600))
  expect(h.puts).toHaveLength(1)
  expect(h.puts[0].body).toEqual({ agentMaxIterations: 45, stealthMode: true })
})

test('after a save lands, the next change sends only the new field', async () => {
  const hook = await open()
  set(hook, 'agentMaxIterations' as keyof ProjectFormData, 40 as never)
  await waitFor(() => expect(h.puts).toHaveLength(1))
  set(hook, 'stealthMode' as keyof ProjectFormData, true as never)
  await waitFor(() => expect(h.puts).toHaveLength(2))
  expect(h.puts[1].body).toEqual({ stealthMode: true })
})

test('a refused PUT shows the server error in a toast and its keys go again with the next change', async () => {
  h.putAnswer = () => json(409, { error: 'too_many_enabled_skills' })
  const hook = await open()
  set(hook, 'agentMaxIterations' as keyof ProjectFormData, 40 as never)
  await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Settings not saved: too_many_enabled_skills'))
  h.putAnswer = null
  set(hook, 'stealthMode' as keyof ProjectFormData, true as never)
  await waitFor(() => expect(h.puts).toHaveLength(2))
  expect(h.puts[1].body).toEqual({ stealthMode: true, agentMaxIterations: 40 })
})

test('a refused PUT without an error message names the status', async () => {
  h.putAnswer = () => new Response('oops', { status: 500 })
  const hook = await open()
  set(hook, 'stealthMode' as keyof ProjectFormData, true as never)
  await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Settings not saved (HTTP 500).'))
})

test('a network failure says the server could not be reached and re-sends the keys next time', async () => {
  h.putAnswer = () => Promise.reject(new TypeError('Failed to fetch'))
  const hook = await open()
  set(hook, 'agentMaxIterations' as keyof ProjectFormData, 40 as never)
  await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Settings not saved: the server could not be reached.'))
  h.putAnswer = null
  set(hook, 'stealthMode' as keyof ProjectFormData, true as never)
  await waitFor(() => expect(h.puts).toHaveLength(2))
  expect(h.puts[1].body).toEqual(expect.objectContaining({ agentMaxIterations: 40, stealthMode: true }))
})

test('switching to another modal flushes the pending save at once, then reloads with a clean slate', async () => {
  const hook = await open('agent')
  set(hook, 'agentMaxIterations' as keyof ProjectFormData, 40 as never)
  expect(h.puts).toHaveLength(0)
  act(() => hook.result.current.setSettingsModal('attack'))
  // Flushed synchronously on the switch, not after the debounce.
  expect(h.puts).toHaveLength(1)
  expect(h.puts[0].body).toEqual({ agentMaxIterations: 40 })
  await waitFor(() => expect(hook.result.current.projectFormData).not.toBeNull())
  expect(h.gets).toHaveLength(2)
  // Nothing more goes out: the flushed timer does not fire a second PUT.
  await new Promise((r) => setTimeout(r, 600))
  expect(h.puts).toHaveLength(1)
  set(hook, 'stealthMode' as keyof ProjectFormData, true as never)
  await waitFor(() => expect(h.puts).toHaveLength(2))
  expect(h.puts[1].body).toEqual({ stealthMode: true })
})

test('closing the modal flushes the pending save', async () => {
  const hook = await open('attack')
  const next = { builtIn: { xss: true }, user: { sk1: false } }
  set(hook, 'attackSkillConfig', next as never)
  act(() => hook.result.current.setSettingsModal(null))
  expect(h.puts).toHaveLength(1)
  expect(h.puts[0].body).toEqual({ attackSkillConfig: next })
  expect(hook.result.current.projectFormData).toBeNull()
})

test('opening and closing without a change PUTs nothing', async () => {
  const hook = await open()
  act(() => hook.result.current.setSettingsModal(null))
  await new Promise((r) => setTimeout(r, 600))
  expect(h.puts).toHaveLength(0)
})

test('a skill version saved elsewhere for this project does not get written back stale by the next toggle', async () => {
  // The Agent Skills modal mounts AttackSkillsSection, whose versions window can open a
  // user-skill review; saving it with "instead of" switches this project's toggles on the
  // server (and posts on the user-skills channel). The modal's next toggle must build on
  // that map, not on the one it loaded when it opened.
  const hook = await open('attack')
  h.row = { ...ROW, updatedAt: '2026-10-13T09:00:00.000Z', attackSkillConfig: { builtIn: { xss: true }, user: { sk1: false, sk2: true } } }
  act(() => postUserSkillsChanged({ projectId: 'p1' }))
  await new Promise((r) => setTimeout(r, 50))
  const current = hook.result.current.projectFormData!.attackSkillConfig as { builtIn: Record<string, boolean>; user: Record<string, boolean> }
  set(hook, 'attackSkillConfig', { ...current, user: { ...current.user, sk3: true } } as never)
  await waitFor(() => expect(h.puts).toHaveLength(1))
  expect(h.puts[0].body).toEqual({ attackSkillConfig: { builtIn: { xss: true }, user: { sk1: false, sk2: true, sk3: true } } })
})

test("a toggle of this window's not yet saved is laid over the map saved elsewhere, so its save keeps both", async () => {
  const hook = await open('attack')
  // This window turns sk3 on; its save is still waiting for the debounce.
  set(hook, 'attackSkillConfig', { builtIn: { xss: true }, user: { sk1: true, sk3: true } } as never)
  // Meanwhile a version saved elsewhere swapped sk1 for sk2 on the server.
  h.row = { ...ROW, updatedAt: '2026-10-13T09:00:00.000Z', attackSkillConfig: { builtIn: { xss: true }, user: { sk1: false, sk2: true } } }
  act(() => postUserSkillsChanged({ projectId: 'p1' }))
  await waitFor(() => expect(h.puts).toHaveLength(1))
  expect(h.puts[0].body).toEqual({ attackSkillConfig: { builtIn: { xss: true }, user: { sk1: false, sk2: true, sk3: true } } })
  expect(toast.warning).not.toHaveBeenCalled()
})

test('mergeOwnToggles keeps only what this window changed', async () => {
  const { mergeOwnToggles } = await import('./useSettingsModal')
  const base = { builtIn: { xss: true }, user: { a: true, b: false } }
  const local = { builtIn: { xss: false }, user: { a: true, b: true } }
  const fresh = { builtIn: { xss: true, rce: true }, user: { a: false, c: true } }
  expect(mergeOwnToggles(base, local, fresh)).toEqual({ builtIn: { xss: false, rce: true }, user: { a: false, b: true, c: true } })
  expect(mergeOwnToggles(base, base, fresh)).toEqual(fresh)
})

test('a project that cannot be read is an error, not a spinner forever (G-51)', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => json(503, { error: 'Failed to fetch project', code: 'P1001' })))
  const hook = renderHook(() => useSettingsModal('p1'))
  act(() => hook.result.current.setSettingsModal('agent'))
  await waitFor(() => expect(hook.result.current.projectLoadError).toBe('Failed to fetch project (P1001 · HTTP 503)'))
  expect(hook.result.current.projectFormData).toBeNull()
})

test('the settings modal shows the load error in place of the spinner (G-51)', async () => {
  const { render, screen } = await import('@testing-library/react')
  const { SettingsModal } = await import('../SettingsModal')
  render(
    <SettingsModal settingsModal="agent" setSettingsModal={() => {}} projectFormData={null}
      updateProjectField={() => {}} loadError="Failed to fetch project (P1001 · HTTP 503)" />,
  )
  expect(screen.getByRole('alert')).toHaveTextContent('Failed to fetch project (P1001 · HTTP 503)')
})
