/**
 * The drawer saves the tradecraft switches as it saves the skill switches (§3.4, R-050): a moment
 * after the change, only that field, with the row's version; a stale save is refused, says so and
 * reloads the row; a save that lands tells the counter badge (TRADECRAFT_COUNTS_CHANNEL); a skills
 * notice that moves the window's version brings the switches saved elsewhere with it.
 */
import { test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }))
vi.mock('@/components/ui', async (orig) => ({ ...(await orig<typeof import('@/components/ui')>()), useToast: () => toast }))
const posted = vi.hoisted(() => [] as unknown[])
vi.mock('@/lib/tradecraft/channels', () => ({ postTradecraftCountsChanged: (c: unknown) => posted.push(c) }))

import { mergeOwnOff, useSettingsModal } from './useSettingsModal'
import { postUserSkillsChanged } from '@/lib/userSkillsChannel'

const ROW = {
  id: 'p1', userId: 'alice', createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-12T10:00:00.000Z', user: { id: 'alice' },
  name: 'ACME lab', attackSkillConfig: { builtIn: { xss: true }, user: {} }, tradecraftOff: ['r2'],
}
const h = vi.hoisted(() => ({ puts: [] as Record<string, unknown>[], gets: 0, putAnswer: null as null | (() => Response), row: null as null | Record<string, unknown> }))
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
    if (init?.method === 'PUT') {
      h.puts.push(JSON.parse(String(init.body)))
      return h.putAnswer ? h.putAnswer() : json(200, { ...ROW, updatedAt: '2026-10-12T10:05:00.000Z' })
    }
    h.gets += 1
    return json(200, h.row ?? ROW)
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
  h.puts = []
  h.gets = 0
  h.putAnswer = null
  h.row = null
  posted.length = 0
})

async function open() {
  const hook = renderHook(() => useSettingsModal('p1'))
  act(() => hook.result.current.setSettingsModal('attack'))
  await waitFor(() => expect(hook.result.current.projectFormData).not.toBeNull())
  return hook
}

test('the window reads the switches with the project', async () => {
  const hook = await open()
  expect(hook.result.current.projectFormData!.tradecraftOff).toEqual(['r2'])
})

test('drawer_autosave_and_stale: the switches alone, debounced, with the version; the badge is told', async () => {
  const hook = await open()
  act(() => hook.result.current.updateProjectField('tradecraftOff', ['r1', 'r2']))
  expect(h.puts).toHaveLength(0)
  await waitFor(() => expect(h.puts).toHaveLength(1))
  expect(h.puts[0]).toEqual({ tradecraftOff: ['r1', 'r2'], updatedAt: ROW.updatedAt })
  await waitFor(() => expect(posted).toEqual([{ projectId: 'p1' }]))
})

test('drawer_autosave_and_stale: changed meanwhile, the save is refused, the window says so and reloads', async () => {
  const hook = await open()
  h.putAnswer = () => json(409, { error: 'This project changed since you opened it.', code: 'stale_save' })
  h.row = { ...ROW, tradecraftOff: ['r3'], updatedAt: '2026-10-12T11:00:00.000Z' }
  act(() => hook.result.current.updateProjectField('tradecraftOff', ['r1']))
  await waitFor(() => expect(toast.warning).toHaveBeenCalled())
  await waitFor(() => expect(hook.result.current.projectFormData?.tradecraftOff).toEqual(['r3']))
  expect(posted).toEqual([])
})

test('a skill toggle saved from the drawer tells the badge too', async () => {
  const hook = await open()
  act(() => hook.result.current.updateProjectField('attackSkillConfig', { builtIn: { xss: false }, user: {} } as never))
  await waitFor(() => expect(posted).toEqual([{ projectId: 'p1' }]))
})

// The project form saved r1 off with a skill change, which posts on the skills channel: the window
// takes the row's version, so it must take the switches too, or its next save turns r1 back on.
const SAVED_ELSEWHERE = { ...ROW, updatedAt: '2026-10-12T11:00:00.000Z', tradecraftOff: ['r1', 'r2'] }

test('drawer_autosave_and_stale: a switch saved in another window is kept when the skills notice moves the version (R-050, AC-27)', async () => {
  const hook = await open()
  h.row = SAVED_ELSEWHERE
  act(() => postUserSkillsChanged({ projectId: 'p1' }))
  await waitFor(() => expect(hook.result.current.projectFormData?.tradecraftOff).toEqual(['r1', 'r2']))
  act(() => hook.result.current.updateProjectField('tradecraftOff', [...hook.result.current.projectFormData!.tradecraftOff!, 'r3']))
  await waitFor(() => expect(h.puts).toHaveLength(1))
  expect(h.puts[0]).toEqual({ tradecraftOff: ['r1', 'r2', 'r3'], updatedAt: SAVED_ELSEWHERE.updatedAt })
})

test("drawer_autosave_and_stale: this window's unsaved switches are applied to the list saved elsewhere, so its save keeps both", async () => {
  const hook = await open()
  // This window turns r2 back on and r3 off; the save waits for the debounce.
  act(() => hook.result.current.updateProjectField('tradecraftOff', ['r3']))
  h.row = SAVED_ELSEWHERE
  act(() => postUserSkillsChanged({ projectId: 'p1' }))
  await waitFor(() => expect(h.puts).toHaveLength(1))
  expect(h.puts[0]).toEqual({ tradecraftOff: ['r1', 'r3'], updatedAt: SAVED_ELSEWHERE.updatedAt })
  expect(toast.warning).not.toHaveBeenCalled()
})

test('mergeOwnOff keeps only the switches this window changed', () => {
  expect(mergeOwnOff(['a', 'b'], ['b', 'c'], ['a', 'b', 'd'])).toEqual(['b', 'd', 'c'])
  expect(mergeOwnOff(['a'], ['a'], ['d'])).toEqual(['d'])
  expect(mergeOwnOff(undefined, ['x'], null)).toEqual(['x'])
})
