import { createElement, type ReactNode } from 'react'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, cleanup, act } from '@testing-library/react'
import { JevSelectionProvider, useHasJevProvider, useJevProvider, notifyJevProviderChanged } from './useHasJevProvider'

const direct = { id: 'direct', name: 'Lab direct', providerType: 'jev', apiKey: 'masked', modelIdentifier: 'jev-1.13.0' }
const router = { ...direct, id: 'router', name: 'Lab routed', providerType: 'jev_openrouter', modelIdentifier: 'typesafe/jev-1.13' }
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = vi.fn().mockResolvedValue(response([direct, router]))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function mount(selection: string | null = 'direct', owner: string | null = 'owner-1', unavailable = false) {
  let selectedProviderId = selection
  let ownerUserId = owner
  const hook = renderHook(() => useJevProvider(), { wrapper: ({ children }: { children: ReactNode }) =>
    createElement(JevSelectionProvider, { selectedProviderId, ownerUserId, ownerUnavailable: unavailable, children }) })
  return { ...hook,
    select(id: string | null) { selectedProviderId = id; hook.rerender() },
    owner(id: string | null) { ownerUserId = id; hook.rerender() },
  }
}

describe('explicit project Jev selection', () => {
  test('loading is distinct and the lookup asks for the owner, not an acting-user context', async () => {
    const hook = mount()
    expect(hook.result.current.status).toBe('loading')
    await waitFor(() => expect(hook.result.current.status).toBe('yes'))
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith('/api/users/owner-1/llm-providers')
  })

  test('new and legacy null selections never pick the first configured entry', async () => {
    const hook = mount(null)
    await waitFor(() => expect(hook.result.current.status).toBe('no'))
    expect(hook.result.current.providers).toHaveLength(2)
    expect(hook.result.current.provider).toBeNull()
  })

  test('only the selected backend is valid, and unsaved changes and clearing apply immediately', async () => {
    const hook = mount('router')
    await waitFor(() => expect(hook.result.current.provider?.id).toBe('router'))
    hook.select('direct')
    expect(hook.result.current.provider?.id).toBe('direct')
    hook.select(null)
    expect(hook.result.current.status).toBe('no')
    expect(hook.result.current.provider).toBeNull()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test.each(['deleted', 'chat', 'empty'])('an invalid selection %s never falls back to another entry', async id => {
    fetchMock.mockResolvedValue(response([direct, router,
      { ...direct, id: 'chat', providerType: 'openrouter' }, { ...direct, id: 'empty', apiKey: '' }]))
    const hook = mount(id)
    await waitFor(() => expect(hook.result.current.status).toBe('no'))
    expect(hook.result.current.provider).toBeNull()
  })

  test('deletion events invalidate the selected entry; remaining configurations stay unselected', async () => {
    const hook = mount()
    await waitFor(() => expect(hook.result.current.status).toBe('yes'))
    fetchMock.mockResolvedValue(response([router]))
    act(notifyJevProviderChanged)
    expect(hook.result.current.status).toBe('loading')
    await waitFor(() => expect(hook.result.current.status).toBe('no'))
    expect(hook.result.current.selectedProviderId).toBe('direct')
    expect(hook.result.current.provider).toBeNull()
  })

  test('changing owners hides the old owner’s rows before the next lookup resolves', async () => {
    const hook = mount()
    await waitFor(() => expect(hook.result.current.status).toBe('yes'))
    fetchMock.mockImplementation(() => new Promise(() => {}))
    hook.owner('owner-2')
    expect(hook.result.current.status).toBe('loading')
    expect(hook.result.current.providers).toEqual([])
    expect(hook.result.current.provider).toBeNull()
  })

  test('unknown new-project owner stays loading without querying an actor', () => {
    const hook = mount(null, null)
    expect(hook.result.current.status).toBe('loading')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('unknown legacy/shared project owner is limited, not an actor-account picker', () => {
    const hook = mount(null, null, true)
    expect(hook.result.current.lookupStatus).toBe('limited')
    expect(hook.result.current.status).toBe('error')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('without a project scope, no account or first provider is implicitly looked up', () => {
    const hook = renderHook(useHasJevProvider)
    expect(hook.result.current).toBe('error')
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('lookup errors are not missing configurations', () => {
  test.each([401, 403, 500, 503])('HTTP %i is error and preserves its diagnostic code', async status => {
    fetchMock.mockResolvedValue(response({ error: 'Provider lookup failed', code: 'P2024' }, status))
    const hook = mount()
    await waitFor(() => expect(hook.result.current.status).toBe('error'))
    expect(hook.result.current.error).toContain(`P2024 · HTTP ${status}`)
    expect(hook.result.current.provider).toBeNull()
  })

  test.each([null, {}, 'proxy page'])('a non-list body %j is error', async body => {
    fetchMock.mockResolvedValue(response(body))
    const hook = mount()
    await waitFor(() => expect(hook.result.current.status).toBe('error'))
  })

  test('malformed JSON is error', async () => {
    fetchMock.mockResolvedValue(new Response('<html>'))
    const hook = mount()
    await waitFor(() => expect(hook.result.current.status).toBe('error'))
  })

  test('network failures clear stale provider state and allow a retry', async () => {
    const hook = mount()
    await waitFor(() => expect(hook.result.current.status).toBe('yes'))
    fetchMock.mockRejectedValue(new TypeError('network down'))
    act(hook.result.current.refresh)
    await waitFor(() => expect(hook.result.current.status).toBe('error'))
    expect(hook.result.current.provider).toBeNull()
    fetchMock.mockResolvedValue(response([direct]))
    act(hook.result.current.refresh)
    await waitFor(() => expect(hook.result.current.status).toBe('yes'))
  })
})
