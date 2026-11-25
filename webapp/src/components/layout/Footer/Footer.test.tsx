/**
 * A preference write that failed is toasted from the footer, which every page
 * mounts: the tables and the graph that write preferences are not always on
 * screen, and the hook itself also runs outside the toast layer (the theme bridge).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { useEffect } from 'react'
import { render, screen, cleanup, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ToastProvider } from '@/components/ui/Toast/Toast'
import { useUserPreferences } from '@/hooks/useUserPreferences'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/hooks/useVersionCheck', () => ({ useVersionCheck: () => ({ currentVersion: '0.0.0', latestVersion: null, updateAvailable: false }) }))
vi.mock('@/components/system/SystemMeter', () => ({ SystemMeter: () => null }))

import { Footer } from './Footer'

let write: ((key: string, value: unknown) => void) | null = null
function Writer() {
  const { updatePref } = useUserPreferences()
  useEffect(() => { write = updatePref })
  return null
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
    if (init?.method === 'PATCH') {
      return new Response(JSON.stringify({ error: 'Failed to update preferences', code: 'P2024' }), { status: 500 })
    }
    return new Response(JSON.stringify({ theme: 'dark' }), { status: 200 })
  }))
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('Footer: preference write failures', () => {
  test('a write from another component that failed is toasted with its code and status', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <ToastProvider><Writer /><Footer /></ToastProvider>
      </QueryClientProvider>,
    )
    await act(async () => { await new Promise(r => setTimeout(r, 10)) })
    act(() => write!('theme', 'light'))
    expect(await screen.findByText('Failed to update preferences (P2024 · HTTP 500)', {}, { timeout: 2000 })).toBeInTheDocument()
    expect(screen.getByText('Preference not saved')).toBeInTheDocument()
  })

  test('nothing failed, nothing toasted', async () => {
    const client = new QueryClient()
    render(
      <QueryClientProvider client={client}>
        <ToastProvider><Footer /></ToastProvider>
      </QueryClientProvider>,
    )
    expect(screen.queryByText('Preference not saved')).toBeNull()
  })
})
