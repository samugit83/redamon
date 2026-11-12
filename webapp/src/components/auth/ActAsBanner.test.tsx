/**
 * The act-as banner (step 3.14; IM-05, ID-31): while an admin acts as someone, every page shows
 * "You are acting as <name, email, type> · reason · ends in N min · uses <name>'s API keys · [Stop]".
 * Stop goes back to the admin's own account; when the time is up the banner asks once for the same.
 * The slot in the header shows it only while /api/auth/me says the admin acts as someone.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, act } from '@testing-library/react'
import type { ActingAsView } from '@/providers/AuthProvider'

let mockUser: Record<string, unknown> | null = null
const mockSetUserId = vi.fn(async () => null)
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => ({ user: mockUser }) }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ setUserId: mockSetUserId }) }))

import { ActAsBanner, ActAsBannerSlot, minutesLeft } from './ActAsBanner'

const NOW = Date.parse('2026-11-12T10:00:00Z')
const ACTING: ActingAsView = {
  id: 'member-1', name: 'Marco', email: 'marco@e2e.local', accountType: 'member', reason: 'ticket #42',
  endsAt: '2026-11-12T10:54:00.000Z',
}

beforeEach(() => {
  mockUser = null
  mockSetUserId.mockClear()
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

describe('banner content', () => {
  test('whom (name, email, type), why, time left, whose keys, and Stop', () => {
    render(<ActAsBanner actingAs={ACTING} onStop={vi.fn()} now={() => NOW} />)
    const banner = screen.getByRole('status', { name: 'You are acting as Marco' })
    expect(screen.getByRole('group', { name: 'Marco, marco@e2e.local, Member' })).toBeInTheDocument()
    expect(banner).toHaveTextContent('reason: ticket #42')
    expect(banner).toHaveTextContent('ends in 54 min')
    expect(banner).toHaveTextContent("uses Marco's API keys")
    expect(screen.getByRole('button', { name: 'Stop' })).toBeInTheDocument()
  })

  test('no reason given says so; an unknown end shows no countdown', () => {
    render(<ActAsBanner actingAs={{ ...ACTING, reason: null, endsAt: null }} onStop={vi.fn()} now={() => NOW} />)
    const banner = screen.getByRole('status')
    expect(banner).toHaveTextContent('no reason given')
    expect(banner).not.toHaveTextContent('ends in')
  })

  test('minutes left round up and never go below zero', () => {
    expect(minutesLeft('2026-11-12T10:00:30.000Z', NOW)).toBe(1)
    expect(minutesLeft('2026-11-12T09:59:00.000Z', NOW)).toBe(0)
    expect(minutesLeft(null, NOW)).toBeNull()
    expect(minutesLeft('not a date', NOW)).toBeNull()
  })

  test('Stop calls back once and is disabled while it runs', async () => {
    let finish: () => void = () => {}
    const onStop = vi.fn(() => new Promise<void>((r) => { finish = r }))
    render(<ActAsBanner actingAs={ACTING} onStop={onStop} now={() => NOW} />)
    fireEvent.click(screen.getByRole('button', { name: 'Stop' }))
    expect(screen.getByRole('button', { name: 'Stopping...' })).toBeDisabled()
    finish()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Stop' })).not.toBeDisabled())
    expect(onStop).toHaveBeenCalledTimes(1)
  })

  test('the countdown moves, and the end of the time is announced once', () => {
    vi.useFakeTimers()
    let clock = NOW
    const onExpired = vi.fn()
    render(<ActAsBanner actingAs={{ ...ACTING, endsAt: '2026-11-12T10:01:00.000Z' }} onStop={vi.fn()} onExpired={onExpired} now={() => clock} />)
    expect(screen.getByRole('status')).toHaveTextContent('ends in 1 min')
    clock = NOW + 61_000
    act(() => { vi.advanceTimersByTime(15_000) })
    expect(screen.getByRole('status')).toHaveTextContent('ended')
    act(() => { vi.advanceTimersByTime(60_000) })
    expect(onExpired).toHaveBeenCalledTimes(1)
  })
})

describe('the header slot', () => {
  test('nothing while not acting', () => {
    mockUser = { id: 'admin-1', actingAs: null }
    const { container } = render(<ActAsBannerSlot />)
    expect(container).toBeEmptyDOMElement()
  })

  test('shown while acting; Stop goes back to the admin\'s own account', async () => {
    mockUser = { id: 'admin-1', actingAs: ACTING }
    render(<ActAsBannerSlot />)
    fireEvent.click(screen.getByRole('button', { name: 'Stop' }))
    await waitFor(() => expect(mockSetUserId).toHaveBeenCalledWith('admin-1'))
  })
})
