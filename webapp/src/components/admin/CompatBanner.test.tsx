/**
 * The header's admin banners (HD-30, HD-29, step 1.18): a red banner while
 * REDAMON_SHARED_TOOLS_COMPAT is on, and a small one linking to the legacy access review
 * while grants wait for a decision. Admins only, never blocking, read from /api/auth/me's
 * `rbac` block; the review banner reads the count again after a decision.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, act, waitFor } from '@testing-library/react'
import React from 'react'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: React.AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) =>
    <a href={href} {...rest}>{children}</a>,
}))

import { AdminBanners, CompatBanner } from './CompatBanner'
import { LEGACY_GRANTS_CHANGED_EVENT } from './updateNotes'

const fetchMock = vi.fn()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const OFF = { compat: false, legacyGrantsPending: 0 }

describe('banner only while compat is on', () => {
  test('compat on: the red banner names the switch, for an admin', () => {
    render(<AdminBanners isAdmin rbac={{ compat: true, legacyGrantsPending: 0 }} pathname="/graph" />)
    const banner = screen.getByRole('status', { name: 'Compatibility mode is on' })
    expect(banner.textContent).toContain('REDAMON_SHARED_TOOLS_COMPAT')
    expect(banner.textContent).toMatch(/created before the upgrade/)
    expect(banner.textContent).toMatch(/every use is audited/i)
  })

  test('compat off: no banner', () => {
    const { container } = render(<AdminBanners isAdmin rbac={OFF} pathname="/graph" />)
    expect(container.textContent).toBe('')
  })

  test('a member never sees it, whatever reaches the page', () => {
    const { container } = render(<AdminBanners isAdmin={false} rbac={{ compat: true, legacyGrantsPending: 3 }} pathname="/graph" />)
    expect(container.textContent).toBe('')
  })

  test('no rbac block (an older answer, or still loading): no banner', () => {
    const { container } = render(<AdminBanners isAdmin rbac={undefined} pathname="/graph" />)
    expect(container.textContent).toBe('')
  })

  test('the banner itself has the error style and is not a dialog', () => {
    render(<CompatBanner />)
    const banner = screen.getByRole('status', { name: 'Compatibility mode is on' })
    expect(banner.className).toMatch(/compat/)
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe('the legacy review banner', () => {
  test('links to the review card while grants are pending', () => {
    render(<AdminBanners isAdmin rbac={{ compat: false, legacyGrantsPending: 3 }} pathname="/graph" />)
    const banner = screen.getByRole('status', { name: 'Legacy access waits for review' })
    expect(banner.textContent).toMatch(/3 legacy grants from the previous version wait for your review/)
    expect(screen.getByRole('link', { name: 'Review on the Users page' })).toHaveAttribute('href', '/settings/users#legacy-access')
  })

  test('hidden on the Users page itself, where the card is', () => {
    const { container } = render(<AdminBanners isAdmin rbac={{ compat: false, legacyGrantsPending: 3 }} pathname="/settings/users" />)
    expect(container.textContent).toBe('')
  })

  test('a count that could not be read (null) shows no review banner', () => {
    const { container } = render(<AdminBanners isAdmin rbac={{ compat: false, legacyGrantsPending: null }} pathname="/graph" />)
    expect(container.textContent).toBe('')
  })

  test('both banners together', () => {
    render(<AdminBanners isAdmin rbac={{ compat: true, legacyGrantsPending: 1 }} pathname="/graph" />)
    expect(screen.getByRole('status', { name: 'Compatibility mode is on' })).toBeInTheDocument()
    expect(screen.getByText(/1 legacy grant from the previous version waits for your review/)).toBeInTheDocument()
  })

  test('a decision elsewhere makes it read /api/auth/me again', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ id: 'a', role: 'admin', rbac: OFF }), { status: 200 }))
    render(<AdminBanners isAdmin rbac={{ compat: false, legacyGrantsPending: 2 }} pathname="/graph" />)
    expect(screen.getByRole('status', { name: 'Legacy access waits for review' })).toBeInTheDocument()
    await act(async () => { window.dispatchEvent(new Event(LEGACY_GRANTS_CHANGED_EVENT)) })
    await waitFor(() => expect(screen.queryByRole('status', { name: 'Legacy access waits for review' })).toBeNull())
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/me', { cache: 'no-store' })
  })

  test('a member never asks /api/auth/me again', async () => {
    render(<AdminBanners isAdmin={false} rbac={undefined} pathname="/graph" />)
    await act(async () => { window.dispatchEvent(new Event(LEGACY_GRANTS_CHANGED_EVENT)) })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
