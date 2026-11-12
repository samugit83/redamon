/**
 * The Root banner (step 2.5, ID-10, master plan §14.4): in the header's admin banner slot,
 * with the identity switch on (/api/auth/me sends `rbac.root` then). While the automatic
 * choice waits for the host it names Root, the day it was chosen and how to change it; when
 * the instance has no Root it says so. A confirmed Root needs no banner, a member never sees
 * it, and with the switch off (no `root` field) nothing shows.
 *
 * Run: npx vitest run --no-file-parallelism src/components/admin/RootBanner.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import React from 'react'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: React.AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) =>
    <a href={href} {...rest}>{children}</a>,
}))

import { RootBanner } from './RootBanner'
import { AdminBanners } from './CompatBanner'

afterEach(cleanup)

const BASE = { compat: false, legacyGrantsPending: 0, identity: true as const }
const UNCONFIRMED = { email: 'root@e2e.local', confirmed: false, chosenAt: '2026-11-12T08:30:00.000Z' }

describe('RootBanner', () => {
  test('unconfirmed: names Root, the day it was chosen and the host command', () => {
    render(<AdminBanners adminAccount rbac={{ ...BASE, root: UNCONFIRMED }} pathname="/graph" />)
    const banner = screen.getByRole('status', { name: 'Root was chosen automatically' })
    expect(banner.textContent).toContain('Root is root@e2e.local, chosen automatically on 2026-11-12.')
    expect(banner.textContent).toContain('./redamon.sh set-root <email>')
    expect(banner.textContent).toMatch(/transfer it once the host confirms it/)
  })

  test('unconfirmed without a recorded date: no date, the rest unchanged', () => {
    render(<RootBanner root={{ ...UNCONFIRMED, chosenAt: null }} />)
    expect(screen.getByRole('status').textContent).toContain('Root is root@e2e.local, chosen automatically.')
  })

  test('none: says the instance has no Root and how the host names one', () => {
    render(<AdminBanners adminAccount rbac={{ ...BASE, root: null }} pathname="/graph" />)
    const banner = screen.getByRole('status', { name: 'This instance has no Root' })
    expect(banner.textContent).toContain('This instance has no Root')
    expect(banner.textContent).toContain('./redamon.sh set-root <email>')
  })

  test('confirmed → no banner', () => {
    const { container } = render(
      <AdminBanners adminAccount rbac={{ ...BASE, root: { ...UNCONFIRMED, confirmed: true, chosenAt: null } }} pathname="/graph" />)
    expect(container.textContent).toBe('')
  })

  test('members never see it, whatever reaches the page', () => {
    const { container } = render(<AdminBanners adminAccount={false} rbac={{ ...BASE, root: null }} pathname="/graph" />)
    expect(container.textContent).toBe('')
  })

  test('switch off (no root field) or a Root that could not be read: nothing', () => {
    const { container } = render(<AdminBanners adminAccount rbac={{ compat: false, legacyGrantsPending: 0 }} pathname="/graph" />)
    expect(container.textContent).toBe('')
  })

  test('it shares the slot with the compat banner, and is a status line, not a dialog', () => {
    render(<AdminBanners adminAccount rbac={{ ...BASE, compat: true, root: UNCONFIRMED }} pathname="/graph" />)
    expect(screen.getByRole('status', { name: 'Compatibility mode is on' })).toBeTruthy()
    expect(screen.getByRole('status', { name: 'Root was chosen automatically' })).toBeTruthy()
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})
