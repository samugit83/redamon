/**
 * Unit tests for GlobalHeader – logo link behaviour.
 *
 * Run: npx vitest run src/components/layout/GlobalHeader/GlobalHeader.test.tsx
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import React from 'react'

/* ------------------------------------------------------------------ */
/*  Mocks – Next.js modules & child components                       */
/* ------------------------------------------------------------------ */

let mockPathname = '/graph'
let mockAdmin = true
// What an admin holds here (hooks/useCan.ts); a member holds none of these.
let mockGranted = new Set<string>(['users:read'])
// What /api/auth/me answered for the switches; null until read (the header then shows Phase 3's links).
let mockFlags: Record<string, boolean> | null = null

vi.mock('next/navigation', () => ({
  usePathname: () => mockPathname,
  useRouter: () => ({ push: vi.fn() }),
  redirect: vi.fn(),
}))

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, className, ...rest }: React.AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) =>
    <a href={href} className={className} {...rest}>{children}</a>,
}))

vi.mock('next/image', () => ({
  __esModule: true,
  default: (props: React.ImgHTMLAttributes<HTMLImageElement>) =>
    // eslint-disable-next-line @next/next/no-img-element, jsx-a11y/alt-text
    <img {...props} />,
}))

vi.mock('@/components/ThemeToggle', () => ({
  ThemeToggle: () => <div data-testid="theme-toggle" />,
}))

vi.mock('./ProjectSelector', () => ({
  ProjectSelector: () => <div data-testid="project-selector" />,
}))

vi.mock('./UserSelector', () => ({
  UserSelector: () => <div data-testid="user-selector" />,
}))

vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({
    user: { id: 'test-user', name: 'Test Admin', email: 'admin@test.com', role: mockAdmin ? 'admin' : 'standard' },
    isLoading: false,
    capabilities: new Set(mockAdmin ? mockGranted : []),
    flags: mockFlags,
    login: vi.fn(),
    logout: vi.fn(),
  }),
}))

vi.mock('@/hooks/useCan', () => ({
  useCan: (permission: string) => mockAdmin && mockGranted.has(permission),
  useRbacFlags: () => mockFlags,
}))

vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({
    currentProject: null,
    setCurrentProject: vi.fn(),
    projectId: null,
    userId: null,
    setUserId: vi.fn(),
    isLoading: false,
  }),
}))

import { GlobalHeader } from './GlobalHeader'

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function getLogoLink() {
  const imgs = screen.getAllByAltText('RedAmon')
  expect(imgs).toHaveLength(1)
  const anchor = imgs[0].closest('a')
  if (!anchor) throw new Error('Logo image is not wrapped in an anchor')
  return anchor
}

/* ------------------------------------------------------------------ */
/*  Tests                                                              */
/* ------------------------------------------------------------------ */

beforeEach(() => {
  mockPathname = '/graph'
  mockAdmin = true
  mockGranted = new Set(['users:read'])
  mockFlags = null
})

afterEach(() => {
  cleanup()
})

describe('GlobalHeader – logo link', () => {
  test('logo is rendered as a link (anchor element)', () => {
    render(<GlobalHeader />)
    const logoLink = getLogoLink()
    expect(logoLink.tagName).toBe('A')
  })

  test('logo links to /graph', () => {
    render(<GlobalHeader />)
    const logoLink = getLogoLink()
    expect(logoLink.getAttribute('href')).toBe('/graph')
  })

  test('logo contains the brand image with correct src and alt', () => {
    render(<GlobalHeader />)
    const img = screen.getByAltText('RedAmon')
    expect(img.getAttribute('src')).toBe('/logo.png')
    expect(img.getAttribute('width')).toBe('28')
    expect(img.getAttribute('height')).toBe('28')
  })

  test('logo contains the "Red" accent and "Amon" text', () => {
    render(<GlobalHeader />)
    const logoLink = getLogoLink()
    expect(logoLink.textContent).toContain('Red')
    expect(logoLink.textContent).toContain('Amon')
  })

  test('logo link has the logo CSS class applied', () => {
    render(<GlobalHeader />)
    const logoLink = getLogoLink()
    expect(logoLink.className).toContain('logo')
  })

  test('logo link does not open in a new tab', () => {
    render(<GlobalHeader />)
    const logoLink = getLogoLink()
    expect(logoLink.getAttribute('target')).toBeNull()
  })
})

describe('GlobalHeader – logo href is /graph on every route', () => {
  test.each([
    '/graph',
    '/cypherfix',
    '/insights',
    '/reports',
    '/projects',
    '/settings',
    '/graph/some-sub-view',
    '/projects/123/edit',
  ])('logo links to /graph when pathname is %s', (route) => {
    mockPathname = route
    render(<GlobalHeader />)
    const logoLink = getLogoLink()
    expect(logoLink.getAttribute('href')).toBe('/graph')
  })
})

describe('GlobalHeader – structure', () => {
  test('exactly one logo image exists in the header', () => {
    render(<GlobalHeader />)
    const imgs = screen.getAllByAltText('RedAmon')
    expect(imgs).toHaveLength(1)
  })

  test('logo link is distinct from the Red Zone nav link', () => {
    render(<GlobalHeader />)
    const logoLink = getLogoLink()
    const redZoneLink = screen.getByRole('link', { name: /red zone/i })
    expect(logoLink).not.toBe(redZoneLink)
    expect(redZoneLink.getAttribute('href')).toBe('/graph')
  })

  test('header contains all core nav links', () => {
    render(<GlobalHeader />)
    const expectedLabels = ['Red Zone', 'CypherFix', 'Insights', 'Reports']
    for (const label of expectedLabels) {
      const link = screen.getByRole('link', { name: new RegExp(label, 'i') })
      expect(link).toBeDefined()
    }
  })
})

/* ------------------------------------------------------------------ */
/*  The Plugins button (README.PLUGINS.md §7.1, F-06, F-07, R-02)      */
/* ------------------------------------------------------------------ */

describe('GlobalHeader – Plugins button', () => {
  // The accessible name includes the "New!" badge text, so match the prefix.
  const pluginsLink = () => screen.queryByRole('link', { name: /^plugins/i })

  test('"Plugins" with the Puzzle icon, linking to /plugins', () => {
    render(<GlobalHeader />)
    const link = pluginsLink()!
    expect(link.getAttribute('href')).toBe('/plugins')
    expect(link.querySelector('svg.lucide-puzzle')).not.toBeNull()
    expect(link.className).toContain('coreNavItem')
  })

  test('no longer carries the "New!" badge', () => {
    // db045488 moved the badge to the Route Exposure workflow node.
    render(<GlobalHeader />)
    expect(pluginsLink()!.querySelector('span[class*="newBadge"]')).toBeNull()
  })

  test('in the core nav group, directly before Reports', () => {
    render(<GlobalHeader />)
    const reports = screen.getByRole('link', { name: /^reports$/i })
    expect(pluginsLink()!.nextElementSibling).toBe(reports)
    expect(pluginsLink()!.closest('nav')).toBe(reports.closest('nav'))
  })

  test('shown to every signed-in user, not only admins', () => {
    mockAdmin = false
    render(<GlobalHeader />)
    expect(pluginsLink()).not.toBeNull()
    expect(screen.queryByRole('link', { name: /^users$/i })).toBeNull()
  })

  test.each(['/plugins', '/plugins/echo'])('active on %s', (route) => {
    mockPathname = route
    render(<GlobalHeader />)
    expect(pluginsLink()!.className).toContain('coreNavItemActive')
  })

  test('not active elsewhere, and Projects is not active on /plugins', () => {
    mockPathname = '/projects'
    render(<GlobalHeader />)
    expect(pluginsLink()!.className).not.toContain('coreNavItemActive')
    cleanup()
    mockPathname = '/plugins'
    render(<GlobalHeader />)
    expect(screen.getByRole('link', { name: /^projects$/i }).className).not.toContain('navItemActive')
  })
})

/* ------------------------------------------------------------------ */
/*  The Users link follows users:read (step 3.12, UI-01)                */
/* ------------------------------------------------------------------ */

describe('GlobalHeader – Users link', () => {
  const usersLink = () => screen.queryByRole('link', { name: /^users$/i })

  test('shown with users:read, linking to the Users page', () => {
    render(<GlobalHeader />)
    expect(usersLink()?.getAttribute('href')).toBe('/settings/users')
  })

  test('an admin whose profile lacks users:read gets no Users link; nor does a member', () => {
    mockGranted = new Set()
    render(<GlobalHeader />)
    expect(usersLink()).toBeNull()
    cleanup()
    mockGranted = new Set(['users:read'])
    mockAdmin = false
    render(<GlobalHeader />)
    expect(usersLink()).toBeNull()
  })
})

/* ------------------------------------------------------------------ */
/*  The Admin link replaces Users with the governance switch on (6.1)  */
/* ------------------------------------------------------------------ */

describe('GlobalHeader – Admin link (step 6.1, UI-10, OQ-44)', () => {
  const PERMISSIONS_ON = { sharedToolsCompat: false, identity: true, permissions: true, sharing: false, sharingWrite: false, governance: false }
  const GOVERNANCE_ON = { ...PERMISSIONS_ON, governance: true }
  const adminLink = () => screen.queryByRole('link', { name: /^IAM$/ })
  const usersLink = () => screen.queryByRole('link', { name: /^users$/i })

  test('on: "IAM" to the console replaces "Users"', () => {
    mockFlags = GOVERNANCE_ON
    render(<GlobalHeader />)
    expect(adminLink()?.getAttribute('href')).toBe('/admin')
    expect(usersLink()).toBeNull()
  })

  test('on: any console permission shows it, users:read or not', () => {
    mockFlags = GOVERNANCE_ON
    for (const held of [['audit:read'], ['platform:tunnels'], ['instance:quotas'], ['roles:manage']]) {
      mockGranted = new Set(held)
      render(<GlobalHeader />)
      expect(adminLink()).not.toBeNull()
      cleanup()
    }
  })

  test('on: nobody holding a console permission gets neither link', () => {
    mockFlags = GOVERNANCE_ON
    mockGranted = new Set(['recon:scan', 'self:mcp_tokens'])
    render(<GlobalHeader />)
    expect(adminLink()).toBeNull()
    expect(usersLink()).toBeNull()
  })

  test.each(['/admin', '/admin/users', '/admin/audit'])('on: active on %s', (route) => {
    mockFlags = GOVERNANCE_ON
    mockPathname = route
    render(<GlobalHeader />)
    expect(adminLink()!.className).toContain('navItemActive')
  })

  test('off: "Users" stays, linking to the Users page, and no "IAM" whatever is held', () => {
    for (const flags of [null, PERMISSIONS_ON]) {
      mockFlags = flags
      mockGranted = new Set(['users:read', 'audit:read', 'platform:tunnels'])
      render(<GlobalHeader />)
      expect(usersLink()?.getAttribute('href')).toBe('/settings/users')
      expect(adminLink()).toBeNull()
      cleanup()
    }
  })
})
