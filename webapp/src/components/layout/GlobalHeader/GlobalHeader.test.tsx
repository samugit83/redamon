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

vi.mock('next/navigation', () => ({
  usePathname: () => mockPathname,
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
    user: { id: 'test-user', name: 'Test Admin', email: 'admin@test.com', role: 'admin' },
    isLoading: false,
    isAdmin: true,
    login: vi.fn(),
    logout: vi.fn(),
  }),
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
