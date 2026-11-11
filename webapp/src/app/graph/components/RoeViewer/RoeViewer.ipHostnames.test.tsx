/**
 * The engagement panel's Scope card names the "Hostnames on target IPs" mode of
 * an IP-mode project (04_ui_spec §5): which names a run may reach is part of
 * what the engagement allows, next to the IP ranges it lists.
 *
 * @vitest-environment jsdom
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import { RoeViewer } from './RoeViewer'
import { ToastProvider } from '@/components/ui'

vi.mock('./AuthorizationHistory', () => ({ AuthorizationHistory: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ currentProject: null, setCurrentProject: () => {}, userId: null }),
}))

afterEach(cleanup)

// A rate ceiling, so the panel renders its cards instead of the empty state.
const IP_PROJECT = {
  engagementKind: 'internal',
  roeGlobalMaxRps: 5,
  ipMode: true,
  targetIps: ['203.0.113.10', '203.0.113.0/30'],
  ipHostnameMode: 'ip_only',
  ipHostnameInclude: [],
  ipHostnameExclude: [],
}

function panel(over: Record<string, unknown> = {}) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider>
        <RoeViewer projectId="p1" project={{ ...IP_PROJECT, ...over } as never} />
      </ToastProvider>
    </QueryClientProvider>
  )
  return screen.queryByTestId('roe-ip-hostname-mode')
}

describe('the hostname mode row', () => {
  test.each([
    ['ip_only', 'IP only'],
    ['record_only', 'Record hostnames'],
    ['scan_all', 'Record + scan all'],
  ])('%s reads as its card label', (mode, label) => {
    const row = panel({ ipHostnameMode: mode })!
    expect(row).toHaveTextContent(`Hostnames on target IPs${label}`)
    expect(row).not.toHaveTextContent('include')
  })

  test('record_filter adds the include and exclude counts', () => {
    const row = panel({
      ipHostnameMode: 'record_filter',
      ipHostnameInclude: ['*.example.com', '*.example.de', 'shop.example.fr'],
      ipHostnameExclude: ['old.example.com'],
    })!
    expect(row).toHaveTextContent('Record + scan matching · include 3, exclude 1')
  })

  test('a domain project has no row', () => {
    expect(panel({ ipMode: false, targetIps: [], targetDomain: 'example.com' })).toBeNull()
  })

  test('a read that did not carry the mode shows no row rather than guessing IP only', () => {
    expect(panel({ ipHostnameMode: undefined })).toBeNull()
  })
})
