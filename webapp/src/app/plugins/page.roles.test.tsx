/**
 * Who manages plugins (README.PLUGINS.md §7.1, D-36, OQ-09): admins only. A standard user
 * sees every card read-only, in plain words ("Installed", "Disabled", "Unavailable", "Needs
 * an update", the revocation reason) and no management control at all.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('next/navigation', () => ({ notFound: vi.fn(), usePathname: () => '/plugins', useRouter: () => ({ push: vi.fn() }) }))

import { AlertProvider } from '@/components/ui'
import { PluginsPageClient } from './PluginsPageClient'
import type { PluginEntry, PluginsPage } from '@/lib/plugins/pageModel'

const STATES: [PluginEntry['state'], string][] = [
  ['not_installed', 'Not installed'],
  ['ready', 'Installed'],
  ['disabled', 'Disabled'],
  ['failed', 'Unavailable'],
  ['incompatible', 'Needs an update'],
  ['revoked', 'Revoked'],
  ['installing', 'Installing…'],
]

function entries(): PluginEntry[] {
  return STATES.map(([state], i) => ({
    id: `p${i}x`, displayName: `Plugin ${i}`, description: 'x', inCatalog: true, state,
    installed: state === 'not_installed' ? null : {
      version: '1.0.0', previousVersion: null, status: 'ready', enabled: state !== 'disabled', dataVersion: 1,
      grantedPermissions: [], installedAt: null, revokedReason: state === 'revoked' ? 'Sends transcripts out.' : null, operationKind: null,
    },
    available: { version: '1.1.0', dataVersion: 1, platform: '>=1.0.0', permissions: [] },
    update: state === 'ready' ? { version: '1.1.0', newPermissions: [], migratesData: false } : null,
    installBlocked: null,
  }))
}

// Whether the viewer manages plugins (platform:plugins): the page model's managesPlugins.
let managesPlugins = false
beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url === '/api/plugins/status') return new Response(JSON.stringify({ platformVersion: '1.0.0', runner: { reachable: true, state: 'ok' } }))
    const page: PluginsPage = {
      platformVersion: '1.0.0', managesPlugins,
      catalog: { state: 'ok', message: null, official: true, extraKey: false, replayed: false, serial: 1 },
      plugins: entries(),
    }
    return new Response(JSON.stringify(page))
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={qc}><AlertProvider><PluginsPageClient /></AlertProvider></QueryClientProvider>)
}

describe('a standard user', () => {
  test('sees each card read-only, in plain words', async () => {
    managesPlugins = false
    show()
    for (const [i, [, label]] of STATES.entries()) {
      const c = within(await screen.findByTestId(`plugin-card-p${i}x`))
      expect(c.getByTestId('plugin-state').textContent).toContain(label)
      expect(c.queryAllByRole('button')).toEqual([])
    }
    expect(within(screen.getByTestId('plugin-card-p5x')).getByText(/Sends transcripts out\./)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /install from file/i })).toBeNull()
  })
})

describe('an admin', () => {
  test('sees the management controls', async () => {
    managesPlugins = true
    show()
    const ready = within(await screen.findByTestId('plugin-card-p1x'))
    expect(ready.getByRole('button', { name: 'Disable' })).toBeTruthy()
    expect(ready.getByRole('button', { name: 'Update to 1.1.0' })).toBeTruthy()
    expect(screen.getByRole('button', { name: /install from file/i })).toBeTruthy()
  })
})
