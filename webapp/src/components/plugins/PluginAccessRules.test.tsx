/**
 * Who may use a plugin (GV-16, step 6.9), on the plugin's details drawer: the member permission
 * sets a plugin is limited to, ticked and saved by whoever manages plugins after a confirmation
 * (useAlertModal). Loading, load error with Retry, save error and the saved state; controls labelled
 * and reachable by keyboard (DV-06, DV-19). With RBAC_GOVERNANCE_ENABLED off the section is not there
 * and its route is never asked.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AlertProvider } from '@/components/ui'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import type { RbacFlags } from '@/lib/authz/flags'
import { PluginDetailsDrawer } from './PluginDetailsDrawer'

const GOVERNANCE_ON: RbacFlags = { ...FLAGS_ON, governance: true }
const SETS = [
  { id: 'builtin:default-member', name: 'Default member', builtin: true },
  { id: 'builtin:recon-operator', name: 'Recon operator', builtin: true },
  { id: 'set-red', name: 'Red team', builtin: false },
]

let rules: { status: number; body: unknown }
let putAnswer: { status: number; body: unknown }
const puts: unknown[] = []
const calls: string[] = []

const detail = {
  plugin: {
    id: 'echo', displayName: 'Echo', description: 'x', inCatalog: true, state: 'enabled',
    installed: { version: '1.0.0', previousVersion: null, status: 'ready', enabled: true, dataVersion: 1, grantedPermissions: [], installedAt: null, revokedReason: null, operationKind: null },
    available: null, update: null, installBlocked: null,
  },
  admin: {
    lastError: null, versionsOnDisk: ['1.0.0'], grantedPermissions: [],
    data: { rows: 0, bytes: 0, maxRows: 10_000, maxBytes: 52_428_800 },
    activeVersions: 0, dormantVersions: 0, rollback: { possible: false, reason: 'no_previous' },
  },
}

beforeEach(() => {
  rules = { status: 200, body: { pluginId: 'echo', setIds: [], sets: SETS } }
  putAnswer = { status: 200, body: { pluginId: 'echo', setIds: ['set-red'] } }
  puts.length = 0
  calls.length = 0
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push(url)
    if (url === '/api/plugins/echo') return new Response(JSON.stringify(detail))
    if (url.startsWith('/api/plugins/echo/logs')) return new Response(JSON.stringify({ lines: [] }))
    if (url === '/api/plugins/echo/access-rules' && init?.method === 'PUT') {
      puts.push(JSON.parse(String(init.body)))
      return new Response(JSON.stringify(putAnswer.body), { status: putAnswer.status })
    }
    if (url === '/api/plugins/echo/access-rules') return new Response(JSON.stringify(rules.body), { status: rules.status })
    return new Response('{}', { status: 404 })
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function show(flags: RbacFlags | null = GOVERNANCE_ON) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <AuthContext.Provider value={fakeAuth(flags, ['platform:plugins', 'plugins:use'])}>
      <AlertProvider>
        <QueryClientProvider client={qc}>
          <PluginDetailsDrawer pluginId="echo" isOpen onClose={vi.fn()} onRollback={vi.fn()} />
        </QueryClientProvider>
      </AlertProvider>
    </AuthContext.Provider>,
  )
}

const section = async () => within(await screen.findByTestId('plugin-access-rules'))
const confirmDialog = async () => screen.findByRole('dialog')

describe('who may use the plugin', () => {
  test.each([
    ['governance off', { ...FLAGS_ON }],
    ['every switch off', null],
  ])('switch off (%s): no section, the route is never asked', async (_name, flags) => {
    show(flags as RbacFlags | null)
    expect(await screen.findByTestId('plugin-versions')).toBeTruthy()
    expect(screen.queryByTestId('plugin-access-rules')).toBeNull()
    expect(calls).not.toContain('/api/plugins/echo/access-rules')
  })

  test('no rule: everyone; each set is a labelled checkbox; Save stays off until something changes', async () => {
    show()
    const s = await section()
    expect(await s.findByText(/Everyone who can use plugins can use it/)).toBeTruthy()
    expect(s.getByRole('checkbox', { name: /Red team/ })).toHaveProperty('checked', false)
    expect(s.getByRole('checkbox', { name: /Recon operator \(built-in\)/ })).toBeTruthy()
    expect(s.getByRole('button', { name: /Save who may use it/ })).toHaveProperty('disabled', true)
  })

  test('ticking a set and confirming saves exactly the ticked sets', async () => {
    show()
    const s = await section()
    fireEvent.click(await s.findByRole('checkbox', { name: /Red team/ }))
    fireEvent.click(s.getByRole('button', { name: /Save who may use it/ }))
    const dialog = await confirmDialog()
    expect(dialog.textContent).toMatch(/Only holders of the 1 chosen set/)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(puts).toEqual([{ setIds: ['set-red'] }]))
    expect(await s.findByRole('status')).toHaveProperty('textContent', 'Saved.')
  })

  test('cancelling the confirmation saves nothing', async () => {
    show()
    const s = await section()
    fireEvent.click(await s.findByRole('checkbox', { name: /Red team/ }))
    fireEvent.click(s.getByRole('button', { name: /Save who may use it/ }))
    fireEvent.click(within(await confirmDialog()).getByRole('button', { name: /cancel/i }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(puts).toEqual([])
  })

  test('a limited plugin: its sets ticked, a set that no longer exists still shown; unticking all opens it', async () => {
    rules = { status: 200, body: { pluginId: 'echo', setIds: ['set-gone', 'set-red'], sets: SETS } }
    putAnswer = { status: 200, body: { pluginId: 'echo', setIds: [] } }
    show()
    const s = await section()
    expect(await s.findByText(/Only holders of the ticked sets/)).toBeTruthy()
    expect(s.getByRole('checkbox', { name: /Red team/ })).toHaveProperty('checked', true)
    const gone = s.getByRole('checkbox', { name: /set-gone \(this set no longer exists\)/ })
    expect(gone).toHaveProperty('checked', true)
    fireEvent.click(gone)
    fireEvent.click(s.getByRole('checkbox', { name: /Red team/ }))
    fireEvent.click(s.getByRole('button', { name: /Save who may use it/ }))
    const dialog = await confirmDialog()
    expect(dialog.textContent).toMatch(/Everyone who can use plugins will be able to use Echo/)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(puts).toEqual([{ setIds: [] }]))
  })

  test('the save refused: the error names its code, the choice stays', async () => {
    putAnswer = { status: 400, body: { error: 'A plugin can be limited only to member permission sets that exist.', code: 'unknown_set' } }
    show()
    const s = await section()
    fireEvent.click(await s.findByRole('checkbox', { name: /Red team/ }))
    fireEvent.click(s.getByRole('button', { name: /Save who may use it/ }))
    fireEvent.click(within(await confirmDialog()).getByRole('button', { name: 'Save' }))
    expect((await s.findByRole('alert')).textContent).toMatch(/unknown_set/)
    expect(s.getByRole('checkbox', { name: /Red team/ })).toHaveProperty('checked', true)
  })

  test('the rules cannot be read: the error and a Retry that reads them again', async () => {
    rules = { status: 403, body: { error: 'Only an administrator can manage plugins.', code: 'admin_required', permission: 'platform:plugins' } }
    show()
    const s = await section()
    expect((await s.findByRole('alert')).textContent).toMatch(/admin_required/)
    rules = { status: 200, body: { pluginId: 'echo', setIds: [], sets: SETS } }
    fireEvent.click(s.getByRole('button', { name: 'Retry' }))
    expect(await s.findByRole('checkbox', { name: /Red team/ })).toBeTruthy()
  })
})
