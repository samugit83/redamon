/**
 * The Instance page's Quotas panel (step 6.8; GV-09..GV-13; DV-06, DV-19): an instance:quotas holder
 * edits the defaults, an entry per set and per account, and the Save sends only what changed through
 * the `quotas` group of /api/admin/instance-settings. Bad limits keep Save disabled; a refusal is
 * shown in the panel; without the quotas in the answer the panel shows the denied notice; every
 * control is labelled.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/instance/QuotasPanel.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

vi.mock('next/navigation', () => ({
  usePathname: () => '/admin/instance',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))

import { QuotasPanel } from './QuotasPanel'
import type { InstanceSettingsView } from './instanceView'

const SETS = [
  { id: 'builtin:default-member', name: 'Default member', kind: 'member' },
  { id: 'builtin:full-admin', name: 'Full admin', kind: 'admin' },
  { id: 'cset-1', name: 'Lab team', kind: 'member' },
]

function settings(over: Partial<InstanceSettingsView> = {}): InstanceSettingsView {
  return {
    canManageQuotas: true,
    quotas: { defaults: { maxProjects: 3 }, perSet: { 'cset-1': { maxProjects: null } }, perUser: { 'mem-c': { maxMcpTokens: 1 } } },
    quotaSets: SETS,
    quotaUsers: [{ id: 'mem-c', email: 'mem-c@e2e.local', name: 'Mem C' }],
    ...over,
  }
}

let fetchMock: ReturnType<typeof vi.fn>
let putAnswer: { status: number; body: unknown }
const onSaved = vi.fn()

beforeEach(() => {
  putAnswer = { status: 200, body: settings() }
  fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (String(url).startsWith('/api/admin/users?')) {
      return new Response(JSON.stringify({ users: [{ id: 'mem-d', email: 'mem-d@e2e.local', name: 'Mem D', status: 'active' }] }))
    }
    if (url === '/api/admin/instance-settings' && init?.method === 'PUT') {
      return new Response(JSON.stringify(putAnswer.body), { status: putAnswer.status })
    }
    return new Response(JSON.stringify({ error: 'unexpected' }), { status: 500 })
  })
  vi.stubGlobal('fetch', fetchMock)
  onSaved.mockClear()
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const renderPanel = (s: InstanceSettingsView = settings()) =>
  render(<ToastProvider><QuotasPanel settings={s} onSaved={onSaved} /></ToastProvider>)
const puts = () => fetchMock.mock.calls.filter(([, init]) => init?.method === 'PUT')
const bodyOf = (call: unknown[]) => JSON.parse(String((call[1] as RequestInit).body))
const save = () => screen.getByRole('button', { name: 'Save quotas' })

describe('the Quotas panel', () => {
  test('shows the stored quotas: defaults, sets by name, accounts by name with a link', () => {
    renderPanel()
    const region = screen.getByRole('region', { name: 'Quotas' })
    expect(within(region).getByRole('group', { name: 'Default for everyone' })).toBeInTheDocument()
    expect(screen.getByLabelText('Projects owned: limit in projects for Default for everyone')).toHaveValue('3')
    const lab = screen.getByRole('group', { name: 'Lab team' })
    expect(within(lab).getAllByRole('combobox')[0]).toHaveValue('unlimited')
    expect(within(lab).getAllByRole('combobox')[1]).toHaveValue('inherit')
    expect(screen.getByRole('link', { name: 'Mem C (mem-c@e2e.local)' })).toHaveAttribute('href', '/admin/users/mem-c')
    expect(save()).toBeDisabled()
  })

  test('values saved: only the changed defaults are sent, then the answer replaces the panel', async () => {
    renderPanel()
    fireEvent.change(screen.getByLabelText('Projects owned: limit in projects for Default for everyone'), { target: { value: '5' } })
    const scans = within(screen.getByRole('group', { name: 'Default for everyone' })).getByLabelText('Scans at once')
    fireEvent.change(scans, { target: { value: 'limit' } })
    fireEvent.change(screen.getByLabelText('Scans at once: limit in scans for Default for everyone'), { target: { value: '2' } })
    fireEvent.click(save())
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(puts()).toHaveLength(1)
    expect(bodyOf(puts()[0])).toEqual({ quotas: { defaults: { maxProjects: 5, maxConcurrentScans: 2 } } })
  })

  test('a set added and an account removed: the patch names those two only', async () => {
    renderPanel()
    fireEvent.change(screen.getByLabelText('Give a set its own quota'), { target: { value: 'builtin:full-admin' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add set' }))
    const profile = screen.getByRole('group', { name: 'Full admin (admin profile)' })
    fireEvent.change(within(profile).getByLabelText('Projects owned'), { target: { value: 'unlimited' } })
    fireEvent.click(screen.getByRole('button', { name: 'Remove the quota of Mem C (mem-c@e2e.local)' }))
    fireEvent.click(save())
    await waitFor(() => expect(puts()).toHaveLength(1))
    expect(bodyOf(puts()[0])).toEqual({ quotas: { perSet: { 'builtin:full-admin': { maxProjects: null } }, perUser: { 'mem-c': null } } })
  })

  test('an account found through the directory gets its own entry', async () => {
    renderPanel()
    fireEvent.change(screen.getByLabelText('Give an account its own quota'), { target: { value: 'mem-d' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Add mem-d@e2e.local' }))
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/admin/users?q=mem-d&limit=8')
    const entry = screen.getByRole('group', { name: 'Mem D (mem-d@e2e.local)' })
    fireEvent.change(within(entry).getByLabelText('Projects owned'), { target: { value: 'limit' } })
    fireEvent.change(screen.getByLabelText('Projects owned: limit in projects for Mem D (mem-d@e2e.local)'), { target: { value: '1' } })
    fireEvent.click(save())
    await waitFor(() => expect(puts()).toHaveLength(1))
    expect(bodyOf(puts()[0])).toEqual({ quotas: { perUser: { 'mem-d': { maxProjects: 1 } } } })
  })

  test('a bad limit keeps Save disabled and says why', () => {
    renderPanel()
    fireEvent.change(screen.getByLabelText('Projects owned: limit in projects for Default for everyone'), { target: { value: '-2' } })
    expect(save()).toBeDisabled()
    expect(screen.getAllByText('A whole number of projects from 0 to 100000.').length).toBeGreaterThan(0)
  })

  test('the route refuses: the reason is shown in the panel and nothing is replaced', async () => {
    putAnswer = { status: 400, body: { error: 'A quota names a permission set or an account that does not exist.', code: 'unknown_quota_target' } }
    renderPanel()
    fireEvent.change(screen.getByLabelText('Projects owned: limit in projects for Default for everyone'), { target: { value: '4' } })
    fireEvent.click(save())
    expect(await screen.findByRole('alert')).toHaveTextContent('does not exist')
    expect(onSaved).not.toHaveBeenCalled()
  })

  test('without users:read: accounts shown by id, no search, a line saying why', () => {
    renderPanel(settings({ quotaUsers: undefined }))
    expect(screen.getByRole('group', { name: 'mem-c' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Give an account its own quota')).toBeNull()
    expect(screen.getByText(/users:read/)).toBeInTheDocument()
  })

  test('denied: the answer carries no quotas', () => {
    renderPanel(settings({ quotas: undefined, canManageQuotas: undefined }))
    expect(screen.getByRole('alert')).toHaveTextContent('instance:quotas')
  })

  test('empty: no set or account has its own quota', () => {
    renderPanel(settings({ quotas: { defaults: {}, perSet: {}, perUser: {} } }))
    expect(screen.getByText('No set has its own quota.')).toBeInTheDocument()
    expect(screen.getByText('No account has its own quota.')).toBeInTheDocument()
    expect(within(screen.getByRole('group', { name: 'Default for everyone' })).getAllByRole('combobox').every((c) => (c as HTMLSelectElement).value === 'unlimited')).toBe(true)
  })

  test('labels: every control is named and none is taken out of the tab order', () => {
    renderPanel()
    for (const el of [...screen.getAllByRole('combobox'), ...screen.getAllByRole('textbox')]) {
      expect(el).toHaveAccessibleName()
      expect(el).not.toHaveAttribute('tabindex', '-1')
    }
  })
})
