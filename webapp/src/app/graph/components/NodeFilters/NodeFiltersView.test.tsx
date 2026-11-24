/**
 * The Mute Rules page: its states, the armed status, saving (and a save that
 * lost a race), and the live preview.
 *
 * Run: npx vitest run src/app/graph/components/NodeFilters/NodeFiltersView.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { useEffect, type ReactNode } from 'react'

const confirm = vi.fn()
const alertError = vi.fn()
const alertWarning = vi.fn()
const dangerConfirm = vi.fn()
const toast = { success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ confirm, alertError, alertWarning, dangerConfirm }),
  useToast: () => toast,
  WikiInfoButton: () => null,
  Toggle: ({ checked, onChange, disabled, 'aria-label': label }: {
    checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; 'aria-label'?: string
  }) => (
    <input type="checkbox" aria-label={label} checked={checked} disabled={disabled}
      onChange={e => onChange(e.target.checked)} />
  ),
  Modal: ({ isOpen, children, footer }: { isOpen: boolean; children: ReactNode; footer?: ReactNode }) =>
    (isOpen ? <div>{children}{footer}</div> : null),
}))

import { NodeFiltersView } from './NodeFiltersView'
import { NavigationGuardProvider, useNavigationGuard } from '@/context/NavigationGuardContext'

const RULE = { id: 'k3f9a2', name: 'Informational templates', enabled: true,
               all: [{ field: 'severity', op: 'in', value: ['info'] }] }
const STATE = {
  mode: 'denylist', applyToScans: true, revision: 3, exists: true,
  rules: { version: 1, kinds: { 'vuln.nuclei': { enabled: true, action: 'mute', rules: [RULE] } } },
  exemptionCounts: { Vulnerability: 2 }, activeVersion: { id: 'v7', label: 'Scan 7' },
  lastRun: null, lastCompleted: null, liveRunId: null, loadedPreset: null,
}
const PRESET_RULE = { id: 'p7q8r9', name: 'Low severity noise', enabled: true,
                      all: [{ field: 'severity', op: 'in', value: ['low'] }] }
const PRESET = {
  id: 'preset1', name: 'Quiet perimeter', description: 'Mutes the low noise', mode: 'denylist',
  counts: { rules: 1, kinds: 1 }, createdAt: '2026-09-24T10:00:00Z', updatedAt: '2026-09-24T10:00:00Z',
  rules: { version: 1, kinds: { 'vuln.nuclei': { enabled: true, action: 'mute', rules: [PRESET_RULE] } } },
}
const PREVIEW = {
  ok: true, partial: false, totals: { scanned: 1930, to_mute: 412, to_unmute: 0 },
  kinds: { 'vuln.nuclei': { active: true, scanned: 1930, would_mute: 412, to_mute: 412, to_unmute: 0,
    to_restamp: 0, guarded: 14, exempt: 2, operator_muted: 0, missing: {},
    rules: { k3f9a2: { name: 'Informational templates', matched: 398,
      samples: [{ key: 'v1', name: 'tech-detect:nginx', host: 'api.example.com', guards: [] }] } } } },
}

function reply(body: unknown, status = 200) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) })
}

let fetchMock: ReturnType<typeof vi.fn>
let putStatus = 200
let putErrors: string[] | null = null
let putThrows = false

beforeEach(() => {
  putStatus = 200
  putErrors = null
  putThrows = false
  fetchMock = vi.fn((url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (url.endsWith('/node-filters') && method === 'GET') return reply(STATE)
    if (url.endsWith('/node-filters') && method === 'PUT') {
      if (putThrows) return Promise.reject(new TypeError('Failed to fetch'))
      if (putErrors) return reply({ error: 'The rules are not valid.', errors: putErrors }, 400)
      return putStatus === 200 ? reply({ ok: true, revision: 4 }) : reply({ error: 'changed', currentRevision: 5 }, putStatus)
    }
    if (url.endsWith('/api/mute-rule-presets') && method === 'GET') {
      const { rules: _omitted, ...summary } = PRESET
      return reply([summary])
    }
    if (url.endsWith('/api/mute-rule-presets') && method === 'POST') return reply({ ...PRESET, id: 'new' }, 201)
    if (url.endsWith('/api/mute-rule-presets/preset1')) return reply(PRESET)
    if (url.endsWith('/preview')) return reply(PREVIEW)
    if (url.endsWith('/disarm')) return reply({ armed: false })
    if (url.endsWith('/apply') && method === 'GET') return reply({ busy: null, activeVersion: STATE.activeVersion })
    if (url.endsWith('/apply') && method === 'POST') return reply({ runId: 'run1', armed: true }, 202)
    if (url.includes('/runs/')) return reply({ id: 'run1', status: 'running', stats: null })
    return reply({}, 404)
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

const view = (props: Partial<Parameters<typeof NodeFiltersView>[0]> = {}) =>
  render(<NodeFiltersView projectId="p1" isViewingPastVersion={false} {...props} />)

describe('NodeFiltersView', () => {
  test('a project the caller does not own shows nothing to edit', async () => {
    fetchMock.mockImplementation(() => reply({ error: 'Not found' }, 404))
    view()
    expect(await screen.findByText('Mute rules are not available for this project.')).toBeInTheDocument()
  })

  test('shows the armed state and turns it off', async () => {
    const onStatusChange = vi.fn()
    view({ onStatusChange })
    expect(await screen.findByText(/Active on new scans · 1 rule in 1 kind · denylist/)).toBeInTheDocument()
    fireEvent.click(screen.getByText('Turn off'))
    await waitFor(() => expect(onStatusChange).toHaveBeenCalled())
    const disarm = fetchMock.mock.calls.find(c => String(c[0]).endsWith('/disarm'))!
    expect(disarm[1].headers).toEqual({ 'Content-Type': 'application/json' })
  })

  test('the preview counts, per kind and per rule, with examples', async () => {
    view()
    expect(await screen.findByText('412', {}, { timeout: 3000 })).toBeInTheDocument()
    expect(screen.getByText(/14 kept by guards/)).toBeInTheDocument()
    expect(screen.getByText('· 2 exempt')).toBeInTheDocument()
    expect(screen.getByText('398')).toBeInTheDocument()
    expect(screen.getByText('tech-detect:nginx')).toBeInTheDocument()
    expect(screen.getByText('Clear 2 exemptions')).toBeInTheDocument()
  })

  test('Save is only possible with unsaved changes, and sends the loaded revision', async () => {
    view()
    const save = await screen.findByText('Save')
    expect((save as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByLabelText('Filter Nuclei'))
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Rules saved.', 'Mute rules'))
    const put = fetchMock.mock.calls.find(c => c[1]?.method === 'PUT')!
    const body = JSON.parse(put[1].body)
    expect(body.revision).toBe(3)
    expect(body.rules.kinds['vuln.nuclei'].enabled).toBe(false)
  })

  test('unsaved edits ask before leaving, with the discard prompt the other forms use', async () => {
    let guard: ReturnType<typeof useNavigationGuard> = null
    const Probe = () => {
      const current = useNavigationGuard()
      useEffect(() => { guard = current })
      return null
    }
    render(
      <NavigationGuardProvider>
        <Probe />
        <NodeFiltersView projectId="p1" isViewingPastVersion={false} />
      </NavigationGuardProvider>,
    )
    await screen.findByText('Save')
    expect(guard!.hasGuards()).toBe(false)

    fireEvent.click(screen.getByLabelText('Filter Nuclei'))
    await waitFor(() => expect(guard!.hasGuards()).toBe(true))
    const unload = new Event('beforeunload', { cancelable: true })
    window.dispatchEvent(unload)
    expect(unload.defaultPrevented).toBe(true)
    confirm.mockResolvedValueOnce(false)
    expect(await guard!.confirmAllGuards()).toBe(false)
    expect(confirm).toHaveBeenCalledWith('You have unsaved changes. Discard them and leave?', 'Discard changes?')
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Discard'))
    await waitFor(() => expect(guard!.hasGuards()).toBe(false))
  })

  test('a save that lost a race offers Overwrite, which forces it', async () => {
    putStatus = 409
    confirm.mockResolvedValue(true)
    view()
    await screen.findByText('Save')
    fireEvent.click(screen.getByLabelText('Filter Nuclei'))
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(confirm).toHaveBeenCalled())
    await waitFor(() => {
      const puts = fetchMock.mock.calls.filter(c => c[1]?.method === 'PUT')
      expect(JSON.parse(puts.at(-1)![1].body).force).toBe(true)
    })
  })

  test('conflict_dialog_dismiss_discards_edits: closing the conflict dialog keeps the edits', async () => {
    // Escape, the X and Cancel all resolve the dialog as "no". That used to mean
    // "reload theirs", so dismissing it threw every unsaved edit away.
    putStatus = 409
    confirm.mockResolvedValue(false)
    view()
    await screen.findByText('Save')
    fireEvent.click(screen.getByLabelText('Filter Nuclei'))
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(confirm).toHaveBeenCalled())
    await waitFor(() => expect(fetchMock.mock.calls.filter(c => (c[1]?.method ?? 'GET') === 'GET'
      && String(c[0]).endsWith('/node-filters')).length).toBe(2))
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument()
    expect((screen.getByLabelText('Filter Nuclei') as HTMLInputElement).checked).toBe(false)
  })

  test('an invalid rule blocks Save and Apply and is marked', async () => {
    view()
    const name = await screen.findByDisplayValue('Informational templates')
    fireEvent.change(name, { target: { value: '<b>bad</b>' } })
    expect(await screen.findByText(/rule names are 1-80 letters/)).toBeInTheDocument()
    expect((screen.getByText('Save') as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByText('Apply…') as HTMLButtonElement).disabled).toBe(true)
  })

  test('an inactive kind says nothing is filtered, not "0 of 0"', async () => {
    view({ focus: { kind: 'secret' } })
    expect(await screen.findByText('Nothing is filtered.')).toBeInTheDocument()
  })

  test('a link from Muted Nodes opens the rule\'s kind', async () => {
    view({ focus: { kind: 'secret' } })
    expect(await screen.findByRole('heading', { name: 'Secrets' })).toBeInTheDocument()
  })

  test('apply targets the version on screen, not the one the server calls active', async () => {
    // The page shows v5 while the server has since moved to v7 (another tab
    // activated it). Sending v7 would let the server's "only the active
    // version" check pass and apply to a graph the operator is not looking at.
    view({ viewedVersionId: 'v5' })
    fireEvent.click(await screen.findByText('Apply…'))
    const confirmApply = await screen.findByRole('button', { name: 'Apply' })
    await waitFor(() => expect((confirmApply as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(confirmApply)
    await waitFor(() => expect(fetchMock.mock.calls.some(c => c[1]?.method === 'POST' && String(c[0]).endsWith('/apply'))).toBe(true))
    const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST' && String(c[0]).endsWith('/apply'))!
    expect(JSON.parse(post[1].body)).toMatchObject({ versionId: 'v5', revision: 3 })
  })

  test('switching to allowlist while armed asks first', async () => {
    confirm.mockResolvedValue(false)
    view()
    fireEvent.click(await screen.findByText('Allowlist: keep only what matches'))
    await waitFor(() => expect(confirm).toHaveBeenCalled())
    expect(screen.queryByText('Unsaved changes')).toBeNull()
  })

  describe('presets', () => {
    const putBodies = () => fetchMock.mock.calls
      .filter(([u, i]) => String(u).endsWith('/node-filters') && i?.method === 'PUT')
      .map(([, i]) => JSON.parse(String(i.body)))

    async function openMenuItem(label: string) {
      fireEvent.click(await screen.findByRole('button', { name: /Presets/ }))
      fireEvent.click(screen.getByRole('menuitem', { name: label }))
    }

    test('the Presets menu offers save, load and manage', async () => {
      view()
      fireEvent.click(await screen.findByRole('button', { name: /Presets/ }))
      expect(screen.getByRole('menuitem', { name: 'Save as preset…' })).toBeTruthy()
      expect(screen.getByRole('menuitem', { name: 'Load preset…' })).toBeTruthy()
      expect(screen.getByRole('menuitem', { name: 'Manage presets…' })).toBeTruthy()
    })

    test('Save as preset posts the rules on screen with the name', async () => {
      view()
      await openMenuItem('Save as preset…')
      fireEvent.change(screen.getByPlaceholderText(/Quiet external perimeter/), { target: { value: 'My preset' } })
      fireEvent.click(screen.getByRole('button', { name: 'Save preset' }))
      await waitFor(() => expect(toast.success).toHaveBeenCalledWith('Preset "My preset" saved.', 'Mute rules'))
      const post = fetchMock.mock.calls.find(([u, i]) => String(u).endsWith('/api/mute-rule-presets') && i?.method === 'POST')!
      const body = JSON.parse(String(post[1].body))
      expect(body).toMatchObject({ name: 'My preset', mode: 'denylist' })
      expect(body.rules.kinds['vuln.nuclei'].rules[0].id).toBe(RULE.id)
    })

    test('loading asks first, saves the preset with its record, and badges its name', async () => {
      confirm.mockResolvedValue(true)
      view()
      await openMenuItem('Load preset…')
      fireEvent.click(await screen.findByRole('button', { name: 'Load' }))

      await waitFor(() => expect(putBodies()).toHaveLength(1))
      const [body] = putBodies()
      expect(body.revision).toBe(3)
      expect(body.rules.kinds['vuln.nuclei'].rules[0].id).toBe(PRESET_RULE.id)
      expect(body.loadedPreset.name).toBe('Quiet perimeter')
      // armed: the confirmation must say the next scan uses the preset
      expect(String(confirm.mock.calls[0][0])).toMatch(/active on new scans/)
      expect(await screen.findByTitle(/match the "Quiet perimeter" preset/)).toBeTruthy()
    })

    test('declining the confirmation changes nothing', async () => {
      confirm.mockResolvedValue(false)
      view()
      await openMenuItem('Load preset…')
      fireEvent.click(await screen.findByRole('button', { name: 'Load' }))
      await waitFor(() => expect(confirm).toHaveBeenCalled())
      expect(putBodies()).toHaveLength(0)
      expect(screen.queryByTitle(/preset\. Changing/)).toBeNull()
    })

    test('badge_hides_on_edit: turning a kind off after a load removes the preset name', async () => {
      confirm.mockResolvedValue(true)
      view()
      await openMenuItem('Load preset…')
      fireEvent.click(await screen.findByRole('button', { name: 'Load' }))
      expect(await screen.findByTitle(/match the "Quiet perimeter" preset/)).toBeTruthy()

      fireEvent.click(screen.getByLabelText('Filter Nuclei'))
      expect(screen.queryByTitle(/match the "Quiet perimeter" preset/)).toBeNull()
    })

    test('a preset whose rules no longer validate is loaded but NOT saved, and says why', async () => {
      confirm.mockResolvedValue(true)
      putErrors = ['vuln.nuclei rule 1 condition 1: unknown field "old_field"']
      view()
      await openMenuItem('Load preset…')
      fireEvent.click(await screen.findByRole('button', { name: 'Load' }))
      await waitFor(() => expect(alertWarning).toHaveBeenCalled())
      expect(String(alertWarning.mock.calls[0][0])).toMatch(/loaded but NOT saved[\s\S]*old_field/)
      expect(await screen.findByText('Unsaved changes')).toBeTruthy()
    })

    test('load_network_failure: a dropped connection is reported and the saved copy re-read, not swallowed', async () => {
      confirm.mockResolvedValue(true)
      putThrows = true
      view()
      await openMenuItem('Load preset…')
      const reads = () => fetchMock.mock.calls.filter(([u, i]) => String(u).endsWith('/node-filters') && (i?.method ?? 'GET') === 'GET').length
      await screen.findByRole('button', { name: 'Load' })
      const before = reads()
      fireEvent.click(screen.getByRole('button', { name: 'Load' }))
      await waitFor(() => expect(alertError).toHaveBeenCalled())
      expect(String(alertError.mock.calls[0][0])).toMatch(/could not be loaded: Failed to fetch[\s\S]*Check whether/)
      expect(reads()).toBeGreaterThan(before)
      expect(toast.success).not.toHaveBeenCalled()
    })
  })

  describe('preset failures say why', () => {
    async function openMenuItem(label: string) {
      fireEvent.click(await screen.findByRole('button', { name: /Presets/ }))
      fireEvent.click(screen.getByRole('menuitem', { name: label }))
    }
    function answer(match: (url: string, method: string) => boolean, body: unknown, status: number) {
      const real = fetchMock.getMockImplementation() as (url: string, init?: RequestInit) => unknown
      fetchMock.mockImplementation((url: string, init?: RequestInit) => (
        match(url, init?.method ?? 'GET') ? reply(body, status) : real(url, init)
      ))
    }

    test('a save the server could not write shows its sentence and Prisma code (it read "Save failed (500)")', async () => {
      answer((u, m) => u.endsWith('/api/mute-rule-presets') && m === 'POST', { error: 'Failed to save the preset', code: 'P1001' }, 500)
      view()
      await openMenuItem('Save as preset…')
      fireEvent.change(screen.getByPlaceholderText(/Quiet external perimeter/), { target: { value: 'My preset' } })
      fireEvent.click(screen.getByRole('button', { name: 'Save preset' }))
      expect(await screen.findByText('Failed to save the preset (P1001 · HTTP 500)')).toBeTruthy()
    })

    test('refused rules are all listed under the reason, past ten', async () => {
      const errors = Array.from({ length: 12 }, (_, i) => `vuln.nuclei rule ${i + 1}: unknown field`)
      answer((u, m) => u.endsWith('/api/mute-rule-presets') && m === 'POST', { error: 'The rules are not valid.', errors }, 400)
      view()
      await openMenuItem('Save as preset…')
      fireEvent.change(screen.getByPlaceholderText(/Quiet external perimeter/), { target: { value: 'My preset' } })
      fireEvent.click(screen.getByRole('button', { name: 'Save preset' }))
      expect(await screen.findByText('The rules are not valid. (HTTP 400)')).toBeTruthy()
      expect(screen.getByText('vuln.nuclei rule 12: unknown field')).toBeTruthy()
    })

    test('a list that cannot be read says why, with Retry', async () => {
      answer((u, m) => u.endsWith('/api/mute-rule-presets') && m === 'GET', { error: 'Failed to load the presets', code: 'P1001' }, 500)
      view()
      await openMenuItem('Load preset…')
      expect(await screen.findByText('Failed to load the presets (P1001 · HTTP 500)')).toBeTruthy()
      expect(screen.getByRole('button', { name: 'Retry' })).toBeTruthy()
    })

    test('a preset that cannot be read names the status (a deleted one is a 404)', async () => {
      confirm.mockResolvedValue(true)
      answer(u => u.endsWith('/api/mute-rule-presets/preset1'), { error: 'Preset not found' }, 404)
      view()
      await openMenuItem('Load preset…')
      fireEvent.click(await screen.findByRole('button', { name: 'Load' }))
      await waitFor(() => expect(alertError).toHaveBeenCalledWith(
        'The preset "Quiet perimeter" could not be read (HTTP 404).', 'Load preset'))
    })

    test('a rename that got no answer says so in the row (it used to throw unhandled)', async () => {
      const real = fetchMock.getMockImplementation() as (url: string, init?: RequestInit) => unknown
      fetchMock.mockImplementation((url: string, init?: RequestInit) => (
        url.endsWith('/api/mute-rule-presets/preset1') && init?.method === 'PATCH'
          ? Promise.reject(new TypeError('Failed to fetch'))
          : real(url, init)
      ))
      view()
      await openMenuItem('Manage presets…')
      fireEvent.click(await screen.findByRole('button', { name: 'Rename Quiet perimeter' }))
      fireEvent.change(screen.getByLabelText('Preset name'), { target: { value: 'Renamed' } })
      fireEvent.click(within(screen.getByLabelText('Preset name').closest('li')!).getByRole('button', { name: /Save/ }))
      expect(await screen.findByText('Rename failed (network_error)')).toBeTruthy()
    })

    test('a refused rename shows the server reason with its status', async () => {
      answer((u, m) => u.endsWith('/api/mute-rule-presets/preset1') && m === 'PATCH', { error: 'Preset not found' }, 404)
      view()
      await openMenuItem('Manage presets…')
      fireEvent.click(await screen.findByRole('button', { name: 'Rename Quiet perimeter' }))
      fireEvent.change(screen.getByLabelText('Preset name'), { target: { value: 'Renamed' } })
      fireEvent.click(within(screen.getByLabelText('Preset name').closest('li')!).getByRole('button', { name: /Save/ }))
      expect(await screen.findByText('Preset not found (HTTP 404)')).toBeTruthy()
    })

    test('a delete the server refused names the code and status', async () => {
      dangerConfirm.mockResolvedValue(true)
      answer((u, m) => u.endsWith('/api/mute-rule-presets/preset1') && m === 'DELETE', { error: 'Failed to delete the preset', code: 'P1001' }, 500)
      view()
      await openMenuItem('Manage presets…')
      fireEvent.click(await screen.findByRole('button', { name: 'Delete Quiet perimeter' }))
      await waitFor(() => expect(toast.error).toHaveBeenCalledWith(
        'Preset "Quiet perimeter" could not be deleted (P1001 · HTTP 500).', 'Mute rules'))
    })

    test("an apply the agent refused shows the agent's sentence with both statuses", async () => {
      answer((u, m) => u.endsWith('/apply') && m === 'POST',
        { error: 'INTERNAL_API_KEY is not configured; mute rules are disabled.', code: 'agent_error', upstreamStatus: 503 }, 502)
      view()
      fireEvent.click(await screen.findByText('Apply…'))
      const confirmApply = await screen.findByRole('button', { name: 'Apply' })
      await waitFor(() => expect((confirmApply as HTMLButtonElement).disabled).toBe(false))
      fireEvent.click(confirmApply)
      await waitFor(() => expect(alertError).toHaveBeenCalledWith(
        'INTERNAL_API_KEY is not configured; mute rules are disabled. (agent_error · HTTP 502 · upstream HTTP 503)',
        'Apply mute rules'))
    })
  })
})
