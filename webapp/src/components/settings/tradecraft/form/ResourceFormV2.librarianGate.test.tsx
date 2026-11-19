/**
 * Add and Enable through the librarian gate (Q10, T7.5; R-404, AC-71): while Librarian use is
 * "Agent decides" and the account has no librarian model, an Add, and Enabled turned on, answer 409
 * `model_required`; the gate opens with the section picker's model suggested, saves it only on
 * confirm, and the save runs once more. Cancel saves neither the model nor the resource.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))
vi.mock('@/components/shared/ModelPicker', async orig => {
  const real = await orig<typeof import('@/components/shared/ModelPicker')>()
  return {
    ...real,
    // The resource form's own model field is a plain input; the gate keeps the real picker.
    ModelPicker: (props: Parameters<typeof real.ModelPicker>[0]) => props.hideManualFallback
      ? real.ModelPicker(props)
      : <input aria-label="Model" value={props.value} onChange={e => props.onChange(e.target.value)} />,
  }
})
const alerts = vi.hoisted(() => ({ confirm: vi.fn(async () => true), dangerConfirm: vi.fn(async () => true), alert: vi.fn(), alertError: vi.fn(), alertWarning: vi.fn() }))
vi.mock('@/components/ui', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useAlertModal: () => alerts, useOptionalAlertModal: () => alerts,
}))

import { ToastProvider } from '@/components/ui/Toast/Toast'
import { FeatureModelGateProvider } from '@/components/shared/FeatureModelGate'
import { jsonResponse, stubGateFetch, type GateFetchStub } from '@/components/shared/featureModelGate.testUtils'
import { ResourceFormV2 } from './ResourceFormV2'
import { ResourceListV2 } from '../ResourceListV2'
import { RESOURCE } from '../__testing__/resourceView'

const BASE = '/api/users/user-1/tradecraft-resources'
const REQUIRED = { error: 'Choose a model for Tradecraft librarian first', code: 'model_required', featureId: 'tradecraft_librarian' }
let stub: GateFetchStub
let writes: { method: string; url: string }[]

function routeWith(answers: Record<string, { status: number; body: unknown }[]>) {
  writes = []
  stub = stubGateFetch({ tradecraft_section_picker: 'claude-haiku-4-5' }, (url, init) => {
    const method = init?.method ?? 'GET'
    if (method !== 'GET') writes.push({ method, url })
    const list = answers[`${method} ${url}`]
    if (list && list.length > 0) {
      const a = list.length > 1 ? list.shift()! : list[0]
      return jsonResponse(a.status, a.body)
    }
    if (url === `${BASE}/r1/enabled-impact?next=true`) return jsonResponse(200, { next: true, projects: 2, turnedOffIn: 0 })
    if (url === '/api/users/user-1/tradecraft-settings') return jsonResponse(200, { v2Enabled: true })
    return jsonResponse(404, { error: 'no route' })
  })
}
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
beforeEach(() => { vi.clearAllMocks() })

const providers = (node: React.ReactNode) => render(<ToastProvider><FeatureModelGateProvider>{node}</FeatureModelGateProvider></ToastProvider>)

describe('the librarian gate on Add and Enable', () => {
  test('add_opens_gate_and_retries: model_required opens the gate with the suggestion; confirmed, the Add runs again', async () => {
    routeWith({ [`POST ${BASE}`]: [{ status: 409, body: REQUIRED }, { status: 201, body: { resource: null, job: null } }] })
    const onSaved = vi.fn()
    providers(<ResourceFormV2 userId="user-1" resource={null} onSaved={onSaved} onCancel={vi.fn()} />)
    fireEvent.change(screen.getByPlaceholderText('HackTricks'), { target: { value: 'Lab Wiki' } })
    fireEvent.change(screen.getByPlaceholderText('https://book.hacktricks.wiki'), { target: { value: 'https://wiki.tc-fixture.test/' } })
    fireEvent.change(screen.getByLabelText('Model'), { target: { value: 'gpt-4o' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
    const gate = await screen.findByRole('dialog', { name: /Choose a model for Tradecraft librarian/ })
    expect(await within(gate).findByTestId('gate-suggestion')).toHaveTextContent('Suggested: claude-haiku-4-5 (your Tradecraft section picker model)')
    expect(stub.saved.tradecraft_librarian).toBeUndefined()
    const save = within(gate).getByRole('button', { name: 'Save and continue' })
    await waitFor(() => expect(save).toBeEnabled())
    fireEvent.click(save)
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(stub.saved.tradecraft_librarian).toBe('claude-haiku-4-5')
    expect(writes.filter(w => w.url === BASE)).toHaveLength(2)
  })

  test('Cancel in the gate: no model saved, no resource added, the refusal stays in the form', async () => {
    routeWith({ [`POST ${BASE}`]: [{ status: 409, body: REQUIRED }] })
    const onSaved = vi.fn()
    providers(<ResourceFormV2 userId="user-1" resource={null} onSaved={onSaved} onCancel={vi.fn()} />)
    fireEvent.change(screen.getByPlaceholderText('HackTricks'), { target: { value: 'Lab Wiki' } })
    fireEvent.change(screen.getByPlaceholderText('https://book.hacktricks.wiki'), { target: { value: 'https://wiki.tc-fixture.test/' } })
    fireEvent.change(screen.getByLabelText('Model'), { target: { value: 'gpt-4o' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add & ingest' }))
    const gate = await screen.findByRole('dialog', { name: /Choose a model for Tradecraft librarian/ })
    fireEvent.click(within(gate).getByRole('button', { name: 'Cancel' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/model_required/)
    expect(onSaved).not.toHaveBeenCalled()
    expect(stub.saved.tradecraft_librarian).toBeUndefined()
    expect(writes.filter(w => w.url === BASE)).toHaveLength(1)
  })

  test('Enabled turned on from the card goes through the gate too, and is retried once', async () => {
    routeWith({
      [`GET ${BASE}`]: [{ status: 200, body: [{ ...RESOURCE, enabled: false }] }],
      [`PUT ${BASE}/r1`]: [{ status: 409, body: REQUIRED }, { status: 200, body: { resource: null, job: null } }],
    })
    providers(<ResourceListV2 userId="user-1" onDirtyChange={vi.fn()} />)
    fireEvent.click(await screen.findByRole('switch', { name: 'Enabled: Lab Wiki' }))
    const gate = await screen.findByRole('dialog', { name: /Choose a model for Tradecraft librarian/ })
    await waitFor(() => expect(within(gate).getByRole('button', { name: 'Save and continue' })).toBeEnabled())
    fireEvent.click(within(gate).getByRole('button', { name: 'Save and continue' }))
    await waitFor(() => expect(writes.filter(w => w.method === 'PUT' && w.url === `${BASE}/r1`)).toHaveLength(2))
    expect(stub.saved.tradecraft_librarian).toBe('claude-haiku-4-5')
  })
})
