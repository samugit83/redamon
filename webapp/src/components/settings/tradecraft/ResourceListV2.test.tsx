/**
 * The 2.0 list: its states, Refresh and Cancel, the delete confirmation, and the job views read
 * every 3 s while a job runs and never otherwise (fake timers; the routes are a fetch double).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, act } from '@testing-library/react'
import { isValidElement } from 'react'
import { ToastProvider } from '@/components/ui/Toast/Toast'
import { RESOURCE, job } from './__testing__/resourceView'

const alerts = vi.hoisted(() => ({ confirm: vi.fn(async () => true), dangerConfirm: vi.fn(async () => true), alert: vi.fn(), alertError: vi.fn(), alertWarning: vi.fn() }))
vi.mock('@/components/ui', async orig => ({ ...((await orig()) as Record<string, unknown>), useAlertModal: () => alerts }))
vi.mock('@/components/shared/ModelPicker', () => ({ ModelPicker: () => <input aria-label="Model" /> }))

import { ResourceListV2 } from './ResourceListV2'
import { DeleteConfirm } from './DeleteConfirm'

const BASE = '/api/users/user-1/tradecraft-resources'
type Answer = { status: number; body: unknown }
let routes: Record<string, Answer | Answer[]>
const fetchMock = vi.fn()
const calls = (method: string, url: string) => fetchMock.mock.calls.filter(c => c[0] === url && ((c[1] as RequestInit | undefined)?.method ?? 'GET') === method)

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
  routes = { [`GET ${BASE}`]: { status: 200, body: [RESOURCE] } }
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const key = `${init?.method ?? 'GET'} ${url}`
    const entry = routes[key]
    const a = Array.isArray(entry) ? (entry.length > 1 ? entry.shift()! : entry[0]) : entry ?? { status: 404, body: { error: 'no route' } }
    return new Response(JSON.stringify(a.body), { status: a.status })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals() })

const flush = () => act(async () => { await vi.advanceTimersByTimeAsync(0) })
const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms) })
async function renderList() {
  render(<ToastProvider><ResourceListV2 userId="user-1" onDirtyChange={vi.fn()} /></ToastProvider>)
  await flush()
}

describe('ResourceListV2 states', () => {
  test('loading, then the cards', async () => {
    render(<ToastProvider><ResourceListV2 userId="user-1" onDirtyChange={vi.fn()} /></ToastProvider>)
    expect(screen.getByText('Loading…')).toBeInTheDocument()
    await flush()
    expect(screen.getByText('Lab Wiki')).toBeInTheDocument()
  })

  test('empty', async () => {
    routes[`GET ${BASE}`] = { status: 200, body: [] }
    await renderList()
    expect(screen.getByText(/No resources yet/)).toBeInTheDocument()
  })

  test('error, with its code, and Retry', async () => {
    routes[`GET ${BASE}`] = [{ status: 500, body: { error: 'Failed to fetch tradecraft resources', code: 'P1001' } }, { status: 200, body: [RESOURCE] }]
    await renderList()
    expect(screen.getByRole('alert')).toHaveTextContent(/P1001 · HTTP 500/)
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await flush()
    expect(screen.getByText('Lab Wiki')).toBeInTheDocument()
  })

  test('denied (a 403): says so, offers no Add', async () => {
    routes[`GET ${BASE}`] = { status: 403, body: { error: 'Not available while acting as Ada', code: 'not_while_acting_as' } }
    await renderList()
    expect(screen.getByRole('alert')).toHaveTextContent(/You cannot use these resources: .*not_while_acting_as/)
    expect(screen.queryByRole('button', { name: /Add Resource/ })).toBeNull()
  })
})

describe('ResourceListV2 jobs', () => {
  test('Refresh starts a job: the card shows it queued and offers Cancel', async () => {
    routes[`POST ${BASE}/r1/refresh`] = { status: 202, body: { job: job({ status: 'queued' }) } }
    routes[`GET ${BASE}/r1/jobs`] = { status: 200, body: { job: job({ status: 'queued' }) } }
    await renderList()
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ }))
    await flush()
    expect(calls('POST', `${BASE}/r1/refresh`)).toHaveLength(1)
    expect(screen.getByRole('status')).toHaveTextContent('Queued')
    expect(screen.getByRole('button', { name: /Cancel/ })).toBeInTheDocument()
  })

  test('the job view is read every 3 s while it runs; when it ends the list is read again and polling stops', async () => {
    routes[`GET ${BASE}`] = [{ status: 200, body: [{ ...RESOURCE, job: job({ status: 'running', stage: 'detect' }) }] }, { status: 200, body: [{ ...RESOURCE, job: job({ status: 'succeeded' }), entryCount: 40 }] }]
    routes[`GET ${BASE}/r1/jobs`] = [{ status: 200, body: { job: job({ status: 'running', stage: 'build_map' }) } }, { status: 200, body: { job: job({ status: 'succeeded' }) } }]
    await renderList()
    expect(screen.getByRole('status')).toHaveTextContent('Detecting the site type')
    await tick(2999)
    expect(calls('GET', `${BASE}/r1/jobs`)).toHaveLength(0)
    await tick(1)
    expect(calls('GET', `${BASE}/r1/jobs`)).toHaveLength(1)
    expect(screen.getByRole('status')).toHaveTextContent('Building the map')
    await tick(3000)
    expect(calls('GET', `${BASE}/r1/jobs`)).toHaveLength(2)
    expect(calls('GET', BASE)).toHaveLength(2)
    expect(screen.getByText('40 entries')).toBeInTheDocument()
    await tick(9000)
    expect(calls('GET', `${BASE}/r1/jobs`)).toHaveLength(2)
  })

  test('nothing running: no job view is read', async () => {
    await renderList()
    await tick(10_000)
    expect(calls('GET', `${BASE}/r1/jobs`)).toHaveLength(0)
  })

  test('Cancel sends the cancel and shows Cancelling…', async () => {
    routes[`GET ${BASE}`] = { status: 200, body: [{ ...RESOURCE, job: job({ status: 'running', stage: 'store' }) }] }
    routes[`DELETE ${BASE}/r1/jobs`] = { status: 200, body: { job: job({ status: 'running', stage: 'store', cancelRequested: true }) } }
    await renderList()
    fireEvent.click(screen.getByRole('button', { name: /Cancel/ }))
    await flush()
    expect(calls('DELETE', `${BASE}/r1/jobs`)).toHaveLength(1)
    expect(screen.getByRole('status')).toHaveTextContent('Cancelling…')
  })

  test('a refresh refused while another job runs shows that job and the reason', async () => {
    routes[`POST ${BASE}/r1/refresh`] = { status: 409, body: { error: 'A job is already running', code: 'job_running', job: job({ status: 'running', stage: 'tags' }) } }
    routes[`GET ${BASE}/r1/jobs`] = { status: 200, body: { job: job({ status: 'running', stage: 'tags' }) } }
    await renderList()
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ }))
    await flush()
    expect(screen.getByRole('status')).toHaveTextContent('Tagging pages')
    expect(screen.getByText(/job_running/)).toBeInTheDocument()
  })

  // U-13, U-62: moved from the 1.x tab's tests (page.errors.test.tsx) when the cut-over removed it (T9.3).
  test('a refresh the agent could not start names the cause, its code and the statuses', async () => {
    routes[`POST ${BASE}/r1/refresh`] = { status: 502, body: { error: 'The agent could not start the refresh', code: 'agent_unreachable', upstreamStatus: 503 } }
    await renderList()
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ }))
    await flush()
    await flush()
    expect(screen.getByText('Refresh failed: The agent could not start the refresh (agent_unreachable · HTTP 502 · upstream HTTP 503)')).toBeInTheDocument()
  })

  test('a refused delete names the code', async () => {
    routes[`DELETE ${BASE}/r1`] = { status: 500, body: { error: 'Failed to delete tradecraft resource', code: 'P2024' } }
    await renderList()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Lab Wiki' }))
    await flush()
    await flush()
    expect(screen.getByText('Delete failed: Failed to delete tradecraft resource (P2024 · HTTP 500)')).toBeInTheDocument()
  })
})

describe('ResourceListV2 delete and add', () => {
  test('delete asks with the list of what goes, then deletes and reads the list again', async () => {
    routes[`DELETE ${BASE}/r1`] = { status: 200, body: { success: true } }
    await renderList()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Lab Wiki' }))
    await flush()
    const [message, title] = alerts.dangerConfirm.mock.calls[0] as unknown as [unknown, string]
    expect(title).toBe('Delete tradecraft resource')
    expect(isValidElement(message) && message.type).toBe(DeleteConfirm)
    expect(calls('DELETE', `${BASE}/r1`)).toHaveLength(1)
    expect(calls('GET', BASE)).toHaveLength(2)
  })

  test('a declined delete deletes nothing', async () => {
    alerts.dangerConfirm.mockResolvedValueOnce(false)
    await renderList()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Lab Wiki' }))
    await flush()
    expect(calls('DELETE', `${BASE}/r1`)).toHaveLength(0)
  })

  test('Add Resource opens the basic form', async () => {
    await renderList()
    fireEvent.click(screen.getByRole('button', { name: /Add Resource/ }))
    await flush()
    expect(screen.getByText('Add Tradecraft Resource')).toBeInTheDocument()
  })
})
