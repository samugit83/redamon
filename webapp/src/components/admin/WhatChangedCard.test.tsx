/**
 * The one-time "What changed in this update" admin card (HD-32, OQ-48, step 1.18): what
 * changed for admins and for members (the same lines the upgrade preview prints), and the
 * members whose saved stdio MCP servers no longer load. A single-operator install sees
 * nothing; a dismissed card stays dismissed (the server keeps the dismissal per admin).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { WhatChangedCard } from './WhatChangedCard'
import { ADMIN_CHANGE_LINES, MEMBER_CHANGE_LINES, type WhatsNewAnswer } from './updateNotes'
import { MEMBER_CHANGES } from '../../../scripts/rbac-upgrade-preview.mjs'

const fetchMock = vi.fn()
let state: WhatsNewAnswer

beforeEach(() => {
  state = { dismissed: false, applies: true, stdioMembers: [] }
  fetchMock.mockReset()
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (url !== '/api/admin/whats-new') return new Response('{}', { status: 404 })
    if (init?.method === 'POST') {
      state = { ...state, dismissed: true }
      return new Response(JSON.stringify({ dismissed: true, changed: true }), { status: 200 })
    }
    return new Response(JSON.stringify(state), { status: 200 })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const posts = () => fetchMock.mock.calls.filter(c => (c[1] as RequestInit | undefined)?.method === 'POST')

describe('single-operator install shows nothing', () => {
  test('applies false: nothing rendered', async () => {
    state = { dismissed: false, applies: false, stdioMembers: [] }
    const { container } = render(<WhatChangedCard />)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    await new Promise(r => setTimeout(r, 0))
    expect(container.textContent).toBe('')
  })

  test('nothing while it loads, nothing for a 403', async () => {
    fetchMock.mockImplementationOnce(() => new Promise(() => {}))
    const { container } = render(<WhatChangedCard />)
    expect(container.textContent).toBe('')
    cleanup()
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ code: 'forbidden' }), { status: 403 }))
    const second = render(<WhatChangedCard />)
    await new Promise(r => setTimeout(r, 0))
    expect(second.container.textContent).toBe('')
  })
})

describe('the card', () => {
  test('lists what changed for admins and for members', async () => {
    render(<WhatChangedCard />)
    const card = await screen.findByRole('region', { name: 'What changed in this update' })
    for (const line of [...ADMIN_CHANGE_LINES, ...MEMBER_CHANGE_LINES]) expect(card.textContent).toContain(line)
    expect(within(card).queryByText(/stdio MCP servers that no longer load/)).toBeNull()
  })

  test('the member lines are the upgrade preview\'s', () => {
    expect(MEMBER_CHANGE_LINES).toEqual(MEMBER_CHANGES.map((c: { text: (ctx: { templateFiles: number }) => string }) => c.text({ templateFiles: 0 })))
  })

  test('names the members whose saved stdio MCP servers no longer load', async () => {
    state = {
      dismissed: false, applies: true,
      stdioMembers: [
        { id: 'm1', name: 'Anna', email: 'anna@e2e.local', servers: 2 },
        { id: 'm2', name: 'Marco', email: 'marco@e2e.local', servers: 1 },
      ],
    }
    render(<WhatChangedCard />)
    const card = await screen.findByRole('region', { name: 'What changed in this update' })
    expect(within(card).getByText(/stdio MCP servers that no longer load/)).toBeInTheDocument()
    expect(card.textContent).toContain('Anna (anna@e2e.local): 2 servers')
    expect(card.textContent).toContain('Marco (marco@e2e.local): 1 server')
  })

  test('an error is one line with its cause and Retry', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'x', code: 'P1001' }), { status: 500 }))
    render(<WhatChangedCard />)
    const line = await screen.findByText(/Could not load the update notes/)
    expect(line.closest('[role="status"]')!.textContent).toMatch(/P1001 · HTTP 500/)
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('region', { name: 'What changed in this update' })).toBeInTheDocument()
  })
})

describe('dismissed card stays dismissed', () => {
  test('Got it records the dismissal and hides the card; a fresh mount stays empty', async () => {
    const first = render(<WhatChangedCard />)
    fireEvent.click(await screen.findByRole('button', { name: 'Got it' }))
    await waitFor(() => expect(screen.queryByRole('region', { name: 'What changed in this update' })).toBeNull())
    expect(posts()).toHaveLength(1)
    const body = JSON.parse(String((posts()[0][1] as RequestInit).body))
    expect(body).toEqual({ action: 'dismiss' })
    first.unmount()
    const again = render(<WhatChangedCard />)
    await waitFor(() => expect(fetchMock.mock.calls.filter(c => !(c[1] as RequestInit | undefined)?.method)).toHaveLength(2))
    await new Promise(r => setTimeout(r, 0))
    expect(again.container.textContent).toBe('')
  })

  test('a failed dismissal keeps the card and says why', async () => {
    render(<WhatChangedCard />)
    const button = await screen.findByRole('button', { name: 'Got it' })
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'Could not dismiss', code: 'P2002' }), { status: 500 }))
    fireEvent.click(button)
    expect(await screen.findByRole('alert')).toHaveTextContent(/P2002 · HTTP 500/)
    expect(screen.getByRole('region', { name: 'What changed in this update' })).toBeInTheDocument()
  })
})
