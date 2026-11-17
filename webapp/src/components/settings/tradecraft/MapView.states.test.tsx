/** The Map view's states (D-14): loading, a failure with its code and Retry, denied, 2.0 off, empty, no match. */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { MapView } from './MapView'

const fetchMock = vi.fn()
beforeEach(() => { vi.clearAllMocks(); vi.stubGlobal('fetch', fetchMock) })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
const answer = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const EMPTY = { entries: [], total: 0, nextCursor: null }
const draw = () => render(<MapView userId="user-1" resource={{ id: 'r1', name: 'Lab Wiki', url: 'https://wiki.tc-fixture.test/', storageMode: 'live' }} onClose={vi.fn()} />)

describe('MapView states', () => {
  test('loading, then the empty map', async () => {
    let release!: (r: Response) => void
    fetchMock.mockImplementationOnce(() => new Promise<Response>(r => { release = r }))
    draw()
    expect(screen.getByText('Loading the map…')).toBeInTheDocument()
    release(answer(200, EMPTY))
    expect(await screen.findByText('No pages in the map yet: refresh the resource to build it.')).toBeInTheDocument()
  })

  test('a failure says why with its code; Retry reads again', async () => {
    fetchMock.mockResolvedValueOnce(answer(500, { error: 'Failed to read the map', code: 'P1001' }))
    draw()
    expect(await screen.findByRole('alert')).toHaveTextContent(/P1001 · HTTP 500/)
    fetchMock.mockResolvedValueOnce(answer(200, EMPTY))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText(/No pages in the map yet/)).toBeInTheDocument()
  })

  test('denied: an administrator not acting as the account (403 account_content_only)', async () => {
    fetchMock.mockResolvedValueOnce(answer(403, { error: "Only the account itself reads its content", code: 'account_content_only' }))
    draw()
    expect(await screen.findByRole('alert')).toHaveTextContent(/You cannot see this map: .*account_content_only · HTTP 403/)
  })

  test('2.0 off for the account', async () => {
    fetchMock.mockResolvedValueOnce(answer(404, { error: 'Tradecraft 2.0 is off for this account', code: 'tradecraft_v2_off' }))
    draw()
    expect(await screen.findByRole('alert')).toHaveTextContent('Tradecraft 2.0 is off for this account')
  })

  test('no match for a search; no blocked or dropped page', async () => {
    fetchMock.mockImplementation(async () => answer(200, EMPTY))
    draw()
    await screen.findByText(/No pages in the map yet/)
    fireEvent.change(screen.getByRole('textbox', { name: 'Search the map' }), { target: { value: 'nothing' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    expect(await screen.findByText('No page matches the search.')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: 'Search the map' }), { target: { value: '' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Blocked' }))
    expect(await screen.findByText('No page is blocked.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Dropped' }))
    expect(await screen.findByText('The focus dropped no page.')).toBeInTheDocument()
  })
})
