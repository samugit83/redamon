/** The accordion's states (D-14): loading, a failure with Retry, denied, empty. */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { TradecraftResourcesAccordion } from './TradecraftResourcesAccordion'

const fetchMock = vi.fn()
beforeEach(() => { vi.clearAllMocks(); vi.stubGlobal('fetch', fetchMock) })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
const answer = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const draw = () => render(<TradecraftResourcesAccordion projectId="p1" offIds={[]} onChange={vi.fn()} />)

describe('TradecraftResourcesAccordion states', () => {
  test('loading, then the rows', async () => {
    let release!: (r: Response) => void
    fetchMock.mockImplementationOnce(() => new Promise<Response>(r => { release = r }))
    draw()
    expect(screen.getByText('Loading the tradecraft resources…')).toBeInTheDocument()
    release(answer(200, { v2: true, viewerIsOwner: true, resources: [], counts: null }))
    expect(await screen.findByText(/No tradecraft resources yet/)).toBeInTheDocument()
  })

  test('a failure says why with its code; Retry reads again', async () => {
    fetchMock.mockResolvedValueOnce(answer(500, { error: "Could not read the project's tradecraft resources", code: 'P1001' }))
    draw()
    expect(await screen.findByRole('alert')).toHaveTextContent(/P1001 · HTTP 500/)
    fetchMock.mockResolvedValueOnce(answer(200, { v2: true, viewerIsOwner: true, resources: [], counts: null }))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText(/No tradecraft resources yet/)).toBeInTheDocument()
  })

  test('denied: a refusal names itself, with no switch', async () => {
    fetchMock.mockResolvedValueOnce(answer(403, { error: 'You do not hold the permission', code: 'forbidden', permission: 'recon:read' }))
    draw()
    expect(await screen.findByText(/You cannot see this project's tradecraft resources/)).toBeInTheDocument()
    expect(screen.queryByRole('switch')).toBeNull()
  })
})
