/**
 * The chat's file-download card reads /api/agent/files (the legacy /tmp
 * branch), which now streams its body.
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { FileDownloadCard } from './FileDownloadCard'

let clicked: { href: string; download: string }[]

beforeEach(() => {
  clicked = []
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    clicked.push({ href: this.href, download: this.download })
  })
  URL.createObjectURL = vi.fn(() => 'blob:mock')
  URL.revokeObjectURL = vi.fn()
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

const card = () => render(
  <FileDownloadCard filepath="/tmp/loot/report.txt" filename="report.txt" description="d" source="kali" />,
)

describe('FileDownloadCard', () => {
  test('downloads a streamed response as a blob and names the file', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(c) { c.enqueue(new TextEncoder().encode('chunk-1 ')); c.enqueue(new TextEncoder().encode('chunk-2')); c.close() },
    })
    const fetchMock = vi.fn(async () => new Response(stream, { status: 200, headers: { 'Content-Type': 'text/plain' } }))
    vi.stubGlobal('fetch', fetchMock)
    card()
    fireEvent.click(screen.getByTitle('Download file'))
    await waitFor(() => expect(clicked).toHaveLength(1))
    expect(clicked[0].download).toBe('report.txt')
    expect(fetchMock).toHaveBeenCalledWith('/api/agent/files?path=%2Ftmp%2Floot%2Freport.txt')
    const blob = (URL.createObjectURL as ReturnType<typeof vi.fn>).mock.calls[0][0] as Blob
    expect(await blob.text()).toBe('chunk-1 chunk-2')
    await waitFor(() => expect(screen.getByTitle('Download again')).toBeTruthy())
  })

  test('shows the error for a failed download', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: 'Forbidden: only /tmp/ paths allowed', code: 'agent_error' }),
      { status: 403, headers: { 'Content-Type': 'application/json' } },
    )))
    card()
    fireEvent.click(screen.getByTitle('Download file'))
    await waitFor(() => expect(screen.getByText(/only \/tmp\/ paths allowed/)).toBeTruthy())
    expect(clicked).toHaveLength(0)
  })
})
