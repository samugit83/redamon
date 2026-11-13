/**
 * The chat's file-download card reads /api/agent/files for the file's project (4.9 review): the
 * agent offers a card only for a file of the run's project workspace and names the project. A
 * card restored from an older message (a /tmp file, no project) says why it cannot download and
 * makes no request. FileDownloadCard.route.test.tsx runs the real route behind it.
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
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
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

const card = () => render(
  <FileDownloadCard filepath="/workspace/p1/notes/report.txt" filename="report.txt" description="d" source="kali" projectId="p1" />,
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
    expect(fetchMock).toHaveBeenCalledWith('/api/agent/files?projectId=p1&path=%2Fworkspace%2Fp1%2Fnotes%2Freport.txt')
    const blob = (URL.createObjectURL as ReturnType<typeof vi.fn>).mock.calls[0][0] as Blob
    expect(await blob.text()).toBe('chunk-1 chunk-2')
    await waitFor(() => expect(screen.getByTitle('Download again')).toBeTruthy())
  })

  test('shows the error for a failed download', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: 'Failed to download file', code: 'agent_error', upstreamStatus: 404 }),
      { status: 404, headers: { 'Content-Type': 'application/json' } },
    )))
    card()
    fireEvent.click(screen.getByTitle('Download file'))
    await waitFor(() => expect(screen.getByText(/Failed to download file/)).toBeTruthy())
    expect(clicked).toHaveLength(0)
  })

  test('a card from an older message, outside any project workspace, says why and makes no request', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    render(<FileDownloadCard filepath="/tmp/loot/report.txt" filename="report.txt" description="d" source="kali" />)
    fireEvent.click(screen.getByTitle('Download file'))
    await waitFor(() => expect(screen.getByText(/outside the project's workspace/)).toBeTruthy())
    expect(fetchMock).not.toHaveBeenCalled()
    expect(clicked).toHaveLength(0)
  })
})
