/** Check URL (§6.3): the one-line result, the Live cost (R-081), a failure with its code, a run per preset pick. */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { CheckUrlButton, LIVE_COST, checkSummary } from './CheckUrlButton'
import { CheckUrlResult } from '@/lib/tradecraft/agentContract'

const RESULT = CheckUrlResult.parse({
  ok: true, final_url: 'https://blog.tc-fixture.test/', detected_type: 'agentic-crawl', robots_allows: true,
  index: { kind: 'sitemap', url: 'https://blog.tc-fixture.test/sitemap.xml', count: 412 }, recommended_storage: 'stored', estimated_bytes: 6 * 1024 * 1024,
})
const fetchMock = vi.fn()
const onResult = vi.fn()
beforeEach(() => { vi.clearAllMocks(); vi.stubGlobal('fetch', fetchMock) })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
const answer = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

describe('CheckUrlButton', () => {
  test('the one-line result, and the result handed to the form; the request carries the form\'s input', async () => {
    fetchMock.mockResolvedValue(answer(200, { result: RESULT }))
    render(<CheckUrlButton userId="user-1" input={{ url: 'https://blog.tc-fixture.test/', forcedType: '' }} onResult={onResult} />)
    fireEvent.click(screen.getByRole('button', { name: /Check URL/ }))
    expect(await screen.findByRole('status')).toHaveTextContent(
      '✓ Website · sitemap.xml found (412 pages) · robots.txt allows · Stored recommended, about 6 MB')
    expect(onResult).toHaveBeenCalledWith(RESULT)
    expect(fetchMock.mock.calls[0][0]).toBe('/api/users/user-1/tradecraft-resources/check-url')
    expect(JSON.parse(String((fetchMock.mock.calls[0][1] as RequestInit).body))).toEqual({ url: 'https://blog.tc-fixture.test/', forcedType: '' })
  })

  test('live_note: a Live recommendation says what Live costs (R-081)', async () => {
    fetchMock.mockResolvedValue(answer(200, { result: { ...RESULT, recommended_storage: 'live' } }))
    render(<CheckUrlButton userId="user-1" input={{ url: 'https://x.tc-fixture.test/' }} onResult={onResult} />)
    fireEvent.click(screen.getByRole('button', { name: /Check URL/ }))
    expect(await screen.findByRole('status')).toHaveTextContent(LIVE_COST)
  })

  test('the agent\'s refusal and the route\'s failure say why', async () => {
    fetchMock.mockResolvedValueOnce(answer(200, { result: CheckUrlResult.parse({ ok: false, error_code: 'blocked_private_address' }) }))
    render(<CheckUrlButton userId="user-1" input={{ url: 'https://x.tc-fixture.test/' }} onResult={onResult} />)
    fireEvent.click(screen.getByRole('button', { name: /Check URL/ }))
    expect(await screen.findByRole('status')).toHaveTextContent('✗ the address is private or internal, and is never fetched')
    fetchMock.mockResolvedValueOnce(answer(504, { error: 'The check took too long', code: 'timeout' }))
    fireEvent.click(screen.getByRole('button', { name: /Check URL/ }))
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/timeout · HTTP 504/))
    expect(onResult).toHaveBeenLastCalledWith(null)
  })

  test('runs by itself each time the run token moves (a preset was picked)', async () => {
    fetchMock.mockResolvedValue(answer(200, { result: RESULT }))
    const { rerender } = render(<CheckUrlButton userId="user-1" input={{ url: 'https://a.tc-fixture.test/' }} runToken={0} onResult={onResult} />)
    expect(fetchMock).not.toHaveBeenCalled()
    rerender(<CheckUrlButton userId="user-1" input={{ url: 'https://a.tc-fixture.test/' }} runToken={1} onResult={onResult} />)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
  })

  test('the summary of other indexes', () => {
    expect(checkSummary(CheckUrlResult.parse({ ok: true, detected_type: 'github-repo', index: { kind: 'github_tree', count: 90 }, needs_browser: true })))
      .toBe('✓ GitHub repository · 90 files · no robots.txt · needs the browser · Live recommended')
  })
})
