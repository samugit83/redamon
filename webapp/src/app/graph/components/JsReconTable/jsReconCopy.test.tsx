/**
 * The Secrets tab's copy button, opened the way a teammate opens RedAmon:
 * http://<lan-ip>:3000, not a secure context, so `navigator.clipboard` is
 * undefined. The button must still copy the FULL matched value (the cell only
 * shows the redacted one) and show its tick.
 *
 * Run: npx vitest run src/app/graph/components/JsReconTable/jsReconCopy.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, act, waitFor, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createElement } from 'react'

import { JsReconTable } from './JsReconTable'

const FULL_VALUE = 'password = "not-a-real-secret-0123"'

const DATA = {
  secrets: [
    { nodeId: '101', id: 's1', severity: 'medium', name: 'generic_secret', redacted_value: 'passwo...0123"',
      matched_text: FULL_VALUE, category: 'generic', source_url: 'https://a.invalid/app.js',
      detection_method: 'regex', confidence: 0.5, validation: { status: 'unvalidated' } },
  ],
}

function installFetch() {
  globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
    const u = typeof url === 'string' ? url : url.toString()
    const body = u.includes('/api/js-recon/') ? DATA : u === '/api/user/preferences' ? {} : null
    return body === null
      ? new Response('not found', { status: 404 })
      : new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }) as typeof fetch
}

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client }, children)
}

/** jsdom has no execCommand; record what the hidden textarea held when copied. */
function stubExecCommand() {
  const copied: string[] = []
  const exec = vi.fn((cmd: string) => {
    const el = document.querySelector('body > textarea')
    if (cmd === 'copy' && el instanceof HTMLTextAreaElement) copied.push(el.value)
    return true
  })
  Object.defineProperty(document, 'execCommand', { value: exec, configurable: true, writable: true })
  return copied
}

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
  delete (navigator as { clipboard?: unknown }).clipboard
  delete (document as { execCommand?: unknown }).execCommand
})

describe('JS Recon secret copy button', () => {
  test('copies the full value over plain http, where the Clipboard API is missing', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true })
    installFetch()
    const copied = stubExecCommand()
    render(<JsReconTable projectId="proj-1" search="" />, { wrapper: makeWrapper() })

    const btn = await screen.findByTitle('Copy full value')
    await act(async () => { fireEvent.click(btn) })

    expect(copied).toEqual([FULL_VALUE])
    await waitFor(() => expect(btn.querySelector('svg.lucide-check')).not.toBeNull())
    expect(document.querySelector('body > textarea')).toBeNull()
  })

  test('uses the Clipboard API where it exists', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    installFetch()
    render(<JsReconTable projectId="proj-1" search="" />, { wrapper: makeWrapper() })

    const btn = await screen.findByTitle('Copy full value')
    await act(async () => { fireEvent.click(btn) })

    expect(writeText).toHaveBeenCalledWith(FULL_VALUE)
    await waitFor(() => expect(btn.querySelector('svg.lucide-check')).not.toBeNull())
  })

  test('a TruffleHog-only row copies its full value the same way', async () => {
    // Built in parts so no key-shaped literal sits in the repository.
    const value = ['ghp', '_', 'x'.repeat(36)].join('')
    DATA.secrets.push({ nodeId: '102', id: 's2', severity: 'high', name: 'GitHub Token Classic', redacted_value: 'ghp_xx...xxxx',
      matched_text: value, category: 'vcs', source_url: 'https://a.invalid/app.js',
      detection_method: 'trufflehog', confidence: 0.5, validation: { status: 'unknown' } })
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    installFetch()
    try {
      render(<JsReconTable projectId="proj-1" search="" />, { wrapper: makeWrapper() })
      const buttons = await screen.findAllByTitle('Copy full value')
      expect(buttons).toHaveLength(2)
      const row = (await screen.findByText('TruffleHog')).closest('tr')!
      await act(async () => { fireEvent.click(row.querySelector('button[title="Copy full value"]')!) })
      expect(writeText).toHaveBeenCalledWith(value)
    } finally {
      DATA.secrets.pop()
    }
  })
})
