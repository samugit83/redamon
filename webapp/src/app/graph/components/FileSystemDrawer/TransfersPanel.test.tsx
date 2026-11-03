/**
 * The transfers panel's lines for a website mirror: counts while it crawls,
 * then why it stopped.
 *
 * Run: npx vitest run src/app/graph/components/FileSystemDrawer/TransfersPanel.test.tsx
 */

import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { TransfersPanel } from './TransfersPanel'
import { jobFailureMessage } from './transferMessages'
import type { Transfer } from './useTransfers'

afterEach(cleanup)

function transfer(over: Partial<Transfer>): Transfer {
  return {
    id: 't1', projectId: 'p1', kind: 'import', name: 'docs.example.test', destDir: 'uploads', status: 'processing',
    sentBytes: 0, totalBytes: 0, waiting: false, jobId: 'a'.repeat(32), ...over,
  }
}

function renderPanel(t: Transfer) {
  render(<TransfersPanel transfers={[t]} onCancel={vi.fn()} onDismiss={vi.fn()} onOpen={vi.fn()} />)
}

describe('TransfersPanel: website mirrors', () => {
  test('crawl progress shows pages, assets and bytes', () => {
    renderPanel(transfer({ phase: 'crawling', pages: 12, assets: 1, bytes: 2048 }))
    expect(screen.getByText('Crawling')).toBeInTheDocument()
    expect(screen.getByText('12 pages · 1 asset · 2.0K')).toBeInTheDocument()
  })

  test('a mirror that hit a limit says so; a complete one does not', () => {
    renderPanel(transfer({ status: 'done', savedPath: 'uploads/docs.example.test', stoppedBecause: 'max_pages' }))
    expect(screen.getByText('Stopped at the page limit')).toBeInTheDocument()
    cleanup()
    renderPanel(transfer({ status: 'done', savedPath: 'uploads/docs.example.test', stoppedBecause: 'complete' }))
    expect(screen.queryByText(/^Stopped/)).not.toBeInTheDocument()
  })

  test('mirror failure codes have sentences', () => {
    for (const code of ['hard_blocked', 'roe_excluded', 'roe_outside_window', 'robots_disallowed',
      'robots_unavailable', 'nothing_saved', 'invalid_option']) {
      const message = jobFailureMessage(code)
      expect(message).toContain(`(${code})`)
      expect(message).not.toMatch(/^The transfer failed on the server/)
    }
  })
})
