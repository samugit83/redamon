/**
 * Every state a card shows (D-14): queued, cancelling, failed with its code, cancelled, done, disabled.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { ResourceCard } from './ResourceCard'
import { RESOURCE, job } from './__testing__/resourceView'

const h = { userId: 'user-1', onRefresh: vi.fn(), onCancel: vi.fn(), onEdit: vi.fn(), onDelete: vi.fn(), onToggleEnabled: vi.fn() }
afterEach(cleanup)

describe('ResourceCard states', () => {
  test.each([
    ['queued', job({ status: 'queued' }), 'Queued'],
    ['cancelling', job({ status: 'running', stage: 'store', cancelRequested: true }), 'Cancelling…'],
    ['failed', job({ status: 'failed', errorCode: 'fetch_failed' }), 'Failed (fetch_failed): the previous version is kept'],
    ['lost', job({ status: 'failed', errorCode: 'agent_lost' }), 'Failed (agent_lost): the previous version is kept'],
    ['cancelled', job({ status: 'cancelled', errorCode: 'cancelled' }), 'Cancelled: the previous version is kept'],
  ])('%s', (_name, j, text) => {
    render(<ResourceCard resource={{ ...RESOURCE, job: j }} {...h} />)
    expect(screen.getByRole('status')).toHaveTextContent(text)
  })

  test('a job that succeeded shows no status line, the report does', () => {
    render(<ResourceCard resource={{ ...RESOURCE, job: job({ status: 'succeeded' }), report: { visited: 40, kept: 31, stopReason: 'frontier_empty' } as never }} {...h} />)
    expect(screen.queryByRole('status')).toBeNull()
    expect(screen.getByTestId('tc-report')).toHaveTextContent('40 visited, 31 kept, stopped: frontier_empty')
  })

  test('a cancel already asked cannot be asked twice', () => {
    render(<ResourceCard resource={{ ...RESOURCE, job: job({ cancelRequested: true }) }} {...h} />)
    expect(screen.getByRole('button', { name: /Cancel/ })).toBeDisabled()
  })

  test('a busy card (its Refresh sent) cannot send another', () => {
    render(<ResourceCard resource={RESOURCE} busy {...h} />)
    expect(screen.getByRole('button', { name: /Refresh/ })).toBeDisabled()
  })

  test('Live or Stored, the count, a disabled resource dimmed, Edit locked while a job runs', () => {
    const { container } = render(<ResourceCard resource={{ ...RESOURCE, storageMode: 'stored', enabled: false, job: job({}) }} {...h} />)
    expect(screen.getByText('Stored')).toBeInTheDocument()
    expect(screen.getByText('12 entries')).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Enabled: Lab Wiki' })).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByRole('button', { name: 'Edit Lab Wiki' })).toBeDisabled()
    expect(container.firstElementChild?.className).toMatch(/cardDisabled/)
  })
})
