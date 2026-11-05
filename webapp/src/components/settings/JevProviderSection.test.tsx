import { afterEach, describe, expect, test, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { isChatProvider, isJevProvider } from '@/lib/llmProviderKinds'
import { JevProviderSection } from './JevProviderSection'
import type { ProviderData } from './LlmProviderForm'

vi.mock('./LlmProviderForm', () => ({
  LlmProviderForm: ({ provider, onSave, onCancel, onDirtyChange }: {
    provider: ProviderData | null; onSave: () => void; onCancel: () => void; onDirtyChange: (dirty: boolean) => void
  }) => <div>
    <span>{provider?.name ?? 'New configuration'}</span>
    <button onClick={() => onDirtyChange(true)}>Edit name</button>
    <button onClick={onSave}>Save</button>
    <button onClick={onCancel}>Cancel</button>
  </div>,
}))

afterEach(cleanup)
const rows = [
  { id: 'direct', name: 'Direct staging', providerType: 'jev', apiKey: '••••abcd', modelIdentifier: 'jev-1.13.0' },
  { id: 'router', name: 'OpenRouter staging', providerType: 'jev_openrouter', apiKey: '••••efgh', modelIdentifier: 'typesafe/jev-1.13' },
] as ProviderData[]
const props = () => ({
  userId: 'synthetic-owner', providers: rows, loading: false, error: false,
  onRetry: vi.fn(), formOpen: false, editingProvider: null,
  onOpenForm: vi.fn(), onFormDone: vi.fn(), onDelete: vi.fn(), onDirtyChange: vi.fn(),
})

describe('Jev-only configuration list', () => {
  test('both Jev types remain non-chat while ordinary OpenRouter stays chat', () => {
    expect(rows.every(isJevProvider)).toBe(true)
    expect(rows.some(isChatProvider)).toBe(false)
    expect(isChatProvider({ providerType: 'openrouter' })).toBe(true)
    expect(isJevProvider({ providerType: 'openrouter' })).toBe(false)
  })
  test('each named row gets its own usage chip, edit/delete actions, and Add stays available', () => {
    const p = props()
    render(<JevProviderSection {...p} usageChip={row => <span>Usage {row.id}</span>} />)
    expect(screen.getByText('Usage direct')).toBeInTheDocument()
    expect(screen.getByText('Usage router')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Edit Jev provider OpenRouter staging' }))
    expect(p.onOpenForm).toHaveBeenCalledWith(rows[1])
    fireEvent.click(screen.getByRole('button', { name: 'Delete Jev provider Direct staging' }))
    expect(p.onDelete).toHaveBeenCalledWith('direct')
    fireEvent.click(screen.getByRole('button', { name: 'Add Jev provider' }))
    expect(p.onOpenForm).toHaveBeenLastCalledWith(null)
  })
  test('editing delegates dirty tracking and save/cancel outcomes', () => {
    const p = props()
    render(<JevProviderSection {...p} formOpen editingProvider={rows[1]} />)
    fireEvent.click(screen.getByText('Edit name'))
    expect(p.onDirtyChange).toHaveBeenCalledWith(true)
    fireEvent.click(screen.getByText('Save'))
    fireEvent.click(screen.getByText('Cancel'))
    expect(p.onFormDone.mock.calls).toEqual([[true], [false]])
  })
  test('lookup failure never renders stale rows or add actions', () => {
    const p = props()
    render(<JevProviderSection {...p} error errorText="Lookup failed (P1001 · HTTP 500)" />)
    expect(screen.getByRole('alert')).toHaveTextContent('P1001')
    expect(screen.queryByText('Direct staging')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add Jev provider' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(p.onRetry).toHaveBeenCalledTimes(1)
  })
})
