/**
 * A secret in the UI: its last four characters, a copy button that copies all
 * of it, and nothing more anywhere in the markup (no tooltip, no attribute).
 * Run: npx vitest run src/components/ui/SecretValue/SecretValue.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { cleanup, render, screen, fireEvent, waitFor } from '@testing-library/react'

const copied: string[] = []
vi.mock('@/lib/copyText', () => ({
  copyText: (text: string) => { copied.push(text); return Promise.resolve() },
}))

import { SecretValue } from './SecretValue'
import { secretTail } from '@/lib/secrets/secretTail'

const KEY = 'AKIAQ7R2M9X4K1T8B3V6'

beforeEach(() => { copied.length = 0 })
afterEach(cleanup)

describe('secretTail', () => {
  test('four dots and the last four characters', () => {
    expect(secretTail(KEY)).toBe('••••B3V6')
  })
  test('a value of four characters or fewer shows the dots only', () => {
    expect(secretTail('abcd')).toBe('••••')
    expect(secretTail('a')).toBe('••••')
  })
  test('nothing for nothing', () => {
    expect(secretTail('')).toBe('')
    expect(secretTail(null)).toBe('')
  })
})

describe('SecretValue', () => {
  test('shows the last four characters and never the rest', () => {
    const { container } = render(<SecretValue value={KEY} />)
    expect(screen.getByText('••••B3V6')).toBeTruthy()
    expect(container.innerHTML).not.toContain('AKIAQ7R2')
  })

  test('the copy button copies the full value', async () => {
    render(<SecretValue value={KEY} />)
    fireEvent.click(screen.getByTitle('Copy full value'))
    await waitFor(() => expect(copied).toEqual([KEY]))
    await waitFor(() => expect(screen.getByTitle('Copied')).toBeTruthy())
  })

  test('a label names the value', () => {
    render(<SecretValue label="secret" value={KEY} />)
    expect(screen.getByText('secret')).toBeTruthy()
  })

  test('no value shows the empty mark and no button', () => {
    render(<SecretValue value={null} />)
    expect(screen.getByText('-')).toBeTruthy()
    expect(screen.queryByTitle('Copy full value')).toBeNull()
  })

  test('the click does not reach the row behind it', () => {
    const onRow = vi.fn()
    render(<div onClick={onRow}><SecretValue value={KEY} /></div>)
    fireEvent.click(screen.getByTitle('Copy full value'))
    expect(onRow).not.toHaveBeenCalled()
  })
})
