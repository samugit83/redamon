/**
 * The nmap Parallelism input falls back to the shipped default, 5.
 *
 * Prisma, DEFAULT_SETTINGS and the registry all say 5; the input showed 2 for a
 * project without the value and saved 2 when it was cleared, so the form
 * quietly ran nmap at less than half the default parallelism.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/sections/NmapSection.parallelism.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { NmapSection } from './NmapSection'
import { field } from '@/lib/reconSettings/registry'

afterEach(cleanup)

const DEFAULT = field('nmapParallelism')!.default

function renderSection(nmapParallelism: number | undefined) {
  const updateField = vi.fn()
  render(
    <NmapSection
      data={{ nmapEnabled: true, nmapParallelism } as never}
      updateField={updateField as never}
    />,
  )
  const input = screen.getByText('Parallelism').parentElement!.querySelector('input')!
  return { updateField, input }
}

const parallelismWrites = (updateField: ReturnType<typeof vi.fn>) =>
  updateField.mock.calls.filter(([key]) => key === 'nmapParallelism').map(([, value]) => value)

describe('the nmap Parallelism input', () => {
  test('the shipped default is 5', () => {
    expect(DEFAULT).toBe(5)
  })

  test('a project without the value shows the shipped default', () => {
    const { input } = renderSection(undefined)
    expect(input.value).toBe(String(DEFAULT))
  })

  test('a cleared input falls back to the shipped default', () => {
    const { updateField, input } = renderSection(3)
    fireEvent.change(input, { target: { value: '' } })
    expect(parallelismWrites(updateField)).toEqual([DEFAULT])
  })

  test('a typed number is stored as typed', () => {
    const { updateField, input } = renderSection(5)
    fireEvent.change(input, { target: { value: '7' } })
    expect(parallelismWrites(updateField)).toEqual([7])
  })
})
