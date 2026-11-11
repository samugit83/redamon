/**
 * naabu's run timeout is a form input bound to `naabuRunTimeout` (R-9).
 *
 * The run timeout was a hardcoded 1800 s in run_port_scan; it is now a project
 * setting, so the form must reach it (parity with MCP), fall back to the shipped
 * default when cleared, and offer no value the save would refuse.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/sections/NaabuSection.runTimeout.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { NaabuSection } from './NaabuSection'
import { field } from '@/lib/reconSettings/registry'

afterEach(cleanup)

function renderSection(naabuRunTimeout?: number) {
  const updateField = vi.fn()
  render(
    <NaabuSection
      data={{ naabuEnabled: true, naabuRunTimeout } as never}
      updateField={updateField as never}
    />,
  )
  const input = screen.getByText('Run Timeout (s)').parentElement!.querySelector('input')!
  return { updateField, input }
}

const writes = (updateField: ReturnType<typeof vi.fn>) =>
  updateField.mock.calls.filter(([key]) => key === 'naabuRunTimeout').map(([, value]) => value)

describe('the naabu run timeout input', () => {
  test('shows the stored value', () => {
    const { input } = renderSection(3600)
    expect(input.value).toBe('3600')
  })

  test('a project saved before the column existed shows the shipped default', () => {
    const { input } = renderSection(undefined)
    expect(Number(input.value)).toBe(field('naabuRunTimeout')!.default)
  })

  test('a typed number is stored as typed', () => {
    const { updateField, input } = renderSection(1800)
    fireEvent.change(input, { target: { value: '7200' } })
    expect(writes(updateField)).toEqual([7200])
  })

  test('a cleared input falls back to the shipped default, 1800 s', () => {
    const { updateField, input } = renderSection(600)
    fireEvent.change(input, { target: { value: '' } })
    expect(writes(updateField)).toEqual([1800])
    expect(field('naabuRunTimeout')!.default).toBe(1800)
  })

  test('the input bounds are the registry bounds', () => {
    const { input } = renderSection(1800)
    const { bounds } = field('naabuRunTimeout')!
    expect([Number(input.min), Number(input.max)]).toEqual([bounds!.min, bounds!.max])
  })

  test('the hint says it caps the whole run and what a cut run keeps', () => {
    renderSection(1800)
    const hint = screen.getByText(/Cap on the whole naabu run/)
    expect(hint.textContent).toMatch(/open ports found so far are kept/)
    expect(hint.textContent).toMatch(/not checked/)
  })
})
