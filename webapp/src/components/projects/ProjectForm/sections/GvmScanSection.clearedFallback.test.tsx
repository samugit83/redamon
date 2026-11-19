/**
 * The GVM timing inputs: a cleared box saves the shipped default, a typed 0 saves 0.
 *
 * The task timeout used to fall back to 0, which GVM reads as "no limit", so
 * clearing the box removed the cap instead of restoring the four-hour default.
 * The fix must not swing the other way: 0 is a value an operator may choose on
 * purpose, and a `|| default` fallback would silently replace it.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { GvmScanSection } from './GvmScanSection'
import { field } from '@/lib/reconSettings/registry'

afterEach(cleanup)

function renderInput(label: string) {
  const updateField = vi.fn()
  render(
    <GvmScanSection
      data={{ gvmTaskTimeout: 600, gvmPollInterval: 60 } as never}
      updateField={updateField as never}
    />,
  )
  const input = screen.getByText(label).parentElement!.querySelector('input')!
  return { updateField, input }
}

const writesOf = (updateField: ReturnType<typeof vi.fn>, key: string) =>
  updateField.mock.calls.filter(([k]) => k === key).map(([, v]) => v)

describe('the GVM task timeout input', () => {
  test('a cleared box saves the shipped default, not unlimited', () => {
    const { updateField, input } = renderInput('Task Timeout (seconds)')
    fireEvent.change(input, { target: { value: '' } })
    expect(writesOf(updateField, 'gvmTaskTimeout')).toEqual([field('gvmTaskTimeout')!.default])
    expect(field('gvmTaskTimeout')!.default).toBe(14400)
  })

  test('a typed 0 is kept: it is the unlimited setting', () => {
    const { updateField, input } = renderInput('Task Timeout (seconds)')
    fireEvent.change(input, { target: { value: '0' } })
    expect(writesOf(updateField, 'gvmTaskTimeout')).toEqual([0])
  })
})

describe('the GVM poll interval input', () => {
  test('a cleared box saves the shipped default', () => {
    const { updateField, input } = renderInput('Poll Interval (seconds)')
    fireEvent.change(input, { target: { value: '' } })
    expect(writesOf(updateField, 'gvmPollInterval')).toEqual([field('gvmPollInterval')!.default])
  })
})
