/**
 * The GraphQL rate input stores what the person typed, 0 included (R-7).
 *
 * `0` means unlimited for this field (registry `zero_means: unlimited`, and the
 * hint under the input says so), but `parseInt(value) || 10` read a typed 0 as
 * "empty" and saved 10: the form could not store the value its own hint
 * describes. A cleared input still falls back to the default.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/sections/GraphqlScanSection.rateLimit.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { GraphqlScanSection } from './GraphqlScanSection'
import { field } from '@/lib/reconSettings/registry'

afterEach(cleanup)

function renderSection(graphqlRateLimit: number) {
  const updateField = vi.fn()
  render(
    <GraphqlScanSection
      data={{ graphqlSecurityEnabled: true, graphqlRateLimit } as never}
      updateField={updateField as never}
    />,
  )
  const input = screen.getByText('Rate Limit (req/s)').parentElement!.querySelector('input')!
  return { updateField, input }
}

const rateWrites = (updateField: ReturnType<typeof vi.fn>) =>
  updateField.mock.calls.filter(([key]) => key === 'graphqlRateLimit').map(([, value]) => value)

describe('the GraphQL rate input', () => {
  test('a typed 0 is stored as 0, not replaced by the default', () => {
    const { updateField, input } = renderSection(10)
    fireEvent.change(input, { target: { value: '0' } })
    expect(rateWrites(updateField)).toEqual([0])
  })

  test('a typed number is stored as typed', () => {
    const { updateField, input } = renderSection(10)
    fireEvent.change(input, { target: { value: '7' } })
    expect(rateWrites(updateField)).toEqual([7])
  })

  test('a cleared input falls back to the shipped default', () => {
    const { updateField, input } = renderSection(5)
    fireEvent.change(input, { target: { value: '' } })
    expect(rateWrites(updateField)).toEqual([field('graphqlRateLimit')!.default])
  })

  test('0 is a value the registry accepts, so the save will not refuse it', () => {
    expect(field('graphqlRateLimit')).toMatchObject({ zero_means: 'unlimited', bounds: { min: 0 } })
  })
})
