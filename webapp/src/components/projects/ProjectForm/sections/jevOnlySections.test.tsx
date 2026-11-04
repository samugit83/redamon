/**
 * The Jev-only hook controls in the tool sections.
 *
 * Each hook's switch lives in two places bound to one field: the AI in Pipeline
 * panel and the tool's own section, which is where partial-recon users reach a
 * tool's settings. This locks in that each section's control writes its own
 * field, shows the stored value, and is disabled until AI in Pipeline is on.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/jevOnlySections.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within, waitFor } from '@testing-library/react'
import { FfufSection } from './FfufSection'
import { JevSelectionProvider } from '@/hooks/useHasJevProvider'
import { HttpxSection } from './HttpxSection'
import { HakrawlerSection } from './HakrawlerSection'
import { ResourceEnumAiSection } from './ResourceEnumAiSection'
import { SerializedScanSection } from './SerializedScanSection'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))

type Data = Record<string, unknown>

const CASES = [
  { name: 'FfufSection', Section: FfufSection, field: 'ffufJevBasePaths', extra: { ffufEnabled: true, ffufSmartFuzz: true } },
  { name: 'HttpxSection', Section: HttpxSection, field: 'httpxJevPageType', extra: { httpxEnabled: true } },
  { name: 'HakrawlerSection', Section: HakrawlerSection, field: 'hakrawlerJevSeedOrder', extra: { hakrawlerEnabled: true } },
  { name: 'ResourceEnumAiSection', Section: ResourceEnumAiSection, field: 'resourceEnumJevToolHealth', extra: {} },
  { name: 'SerializedScanSection', Section: SerializedScanSection, field: 'serializedScanJevRank',
    extra: { serializedScanEnabled: true, captureProxyEnabled: true } },
] as const

function mount(Section: (typeof CASES)[number]['Section'], data: Data) {
  const updateField = vi.fn()
  render(<JevSelectionProvider ownerUserId="u1" selectedProviderId={typeof data.jevProviderId === 'string' ? data.jevProviderId : null}>
    <Section data={data as never} updateField={updateField as never} mode="create" />
  </JevSelectionProvider>)
  const group = screen.getByRole('group', { name: 'Jev hook' })
  return { updateField, off: within(group).getByRole('button', { name: 'Off' }),
           jev: within(group).getByRole('button', { name: 'Jev' }) }
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true, status: 200,
    json: async () => [{ id: 'j', name: 'Synthetic Jev', providerType: 'jev', apiKey: '••••c0de', modelIdentifier: 'jev-1.13.0' }],
  })))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe.each(CASES)('$name', ({ Section, field, extra }) => {
  test('the control writes its own field', async () => {
    const { jev, updateField } = mount(Section, { aiInPipeline: true, jevProviderId: 'j', [field]: false, ...extra })
    await waitFor(() => expect(jev).toBeEnabled())
    fireEvent.click(jev)
    expect(updateField).toHaveBeenCalledWith(field, true)
  })

  test('legacy null selection does not enable Jev even when account credentials exist', async () => {
    const { jev, updateField } = mount(Section, { aiInPipeline: true, jevProviderId: null, [field]: false, ...extra })
    await waitFor(() => expect(jev).toHaveAttribute('title', expect.stringContaining('Select a Jev provider')))
    expect(jev).toBeDisabled()
    fireEvent.click(jev)
    expect(updateField).not.toHaveBeenCalled()
  })

  test('it shows the stored value', () => {
    const { jev, off } = mount(Section, { aiInPipeline: true, [field]: true, ...extra })
    expect(jev).toHaveAttribute('aria-pressed', 'true')
    expect(off).toHaveAttribute('aria-pressed', 'false')
  })

  test('it is disabled until AI in Pipeline is on, and says so', () => {
    const { jev, off } = mount(Section, { aiInPipeline: false, [field]: false, ...extra })
    expect(jev).toBeDisabled()
    expect(off).toBeDisabled()
    expect(jev).toHaveAttribute('title', 'Enable "AI in Pipeline" in the Target tab to turn this on.')
  })
})
