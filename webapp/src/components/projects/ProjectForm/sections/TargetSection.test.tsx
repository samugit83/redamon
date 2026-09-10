/**
 * Strategy row 6: the Domain batch group preview must agree with what is saved.
 *
 * The preview is the ONLY place the grouping rule (last two labels) is visible to
 * an operator, and it is what they approve before the scan runs. If it disagrees
 * with the persisted grouping, or if the input cannot be typed into, the feature's
 * central promise ("you see exactly what will run, in order") is broken.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/TargetSection.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'
import { TargetSection } from './TargetSection'
import { groupHostsByRootDomain } from '@/lib/domainBatch'

vi.mock('@/components/shared/ModelPicker', () => ({ ModelPicker: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))

afterEach(cleanup)

type Data = Record<string, unknown>

const BASE: Data = {
  name: '', description: '', targetDomain: '', subdomainList: [],
  ipMode: false, targetIps: [], domainBatchMode: true, domainBatchHosts: [],
  subdomainDiscoveryEnabled: true, aiInPipeline: false, verifyDomainOwnership: false,
  ownershipToken: '', ownershipTxtPrefix: '', aiPipelineModel: '',
}

/** Renders with live state so a change event feeds the next render, as in the form. */
function renderSection(initial: Partial<Data> = {}) {
  let data: Data = { ...BASE, ...initial }
  const updateField = vi.fn((k: string, v: unknown) => { data[k] = v; rerender() })
  const view = render(<TargetSection data={data as never} updateField={updateField as never} mode="create" />)
  function rerender() {
    view.rerender(<TargetSection data={{ ...data } as never} updateField={updateField as never} mode="create" />)
  }
  return { get data() { return data }, updateField, textarea: () => screen.getByPlaceholderText(/sub1\.domain1\.com/) }
}

describe('the hostname input accepts a multi-line list', () => {
  test('a newline can be typed (the list is editable at all)', () => {
    // Regression: the textarea's value was derived from the PARSED array, so any
    // separator the user typed was stripped on the next render and a second host
    // could never be entered.
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: 'a.example.com\n' } })
    expect((s.textarea() as HTMLTextAreaElement).value).toBe('a.example.com\n')
  })

  test('a second host on a new line survives', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: 'a.example.com\nb.other.com' } })
    expect((s.textarea() as HTMLTextAreaElement).value).toBe('a.example.com\nb.other.com')
    expect(s.data.domainBatchHosts).toEqual(['a.example.com', 'b.other.com'])
  })

  test('a trailing space mid-typing is not swallowed', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: 'a.example.com ' } })
    expect((s.textarea() as HTMLTextAreaElement).value).toBe('a.example.com ')
  })
})

describe('the preview matches the grouping that will be persisted', () => {
  const HOSTS = 'sub1.domain1.com\nsub2.domain2.it\nsub3.domain3.com\nsuba.sub3.domain3.com'

  test('groups render in run order', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: HOSTS } })

    const rows = screen.getAllByRole('row').slice(1) // drop the header
    const domains = rows.map(r => within(r).getAllByRole('cell')[1].textContent)
    expect(domains).toEqual(['domain1.com', 'domain2.it', 'domain3.com'])
  })

  test('the rendered groups equal groupHostsByRootDomain, the helper the server uses', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: HOSTS } })

    const expected = groupHostsByRootDomain(s.data.domainBatchHosts as string[]).groups
    const rows = screen.getAllByRole('row').slice(1)
    expect(rows.map(r => within(r).getAllByRole('cell')[1].textContent))
      .toEqual(expected.map(g => g.rootDomain))
    expect(rows.map(r => within(r).getAllByRole('cell')[2].textContent))
      .toEqual(expected.map(g => g.hosts.join(', ')))
  })

  test('a deep subdomain joins its domain group rather than starting a new one', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: HOSTS } })
    expect(screen.getAllByRole('row').slice(1)).toHaveLength(3)
    expect(screen.getByText('sub3.domain3.com, suba.sub3.domain3.com')).toBeTruthy()
  })

  test('an invalid entry is flagged and not silently grouped', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: 'good.example.com\nlocalhost' } })
    // The warning text is split across nodes, so match on the container's text.
    // getByText matches the <strong> label; the offending entry is its sibling text.
    const label = screen.getByText(/Not valid hostnames/)
    expect(label.parentElement?.textContent).toContain('localhost')
  })

  test('a permanently blocked root is called out before submit', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: 'ok.example.com\nwww.whitehouse.gov' } })
    expect(screen.getByText(/permanently blocked/i)).toBeTruthy()
  })

  test('the counts shown are the real host and group counts', () => {
    const s = renderSection()
    fireEvent.change(s.textarea(), { target: { value: HOSTS } })
    const hint = screen.getAllByText((_t, el) => /\d+ hostnames?/.test(el?.textContent ?? '')).at(-1)!
    expect(hint.textContent).toMatch(/4 hostnames/)
    expect(hint.textContent).toMatch(/3 domains/)
  })
})

describe('mode switching', () => {
  test('choosing Domain batch clears the single-domain target', () => {
    const s = renderSection({ domainBatchMode: false, targetDomain: 'old.example.com' })
    fireEvent.click(screen.getByText('Domain batch'))
    expect(s.data.domainBatchMode).toBe(true)
    expect(s.data.targetDomain).toBe('')
  })

  test('leaving Domain batch clears the host list', () => {
    const s = renderSection({ domainBatchHosts: ['a.example.com'] })
    fireEvent.click(screen.getByText('IP / CIDR'))
    expect(s.data.ipMode).toBe(true)
    expect(s.data.domainBatchMode).toBe(false)
    expect(s.data.domainBatchHosts).toEqual([])
  })
})
