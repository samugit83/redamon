/**
 * JS Recon's TruffleHog controls in "Key Validation": the toggle, the
 * result-class checkboxes, and what each availability answer does to them.
 *
 * The toggle locks only when the image is known to be missing, and never locks
 * an already-on project into on; an orchestrator that did not answer says
 * nothing about the image, so the toggle stays usable with a notice. The
 * checkboxes filter TruffleHog's verification verdicts, so they are inert when
 * key validation is off, whether the person turned it off or stealth did.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/sections/JsReconSection.trufflehog.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within, waitFor } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { JsReconSection, TRUFFLEHOG_IMAGE_MISSING, TRUFFLEHOG_RESULT_OPTIONS } from './JsReconSection'
import { field } from '@/lib/reconSettings/registry'

const AVAILABLE_URL = '/api/js-recon/trufflehog/available'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

let answer: () => Promise<Response>
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  answer = async () => json(200, { available: true, reason: null })
  fetchMock = vi.fn(async (input: string | URL | Request) => {
    const url = typeof input === 'string' ? input : input.toString()
    return url === AVAILABLE_URL ? answer() : json(404, { error: 'not found' })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function renderSection(overrides: Record<string, unknown> = {}) {
  const updateField = vi.fn()
  render(
    <JsReconSection
      data={{ jsReconEnabled: true, stealthMode: false, ...overrides } as never}
      updateField={updateField as never}
    />,
  )
  return { updateField }
}

const toggle = () => screen.getByRole('switch', { name: 'Run TruffleHog' })
const resultsGroup = () => screen.getByRole('group', { name: 'Keep TruffleHog-only keys that are' })
const box = (label: RegExp) => within(resultsGroup()).getByRole('checkbox', { name: label })
const answered = () => waitFor(() => expect(fetchMock).toHaveBeenCalledWith(AVAILABLE_URL))

describe('availability', () => {
  test('while the check is pending the toggle is usable', () => {
    answer = () => new Promise<Response>(() => {})
    const { updateField } = renderSection()
    expect(toggle()).not.toBeDisabled()
    // A project saved before the field existed reads the default: on.
    expect(toggle()).toBeChecked()
    fireEvent.click(toggle())
    expect(updateField).toHaveBeenCalledWith('jsReconTrufflehogEnabled', false)
  })

  test('installed: usable, no notice', async () => {
    renderSection()
    await answered()
    expect(toggle()).not.toBeDisabled()
    expect(screen.queryByText(/Could not check whether the TruffleHog image is installed/)).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('image missing on a project with it off: disabled, the tooltip says how to install it', async () => {
    answer = async () => json(200, { available: false, reason: 'image_missing' })
    const { updateField } = renderSection({ jsReconTrufflehogEnabled: false })
    await waitFor(() => expect(toggle()).toBeDisabled())
    expect(toggle().closest('span[title]')).toHaveAttribute('title', TRUFFLEHOG_IMAGE_MISSING)
    expect(TRUFFLEHOG_IMAGE_MISSING).toBe('TruffleHog image not installed: run ./redamon.sh update')
    fireEvent.click(toggle())
    expect(updateField).not.toHaveBeenCalled()
  })

  test('image missing on a project with it on: kept on, warned, and it can still be turned off', async () => {
    answer = async () => json(200, { available: false, reason: 'image_missing' })
    const { updateField } = renderSection({ jsReconTrufflehogEnabled: true })
    const warning = await screen.findByRole('alert')
    expect(warning).toHaveTextContent(TRUFFLEHOG_IMAGE_MISSING)
    expect(toggle()).toHaveAttribute('aria-checked', 'true')
    expect(toggle()).not.toBeDisabled()
    expect(updateField).not.toHaveBeenCalled()
    fireEvent.click(toggle())
    expect(updateField).toHaveBeenCalledWith('jsReconTrufflehogEnabled', false)
  })

  test.each(['orchestrator_unreachable', 'orchestrator_timeout', 'orchestrator_error'])(
    '%s: usable, with a one-line notice that names the reason',
    async (reason) => {
      answer = async () => json(200, { available: false, reason })
      renderSection()
      const notice = await screen.findByText(/Could not check whether the TruffleHog image is installed/)
      expect(notice).toHaveTextContent(reason)
      expect(toggle()).not.toBeDisabled()
      expect(screen.queryByRole('alert')).toBeNull()
    },
  )

  test('a refused availability request reads as unknown, not as missing', async () => {
    answer = async () => json(401, { error: 'Unauthorized' })
    renderSection()
    expect(await screen.findByText(/Could not check whether the TruffleHog image is installed/)).toHaveTextContent('HTTP 401')
    expect(toggle()).not.toBeDisabled()
  })

  test('JS Recon off: no availability request', () => {
    renderSection({ jsReconEnabled: false })
    expect(fetchMock).not.toHaveBeenCalledWith(AVAILABLE_URL)
  })
})

describe('result classes', () => {
  test('hidden while TruffleHog is off', async () => {
    renderSection({ jsReconTrufflehogEnabled: false })
    await answered()
    expect(screen.queryByRole('group', { name: 'Keep TruffleHog-only keys that are' })).toBeNull()
  })

  test('the options are the registry\'s closed values, never a text box', () => {
    const spec = field('jsReconTrufflehogResults')!
    expect(TRUFFLEHOG_RESULT_OPTIONS.map(o => o.value)).toEqual(spec.values)
    renderSection({ jsReconTrufflehogEnabled: true })
    expect(within(resultsGroup()).getAllByRole('checkbox')).toHaveLength(3)
    expect(within(resultsGroup()).queryByRole('textbox')).toBeNull()
  })

  test('a project saved before the field shows the default, and a change writes from it', () => {
    expect(field('jsReconTrufflehogResults')!.default).toEqual(['verified', 'unknown', 'unverified'])
    const { updateField } = renderSection({ jsReconTrufflehogEnabled: true })
    for (const label of [/^Verified/, /^Unknown/, /^Unverified/]) expect(box(label)).toBeChecked()
    fireEvent.click(box(/^Unknown/))
    expect(updateField).toHaveBeenCalledWith('jsReconTrufflehogResults', ['verified', 'unverified'])
  })

  test('ticking writes the registry order, whatever order was clicked', () => {
    const { updateField } = renderSection({ jsReconTrufflehogEnabled: true, jsReconTrufflehogResults: ['unverified'] })
    fireEvent.click(box(/^Verified/))
    expect(updateField).toHaveBeenCalledWith('jsReconTrufflehogResults', ['verified', 'unverified'])
  })

  test('an empty list says it keeps all three', () => {
    renderSection({ jsReconTrufflehogEnabled: true, jsReconTrufflehogResults: [] })
    for (const label of [/^Verified/, /^Unknown/, /^Unverified/]) expect(box(label)).not.toBeChecked()
    expect(screen.getByText(/Nothing ticked keeps all three/)).toBeInTheDocument()
  })

  test('usable while key validation is on', () => {
    renderSection({ jsReconTrufflehogEnabled: true, jsReconValidateKeys: true })
    for (const el of within(resultsGroup()).getAllByRole('checkbox')) expect(el).not.toBeDisabled()
    expect(screen.queryByText(/TruffleHog checks no key then/)).toBeNull()
  })

  test('disabled with a hint when Validate Discovered Keys is off', () => {
    renderSection({ jsReconTrufflehogEnabled: true, jsReconValidateKeys: false })
    for (const el of within(resultsGroup()).getAllByRole('checkbox')) expect(el).toBeDisabled()
    expect(screen.getByText(/Ignored while Validate Discovered Keys is off: TruffleHog checks no key then/)).toBeInTheDocument()
  })

  test('disabled with a stealth hint when stealth forces validation off', () => {
    // The stored toggle is still on; the registry's stealth rule turns it off at scan time.
    expect(field('jsReconValidateKeys')!.stealth).toEqual({ set: false })
    renderSection({ jsReconTrufflehogEnabled: true, jsReconValidateKeys: true, stealthMode: true })
    for (const el of within(resultsGroup()).getAllByRole('checkbox')) expect(el).toBeDisabled()
    expect(screen.getByText(/Ignored in stealth mode, which turns key validation off/)).toBeInTheDocument()
    expect(screen.getByText(/Stealth mode turns key validation off/)).toBeInTheDocument()
  })

  test('the group wraps instead of scrolling on a narrow screen', () => {
    // jsdom has no layout; what makes it wrap at 375 px is the flex-wrap rule.
    renderSection({ jsReconTrufflehogEnabled: true })
    expect(resultsGroup().className).toContain('checkboxGroup')
    const css = readFileSync(join(__dirname, '../ProjectForm.module.css'), 'utf8')
    expect(css).toMatch(/\.checkboxGroup\s*\{[^}]*flex-wrap:\s*wrap/)
  })
})

describe('wording', () => {
  test('says TruffleHog scans local copies, and what validation changes', () => {
    renderSection()
    const text = toggle().closest(`.toggleRow`)!.textContent!
    expect(text).toMatch(/local copies/)
    expect(text).toMatch(/never with a host named in the JavaScript/)
    expect(text).toMatch(/with key validation off its\s+container has no network/)
  })
})
