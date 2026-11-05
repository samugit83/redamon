/**
 * JevEngineControl: the LLM | Jev switch under a recon AI hook.
 *
 * The state table below is the spec. Its two hard rules are the ones a regression
 * would break quietly:
 *  - a project whose owner has no token must not be able to CHOOSE Jev from the
 *    form (the server refuses it anyway, so the button must not invite it);
 *  - a project that is ALREADY on Jev keeps that choice when the token is gone,
 *    with a badge saying the hook falls back. The control never resets it on its
 *    own, and the person can still switch to the LLM.
 *
 *   enabled=false (AI in Pipeline off)  value kept, both buttons disabled
 *   loading                             Jev disabled, nothing written
 *   error                               switch-on disabled, warning shown
 *   no token, value false               Jev disabled, tooltip points to Settings
 *   no token, value true                Jev stays selected, badge, LLM selectable
 *   yes                                 both enabled
 *
 * Run: npx vitest run src/components/projects/ProjectForm/JevEngineControl.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { JevEngineControl } from './JevEngineControl'
import type { JevProviderStatus } from '@/hooks/useHasJevProvider'

afterEach(cleanup)

function mount(over: Partial<{ value: boolean; enabled: boolean; jevStatus: JevProviderStatus }> = {}) {
  const onSelect = vi.fn()
  render(<JevEngineControl value={false} enabled jevStatus="yes" onSelect={onSelect} {...over} />)
  return {
    onSelect,
    llm: screen.getByRole('button', { name: 'LLM' }),
    jev: screen.getByRole('button', { name: 'Jev' }),
  }
}

const BADGE = /No valid Jev selection: this hook uses its static fallback/
const WARNING = /Couldn't check the selected Jev provider/

describe('with a token', () => {
  test('both engines are selectable and the stored choice is shown', () => {
    const { llm, jev } = mount({ value: false, jevStatus: 'yes' })
    expect(llm).toBeEnabled()
    expect(jev).toBeEnabled()
    expect(llm).toHaveAttribute('aria-pressed', 'true')
    expect(jev).toHaveAttribute('aria-pressed', 'false')
    expect(screen.queryByText(BADGE)).not.toBeInTheDocument()
  })

  test('picking an engine reports a boolean: Jev is true, LLM is false', () => {
    const { onSelect, llm, jev } = mount({ value: false, jevStatus: 'yes' })
    fireEvent.click(jev)
    expect(onSelect).toHaveBeenLastCalledWith(true)
    fireEvent.click(llm)
    expect(onSelect).toHaveBeenLastCalledWith(false)
  })

  test('a stored Jev choice shows Jev as selected', () => {
    const { llm, jev } = mount({ value: true, jevStatus: 'yes' })
    expect(jev).toHaveAttribute('aria-pressed', 'true')
    expect(llm).toHaveAttribute('aria-pressed', 'false')
  })
})

describe('no token', () => {
  test('and the hook on the LLM: Jev cannot be chosen, and the tooltip says where to add a token', () => {
    const { onSelect, jev, llm } = mount({ value: false, jevStatus: 'no' })
    expect(jev).toBeDisabled()
    expect(jev).toHaveAttribute('title', expect.stringContaining('Settings → LLM Providers'))
    expect(llm).toBeEnabled()
    fireEvent.click(jev)
    expect(onSelect).not.toHaveBeenCalled()
    expect(screen.queryByText(BADGE)).not.toBeInTheDocument()
  })

  test('and the hook already on Jev: Jev stays selected, with a badge, and nothing is written', () => {
    const { onSelect, jev } = mount({ value: true, jevStatus: 'no' })
    expect(jev).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByText(BADGE)).toBeInTheDocument()
    expect(onSelect).not.toHaveBeenCalled()
  })

  test('and the hook already on Jev: the person can still switch to the LLM', () => {
    const { onSelect, llm } = mount({ value: true, jevStatus: 'no' })
    expect(llm).toBeEnabled()
    fireEvent.click(llm)
    expect(onSelect).toHaveBeenCalledWith(false)
  })
})

describe('while the token lookup is unresolved', () => {
  test('loading: Jev cannot be chosen yet, the stored value is shown, and nothing is written', () => {
    const { onSelect, jev, llm } = mount({ value: true, jevStatus: 'loading' })
    expect(jev).toBeDisabled()
    expect(jev).toHaveAttribute('aria-pressed', 'true')
    expect(llm).toBeEnabled()
    fireEvent.click(jev)
    expect(onSelect).not.toHaveBeenCalled()
    expect(screen.queryByText(BADGE)).not.toBeInTheDocument()
  })

  test('error: switch-on is disabled until selected-provider validation recovers, with a warning, and no "no token" badge', () => {
    const { llm, jev } = mount({ value: false, jevStatus: 'error' })
    expect(llm).toBeEnabled()
    expect(jev).toBeDisabled()
    expect(screen.getByText(WARNING)).toBeInTheDocument()
    expect(screen.queryByText(BADGE)).not.toBeInTheDocument()
  })

  test('error on a hook already on Jev: no badge claiming the token is missing', () => {
    mount({ value: true, jevStatus: 'error' })
    expect(screen.queryByText(BADGE)).not.toBeInTheDocument()
    expect(screen.getByText(WARNING)).toBeInTheDocument()
  })
})

describe('AI in Pipeline off', () => {
  test.each<JevProviderStatus>(['yes', 'no', 'loading', 'error'])(
    'both buttons are disabled and the value is kept (%s)', status => {
      const { onSelect, llm, jev } = mount({ value: true, enabled: false, jevStatus: status })
      expect(llm).toBeDisabled()
      expect(jev).toBeDisabled()
      expect(jev).toHaveAttribute('aria-pressed', 'true')
      fireEvent.click(llm)
      fireEvent.click(jev)
      expect(onSelect).not.toHaveBeenCalled()
    })

  test('the tooltip names the master switch', () => {
    const { jev } = mount({ value: false, enabled: false, jevStatus: 'yes' })
    expect(jev).toHaveAttribute('title', expect.stringContaining('AI in Pipeline'))
  })
})

describe('the Jev-only variant (Off | Jev)', () => {
  function mountJevOnly(over: Partial<{ value: boolean; enabled: boolean; jevStatus: JevProviderStatus }> = {}) {
    const onSelect = vi.fn()
    render(<JevEngineControl variant="jevOnly" value={false} enabled jevStatus="yes" onSelect={onSelect} {...over} />)
    return {
      onSelect,
      off: screen.getByRole('button', { name: 'Off' }),
      jev: screen.getByRole('button', { name: 'Jev' }),
    }
  }

  test('offers Off instead of LLM, and says what Off means', () => {
    const { off } = mountJevOnly()
    expect(screen.queryByRole('button', { name: 'LLM' })).not.toBeInTheDocument()
    expect(off).toHaveAttribute('title', 'Leave this hook off: the step runs without AI.')
    expect(screen.getByRole('group')).toHaveAttribute('aria-label', 'Jev hook')
  })

  test('Jev cannot be chosen without a token, same rule as the engine switch', () => {
    const { jev } = mountJevOnly({ jevStatus: 'no' })
    expect(jev).toBeDisabled()
    expect(jev).toHaveAttribute('title', expect.stringMatching(/Settings → LLM Providers/))
  })

  test('a stored true without a token stays on, with the badge, and can be switched off', () => {
    const { off, onSelect } = mountJevOnly({ value: true, jevStatus: 'no' })
    expect(screen.getByText(BADGE)).toBeInTheDocument()
    fireEvent.click(off)
    expect(onSelect).toHaveBeenCalledWith(false)
  })

  test('both buttons are disabled with AI in Pipeline off', () => {
    const { off, jev } = mountJevOnly({ enabled: false })
    expect(off).toBeDisabled()
    expect(jev).toBeDisabled()
  })

  test('with a token, Jev switches the hook on', () => {
    const { jev, onSelect } = mountJevOnly()
    expect(jev).toHaveAttribute('title', 'Run this hook on the project’s selected Jev provider.')
    fireEvent.click(jev)
    expect(onSelect).toHaveBeenCalledWith(true)
  })
})
