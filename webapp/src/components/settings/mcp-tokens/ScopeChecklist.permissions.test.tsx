/**
 * The checklist under the permissions switch (step 3.10, PE-20): a scope the token's owner cannot
 * grant (the token list's `ungrantableScopes`) is shown disabled with the permissions it lacks. One
 * the token already holds stays enabled, so it can be taken away, and says the token cannot use it.
 * With no limits (the switch off) the checklist is what it was.
 *
 * @vitest-environment jsdom
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, fireEvent, cleanup } from '@testing-library/react'

import { MCP_SCOPES, type McpScope } from '@/lib/mcpAuth'
import ScopeChecklist from './ScopeChecklist'

afterEach(() => cleanup())

/** A row is the label wrapping its checkbox; its scope code is the row's <code>. */
const rowOf = (scope: McpScope) =>
  [...document.querySelectorAll('label')].find((l) => l.querySelector('code')?.textContent === scope) as HTMLElement
const boxFor = (scope: McpScope) => rowOf(scope).querySelector('input') as HTMLInputElement

const LIMITS = { 'kali:exec': ['agent:kali_exec'], 'recon:scan': ['recon:scan', 'recon:partial'] }

describe('limited by your permissions', () => {
  test('checklist disables ungrantable scopes', () => {
    // Asserted on the inputs: a disabled input's click semantics are a jsdom detail.
    render(<ScopeChecklist selected={['recon:read']} onToggle={vi.fn()} limits={LIMITS} />)
    expect(boxFor('kali:exec').disabled).toBe(true)
    expect(boxFor('recon:scan').disabled).toBe(true)
    for (const scope of MCP_SCOPES.filter((s) => !(s in LIMITS))) expect(boxFor(scope).disabled, scope).toBe(false)
    // The reason names every permission the scope lacks.
    expect(rowOf('kali:exec').textContent).toMatch(/limited by your permissions/i)
    expect(rowOf('kali:exec').textContent).toContain('agent:kali_exec')
    expect(rowOf('recon:scan').textContent).toContain('recon:partial')
  })

  test('a limited scope the token holds stays removable and says the token cannot use it', () => {
    const onToggle = vi.fn()
    render(<ScopeChecklist selected={['recon:read', 'kali:exec']} onToggle={onToggle} limits={LIMITS} />)
    expect(boxFor('kali:exec').checked).toBe(true)
    expect(boxFor('kali:exec').disabled).toBe(false)
    expect(rowOf('kali:exec').textContent).toMatch(/cannot use it/i)
    fireEvent.click(boxFor('kali:exec'))
    expect(onToggle).toHaveBeenCalledWith('kali:exec')
  })

  test('the list says a token is capped by its owner\'s permissions only when limits are known', () => {
    const { container, rerender } = render(<ScopeChecklist selected={[]} onToggle={vi.fn()} limits={{}} />)
    expect(container.textContent).toMatch(/limited by your permissions/i)
    expect([...container.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')].some((b) => b.disabled)).toBe(false)
    rerender(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    expect(container.textContent).not.toMatch(/limited by your permissions/i)
  })
})
