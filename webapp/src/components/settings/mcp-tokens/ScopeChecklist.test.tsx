/**
 * The grouped permission checklist: its GROUPING and its copy.
 *
 * What it does NOT own is which boxes a profile ticks. This component only
 * renders the `selected` array it is handed, so asserting the tick rule here
 * would test the test's own fixture. That rule is owned once in the data
 * (profiles.test.ts) and once through the real handler that computes the set
 * (McpTokensTab.test.tsx "never auto-ticks"), which is where a bug would live.
 *
 * Run: npx vitest run src/components/settings/mcp-tokens/ScopeChecklist.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react'

import { MCP_SCOPES, type McpScope } from '@/lib/mcpAuth'
import { PROFILE_IDS, PROFILES, scopesForProfile } from '@/lib/mcp/profiles'
import { MCP_SCOPE_COPY, SCOPE_GROUPS } from '@/lib/mcp/scopeCopy'
import ScopeChecklist from './ScopeChecklist'

afterEach(() => cleanup())

/**
 * The scope code also appears in the opt-in footnote, so matching on text alone
 * is ambiguous. The label wraps its input, so the row's text IS the checkbox's
 * accessible name.
 */
const boxFor = (scope: McpScope) =>
  screen.getByRole('checkbox', { name: new RegExp(scope.replace(':', '\\:')) }) as HTMLInputElement

describe('the grouping', () => {
  test('every scope renders exactly once, under a group header', () => {
    render(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    for (const scope of MCP_SCOPES) {
      expect(screen.getAllByText(scope), `${scope} renders ${screen.queryAllByText(scope).length} times`).toHaveLength(1)
    }
    for (const group of SCOPE_GROUPS) {
      expect(screen.getByText(group.label), `group ${group.id} has no header`).toBeDefined()
    }
  })

  test('the checkbox count matches the enforcement list, so none is orphaned', () => {
    const { container } = render(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    expect(container.querySelectorAll('input[type="checkbox"]')).toHaveLength(MCP_SCOPES.length)
  })

  test('toggling a row reports that scope', () => {
    const onToggle = vi.fn()
    render(<ScopeChecklist selected={[]} onToggle={onToggle} />)
    fireEvent.click(boxFor('recon:scan'))
    expect(onToggle).toHaveBeenCalledWith('recon:scan')
  })

  test('a disabled checklist disables EVERY box, not just the first', () => {
    // Asserted on the inputs rather than by clicking: a disabled input's click
    // semantics are a jsdom detail, while "is it disabled" is the contract a
    // revoked token relies on.
    const { container } = render(<ScopeChecklist selected={[]} onToggle={vi.fn()} disabled />)
    const boxes = [...container.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')]
    expect(boxes).toHaveLength(MCP_SCOPES.length)
    expect(boxes.every(b => b.disabled)).toBe(true)
  })
})

describe('the access badge', () => {
  /**
   * Whether a permission changes state used to be carried by tinting the row
   * red, which said "be careful" without saying of what, and left the other
   * rows saying nothing at all. Every row now states it.
   */
  const BADGE = { read: 'read', write: 'write', 'read-write': 'read + write' } as const

  test('every row says whether it reads, writes, or both', () => {
    render(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    for (const scope of MCP_SCOPES) {
      const row = boxFor(scope).closest('label') as HTMLElement
      const badge = BADGE[MCP_SCOPE_COPY[scope].access]
      // An exact match, so the blurb's own prose cannot stand in for the badge.
      expect(
        within(row).getAllByText(badge, { exact: true }),
        `${scope} does not badge "${badge}"`
      ).toHaveLength(1)
    }
  })
})

describe('kali:exec is presented as a different KIND of permission', () => {
  test('it carries the long explanation, not the table-cell blurb', () => {
    render(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    // The decision the operator is actually making, which is the framing the
    // short blurb cannot carry.
    expect(screen.getByText(/borrow\s+RedAmon's\?/)).toBeDefined()
    expect(screen.getByText(/not sufficient on its own/)).toBeDefined()
  })

  test('it links out to the toolset AND to what a shell here means', () => {
    render(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    // These used to be "installed" vs "permitted to run", which were different
    // sets. kali_exec is now a shell with no allowlist, so everything installed
    // is runnable and that distinction is gone. The two links still answer
    // different questions - what is in the box, and what handing over a shell
    // means - so both stay.
    const carries = screen.getByText('What the sandbox carries') as HTMLAnchorElement
    const shell = screen.getByText('What a shell here means') as HTMLAnchorElement
    expect(carries.getAttribute('href')).toContain('kali_toolbox')
    expect(shell.getAttribute('href')).toContain('kali_exec')
  })

  test('it does not enumerate the sandbox toolset, which changes with the image', () => {
    const { container } = render(<ScopeChecklist selected={[]} onToggle={vi.fn()} />)
    // A tool list pasted into the UI goes stale the moment the image changes.
    // kali_toolbox serves the real catalogue; the consent screen should say
    // what the permission GRANTS, not try to enumerate a sandbox.
    expect(container.textContent).not.toContain('searchsploit')
    expect(container.textContent).not.toContain('dnsrecon')
  })
})

describe('divergence from the profile is shown, not corrected', () => {
  test('a hand-added scope is tagged as added', () => {
    render(
      <ScopeChecklist
        selected={[...scopesForProfile('soc'), 'triage:write']}
        profile="soc"
        onToggle={vi.fn()}
      />
    )
    expect(screen.getByText('added')).toBeDefined()
    expect(boxFor('triage:write').checked).toBe(true)
  })

  test('a hand-removed scope is tagged as removed, and stays removed', () => {
    render(
      <ScopeChecklist
        selected={scopesForProfile('soc').filter(s => s !== 'graph:cypher')}
        profile="soc"
        onToggle={vi.fn()}
      />
    )
    expect(screen.getByText('removed')).toBeDefined()
    expect(boxFor('graph:cypher').checked).toBe(false)
  })

  test('with no profile there are no tags at all', () => {
    render(<ScopeChecklist selected={['recon:read', 'kali:exec']} onToggle={vi.fn()} />)
    expect(screen.queryByText('from profile')).toBeNull()
    expect(screen.queryByText('added')).toBeNull()
    expect(screen.queryByText(/never ticks those for you/)).toBeNull()
  })
})

describe('Agent in the Loop', () => {
  test('a too-broad driver token is warned about, naming the extra scopes', () => {
    const { rerender } = render(
      <ScopeChecklist selected={['agent:loop', 'recon:read', 'kali:exec', 'recon:scan']} onToggle={vi.fn()} />,
    )
    const warning = screen.getByRole('alert')
    expect(warning.textContent).toMatch(/must not also hold kali:exec, recon:scan/)
    expect(warning.textContent).toMatch(/Mint a separate token/)
    rerender(<ScopeChecklist selected={['agent:loop', 'recon:read', 'triage:read']} onToggle={vi.fn()} />)
    expect(screen.queryByRole('alert')).toBeNull()
    rerender(<ScopeChecklist selected={['recon:read', 'kali:exec']} onToggle={vi.fn()} />)
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('off on this deployment: not offered to a new token', () => {
    render(<ScopeChecklist selected={['recon:read']} onToggle={vi.fn()} loopOff />)
    expect(screen.queryByText('agent:loop')).toBeNull()
    expect(screen.queryByText('Agent in the Loop')).toBeNull()
  })

  test('off on this deployment: a token that holds it shows it marked off', () => {
    render(<ScopeChecklist selected={['recon:read', 'agent:loop']} onToggle={vi.fn()} loopOff />)
    expect(boxFor('agent:loop').checked).toBe(true)
    expect(screen.getByText('(off on this deployment)')).toBeInTheDocument()
  })
})
