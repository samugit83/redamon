/**
 * Effective permissions with the "because" lines (step 3.13; PE-16, UI-12): held permissions by
 * area with what gives each, the others on demand with why not, and the empty line.
 *
 * Run: npx vitest run --no-file-parallelism src/components/admin/EffectivePermissions.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { EffectivePermissions } from './EffectivePermissions'
import { viewOf } from './__testing__/permissionViews'

afterEach(cleanup)

describe('EffectivePermissions', () => {
  test('held permissions by area, each with the set, override or cap that decides it', () => {
    const view = viewOf({
      userId: 'm', sets: [{ id: 'builtin:read-only-analyst', via: 'instance_default' }],
      overrides: [
        { permission: 'recon:scan', effect: 'grant', expiresAt: null, reason: 'pentest week' },
        { permission: 'graph:cypher', effect: 'deny', expiresAt: null, reason: null },
      ],
      capped: ['self:presets'],
    })
    render(<EffectivePermissions explain={view.explain} />)
    expect(screen.getByRole('region', { name: 'Graph and analytics' })).toBeTruthy()
    expect(screen.getByRole('listitem', { name: 'graph:read held' }).textContent)
      .toContain('Because granted by the set Read-only analyst (the instance default, no set assigned)')
    expect(screen.getByRole('listitem', { name: 'recon:scan held' }).textContent).toContain('Because granted by an override: pentest week')
    expect(screen.queryByRole('listitem', { name: 'graph:cypher not held' })).toBeNull()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Show the permissions not held' }))
    const cypher = screen.getByRole('listitem', { name: 'graph:cypher not held' }).textContent
    expect(cypher).toContain('Granted by the set Read-only analyst')
    expect(cypher).toContain('Denied by an override')
    expect(screen.getByRole('listitem', { name: 'self:presets not held' }).textContent)
      .toContain('The MCP server is switched off on this instance (MCP_SERVER_ENABLED)')
  })

  test('nothing held: says so, and the toggle still lists why', () => {
    const view = viewOf({ userId: 'm', sets: [{ id: 'builtin:no-access' }] })
    render(<EffectivePermissions explain={view.explain} emptyText="You hold no permission." />)
    expect(screen.getByRole('status').textContent).toBe('You hold no permission.')
    fireEvent.click(screen.getByRole('checkbox', { name: 'Show the permissions not held' }))
    expect(screen.getByRole('listitem', { name: 'agent:chat not held' }).textContent).toContain('No set in force holds it (No access)')
  })
})
