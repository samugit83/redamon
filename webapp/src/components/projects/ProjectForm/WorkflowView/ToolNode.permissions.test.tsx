/**
 * A Workflow tool's partial-recon play starts a single recon phase, which the partial route asks
 * `recon:partial` for (route manifest). Without it (step 3.16b, UI-12, the permissions switch on) the
 * play is shown disabled with the permission notice as its title, and a click neither starts nor
 * opens the node. With the switch off the play is as before (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/WorkflowView/ToolNode.permissions.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import type { NodeProps } from '@xyflow/react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import { FLAGS_OFF, FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { forbiddenNoticeText } from '@/components/auth/ForbiddenNotice'

// A handle needs a whole flow around it; the play is what is under test.
vi.mock('@xyflow/react', () => ({ Handle: () => null, Position: { Left: 'left', Right: 'right' } }))

import { ToolNode } from './ToolNode'

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

const onRunPartial = vi.fn()
const onNodeClick = vi.fn()
const data = {
  toolId: 'Naabu', label: 'Naabu', enabled: true, enabledField: 'naabuEnabled', group: 3, chainBroken: false,
  starvedInputs: [], groupColor: '#888', onRunPartial, onNodeClick, partialReconSupported: true,
}

function node(value: AuthContextValue | null) {
  const nodeProps = { id: 'tool-Naabu', data } as unknown as NodeProps
  return render(
    <AuthContext.Provider value={value}>
      <ToolNode {...nodeProps} />
    </AuthContext.Provider>,
  )
}

describe('ToolNode partial recon and recon:partial', () => {
  test('switch on, without recon:partial: the play is disabled with the notice and starts nothing', () => {
    node(fakeAuth(FLAGS_ON, ['recon:read', 'recon:scan']))
    expect(screen.queryByTitle('Run partial recon')).toBeNull()
    const play = screen.getByTitle(forbiddenNoticeText('recon:partial'))
    expect(play.getAttribute('aria-disabled')).toBe('true')
    fireEvent.click(play)
    expect(onRunPartial).not.toHaveBeenCalled()
    expect(onNodeClick).not.toHaveBeenCalled()
  })

  test('switch on, with recon:partial: the play starts the phase as before', () => {
    node(fakeAuth(FLAGS_ON, ['recon:read', 'recon:partial']))
    fireEvent.click(screen.getByTitle('Run partial recon'))
    expect(onRunPartial).toHaveBeenCalledWith('Naabu')
  })

  test('switch off, an empty set, and with no provider: as before (DV-30)', () => {
    node(fakeAuth(FLAGS_OFF, []))
    fireEvent.click(screen.getByTitle('Run partial recon'))
    expect(onRunPartial).toHaveBeenCalledTimes(1)
    cleanup()
    node(null)
    expect(screen.getByTitle('Run partial recon')).toBeTruthy()
  })
})
