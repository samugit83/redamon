/**
 * Agent in the Loop is offered only as the agent's own model. Every other
 * picker (recon AI model, Tradecraft, features) passes excludeLoop.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { ModelPicker } from './ModelPicker'
import { excludeLoop } from '@/lib/agentInTheLoop'

const MODELS = {
  'Anthropic (mine)': [{ id: 'claude-opus-4-6', name: 'Claude Opus 4.6', context_length: 200000, description: '' }],
  'Agent in the Loop': [{ id: 'loop/mcp', name: 'Agent in the Loop', context_length: null, description: 'Claude Code, Codex or another MCP agent answers each step' }],
}

afterEach(() => cleanup())

function open(props: Partial<React.ComponentProps<typeof ModelPicker>> = {}) {
  render(<ModelPicker userId="u1" value="" onChange={vi.fn()} models={MODELS as never} {...props} />)
  fireEvent.click(document.querySelector('[class*="modelSelectorInput"]') as HTMLElement)
}

describe('the Agent in the Loop entry', () => {
  test('the agent picker shows it', () => {
    open()
    expect(screen.getAllByText('Agent in the Loop').length).toBeGreaterThan(0)
    expect(screen.getByText('Claude Opus 4.6')).toBeInTheDocument()
  })

  test('a picker filtered with excludeLoop does not', () => {
    open({ filter: excludeLoop })
    expect(screen.queryByText('Agent in the Loop')).toBeNull()
    expect(screen.getByText('Claude Opus 4.6')).toBeInTheDocument()
  })
})
