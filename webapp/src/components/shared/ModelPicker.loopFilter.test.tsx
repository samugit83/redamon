/**
 * Agent in the Loop is offered only as the agent's own model. Every other
 * picker (recon AI model, Tradecraft, features) passes excludeLoop.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { ModelPicker } from './ModelPicker'
import { ModelPickerModal } from '@/app/graph/components/AIAssistantDrawer/ModelPickerModal'
import { LOOP_WIKI_URL } from '@/app/graph/components/AIAssistantDrawer/hooks/loopStatus'
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

describe('the Agent in the Loop wiki link', () => {
  const wikiLinks = () => screen.queryAllByRole('link', { name: 'View wiki documentation' })

  test('the project picker shows it on the loop entry only, and opening it picks nothing', () => {
    const onChange = vi.fn()
    open({ onChange })
    expect(wikiLinks()).toHaveLength(1)
    expect(wikiLinks()[0]).toHaveAttribute('href', LOOP_WIKI_URL)
    fireEvent.click(wikiLinks()[0])
    expect(onChange).not.toHaveBeenCalled()
  })

  test('the chat Change Model modal shows it on the loop entry only, and opening it picks nothing', () => {
    const handleSelectModel = vi.fn()
    render(
      <ModelPickerModal
        showModelModal
        setShowModelModal={vi.fn()}
        modelSearch=""
        setModelSearch={vi.fn()}
        modelSearchRef={{ current: null }}
        modelsLoading={false}
        modelsError={null}
        filteredModels={MODELS as never}
        handleSelectModel={handleSelectModel}
      />,
    )
    expect(wikiLinks()).toHaveLength(1)
    expect(wikiLinks()[0]).toHaveAttribute('href', LOOP_WIKI_URL)
    fireEvent.click(wikiLinks()[0])
    expect(handleSelectModel).not.toHaveBeenCalled()
  })
})
