/**
 * A token, a preset or an import never chooses Agent in the Loop: only a person
 * selects it, in the project form. These are the shared functions every MCP
 * write path and every preset path goes through (update_recon_settings and
 * create_project through filterReconSettings; create/update_recon_preset and
 * apply_recon_preset through the preset validators; the UI save and the
 * project import through presetSettingsForStorage; every apply, client or
 * server, through applyPresetSettings).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { filterReconSettings } from '@/lib/reconSettings/filter'
import { presetSettingsForStorage, validatePresetSettings } from '@/lib/reconPresets/server'
import { applyPresetSettings } from '@/lib/project-preset-utils'

describe('MCP settings writes', () => {
  test.each(['update', 'create'] as const)('%s: a loop agent model is refused as escalation', (mode) => {
    const r = filterReconSettings({ agentOpenaiModel: 'loop/mcp' }, { mode })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.key).toBe('agentOpenaiModel')
    expect(r.error).toMatch(/escalation/)
    expect(r.error).toMatch(/only a person selects Agent in the Loop, in the project form/)
  })

  test('a loop pipeline model is refused as not supported', () => {
    const r = filterReconSettings({ aiPipelineModel: 'loop/x' })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.error).toMatch(/not_supported/)
  })

  test('a provider model is unchanged', () => {
    const r = filterReconSettings({ agentOpenaiModel: 'claude-opus-4-6', aiPipelineModel: 'gpt-5' })
    expect(r).toEqual({ ok: true, data: { agentOpenaiModel: 'claude-opus-4-6', aiPipelineModel: 'gpt-5' } })
  })
})

describe('presets', () => {
  test.each(['agentOpenaiModel', 'aiPipelineModel'])('an MCP preset save naming a loop %s is refused', (key) => {
    const r = validatePresetSettings({ [key]: 'loop/mcp' })
    expect(r.ok).toBe(false)
    if (!r.ok) {
      expect(r.key).toBe(key)
      expect(r.error).toMatch(/a preset cannot choose it/)
    }
  })

  test('a provider model in a preset is still accepted', () => {
    expect(validatePresetSettings({ agentOpenaiModel: 'claude-opus-4-6' }).ok).toBe(true)
  })

  test('a UI save or an import keeps the preset and drops the loop model', () => {
    const r = presetSettingsForStorage({ agentOpenaiModel: 'loop/mcp', aiPipelineModel: 'claude-opus-4-6' })
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.settings).not.toHaveProperty('agentOpenaiModel')
      expect(r.settings.aiPipelineModel).toBe('claude-opus-4-6')
      expect(r.dropped).toBe(1)
    }
  })

  test('an apply never writes a loop model, even from a preset stored before the rule', () => {
    const current = { agentOpenaiModel: 'claude-opus-4-6', aiPipelineModel: 'gpt-5' }
    const next = applyPresetSettings(current, { agentOpenaiModel: 'loop/mcp', aiPipelineModel: 'loop/mcp' }, {})
    expect(next.agentOpenaiModel).toBe('claude-opus-4-6')
    expect(next.aiPipelineModel).toBe('gpt-5')
  })

  test('an apply of a provider model still writes it', () => {
    const next = applyPresetSettings({ agentOpenaiModel: 'claude-opus-4-6' }, { agentOpenaiModel: 'gpt-5' }, {})
    expect(next.agentOpenaiModel).toBe('gpt-5')
  })
})
