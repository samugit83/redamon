/**
 * Unit + regression tests for the project LLM gate decision logic.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/projectLlmGate.logic.test.ts
 *
 * These lock down the rules that decide:
 *  - how a new project's model fields are seeded (remembered default vs blank),
 *  - when the forced model-selection gate must open,
 *  - when the hard provider gate must block creation,
 *  - the server-side backstop that drops blank model fields on create.
 *
 * The gate is the safety net that stops a DeepSeek-only user from silently
 * ending up on the hardcoded claude-* default (the original bug), so the
 * regressions here matter.
 */

import { describe, test, expect } from 'vitest'
import {
  seedInitialModels,
  needsModelGate,
  hasNoConfiguredProvider,
  bothModelsSelected,
  isBlankModelField,
  MODEL_DEFAULT_FIELDS,
  providerGateApplies,
  pipelineModelOptional,
  loopModelOffered,
  instanceModelOffered,
} from './projectLlmGate.logic'

// ---------------------------------------------------------------------------
// seedInitialModels
// ---------------------------------------------------------------------------

describe('seedInitialModels', () => {
  test('uses remembered defaults when present', () => {
    expect(
      seedInitialModels({
        defaultAgentModel: 'deepseek/deepseek-chat',
        defaultAiPipelineModel: 'deepseek/deepseek-reasoner',
      }),
    ).toEqual({
      agentOpenaiModel: 'deepseek/deepseek-chat',
      aiPipelineModel: 'deepseek/deepseek-reasoner',
    })
  })

  test('returns blanks when user is null (no record / fetch failed)', () => {
    expect(seedInitialModels(null)).toEqual({
      agentOpenaiModel: '',
      aiPipelineModel: '',
    })
  })

  test('returns blanks when user is undefined', () => {
    expect(seedInitialModels(undefined)).toEqual({
      agentOpenaiModel: '',
      aiPipelineModel: '',
    })
  })

  test('returns blanks when defaults are null (first project, never chosen)', () => {
    expect(
      seedInitialModels({ defaultAgentModel: null, defaultAiPipelineModel: null }),
    ).toEqual({ agentOpenaiModel: '', aiPipelineModel: '' })
  })

  test('blank string default coerces to empty (forces re-selection)', () => {
    expect(
      seedInitialModels({ defaultAgentModel: '', defaultAiPipelineModel: '' }),
    ).toEqual({ agentOpenaiModel: '', aiPipelineModel: '' })
  })

  test('seeds each field independently (one set, one missing)', () => {
    expect(
      seedInitialModels({ defaultAgentModel: 'deepseek/deepseek-chat', defaultAiPipelineModel: null }),
    ).toEqual({ agentOpenaiModel: 'deepseek/deepseek-chat', aiPipelineModel: '' })
  })
})

// ---------------------------------------------------------------------------
// needsModelGate
// ---------------------------------------------------------------------------

describe('needsModelGate', () => {
  test('gates on create when both models blank', () => {
    expect(needsModelGate('create', '', '')).toBe(true)
  })

  test('gates on create when only agent model blank', () => {
    expect(needsModelGate('create', '', 'deepseek/deepseek-chat')).toBe(true)
  })

  test('gates on create when only pipeline model blank', () => {
    expect(needsModelGate('create', 'deepseek/deepseek-chat', '')).toBe(true)
  })

  test('does NOT gate on create when both models set', () => {
    expect(needsModelGate('create', 'deepseek/deepseek-chat', 'deepseek/deepseek-chat')).toBe(false)
  })

  test('whitespace-only models are treated as blank', () => {
    expect(needsModelGate('create', '   ', '\t')).toBe(true)
  })

  test('null / undefined models are treated as blank', () => {
    expect(needsModelGate('create', null, undefined)).toBe(true)
  })

  // Regression: edit mode must NEVER gate, regardless of model values.
  test('REGRESSION: never gates in edit mode, even with blank models', () => {
    expect(needsModelGate('edit', '', '')).toBe(false)
    expect(needsModelGate('edit', null, null)).toBe(false)
  })

  test('does not gate in edit mode with models set', () => {
    expect(needsModelGate('edit', 'claude-opus-4-6', 'claude-opus-4-6')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// hasNoConfiguredProvider
// ---------------------------------------------------------------------------

describe('hasNoConfiguredProvider', () => {
  test('true for empty array (no providers)', () => {
    expect(hasNoConfiguredProvider([])).toBe(true)
  })

  test('false when at least one provider exists', () => {
    expect(hasNoConfiguredProvider([{ id: 'p1', providerType: 'deepseek' }])).toBe(false)
  })

  test('false for a populated provider list', () => {
    expect(hasNoConfiguredProvider([{ id: 'p1' }, { id: 'p2' }])).toBe(false)
  })

  test('true for non-array error payloads (treated as missing)', () => {
    expect(hasNoConfiguredProvider({ error: 'boom' })).toBe(true)
    expect(hasNoConfiguredProvider(null)).toBe(true)
    expect(hasNoConfiguredProvider(undefined)).toBe(true)
  })

  test('a Jev token alone is not a chat provider: the gate stays closed', () => {
    expect(hasNoConfiguredProvider([{ id: 'j1', providerType: 'jev' }])).toBe(true)
  })

  test('a Jev token next to a chat provider passes', () => {
    expect(hasNoConfiguredProvider([
      { id: 'j1', providerType: 'jev' }, { id: 'p1', providerType: 'anthropic' },
    ])).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// bothModelsSelected
// ---------------------------------------------------------------------------

describe('bothModelsSelected', () => {
  test('true when both set', () => {
    expect(bothModelsSelected('a', 'b')).toBe(true)
  })

  test('false when either blank/whitespace/null', () => {
    expect(bothModelsSelected('a', '')).toBe(false)
    expect(bothModelsSelected('', 'b')).toBe(false)
    expect(bothModelsSelected('  ', 'b')).toBe(false)
    expect(bothModelsSelected(null, 'b')).toBe(false)
    expect(bothModelsSelected('a', undefined)).toBe(false)
  })

  // Invariant: the modal "ready" condition is the exact inverse of the gate
  // trigger on create, so the UI can't enable Save while the gate would re-fire.
  test('is the inverse of needsModelGate on create', () => {
    const cases: Array<[string, string]> = [
      ['', ''],
      ['a', ''],
      ['', 'b'],
      ['a', 'b'],
    ]
    for (const [agent, pipeline] of cases) {
      expect(bothModelsSelected(agent, pipeline)).toBe(!needsModelGate('create', agent, pipeline))
    }
  })
})

// ---------------------------------------------------------------------------
// isBlankModelField / MODEL_DEFAULT_FIELDS (server-side backstop)
// ---------------------------------------------------------------------------

describe('isBlankModelField (server backstop)', () => {
  test('tracks exactly the two model fields', () => {
    expect([...MODEL_DEFAULT_FIELDS].sort()).toEqual(['agentOpenaiModel', 'aiPipelineModel'])
  })

  // Regression: blank model fields must be dropped so the schema default applies
  // instead of persisting "" (the original silent-misconfiguration bug).
  test('REGRESSION: true for blank agentOpenaiModel', () => {
    expect(isBlankModelField('agentOpenaiModel', '')).toBe(true)
    expect(isBlankModelField('agentOpenaiModel', '   ')).toBe(true)
  })

  test('REGRESSION: true for blank aiPipelineModel', () => {
    expect(isBlankModelField('aiPipelineModel', '')).toBe(true)
    expect(isBlankModelField('aiPipelineModel', '\t\n')).toBe(true)
  })

  test('false for a real model value (must be persisted)', () => {
    expect(isBlankModelField('agentOpenaiModel', 'deepseek/deepseek-chat')).toBe(false)
    expect(isBlankModelField('aiPipelineModel', 'claude-opus-4-6')).toBe(false)
  })

  test('false for non-model fields even when blank', () => {
    expect(isBlankModelField('targetDomain', '')).toBe(false)
    expect(isBlankModelField('description', '   ')).toBe(false)
  })

  test('false for non-string model values', () => {
    expect(isBlankModelField('agentOpenaiModel', null)).toBe(false)
    expect(isBlankModelField('agentOpenaiModel', undefined)).toBe(false)
    expect(isBlankModelField('agentOpenaiModel', 123)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Agent in the Loop: no provider needed for the agent model (E3: recon AI
// hooks fall back quietly when their model cannot be built)
// ---------------------------------------------------------------------------


describe('Agent in the Loop and the provider gate', () => {
  const NONE: unknown[] = []
  const ONE = [{ providerType: 'anthropic' }]

  test('loop agent + no provider + switch on: not blocked', () => {
    expect(providerGateApplies(NONE, 'loop/mcp', true)).toBe(false)
  })

  test('loop agent + switch off: blocked as today', () => {
    expect(providerGateApplies(NONE, 'loop/mcp', false)).toBe(true)
  })

  test('provider model + no provider: blocked as today, whatever the switch', () => {
    expect(providerGateApplies(NONE, 'claude-opus-4-6', true)).toBe(true)
    expect(providerGateApplies(NONE, '', true)).toBe(true)
  })

  test('a provider configured: never blocked (unchanged)', () => {
    expect(providerGateApplies(ONE, 'claude-opus-4-6', false)).toBe(false)
    expect(providerGateApplies(ONE, 'loop/mcp', false)).toBe(false)
  })

  test('the pipeline model may stay unset only for a loop agent with no provider', () => {
    expect(pipelineModelOptional('loop/mcp', true)).toBe(true)
    expect(pipelineModelOptional('loop/mcp', false)).toBe(false)
    expect(pipelineModelOptional('gpt-5', true)).toBe(false)
    expect(needsModelGate('create', 'loop/mcp', '', true)).toBe(false)
    expect(needsModelGate('create', 'loop/mcp', '', false)).toBe(true)
    expect(needsModelGate('create', '', '', true)).toBe(true)
    expect(bothModelsSelected('loop/mcp', '', true)).toBe(true)
  })

  test('the model list says whether the loop is offered', () => {
    expect(loopModelOffered({ 'Agent in the Loop': [{ id: 'loop/mcp' }] })).toBe(true)
    expect(loopModelOffered({ Anthropic: [{ id: 'claude-opus-4-6' }] })).toBe(false)
    expect(loopModelOffered({})).toBe(false)
    expect(loopModelOffered(null)).toBe(false)
  })
})

describe('instance providers and the provider gate (step 6.11)', () => {
  test('an instance provider model in the list is a configured provider', () => {
    expect(providerGateApplies([], 'gpt-5', false, true)).toBe(false)
    expect(providerGateApplies(null, '', false, true)).toBe(false)
    // Without one the gate is the one before.
    expect(providerGateApplies([], 'gpt-5', false, false)).toBe(true)
    expect(providerGateApplies([], 'gpt-5', false)).toBe(true)
  })

  test('the model list says whether an instance provider is offered', () => {
    expect(instanceModelOffered({ 'Instance: Shared': [{ id: 'instance/p1/gpt-5' }] })).toBe(true)
    expect(instanceModelOffered({ Custom: [{ id: 'custom/p1' }], 'Agent in the Loop': [{ id: 'loop/mcp' }] })).toBe(false)
    expect(instanceModelOffered({})).toBe(false)
    expect(instanceModelOffered(null)).toBe(false)
  })
})
