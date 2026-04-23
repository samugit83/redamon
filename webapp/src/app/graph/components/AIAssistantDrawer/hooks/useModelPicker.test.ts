/**
 * Unit tests for useModelPicker filtering logic.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/hooks/useModelPicker.test.ts
 *
 * The filtering logic is extracted as a pure function matching the inline computation
 * in useModelPicker (the filteredModels block).
 */

import { describe, test, expect } from 'vitest'
import type { ModelOption } from '../modelUtils'

// ---------------------------------------------------------------------------
// Pure extraction of filtering logic (mirrors useModelPicker.ts lines 47-58)
// ---------------------------------------------------------------------------

function filterModels(
  allModels: Record<string, ModelOption[]>,
  search: string,
): Record<string, ModelOption[]> {
  const filtered: Record<string, ModelOption[]> = {}
  const lowerSearch = search.toLowerCase()
  for (const [provider, models] of Object.entries(allModels)) {
    const matches = models.filter(m =>
      m.id.toLowerCase().includes(lowerSearch) ||
      m.name.toLowerCase().includes(lowerSearch) ||
      m.description.toLowerCase().includes(lowerSearch),
    )
    if (matches.length > 0) filtered[provider] = matches
  }
  return filtered
}

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

function makeModel(overrides: Partial<ModelOption> = {}): ModelOption {
  return {
    id: 'model-default',
    name: 'Default Model',
    context_length: null,
    description: '',
    ...overrides,
  }
}

const SAMPLE_MODELS: Record<string, ModelOption[]> = {
  Anthropic: [
    makeModel({ id: 'claude-opus-4-6', name: 'Claude Opus', description: 'Most capable model' }),
    makeModel({ id: 'claude-sonnet-4-6', name: 'Claude Sonnet', description: 'Fast and capable' }),
    makeModel({ id: 'claude-haiku-4-5', name: 'Claude Haiku', description: 'Lightweight model' }),
  ],
  OpenAI: [
    makeModel({ id: 'gpt-4o', name: 'GPT-4o', description: 'Multimodal model' }),
    makeModel({ id: 'gpt-4o-mini', name: 'GPT-4o Mini', description: 'Small efficient model' }),
  ],
  Mistral: [
    makeModel({ id: 'mistral-large', name: 'Mistral Large', description: 'Large language model' }),
  ],
}

// ---------------------------------------------------------------------------
// Tests: empty search
// ---------------------------------------------------------------------------

describe('filterModels – empty search', () => {
  test('empty string returns all models for all providers', () => {
    const result = filterModels(SAMPLE_MODELS, '')
    expect(Object.keys(result)).toEqual(['Anthropic', 'OpenAI', 'Mistral'])
    expect(result.Anthropic).toHaveLength(3)
    expect(result.OpenAI).toHaveLength(2)
    expect(result.Mistral).toHaveLength(1)
  })

  test('empty allModels returns empty object', () => {
    expect(filterModels({}, '')).toEqual({})
  })

  test('empty allModels with non-empty search returns empty object', () => {
    expect(filterModels({}, 'claude')).toEqual({})
  })
})

// ---------------------------------------------------------------------------
// Tests: search by id
// ---------------------------------------------------------------------------

describe('filterModels – search by id', () => {
  test('exact id match', () => {
    const result = filterModels(SAMPLE_MODELS, 'gpt-4o')
    expect(result.OpenAI).toHaveLength(2) // both gpt-4o and gpt-4o-mini contain 'gpt-4o'
    expect(result.Anthropic).toBeUndefined()
  })

  test('partial id match across providers', () => {
    const result = filterModels(SAMPLE_MODELS, 'claude')
    expect(result.Anthropic).toHaveLength(3)
    expect(result.OpenAI).toBeUndefined()
    expect(result.Mistral).toBeUndefined()
  })

  test('case-insensitive id search (uppercase input)', () => {
    const result = filterModels(SAMPLE_MODELS, 'CLAUDE')
    expect(result.Anthropic).toHaveLength(3)
  })

  test('case-insensitive id search (mixed case)', () => {
    const result = filterModels(SAMPLE_MODELS, 'ClAuDe-SoNnEt')
    expect(result.Anthropic).toHaveLength(1)
    expect(result.Anthropic[0].id).toBe('claude-sonnet-4-6')
  })
})

// ---------------------------------------------------------------------------
// Tests: search by name
// ---------------------------------------------------------------------------

describe('filterModels – search by name', () => {
  test('name substring match', () => {
    const result = filterModels(SAMPLE_MODELS, 'Opus')
    expect(result.Anthropic).toHaveLength(1)
    expect(result.Anthropic[0].name).toBe('Claude Opus')
  })

  test('case-insensitive name match', () => {
    const result = filterModels(SAMPLE_MODELS, 'haiku')
    expect(result.Anthropic).toHaveLength(1)
    expect(result.Anthropic[0].id).toBe('claude-haiku-4-5')
  })

  test('name match across multiple providers', () => {
    const result = filterModels(SAMPLE_MODELS, 'mini')
    expect(result.OpenAI).toHaveLength(1)
    expect(result.OpenAI[0].id).toBe('gpt-4o-mini')
  })
})

// ---------------------------------------------------------------------------
// Tests: search by description
// ---------------------------------------------------------------------------

describe('filterModels – search by description', () => {
  test('description substring match', () => {
    const result = filterModels(SAMPLE_MODELS, 'multimodal')
    expect(result.OpenAI).toHaveLength(1)
    expect(result.OpenAI[0].id).toBe('gpt-4o')
  })

  test('case-insensitive description match', () => {
    const result = filterModels(SAMPLE_MODELS, 'LIGHTWEIGHT')
    expect(result.Anthropic).toHaveLength(1)
    expect(result.Anthropic[0].id).toBe('claude-haiku-4-5')
  })

  test('description word match across multiple providers', () => {
    const result = filterModels(SAMPLE_MODELS, 'model')
    // 'Most capable model', 'Lightweight model', 'Multimodal model', 'Large language model'
    // should all match
    expect(result.Anthropic).toBeDefined()
    expect(result.OpenAI).toBeDefined()
    expect(result.Mistral).toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// Tests: no results
// ---------------------------------------------------------------------------

describe('filterModels – no matches', () => {
  test('search with no matches returns empty object', () => {
    const result = filterModels(SAMPLE_MODELS, 'zzz-nonexistent-xyz')
    expect(Object.keys(result)).toHaveLength(0)
  })

  test('providers with no matching models are excluded', () => {
    const result = filterModels(SAMPLE_MODELS, 'gpt')
    expect(result.OpenAI).toBeDefined()
    expect(result.Anthropic).toBeUndefined()
    expect(result.Mistral).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Tests: provider-level exclusion
// ---------------------------------------------------------------------------

describe('filterModels – provider-level behaviour', () => {
  test('provider is absent when all its models are filtered out', () => {
    const result = filterModels(SAMPLE_MODELS, 'large')
    // 'mistral-large' id and 'Large language model' description → Mistral matches
    // 'Mistral Large' name also matches
    expect(result.Mistral).toBeDefined()
    expect(result.Anthropic).toBeUndefined()
    expect(result.OpenAI).toBeUndefined()
  })

  test('partial provider match keeps only matching models', () => {
    const result = filterModels(SAMPLE_MODELS, 'sonnet')
    expect(result.Anthropic).toHaveLength(1)
    expect(result.Anthropic[0].id).toBe('claude-sonnet-4-6')
  })
})

// ---------------------------------------------------------------------------
// Tests: search matches multiple fields simultaneously
// ---------------------------------------------------------------------------

describe('filterModels – multi-field match', () => {
  test('search term matching id in one model and name in another keeps both', () => {
    // 'gpt' matches id 'gpt-4o' and 'gpt-4o-mini', name 'GPT-4o' and 'GPT-4o Mini'
    const result = filterModels(SAMPLE_MODELS, 'gpt')
    expect(result.OpenAI).toHaveLength(2)
  })

  test('model matching on id is not duplicated even if name also matches', () => {
    // Create a model where both id and name contain the search term
    const models = {
      TestProvider: [
        makeModel({ id: 'claude-test', name: 'Claude Test', description: 'not matching' }),
      ],
    }
    const result = filterModels(models, 'claude')
    expect(result.TestProvider).toHaveLength(1) // not duplicated
  })
})
