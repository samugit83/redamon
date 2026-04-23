/**
 * Unit tests for modelUtils shared helpers.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/modelUtils.test.ts
 */

import { describe, test, expect } from 'vitest'
import { formatContextLength, getDisplayName, type ModelOption } from './modelUtils'

// ---------------------------------------------------------------------------
// formatContextLength
// ---------------------------------------------------------------------------

describe('formatContextLength', () => {
  test('returns empty string for null', () => {
    expect(formatContextLength(null)).toBe('')
  })

  test('returns empty string for 0', () => {
    expect(formatContextLength(0)).toBe('')
  })

  test('formats millions', () => {
    expect(formatContextLength(1_000_000)).toBe('1.0M')
    expect(formatContextLength(2_000_000)).toBe('2.0M')
    expect(formatContextLength(1_500_000)).toBe('1.5M')
  })

  test('formats thousands', () => {
    expect(formatContextLength(128_000)).toBe('128K')
    expect(formatContextLength(4_096)).toBe('4K')
    expect(formatContextLength(1_000)).toBe('1K')
    expect(formatContextLength(200_000)).toBe('200K')
  })

  test('returns raw number for small values', () => {
    expect(formatContextLength(512)).toBe('512')
    expect(formatContextLength(100)).toBe('100')
    expect(formatContextLength(1)).toBe('1')
  })

  test('rounds thousands correctly', () => {
    expect(formatContextLength(4_097)).toBe('4K')
    expect(formatContextLength(32_768)).toBe('33K')
  })
})

// ---------------------------------------------------------------------------
// getDisplayName
// ---------------------------------------------------------------------------

describe('getDisplayName', () => {
  const mockModels: Record<string, ModelOption[]> = {
    Anthropic: [
      { id: 'claude-opus-4-6', name: 'Claude Opus 4.6', context_length: 200_000, description: 'Most capable' },
      { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6', context_length: 200_000, description: 'Fast and capable' },
    ],
    OpenAI: [
      { id: 'gpt-5.2', name: 'GPT-5.2', context_length: 128_000, description: 'Latest GPT' },
    ],
  }

  test('returns display name for known model', () => {
    expect(getDisplayName('claude-opus-4-6', mockModels)).toBe('Claude Opus 4.6')
    expect(getDisplayName('gpt-5.2', mockModels)).toBe('GPT-5.2')
  })

  test('returns model ID for unknown model', () => {
    expect(getDisplayName('unknown-model', mockModels)).toBe('unknown-model')
  })

  test('returns model ID for empty providers', () => {
    expect(getDisplayName('claude-opus-4-6', {})).toBe('claude-opus-4-6')
  })

  test('finds model across multiple providers', () => {
    expect(getDisplayName('claude-sonnet-4-6', mockModels)).toBe('Claude Sonnet 4.6')
  })
})
