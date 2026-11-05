/**
 * The Models by feature registry and its error contract. The ids are stored
 * as keys of UserSettings.featureModels, and the codes drive the client's
 * choice between opening the model gate and showing a message, so both are
 * pinned here.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  FEATURE_IDS,
  FEATURE_MODEL_MAX_LEN,
  FEATURE_MODEL_STATUS,
  GATE_CODES,
  LLM_FEATURES,
  featureModelMessage,
  getLlmFeature,
  isFeatureId,
  modelAllowedForFeature,
  providerFailureDetail,
  readFeatureModelCode,
  type FeatureModelCode,
} from './llmFeatures'

describe('registry', () => {
  test('the nine features, in the grid order', () => {
    expect(FEATURE_IDS).toEqual([
      'triage',
      'codefix',
      'multi_mute',
      'report_narratives',
      'roe_parse',
      'preset_generator',
      'command_whisperer',
      'tradecraft_section_picker',
      'skill_metadata',
    ])
    expect(LLM_FEATURES.map(f => f.label)).toEqual([
      'Triage review',
      'CodeFix',
      'Multi mute',
      'Report narratives',
      'RoE parsing',
      'Recon preset generator',
      'Command whisperer',
      'Tradecraft section picker',
      'Skill names & descriptions',
    ])
  })

  test('every feature has a description, a hint and says where else it is edited', () => {
    for (const f of LLM_FEATURES) {
      expect(f.description, f.id).not.toBe('')
      expect(f.hint, f.id).not.toBe('')
      expect(f.alsoEditedIn.length, f.id).toBeGreaterThan(0)
    }
    expect(getLlmFeature('triage').alsoEditedIn).toEqual(['Project settings → CypherFix'])
    expect(getLlmFeature('codefix').alsoEditedIn).toEqual(['Project settings → CypherFix'])
    expect(getLlmFeature('preset_generator').alsoEditedIn).toEqual(['Generate preset dialog'])
  })

  test('isFeatureId accepts only registry ids', () => {
    for (const id of FEATURE_IDS) expect(isFeatureId(id)).toBe(true)
    for (const bad of ['graph_query', 'TRIAGE', '', null, undefined, 3, {}, '__proto__', 'toString']) {
      expect(isFeatureId(bad), String(bad)).toBe(false)
    }
  })

  test('getLlmFeature throws on an unknown id', () => {
    expect(() => getLlmFeature('nope' as never)).toThrow(/Unknown LLM feature/)
  })

  test('the max model length is 200', () => {
    expect(FEATURE_MODEL_MAX_LEN).toBe(200)
  })
})

describe('exclusions', () => {
  test('the preset generator refuses Bedrock, which its direct provider call cannot run', () => {
    expect(getLlmFeature('preset_generator').excludeModelPrefixes).toEqual(['bedrock/'])
    expect(modelAllowedForFeature('preset_generator', 'bedrock/anthropic.claude-3-5-sonnet')).toBe(false)
    expect(modelAllowedForFeature('preset_generator', 'claude-sonnet-4-5')).toBe(true)
    // A prefix, not a substring.
    expect(modelAllowedForFeature('preset_generator', 'openrouter/bedrock/x')).toBe(true)
  })

  test('no other feature excludes anything', () => {
    for (const f of LLM_FEATURES.filter(f => f.id !== 'preset_generator')) {
      expect(f.excludeModelPrefixes, f.id).toEqual([])
      expect(modelAllowedForFeature(f.id, 'bedrock/anthropic.claude-3-5-sonnet'), f.id).toBe(true)
    }
  })
})

describe('error contract', () => {
  test('status per code', () => {
    expect(FEATURE_MODEL_STATUS).toEqual({
      model_required: 409,
      model_unavailable: 503,
      providers_unreachable: 503,
      agent_unreachable: 503,
      agent_timeout: 504,
      agent_outdated: 502,
    })
  })

  test('only model_required and model_unavailable open the gate', () => {
    expect([...GATE_CODES].sort()).toEqual(['model_required', 'model_unavailable'])
  })

  test('messages', () => {
    expect(featureModelMessage('model_required')).toBe('Choose a model for this feature first')
    expect(featureModelMessage('model_unavailable', 'gpt-4o')).toBe('Your model gpt-4o could not be used')
    expect(featureModelMessage('model_unavailable')).toBe('Your model could not be used')
    expect(featureModelMessage('providers_unreachable')).toBe("Couldn't load your LLM providers, try again")
    expect(featureModelMessage('agent_unreachable')).toBe("The agent service isn't running")
    expect(featureModelMessage('agent_timeout')).toBe('The model took too long, try again')
    expect(featureModelMessage('agent_outdated')).toBe('The agent is older than the webapp: rebuild it')
  })

  test('a provider failure names its class, status and kind of 429', () => {
    expect(providerFailureDetail({ error_class: 'RateLimitError', provider_status: 429 }))
      .toBe('RateLimitError · provider HTTP 429')
    expect(providerFailureDetail({ error_class: 'RateLimitError', provider_status: 429, provider_error_kind: 'quota_exhausted' }))
      .toBe('RateLimitError · provider HTTP 429 · no credit or quota left on the provider account')
    expect(providerFailureDetail({ errorClass: 'ClientError', providerStatus: 429, providerErrorKind: 'rate_limited' }))
      .toBe('ClientError · provider HTTP 429 · rate limited, try again in a minute')
    expect(providerFailureDetail({ provider_status: 429, provider_error_kind: 'constructor' }))
      .toBe('provider HTTP 429')
  })

  test('readFeatureModelCode reads a known code only', () => {
    for (const code of Object.keys(FEATURE_MODEL_STATUS) as FeatureModelCode[]) {
      expect(readFeatureModelCode({ code, error: 'x' })).toBe(code)
    }
    expect(readFeatureModelCode({ code: 'busy' })).toBeNull()
    expect(readFeatureModelCode({ code: 409 })).toBeNull()
    expect(readFeatureModelCode({ error: 'model_required' })).toBeNull()
    expect(readFeatureModelCode(null)).toBeNull()
    expect(readFeatureModelCode('model_required')).toBeNull()
    expect(readFeatureModelCode(undefined)).toBeNull()
  })
})
