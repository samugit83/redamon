/**
 * The JS Recon table's Secret rows, built from the graph by the download route.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  JS_RECON_TRUFFLEHOG_SOURCE,
  alternateNameLabel,
  detectionMethodLabel,
  jsReconSecretFromRecord,
  secretSourceLabel,
} from './jsReconSecret'

function get(values: Record<string, unknown>) {
  return (key: string) => values[key] ?? null
}

describe('jsReconSecretFromRecord: public client keys (plan 05.2)', () => {
  test('a flagged key is info and says so', () => {
    const row = jsReconSecretFromRecord(get({
      id: 's1', name: 'GCP API Key', severity: 'info', public_client_key: true,
    }))
    expect(row.severity).toBe('info')
    expect(row.public_client_key).toBe(true)
  })

  test('a key written before the flag is judged by its name', () => {
    const row = jsReconSecretFromRecord(get({ id: 's1', name: 'Sentry DSN', severity: 'medium' }))
    expect(row.severity).toBe('info')
    expect(row.public_client_key).toBe(true)
  })

  test('any other secret keeps its severity', () => {
    const row = jsReconSecretFromRecord(get({
      id: 's1', name: 'Stripe Secret Key', severity: 'critical', public_client_key: false,
    }))
    expect(row.severity).toBe('critical')
    expect(row.public_client_key).toBe(false)
  })
})

describe('jsReconSecretFromRecord: validation', () => {
  test('the stored validation details are kept', () => {
    const row = jsReconSecretFromRecord(get({
      id: 's1', name: 'GitHub Token Classic', validation_status: 'validated',
      validation_info: JSON.stringify({ status: 'validated', scope: 'repo', info: 'user=x' }),
    }))
    expect(row.validation).toEqual({ status: 'validated', scope: 'repo', info: 'user=x' })
  })

  test('no status at all is unvalidated', () => {
    expect(jsReconSecretFromRecord(get({ id: 's1', name: 'X' })).validation).toEqual({ status: 'unvalidated' })
  })

  test('the stored status wins over the one inside the details', () => {
    // validation_status is what the Red Zone, the mute rules and the board read;
    // the details are the validator's answer as written at scan time.
    const row = jsReconSecretFromRecord(get({
      id: 's1', name: 'Stripe Secret Key', validation_status: 'rejected',
      validation_info: JSON.stringify({ status: 'skipped', info: 'status=401' }),
    }))
    expect(row.validation).toEqual({ status: 'rejected', info: 'status=401' })
  })

  test('unreadable details fall back to the status', () => {
    const row = jsReconSecretFromRecord(get({ id: 's1', name: 'X', validation_status: 'skipped', validation_info: '{not json' }))
    expect(row.validation).toEqual({ status: 'skipped' })
  })
})

describe('jsReconSecretFromRecord: line and alternate names (TruffleHog plan 1.10)', () => {
  test('a neo4j Integer line number becomes a number', () => {
    const row = jsReconSecretFromRecord(get({ id: 's1', name: 'X', line_number: { low: 42, high: 0 } }))
    expect(row.line_number).toBe(42)
  })

  test('a plain number line is kept', () => {
    expect(jsReconSecretFromRecord(get({ id: 's1', name: 'X', line_number: 7 })).line_number).toBe(7)
  })

  test('the stored names are kept as written', () => {
    const row = jsReconSecretFromRecord(get({
      id: 's1', name: 'GitHub Token Classic', detection_method: 'regex',
      alternate_names: ['Generic API Key', 'TruffleHog:Github'],
    }))
    expect(row.alternate_names).toEqual(['Generic API Key', 'TruffleHog:Github'])
    expect(row.detection_method).toBe('regex')
  })

  test('a node written before the properties has neither', () => {
    const row = jsReconSecretFromRecord(get({ id: 's1', name: 'X' }))
    expect(row.line_number).toBeNull()
    expect(row.alternate_names).toBeNull()
  })

  test('junk in the list is dropped, not shown', () => {
    const row = jsReconSecretFromRecord(get({ id: 's1', name: 'X', alternate_names: ['A', '', 3, null] }))
    expect(row.alternate_names).toEqual(['A'])
  })

  test('the TruffleHog verdict inside validation_info survives', () => {
    const trufflehog = { detector: 'Github', verified: false, error_class: 'timeout', extra: {} }
    const row = jsReconSecretFromRecord(get({
      id: 's1', name: 'GitHub Token Classic', detection_method: 'trufflehog', validation_status: 'unknown',
      validation_info: JSON.stringify({ status: 'unknown', trufflehog }),
    }))
    expect(row.validation).toEqual({ status: 'unknown', trufflehog })
  })
})

describe('labels', () => {
  test('a js_recon Secret only TruffleHog found reads as TruffleHog (JS Recon)', () => {
    expect(JS_RECON_TRUFFLEHOG_SOURCE).toBe('TruffleHog (JS Recon)')
    expect(secretSourceLabel('js_recon', 'trufflehog')).toBe('TruffleHog (JS Recon)')
  })

  test('every other source keeps its stored name', () => {
    expect(secretSourceLabel('js_recon', 'regex')).toBe('js_recon')
    expect(secretSourceLabel('js_recon', null)).toBe('js_recon')
    // Only js_recon writes TruffleHog rows as :Secret; another source is not relabelled.
    expect(secretSourceLabel('resource_enum', 'trufflehog')).toBe('resource_enum')
    expect(secretSourceLabel(null, 'trufflehog')).toBeNull()
    expect(secretSourceLabel('', 'regex')).toBeNull()
  })

  test('Detection reads TruffleHog or Regex, and nothing for an old node', () => {
    expect(detectionMethodLabel('trufflehog')).toBe('TruffleHog')
    expect(detectionMethodLabel('regex')).toBe('Regex')
    expect(detectionMethodLabel('entropy')).toBe('entropy')
    expect(detectionMethodLabel(null)).toBeNull()
    expect(detectionMethodLabel(undefined)).toBeNull()
  })

  test('a TruffleHog alternate name reads as TruffleHog (<detector>)', () => {
    expect(alternateNameLabel('TruffleHog:Github')).toBe('TruffleHog (Github)')
    expect(alternateNameLabel('TruffleHog:GoogleGeminiAPIKey')).toBe('TruffleHog (GoogleGeminiAPIKey)')
    expect(alternateNameLabel('Generic API Key')).toBe('Generic API Key')
    expect(alternateNameLabel('TruffleHog:')).toBe('TruffleHog:')
  })
})
