/**
 * The resource's ingestion focus (§6.14), as the form sends it. Phase 5 (T5.5) defines the
 * fields; until then a resource has no focus, so only an empty one is accepted.
 */
export type FocusResult = { ok: true; value: Record<string, never> } | { ok: false; error: string }

export function validateFocus(input: unknown): FocusResult {
  if (input === undefined) return { ok: true, value: {} }
  if (input && typeof input === 'object' && !Array.isArray(input) && Object.keys(input).length === 0) {
    return { ok: true, value: {} }
  }
  return { ok: false, error: 'An ingestion focus cannot be set yet' }
}
