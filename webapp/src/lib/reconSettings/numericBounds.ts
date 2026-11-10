/**
 * The registry bounds the MCP write tools apply to a number, for the routes that
 * write Project columns without `filterReconSettings`: the form's create and
 * save, and the project import (R-7).
 *
 * Refused in the MCP validator's own words, never clamped, so the two doors
 * give one verdict per value. Without it those routes were the way around the
 * bounds: a `nucleiRateLimit: 0` the MCP tools refuse was stored there, and
 * nuclei then ran at its built-in rate.
 *
 * Only numbers: the other validators judge text the form legitimately writes
 * differently from an MCP caller (a header list, an optional id), and widening
 * them here would refuse saves the form has always made.
 */
import { field } from './registry'
import { validateValue } from './validators'

export interface NumericBoundsRefusal {
  key: string
  error: string
}

/**
 * The first registry-bounded number in `data` the MCP validator refuses, or null.
 *
 * `skip` names the keys not to judge: the form's save passes the ones it sends
 * back unchanged, so a number stored before its bound existed does not block an
 * unrelated edit.
 */
export function numericBoundsRefusal(
  data: Record<string, unknown>,
  skip: (key: string) => boolean = () => false,
): NumericBoundsRefusal | null {
  for (const [key, value] of Object.entries(data)) {
    const spec = field(key)
    if (!spec?.bounds || (spec.type !== 'int' && spec.type !== 'float')) continue
    if ((value === null && spec.optional) || skip(key)) continue
    const problem = validateValue(key, spec, value)
    if (problem) return { key, error: `'${key}' ${problem}` }
  }
  return null
}
