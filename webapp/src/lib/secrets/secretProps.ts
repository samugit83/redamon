/**
 * The graph properties that hold a secret, or a URL with its secret left in it.
 *
 * Recon keeps them beside the masked fields so the operator can read, copy and
 * open them; the masked fields stay the identities and the request inputs.
 * Mirrors graph_db/display_only.py (tests/test_display_only.py keeps the two
 * equal).
 */

/** A secret itself: shown as its last four characters with a copy button. */
export const SECRET_VALUE_PROPS: ReadonlySet<string> = new Set([
  'secret_value',
  'paired_secret',
  'secret_values',
])

/** A URL or text with a secret left in it: shown whole, links clickable. */
export const UNMASKED_PROPS: ReadonlySet<string> = new Set([
  'unmasked_url',
  'unmasked_urls',
  'unmasked_start_url',
  'unmasked_redirect_from_url',
  'unmasked_redirect_from_urls',
  'raw_context',
])

export const DISPLAY_ONLY_PROPS: ReadonlySet<string> = new Set([
  'secret_value',
  'paired_secret',
  'secret_values',
  'unmasked_url',
  'unmasked_urls',
  'unmasked_start_url',
  'unmasked_redirect_from_url',
  'unmasked_redirect_from_urls',
  'raw_context',
])

/**
 * Whether a node property holds a secret value. `matched_text` is one only on a
 * Secret node (JS Recon's full match); elsewhere it is ordinary evidence text.
 */
export function isSecretValueProp(key: string, nodeType?: string | null): boolean {
  if (SECRET_VALUE_PROPS.has(key)) return true
  return key === 'matched_text' && nodeType === 'Secret'
}
