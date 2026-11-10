/**
 * A recon evidence snippet, masked again before display: e-mails and digit runs
 * of six or more become placeholders. The route exposure scan already masks
 * them (personal data); this keeps a snippet from an older or foreign writer
 * from showing one. A token stays: a secret the snippet shows is the finding,
 * and the operator reads it whole. Render the result as text, never as HTML.
 */
export function maskSnippet(value: string | null | undefined): string {
  if (!value) return '-'
  return String(value)
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '<email>')
    .replace(/\d{6,}/g, '<n>')
}
