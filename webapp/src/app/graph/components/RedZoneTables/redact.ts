/**
 * A recon evidence snippet, masked again before display: e-mails, digit runs of
 * six or more and token-shaped strings become placeholders. The route exposure
 * scan already masks them (the agent reads the snippet too); this keeps a
 * snippet from an older or foreign writer from showing a value. The secrets a
 * response held are shown whole-on-copy in the Secrets column instead. Render
 * the result as text, never as HTML.
 */
export function maskSnippet(value: string | null | undefined): string {
  if (!value) return '-'
  return String(value)
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '<email>')
    .replace(/[A-Za-z0-9_\-+/=]{20,}/g, '<tok>')
    .replace(/\d{6,}/g, '<n>')
}
