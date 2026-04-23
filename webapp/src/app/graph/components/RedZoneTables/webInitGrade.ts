/**
 * Grading rubric for the Web Initial-Access Panel.
 * Combines missing security-header count with present-vulnerability-tag count
 * into a single A-F grade for scannable report delivery.
 *
 * Thresholds (total = missing headers + vuln tags):
 *   0-1 → A   (clean)
 *   2   → B
 *   3   → C
 *   4-5 → D
 *   6+  → F
 */

export const WEB_INIT_HEADER_CHECKS = [
  'Content-Security-Policy',
  'Strict-Transport-Security',
  'X-Frame-Options',
  'X-Content-Type-Options',
  'Referrer-Policy',
  'Permissions-Policy',
] as const

export type WebInitGrade = 'A' | 'B' | 'C' | 'D' | 'F'

export function computeWebInitGrade(missingCount: number): WebInitGrade {
  if (missingCount >= 6) return 'F'
  if (missingCount >= 4) return 'D'
  if (missingCount >= 3) return 'C'
  if (missingCount >= 2) return 'B'
  return 'A'
}

/**
 * Build the present/missing matrix for the standard header checklist from a
 * list of security-header names observed on a BaseURL. Comparison is
 * case-insensitive to tolerate "Content-Security-Policy" vs "content-security-policy".
 */
export function buildHeaderGrid(presentHeaderNames: string[]): Record<string, boolean> {
  const seen = new Set((presentHeaderNames || []).map(h => (h || '').toLowerCase()))
  const grid: Record<string, boolean> = {}
  for (const h of WEB_INIT_HEADER_CHECKS) grid[h] = seen.has(h.toLowerCase())
  return grid
}

/**
 * Aggregate grade derivation: count missing headers, add vuln-tag count,
 * return {grade, missingHeaderCount}.
 */
export function deriveWebInitGrade(
  presentHeaderNames: string[],
  vulnTags: string[],
): { grade: WebInitGrade; headerGrid: Record<string, boolean>; missingHeaderCount: number } {
  const headerGrid = buildHeaderGrid(presentHeaderNames)
  const missingHeaderCount = WEB_INIT_HEADER_CHECKS.filter(h => !headerGrid[h]).length
  const total = missingHeaderCount + (vulnTags?.length || 0)
  return { grade: computeWebInitGrade(total), headerGrid, missingHeaderCount }
}
