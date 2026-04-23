export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown'

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5,
}

export function normalizeSeverity(raw: unknown): Severity {
  const s = typeof raw === 'string' ? raw.toLowerCase() : ''
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low' || s === 'info') return s
  return 'unknown'
}

export function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

export type RedZoneTableSlug =
  | 'killChain'
  | 'blastRadius'
  | 'takeover'
  | 'secrets'
  | 'netInitAccess'
  | 'graphql'
  | 'webInitAccess'
  | 'paramMatrix'
  | 'sharedInfra'
  | 'dnsEmail'
  | 'threatIntel'
  | 'supplyChain'
  | 'dnsDrift'

export interface RedZoneTableResponse<T> {
  rows: T[]
  meta?: {
    totalRows?: number
    scanTimestamp?: string | null
    [key: string]: unknown
  }
}
