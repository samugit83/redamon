export function formatTokenCount(n: number): string {
  const v = Math.max(0, Math.round(n || 0))
  if (v < 1000) return String(v)
  if (v < 1_000_000) return `${Math.round(v / 1000)}k`
  const m = v / 1_000_000
  return m >= 10 ? `${Math.round(m)}M` : `${m.toFixed(1)}M`
}
