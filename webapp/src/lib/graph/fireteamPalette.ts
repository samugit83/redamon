/**
 * Fireteam (multi-agent) color palette for graph visualization.
 *
 * When the "Color by wave" overlay is active in the chain graph canvas,
 * nodes with a `fireteam_id` / `agent_id` should be colored by a stable
 * hash so each member has a consistent color within a wave and across
 * sessions.
 */

export const AGENT_PALETTE: readonly string[] = [
  '#e91e63', // pink
  '#9c27b0', // purple
  '#673ab7', // deep purple
  '#3f51b5', // indigo
  '#2196f3', // blue
  '#03a9f4', // light blue
  '#00bcd4', // cyan
  '#009688', // teal
  '#4caf50', // green
  '#8bc34a', // light green
  '#ff9800', // orange
  '#ff5722', // deep orange
] as const

/**
 * Deterministic color for an agent identifier. Uses a cheap non-crypto
 * string hash (same key -> same color across reloads and sessions).
 */
export function agentColor(agentId: string | null | undefined): string {
  if (!agentId) return '#6b7280' // neutral gray for root / unattributed
  let h = 0
  for (let i = 0; i < agentId.length; i++) {
    h = ((h << 5) - h) + agentId.charCodeAt(i)
    h |= 0
  }
  return AGENT_PALETTE[Math.abs(h) % AGENT_PALETTE.length]
}

/**
 * Color for a fireteam as a whole (distinct from per-member colors).
 * Used for cards and wave-level badges; uses the same palette but hashes
 * on the fireteam_id so the parent and its members are visually linked.
 */
export function fireteamColor(fireteamId: string | null | undefined): string {
  if (!fireteamId) return '#3b82f6' // default blue accent
  return agentColor(fireteamId)
}
