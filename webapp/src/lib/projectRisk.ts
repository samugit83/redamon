/**
 * One number for "how much risk is this project carrying", computed one way.
 *
 * There were three separate scoring systems in the product: the Priority
 * Board's, the report's, and the Insights gauge's. The last two shared a
 * weighted-sum-then-log formula whose real problem was not the weights but the
 * shape: it added a term per finding, so it measured how BIG a project is at
 * least as much as how exposed it is. Scanning more hosts raised the risk score
 * even when every new finding was a missing header, and there was no way to say
 * "these ten findings are all the same CVE, so fixing it once clears them".
 *
 * This uses the same probability the Priority Board already computes per
 * finding. If each finding has an independent chance `r` of being exploited,
 * the chance that AT LEAST ONE of them is is:
 *
 *     1 - PROD(1 - r)
 *
 * which is what "how much risk am I carrying" actually means. It rises with
 * diminishing returns, it can never exceed 100, and one genuinely dangerous
 * finding moves it more than fifty missing headers, because that is true.
 *
 * The top 20 is a deliberate cut: past that, the terms are so small that
 * including them only adds noise, and it keeps the number stable as a scan
 * turns up more low-value findings.
 */

/** The number of findings that contribute. See the note above. */
export const RISK_TOP_N = 20

export interface RiskFinding {
  /** `triage_risk`: C x L x I x R, before the tier is folded into the score. */
  triage_risk?: number | null
  triage_state?: string | null
  triage_status?: string | null
}

export type RiskLabel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Minimal'

export interface ProjectRisk {
  score: number
  label: RiskLabel
  /** How many findings actually contributed. 0 means "not measured". */
  contributing: number
  /** True when no triage run has produced the per-finding risks yet. */
  unmeasured: boolean
}

export function riskLabel(score: number): RiskLabel {
  if (score >= 80) return 'Critical'
  if (score >= 60) return 'High'
  if (score >= 40) return 'Medium'
  if (score >= 20) return 'Low'
  return 'Minimal'
}

/**
 * The project's risk from its findings' own risks.
 *
 * Returns `unmeasured` when nothing has been triaged. The caller must NOT
 * render that as 0: a project nobody has triaged is not a safe project, and
 * showing it as one is worse than showing nothing.
 */
export function projectRisk(findings: RiskFinding[]): ProjectRisk {
  const risks = (findings ?? [])
    .filter((f) => {
      // Only findings that are actually open. A fixed or false-positive one
      // carrying an old risk would keep inflating the number for ever.
      const state = f.triage_state ?? 'open'
      if (state !== 'open') return false
      if (f.triage_status === 'likely_noise') return false
      return typeof f.triage_risk === 'number' && Number.isFinite(f.triage_risk)
    })
    .map((f) => Math.min(1, Math.max(0, f.triage_risk as number)))
    .sort((a, b) => b - a)
    .slice(0, RISK_TOP_N)

  if (risks.length === 0) {
    return { score: 0, label: 'Minimal', contributing: 0, unmeasured: true }
  }

  let survives = 1
  for (const r of risks) survives *= 1 - r
  const score = Math.round(100 * (1 - survives))
  return {
    score,
    label: riskLabel(score),
    contributing: risks.length,
    unmeasured: false,
  }
}
