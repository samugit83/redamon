/**
 * Hostnames on target IPs: the settings an IP-mode project's hostname mode forces.
 *
 * The rule is `_IP_HOSTNAME_FORCED` in `recon/project_settings.py`, applied at
 * scan start by `apply_ip_hostname_overrides`. A stored toggle the mode forbids
 * (tlsx's reverse-PTR SNI, Shodan's reverse DNS, graph names for vhost/SNI) keeps
 * its stored value and is ignored by the run, so readers of the row need this
 * copy to say which value a run will not use: MCP `get_recon_settings` returns it
 * as `effective_overrides`, and the form disables those toggles (P8).
 *
 * Keyed by Prisma column. `recon/tests/test_ip_hostname_overrides.py` parses this
 * object and holds it equal to the Python table, so keep its literal shape: one
 * `mode: { column: boolean, ... }` line per mode.
 */
import type { IpHostnameMode } from '@/lib/ipHostnameFilter'
import { ipHostnameModeOf } from '@/lib/scopeGroups'

export const IP_HOSTNAME_FORCED: Readonly<Record<IpHostnameMode, Readonly<Record<string, boolean>>>> = {
  ip_only: { tlsxRevPtrSni: false, shodanReverseDns: false, vhostSniUseGraphCandidates: false },
  record_only: { tlsxRevPtrSni: false },
  record_filter: { tlsxRevPtrSni: false },
  scan_all: { tlsxRevPtrSni: false },
}

export interface EffectiveOverride {
  /** The Prisma column, as `get_recon_settings` names it. */
  key: string
  /** The value every run of this project uses, whatever is stored. */
  value: boolean
  reason: string
}

/** The forced settings for this row; none outside IP mode. An unknown or absent
 *  mode is ip_only, the strictest row, as in recon. */
export function ipHostnameOverrides(row: { ipMode?: unknown; ipHostnameMode?: unknown }): EffectiveOverride[] {
  if (row.ipMode !== true) return []
  const mode = ipHostnameModeOf(row.ipHostnameMode)
  return Object.entries(IP_HOSTNAME_FORCED[mode]).map(([key, value]) => ({
    key,
    value,
    reason: `forced by Hostnames on target IPs: ${mode}`,
  }))
}
