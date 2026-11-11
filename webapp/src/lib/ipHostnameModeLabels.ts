/**
 * Hostnames on target IPs: the name of each mode as every surface shows it.
 *
 * The one source of these labels. The form's mode cards and info modals
 * (components/projects/ProjectForm/ipHostnameModes.ts) take them from here, and
 * so do the lib/ readers that name a mode (project summary, report), which must
 * not import from the components folder.
 */
import type { IpHostnameMode } from '@/lib/ipHostnameFilter'

export const IP_HOSTNAME_MODE_LABELS: Readonly<Record<IpHostnameMode, string>> = {
  ip_only: 'IP only',
  record_only: 'Record hostnames',
  record_filter: 'Record + scan matching',
  scan_all: 'Record + scan all',
}

/** The section's own name, used wherever the setting is referred to. */
export const IP_HOSTNAME_SECTION_LABEL = 'Hostnames on target IPs'

/** The label of a mode; an unknown or absent mode is ip_only, as in recon. */
export function ipHostnameModeLabel(mode: unknown): string {
  return Object.prototype.hasOwnProperty.call(IP_HOSTNAME_MODE_LABELS, mode as string)
    ? IP_HOSTNAME_MODE_LABELS[mode as IpHostnameMode]
    : IP_HOSTNAME_MODE_LABELS.ip_only
}
