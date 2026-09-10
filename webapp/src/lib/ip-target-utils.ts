/**
 * Helpers for reasoning about IP-mode targets in the project form.
 *
 * The recon UI needs to warn a user when their IP targets are on a
 * private/local network: passive OSINT (Shodan, Censys, crt.sh, ...) only
 * indexes the public internet, so it returns nothing for RFC1918 space, and
 * public subdomain enumeration / WHOIS are equally useless there. Detecting
 * this lets the form nudge the user toward an internal-network configuration
 * instead of silently running lookups that can never return data.
 *
 * This is a best-effort classifier for UI guidance only. It is intentionally
 * lenient: anything it cannot parse is treated as "not clearly private" so the
 * form never blocks a scan on a parsing edge case.
 */

export type IpTargetClass = 'empty' | 'private' | 'public' | 'mixed'

/** IPv4 private / local / non-routable ranges, as [firstOctet-based] checks. */
function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split('.')
  if (parts.length !== 4) return false
  const octets = parts.map((p) => Number(p))
  if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return false
  const [a, b] = octets
  if (a === 10) return true // 10.0.0.0/8
  if (a === 127) return true // 127.0.0.0/8 loopback
  if (a === 172 && b >= 16 && b <= 31) return true // 172.16.0.0/12
  if (a === 192 && b === 168) return true // 192.168.0.0/16
  if (a === 169 && b === 254) return true // 169.254.0.0/16 link-local
  if (a === 100 && b >= 64 && b <= 127) return true // 100.64.0.0/10 CGNAT
  return false
}

/** IPv6 private / local ranges: ULA (fc00::/7), link-local (fe80::/10), loopback (::1). */
function isPrivateIpv6(ip: string): boolean {
  const lower = ip.toLowerCase()
  if (lower === '::1') return true
  const firstHextet = lower.split(':')[0]
  if (!firstHextet) return false // leading "::" -> unspecified / loopback-ish, not clearly public
  // ULA fc00::/7 -> first hextet starts fc or fd
  if (firstHextet.startsWith('fc') || firstHextet.startsWith('fd')) return true
  // link-local fe80::/10 -> fe8, fe9, fea, feb
  if (/^fe[89ab]/.test(firstHextet)) return true
  return false
}

/**
 * True when a single IP or CIDR entry is on a private / local / non-routable
 * range. For a CIDR, the network address is what is classified.
 */
export function isPrivateOrLocalIp(entry: string): boolean {
  const trimmed = entry.trim()
  if (!trimmed) return false
  const addr = trimmed.split('/')[0].trim() // strip CIDR suffix
  if (addr.includes(':')) return isPrivateIpv6(addr)
  return isPrivateIpv4(addr)
}

/**
 * Classify a list of IP / CIDR targets:
 * - 'empty'   : nothing entered
 * - 'private' : every entry is on a private/local range
 * - 'public'  : every entry is public (or unparseable, treated as public)
 * - 'mixed'   : a blend of private and public entries
 */
export function classifyIpTargets(targetIps: string[] | null | undefined): IpTargetClass {
  const entries = (targetIps ?? []).map((e) => e.trim()).filter(Boolean)
  if (entries.length === 0) return 'empty'
  let priv = 0
  for (const e of entries) {
    if (isPrivateOrLocalIp(e)) priv += 1
  }
  if (priv === 0) return 'public'
  if (priv === entries.length) return 'private'
  return 'mixed'
}
