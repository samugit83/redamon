/**
 * Hostnames on target IPs: the copy behind the four mode cards, their info
 * modals and diagrams.
 *
 * The labels come from lib/ipHostnameModeLabels.ts, the one source every other
 * surface that names a mode reads (lib/ readers import it directly, never this
 * file). The behaviour this text describes is recon_settings/ip_hostnames.py and
 * recon/project_settings.py; when that changes, this text changes with it
 * (02_target_design.md §1, 04_ui_spec.md §3).
 */
import type { IpHostnameMode } from '@/lib/ipHostnameFilter'
import { IP_HOSTNAME_MODE_LABELS as LABELS } from '@/lib/ipHostnameModeLabels'

export type { IpHostnameMode }
export { IP_HOSTNAME_SECTION_LABEL, ipHostnameModeLabel } from '@/lib/ipHostnameModeLabels'

/** One configuration of the diagram (04_ui_spec.md §4). */
export interface DiagramSpec {
  /** The discover lane: drawn dashed with "off" when no name is looked up. */
  discover: 'off' | 'active'
  /** M4's "Passive search of *.filters" chip under the discover lane. */
  passiveChip: boolean
  decide: { text: string; dimmed: boolean; confirmedChip: boolean }
  /** The names box of the scan lane; null when no name is scanned. */
  scanNames: string | null
  /** What the graph strip draws, from least to most. */
  graph: 'ip' | 'recorded' | 'scanned'
  graphCaption: string
  traffic: string
  /** What a screen reader hears for the whole diagram. */
  ariaLabel: string
}

export interface IpHostnameModeInfo {
  mode: IpHostnameMode
  label: string
  badge?: 'DEFAULT' | 'NEEDS CONFIRM'
  /** One line on the card. */
  summary: string
  /** Modal: "In one sentence". */
  sentence: string
  whenToUse: string[]
  whenNotToUse: string[]
  /** "What RedAmon does", in order. */
  steps: string[]
  /** "What you will see in the graph". */
  graph: string[]
  traffic: { targets: string; lookups: string }
  guarantees: string[]
  /** Shown in red under the guarantees (M1's confirmation). */
  warning?: string
  example: { setup: string; outcome: string[] }
  diagram: DiagramSpec
}

const CREDENTIALS =
  'Login credentials from an auth profile go to the target IPs only, never to a hostname (in every mode).'
const GUARDRAIL = 'The permanent guardrail (government, military, education) and your RoE exclusions apply to every name.'

export const IP_HOSTNAME_MODES: readonly IpHostnameModeInfo[] = [
  {
    mode: 'ip_only',
    label: LABELS.ip_only,
    badge: 'DEFAULT',
    summary: 'Scan the addresses only. No hostname lookups.',
    sentence:
      'RedAmon scans your IP addresses and nothing else: it never looks up, records or uses hostnames.',
    whenToUse: [
      'Network and infrastructure tests.',
      'The client gave you addresses only.',
      'Shared hosting, where the sites are not yours to test.',
      'Private ranges: reverse DNS and passive sources see nothing there anyway.',
      'The fastest run, with no lookups about names at all.',
    ],
    whenNotToUse: [
      'You need the websites hosted on the IP tested by name (an HTTPS site usually answers only to its ' +
        'name): use Record + scan matching.',
    ],
    steps: [
      'Expands your CIDRs and removes the RoE exclusions.',
      'Port scan, TLS certificates and HTTP(S) on every IP, by address.',
      'Crawls and vulnerability checks on the live IP URLs.',
      'Passive lookups about the IPs only (ports, CVEs, ownership).',
    ],
    graph: [
      'One IP node per address (with a placeholder name), its ports, services and certificates.',
      'URLs like https://203.0.113.10.',
      'No hostnames.',
    ],
    traffic: {
      targets: 'Packets go to your IPs only.',
      lookups: 'No reverse DNS and no hostname lookups. VHost/SNI tries only the names of your own custom wordlist.',
    },
    guarantees: [
      'No packet leaves your target list.',
      'No reverse DNS, no passive DNS call, and no hostname sent as SNI or Host.',
      CREDENTIALS,
    ],
    example: {
      setup: '203.0.113.10 hosts app.example.com and shop.example.de.',
      outcome: ["RedAmon tests https://203.0.113.10 (the server's default site) only."],
    },
    diagram: {
      discover: 'off',
      passiveChip: false,
      decide: { text: 'Nothing to decide', dimmed: true, confirmedChip: false },
      scanNames: null,
      graph: 'ip',
      graphCaption: 'IP + certificates only',
      traffic: 'Packets → your IPs only. No hostname lookups.',
      ariaLabel:
        'No hostname is discovered: the IP addresses are scanned by address only, and the graph holds the ' +
        'IPs and their certificates.',
    },
  },
  {
    mode: 'record_only',
    label: LABELS.record_only,
    summary: 'Find the sites hosted on your IPs and save them. Scan the IPs only.',
    sentence:
      'RedAmon finds the hostnames that live on your IPs and saves them to the graph, but scans only the IPs.',
    whenToUse: [
      'A first run on a new engagement: see which sites live on the IPs before deciding anything.',
      'Inventory and reporting.',
      'Third-party engagements where the authorisation covers addresses, not names.',
    ],
    whenNotToUse: [
      'You want the names themselves tested: use Record + scan matching.',
      'Private ranges with no internal DNS: there is nothing to find, so IP only is faster.',
    ],
    steps: [
      'Everything IP only does.',
      'Reverse DNS (every answer), the names in TLS certificates, passive DNS from the OSINT sources you ' +
        'enabled, and redirect targets.',
      'Saves each name with where it came from and why it was not scanned.',
    ],
    graph: [
      'Grey ExternalDomain nodes linked to the IP they were seen on (SEEN_ON), with the sources, the dates, ' +
        '"resolves here now" and "certificate covers it".',
      'After each full run they count as new rows in the graph tables\' "unseen" badges, like every node a ' +
        'run recreates, so a large badge on shared hosting is expected.',
    ],
    traffic: {
      targets: 'Packets go to your IPs only. VHost/SNI may try the recorded names, on your IPs only.',
      lookups: 'DNS and OSINT API lookups about the names (no packets to the sites themselves).',
    },
    guarantees: [
      'Recorded names are never targets: nothing is scanned by name.',
      'IP attribution counts the names seen on each IP as evidence for spotting shared hosting.',
      CREDENTIALS,
    ],
    example: {
      setup: '203.0.113.10 hosts app.example.com and shop.example.de.',
      outcome: [
        'The graph shows app.example.com and shop.example.de on 203.0.113.10, reason "recorded only".',
        'Switch to Record + scan matching to test them.',
      ],
    },
    diagram: {
      discover: 'active',
      passiveChip: false,
      decide: { text: 'Record all · scan none', dimmed: false, confirmedChip: false },
      scanNames: null,
      graph: 'recorded',
      graphCaption: 'IP + grey ExternalDomains',
      traffic: 'Packets → your IPs only. + DNS/API lookups about the names → resolvers and OSINT services.',
      ariaLabel:
        'Hostnames are discovered from reverse DNS, certificates, passive DNS and redirects and saved to the ' +
        'graph with the IP they were seen on; none is scanned, only the IPs are.',
    },
  },
  {
    mode: 'record_filter',
    label: LABELS.record_filter,
    summary: 'Also scan the names that match your filters, only on your IPs.',
    sentence:
      'As Record hostnames, then RedAmon also scans the names matching your filters, and only when they point ' +
      'to your IPs.',
    whenToUse: [
      'The client owns specific domains hosted on these IPs (for example *.example.com, *.example.de, ' +
        '*.example.fr) and you want them tested by name, on these IPs only.',
    ],
    whenNotToUse: [
      'A site that also runs on servers outside your target list: a name that points to another server is ' +
        'never scanned (reason "points outside your IPs").',
    ],
    steps: [
      'Everything IP only does.',
      'Finds and saves the hostnames on your IPs, as Record hostnames does.',
      'Optionally searches public sources for more subdomains of your *. filter domains.',
      'Keeps the names matching Include and not Exclude (exclude wins).',
      'Checks DNS right before scanning: every address must be one of your IPs.',
      'Scans the kept names on their IP (reusing the port scan), then crawls and vulnerability-checks them ' +
        'like the IPs.',
    ],
    graph: [
      'Scanned names become coloured Subdomain nodes under their domain (e.g. example.com), with URLs like ' +
        'https://app.example.com.',
      'Refused names stay grey ExternalDomains with the reason.',
    ],
    traffic: {
      targets: 'Packets go to your IPs only, now with the names as SNI/Host.',
      lookups: 'DNS lookups about the names. Passive searches go to public APIs only.',
    },
    guarantees: [
      'A name is scanned only when every address it resolves to right before the scan is one of your IPs.',
      GUARDRAIL,
      'At most the per-run limit of names is scanned.',
      CREDENTIALS,
    ],
    example: {
      setup: 'Include *.example.com, on 203.0.113.10.',
      outcome: [
        'app.example.com is scanned on 203.0.113.10.',
        'shop.example.de is recorded ("matches no include entry").',
        'old.example.com, also on 198.51.100.7, is recorded ("points outside your IPs").',
      ],
    },
    diagram: {
      discover: 'active',
      passiveChip: true,
      decide: {
        text: 'Include − Exclude → DNS check: every address is one of your IPs → limit',
        dimmed: false,
        confirmedChip: false,
      },
      scanNames: 'Matching names, on your IPs',
      graph: 'scanned',
      graphCaption: '+ Subdomains under their Domain',
      traffic: 'Packets → your IPs only, + names sent as SNI/Host. DNS/API lookups → resolvers, OSINT services ' +
        'and passive search APIs.',
      ariaLabel:
        'Hostnames are discovered from reverse DNS, certificates, passive DNS and redirects, filtered by your ' +
        'include and exclude lists, checked to point only to your IPs, then scanned on your IPs; refused names ' +
        'are saved with the reason.',
    },
  },
  {
    mode: 'scan_all',
    label: LABELS.scan_all,
    badge: 'NEEDS CONFIRM',
    summary: 'Scan every name found on your IPs, except CDN edges.',
    sentence:
      'As Record hostnames, then RedAmon scans every name found on your IPs that points only to them, except on ' +
      'CDN edge addresses.',
    whenToUse: ['Your own dedicated servers (internal engagement), where everything on them is yours.'],
    whenNotToUse: [
      'Shared hosting or CDN ranges.',
      'Any third-party engagement: refused.',
    ],
    steps: [
      'Everything IP only does.',
      'Finds and saves the hostnames on your IPs, as Record hostnames does.',
      'Skips every name seen on an IP that IP attribution identified as a shared CDN or hosting edge (and every ' +
        'name when attribution did not run).',
      'Checks DNS right before scanning: every address must be one of your IPs.',
      'Scans the names on their IP up to the per-run limit, then crawls and vulnerability-checks them like the IPs.',
    ],
    graph: [
      'Scanned names become coloured Subdomain nodes under their domain (e.g. example.com), with URLs like ' +
        'https://app.example.com.',
      'Refused names stay grey ExternalDomains with the reason.',
    ],
    traffic: {
      targets: 'Packets go to your IPs only, now with the names as SNI/Host.',
      lookups: 'DNS lookups about the names.',
    },
    guarantees: [
      'A name is scanned only when every address it resolves to right before the scan is one of your IPs.',
      'Names on CDN edge addresses are never scanned.',
      GUARDRAIL,
      CREDENTIALS,
    ],
    warning: 'You must confirm that every site hosted on these IPs is in scope.',
    example: {
      setup: '203.0.113.10 is your own server, hosting app.example.com and intranet.example.org.',
      outcome: [
        'Both names are scanned on 203.0.113.10 once DNS shows they point only there.',
        'A name seen on 203.0.113.20, identified as a CDN edge, is recorded ("seen on a shared CDN or hosting ' +
          'edge address").',
      ],
    },
    diagram: {
      discover: 'active',
      passiveChip: false,
      decide: { text: 'All names → skip CDN edges → DNS check → limit', dimmed: false, confirmedChip: true },
      scanNames: 'All eligible names, on your IPs',
      graph: 'scanned',
      graphCaption: '+ Subdomains under their Domain',
      traffic: 'Packets → your IPs only, + names sent as SNI/Host. DNS/API lookups → resolvers and OSINT services.',
      ariaLabel:
        'Hostnames are discovered from reverse DNS, certificates, passive DNS and redirects; every name not on a ' +
        'CDN edge and checked to point only to your IPs is scanned on your IPs, up to the limit; refused names ' +
        'are saved with the reason.',
    },
  },
]

const BY_MODE = new Map(IP_HOSTNAME_MODES.map(m => [m.mode, m]))

/** The info for a mode; an unknown or absent mode is ip_only, as in recon. */
export function ipHostnameModeInfo(mode: unknown): IpHostnameModeInfo {
  return BY_MODE.get(mode as IpHostnameMode) ?? IP_HOSTNAME_MODES[0]
}

/** "Compare all four modes" (04_ui_spec.md §3.5), one row per question. */
export const IP_HOSTNAME_COMPARISON: readonly { question: string; answers: Record<IpHostnameMode, string> }[] = [
  {
    question: 'Looks up hostnames',
    answers: { ip_only: 'No', record_only: 'Yes', record_filter: 'Yes', scan_all: 'Yes' },
  },
  {
    question: 'Saves hostnames in the graph',
    answers: { ip_only: 'No', record_only: 'Yes', record_filter: 'Yes', scan_all: 'Yes' },
  },
  {
    question: 'Scans hostnames',
    answers: { ip_only: 'No', record_only: 'No', record_filter: 'Matching your filters', scan_all: 'All (not CDN edges)' },
  },
  {
    question: 'Packets only to your IPs',
    answers: { ip_only: 'Yes', record_only: 'Yes', record_filter: 'Yes', scan_all: 'Yes' },
  },
  {
    question: 'Needs confirmation',
    answers: { ip_only: 'No', record_only: 'No', record_filter: 'No', scan_all: 'Yes' },
  },
  {
    question: 'Third-party engagements',
    answers: { ip_only: 'Yes', record_only: 'Yes', record_filter: 'Yes (authorisation)', scan_all: 'No' },
  },
]
