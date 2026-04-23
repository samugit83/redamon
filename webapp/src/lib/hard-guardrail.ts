/**
 * Hard Guardrail — deterministic, non-disableable check for government/public domains.
 *
 * Blocks government, military, education, and international organization domains
 * regardless of project settings. This check cannot be toggled off.
 *
 * Mirror of agentic/hard_guardrail.py — keep patterns in sync.
 */

// TLD suffix patterns (case-insensitive)
const TLD_PATTERNS: RegExp[] = [
  // Government
  /\.gov$/i,
  /\.gov\.[a-z]{2,3}$/i,
  /\.gob\.[a-z]{2,3}$/i,
  /\.gouv\.[a-z]{2,3}$/i,
  /\.govt\.[a-z]{2,3}$/i,
  /\.go\.[a-z]{2}$/i,            // .go.jp, .go.kr, .go.id (2-letter ccTLDs only to avoid .go.dev etc.)
  /\.gv\.[a-z]{2}$/i,            // .gv.at (Austria) (2-letter ccTLDs only)
  /\.government\.[a-z]{2,3}$/i,

  // Military
  /\.mil$/i,
  /\.mil\.[a-z]{2,3}$/i,

  // Education
  /\.edu$/i,
  /\.edu\.[a-z]{2,3}$/i,
  /\.ac\.[a-z]{2,3}$/i,

  // International organizations
  /\.int$/i,
]

// Exact domain matches for intergovernmental orgs on generic TLDs
// Mirror of agentic/hard_guardrail.py _EXACT_BLOCKED_DOMAINS — keep in sync
const EXACT_BLOCKED_DOMAINS = new Set([
  // UN System: Core Bodies & Programmes
  'un.org', 'undp.org', 'unep.org', 'unicef.org', 'unhcr.org', 'unrwa.org',
  'unfpa.org', 'unctad.org', 'unido.org', 'unwto.org', 'unhabitat.org',
  'unodc.org', 'unops.org', 'unssc.org', 'unitar.org', 'uncdf.org',
  'unrisd.org', 'unaids.org', 'undrr.org', 'unwater.org', 'unwomen.org',
  'un-women.org', 'undss.org', 'unjiu.org', 'unscear.org', 'uncitral.org',
  'wfp.org', 'ohchr.org', 'unocha.org',

  // UN Regional Commissions
  'unece.org', 'unescap.org', 'uneca.org', 'cepal.org', 'unescwa.org',

  // UN Specialized Agencies (on generic TLDs)
  'ilo.org', 'fao.org', 'unesco.org', 'imf.org', 'worldbank.org',
  'ifad.org', 'iaea.org', 'imo.org',

  // UN Tribunals & International Courts
  'icj-cij.org', 'icty.org', 'irmct.org', 'itlos.org',
  'african-court.org', 'corteidh.or.cr',

  // World Bank Group
  'ifc.org', 'miga.org',

  // EU Institutions
  'europa.eu', 'eib.org', 'eurocontrol.eu',

  // Security & Defence Organizations
  'osce.org', 'csto.org', 'odkb-csto.org',

  // Regional Intergovernmental Organizations
  'asean.org', 'african-union.org', 'oas.org', 'caricom.org', 'apec.org',
  'gcc-sg.org', 'bimstec.org', 'saarc-sec.org', 'oic-oci.org',
  'comunidadandina.org', 'aladi.org', 'sela.org',
  'norden.org', 'thecommonwealth.org', 'francophonie.org', 'cplp.org',
  'forumsec.org', 'acs-aec.org', 'eaeunion.org', 'eurasiancommission.org',
  'ceeac-eccas.org', 'sectsco.org', 'turkicstates.org',
  'leagueofarabstates.net', 'lasportal.org', 'celacinternational.org',
  's-cica.org', 'visegradfund.org', 'colombo-plan.org',
  'eria.org', 'nepad.org', 'aprm-au.org',

  // Development Banks & International Financial Institutions
  'bis.org', 'adb.org', 'afdb.org', 'aiib.org', 'ebrd.com', 'isdb.org',
  'bstdb.org', 'opec.org', 'opecfund.org', 'fatf-gafi.org',
  'iadb.org', 'caf.com', 'bcie.org', 'fonplata.org', 'caribank.org',
  'boad.org', 'eabr.org', 'eadb.org', 'tdbgroup.org', 'coebank.org',
  'afreximbank.com',

  // Financial Governance & Regulation
  'fsb.org', 'egmontgroup.org',

  // International Trade & Commodity Organizations
  'wto.org', 'intracen.org', 'iccwbo.org',
  'ico.org', 'icco.org', 'isosugar.org', 'internationaloliveoil.org',
  'ief.org', 'ilzsg.org', 'insg.org', 'icsg.org',

  // International Health
  'gavi.org', 'theglobalfund.org', 'cepi.net', 'unitaid.org',

  // Arms Control, Non-Proliferation & Treaty Bodies
  'ctbto.org', 'opcw.org', 'wassenaar.org', 'nuclearsuppliersgroup.org',
  'australiagroup.net', 'mtcr.info', 'opanal.org',
  'apminebanconvention.org', 'clusterconvention.org', 'brsmeas.org',

  // International Science & Research
  'cern.ch', 'home.cern', 'iter.org', 'esrf.eu', 'embl.org', 'eso.org',
  'cgiar.org', 'irena.org', 'ipcc.ch', 'xfel.eu', 'ill.eu',
  'euro-fusion.org', 'sesame.org.jo', 'icgeb.org', 'isolaralliance.org',

  // Environment & Climate Organizations
  'thegef.org', 'greenclimate.fund', 'adaptation-fund.org', 'cif.org',
  'ramsar.org', 'cites.org', 'iucn.org',

  // Red Cross / Red Crescent (Geneva Convention status)
  'icrc.org', 'ifrc.org',

  // Migration, Humanitarian & Cultural Heritage
  'icmpd.org', 'iccrom.org', 'gichd.org', 'dcaf.ch',

  // River Basin & Navigation Commissions
  'mrcmekong.org', 'nilebasin.org', 'danubecommission.org',
  'icpdr.org', 'ccr-zkr.org',

  // Sport Governance (intergovernmental)
  'wada-ama.org', 'tas-cas.org',

  // Standards, Metrology & Other Intergovernmental Bodies
  'oecd.org', 'g20.org', 'pca-cpa.org', 'hcch.net', 'unidroit.org',
  'wco.org', 'wcoomd.org', 'oiml.org', 'bipm.org', 'iso.org', 'iec.ch',
  'iea.org', 'icglr.org', 'isa.org.jm', 'gggi.org',
])

function normalizeDomain(raw: string): string {
  let d = raw.trim().toLowerCase()
  // Strip protocol
  if (d.startsWith('https://')) d = d.slice(8)
  if (d.startsWith('http://')) d = d.slice(7)
  // Strip path
  d = d.split('/')[0]
  // Strip port
  d = d.split(':')[0]
  // Strip trailing dot (FQDN notation)
  d = d.replace(/\.+$/, '')
  return d
}

export function isHardBlockedDomain(domain: string): { blocked: boolean; reason: string } {
  if (!domain) return { blocked: false, reason: '' }

  const d = normalizeDomain(domain)
  if (!d) return { blocked: false, reason: '' }

  // Exact match (intergovernmental orgs on generic TLDs)
  if (EXACT_BLOCKED_DOMAINS.has(d)) {
    return {
      blocked: true,
      reason: `'${d}' is a protected intergovernmental organization domain. Scanning government and public institutional websites is permanently blocked.`,
    }
  }

  // Subdomain of exact-blocked domain
  for (const blocked of EXACT_BLOCKED_DOMAINS) {
    if (d.endsWith('.' + blocked)) {
      return {
        blocked: true,
        reason: `'${d}' is a subdomain of the protected domain '${blocked}'. Scanning government and public institutional websites is permanently blocked.`,
      }
    }
  }

  // TLD suffix match
  for (const pattern of TLD_PATTERNS) {
    if (pattern.test(d)) {
      return {
        blocked: true,
        reason: `'${d}' belongs to a government, military, educational, or international organization TLD. Scanning these targets is permanently blocked.`,
      }
    }
  }

  return { blocked: false, reason: '' }
}
