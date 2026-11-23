/**
 * Hard Guardrail - deterministic, non-disableable check for government/public domains.
 *
 * Blocks government, military, education, and international organization domains
 * regardless of project settings. This check cannot be toggled off.
 *
 * Mirrors: recon_orchestrator/hard_guardrail.py and
 * agentic/orchestrator_helpers/hard_guardrail.py. All three read the same test
 * vectors (recon_orchestrator/tests/fixtures/hard_guardrail_vectors.json), so a
 * pattern added to one copy only fails a test.
 */

// TLD suffix patterns (case-insensitive). Anchored on a label boundary, (^|\.),
// so the bare suffix is blocked too: a batch whose hosts group under `gov.uk`
// hands this check `gov.uk` itself.
const TLD_PATTERNS: RegExp[] = [
  // Government
  /(^|\.)gov$/i,
  /(^|\.)gov\.[a-z]{2,3}$/i,
  /(^|\.)gob\.[a-z]{2,3}$/i,
  /(^|\.)gouv\.[a-z]{2,3}$/i,
  /(^|\.)govt\.[a-z]{2,3}$/i,
  /(^|\.)go\.(?!id$)[a-z]{2}$/i,            // .go.jp, .go.kr (exclude .go.id)
  /(^|\.)gv\.[a-z]{2}$/i,            // .gv.at (Austria) (2-letter ccTLDs only)
  /(^|\.)government\.[a-z]{2,3}$/i,

  // Military
  /(^|\.)mil$/i,
  /(^|\.)mil\.[a-z]{2,3}$/i,

  // Education
  /(^|\.)edu$/i,
  /(^|\.)edu\.[a-z]{2,3}$/i,
  /(^|\.)ac\.[a-z]{2,3}$/i,

  // International organizations
  /(^|\.)int$/i,
]

// Exact domain matches for intergovernmental orgs on generic TLDs
// Mirror of the Python copies' _EXACT_BLOCKED_DOMAINS
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

  // Government namespaces no keyword pattern matches. Under the Public Suffix
  // List each label below them is a registrable org, so without these
  // `*.met.police.uk` would be a valid, unblocked wildcard.
  'police.uk', 'nhs.uk', 'mod.uk', 'sch.uk', 'parliament.uk',
  'gc.ca', 'gouv.qc.ca', 'gov.scot', 'gov.wales', 'llyw.cymru',
])

/** Strip scheme, credentials, path, port, trailing dot and a leading wildcard
 *  marker, so a raw batch entry cannot slip past as typed. */
function normalizeDomain(raw: string): string {
  let d = raw.trim().toLowerCase()
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
  d = d.split(/[/?#]/)[0]
  d = d.slice(d.lastIndexOf('@') + 1)
  d = d.split(':')[0]
  d = d.replace(/\.+$/, '')
  if (d.startsWith('*.')) d = d.slice(2)
  else if (d.startsWith('*')) d = d.slice(1)
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
      reason: `'${d}' is a protected government or intergovernmental domain. Scanning government and public institutional websites is permanently blocked.`,
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

/**
 * The first blocked name in input order, or null. Callers pass every name a
 * scope would touch (hosts, scan roots, orgs) as the operator typed them, so a
 * refusal names the entry rather than its group.
 */
export function firstHardBlocked(
  names: readonly string[],
): { name: string; reason: string } | null {
  for (const name of names) {
    const check = isHardBlockedDomain(name)
    if (check.blocked) return { name, reason: check.reason }
  }
  return null
}
