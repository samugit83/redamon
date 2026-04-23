"""
Hard Guardrail — deterministic, non-disableable check for government/public domains.

Blocks government, military, education, and international organization domains
regardless of project settings. This check cannot be toggled off.

Mirror of agentic/hard_guardrail.py — keep patterns in sync.
"""

import re

# ---------------------------------------------------------------------------
# TLD suffix patterns (case-insensitive, applied to the full domain)
# ---------------------------------------------------------------------------
_TLD_PATTERNS = [
    # Government
    r'\.gov$',
    r'\.gov\.[a-z]{2,3}$',        # .gov.uk, .gov.au, .gov.br
    r'\.gob\.[a-z]{2,3}$',        # .gob.mx, .gob.es (Spanish-speaking)
    r'\.gouv\.[a-z]{2,3}$',       # .gouv.fr, .gouv.ci (French-speaking)
    r'\.govt\.[a-z]{2,3}$',       # .govt.nz
    r'\.go\.[a-z]{2}$',            # .go.jp, .go.kr, .go.id (2-letter ccTLDs only to avoid .go.dev etc.)
    r'\.gv\.[a-z]{2}$',            # .gv.at (Austria) (2-letter ccTLDs only)
    r'\.government\.[a-z]{2,3}$', # rare but exists

    # Military
    r'\.mil$',
    r'\.mil\.[a-z]{2,3}$',        # .mil.br

    # Education
    r'\.edu$',
    r'\.edu\.[a-z]{2,3}$',        # .edu.au
    r'\.ac\.[a-z]{2,3}$',         # .ac.uk, .ac.jp

    # International organizations
    r'\.int$',                     # .int (NATO, WHO, EU agencies)
]

_COMPILED_TLD_RE = re.compile('|'.join(f'(?:{p})' for p in _TLD_PATTERNS), re.IGNORECASE)

# ---------------------------------------------------------------------------
# Exact domain matches for major intergovernmental organizations
# that use generic TLDs (.org, .eu) and would not be caught by suffix rules.
# ---------------------------------------------------------------------------
_EXACT_BLOCKED_DOMAINS: frozenset[str] = frozenset({
    # ===================================================================
    # UN System: Core Bodies & Programmes
    # ===================================================================
    'un.org',
    'undp.org',
    'unep.org',
    'unicef.org',
    'unhcr.org',
    'unrwa.org',
    'unfpa.org',
    'unctad.org',
    'unido.org',
    'unwto.org',
    'unhabitat.org',
    'unodc.org',
    'unops.org',
    'unssc.org',
    'unitar.org',
    'uncdf.org',
    'unrisd.org',
    'unaids.org',
    'undrr.org',
    'unwater.org',
    'unwomen.org',
    'un-women.org',
    'undss.org',
    'unjiu.org',
    'unscear.org',
    'uncitral.org',
    'wfp.org',             # World Food Programme
    'ohchr.org',           # UN High Commissioner for Human Rights
    'unocha.org',          # UN Office for Coordination of Humanitarian Affairs

    # ===================================================================
    # UN Regional Commissions
    # ===================================================================
    'unece.org',
    'unescap.org',
    'uneca.org',
    'cepal.org',
    'unescwa.org',

    # ===================================================================
    # UN Specialized Agencies (on generic TLDs)
    # ===================================================================
    'ilo.org',
    'fao.org',
    'unesco.org',
    'imf.org',
    'worldbank.org',
    'ifad.org',
    'iaea.org',
    'imo.org',

    # ===================================================================
    # UN Tribunals & International Courts
    # ===================================================================
    'icj-cij.org',
    'icty.org',
    'irmct.org',
    'itlos.org',
    'african-court.org',   # African Court on Human and Peoples' Rights
    'corteidh.or.cr',      # Inter-American Court of Human Rights

    # ===================================================================
    # World Bank Group
    # ===================================================================
    'ifc.org',
    'miga.org',

    # ===================================================================
    # EU Institutions
    # ===================================================================
    'europa.eu',           # All EU institutions are subdomains
    'eib.org',             # European Investment Bank
    'eurocontrol.eu',      # European Air Traffic Management

    # ===================================================================
    # Security & Defence Organizations
    # ===================================================================
    'osce.org',
    'csto.org',
    'odkb-csto.org',       # CSTO alternate domain

    # ===================================================================
    # Regional Intergovernmental Organizations
    # ===================================================================
    'asean.org',
    'african-union.org',
    'oas.org',
    'caricom.org',
    'apec.org',
    'gcc-sg.org',
    'bimstec.org',
    'saarc-sec.org',
    'oic-oci.org',
    'comunidadandina.org',
    'aladi.org',
    'sela.org',
    'norden.org',          # Nordic Council / Nordic Council of Ministers
    'thecommonwealth.org', # Commonwealth Secretariat (56 member states)
    'francophonie.org',    # Organisation Internationale de la Francophonie (88 members)
    'cplp.org',            # Community of Portuguese Language Countries
    'forumsec.org',        # Pacific Islands Forum Secretariat
    'acs-aec.org',         # Association of Caribbean States
    'eaeunion.org',        # Eurasian Economic Union
    'eurasiancommission.org',  # Eurasian Economic Commission
    'ceeac-eccas.org',     # Economic Community of Central African States
    'sectsco.org',         # Shanghai Cooperation Organisation
    'turkicstates.org',    # Organization of Turkic States
    'leagueofarabstates.net',  # League of Arab States
    'lasportal.org',       # League of Arab States portal
    'celacinternational.org',  # CELAC (33 Latin American/Caribbean states)
    's-cica.org',          # Conference on Interaction and Confidence Building in Asia
    'visegradfund.org',    # International Visegrad Fund
    'colombo-plan.org',    # Colombo Plan (28 member states)
    'eria.org',            # Economic Research Institute for ASEAN/East Asia
    'nepad.org',           # AUDA-NEPAD, African Union Development Agency
    'aprm-au.org',         # African Peer Review Mechanism

    # ===================================================================
    # Development Banks & International Financial Institutions
    # ===================================================================
    'bis.org',
    'adb.org',
    'afdb.org',
    'aiib.org',
    'ebrd.com',
    'isdb.org',
    'bstdb.org',
    'opec.org',
    'opecfund.org',
    'fatf-gafi.org',
    'iadb.org',            # Inter-American Development Bank
    'caf.com',             # CAF - Development Bank of Latin America
    'bcie.org',            # Central American Bank for Economic Integration
    'fonplata.org',        # FONPLATA Development Bank
    'caribank.org',        # Caribbean Development Bank
    'boad.org',            # West African Development Bank
    'eabr.org',            # Eurasian Development Bank
    'eadb.org',            # East African Development Bank
    'tdbgroup.org',        # Trade and Development Bank (PTA Bank/COMESA)
    'coebank.org',         # Council of Europe Development Bank
    'afreximbank.com',     # African Export-Import Bank

    # ===================================================================
    # Financial Governance & Regulation
    # ===================================================================
    'fsb.org',             # Financial Stability Board
    'egmontgroup.org',     # Egmont Group of Financial Intelligence Units

    # ===================================================================
    # International Trade & Commodity Organizations
    # ===================================================================
    'wto.org',
    'intracen.org',
    'iccwbo.org',
    'ico.org',             # International Coffee Organization
    'icco.org',            # International Cocoa Organization
    'isosugar.org',        # International Sugar Organization
    'internationaloliveoil.org',  # International Olive Council
    'ief.org',             # International Energy Forum (73 member countries)
    'ilzsg.org',           # International Lead and Zinc Study Group
    'insg.org',            # International Nickel Study Group
    'icsg.org',            # International Copper Study Group

    # ===================================================================
    # International Health
    # ===================================================================
    'gavi.org',
    'theglobalfund.org',
    'cepi.net',
    'unitaid.org',

    # ===================================================================
    # Arms Control, Non-Proliferation & Treaty Bodies
    # ===================================================================
    'ctbto.org',           # Comprehensive Nuclear-Test-Ban Treaty Organization
    'opcw.org',            # Organisation for the Prohibition of Chemical Weapons
    'wassenaar.org',       # Wassenaar Arrangement on Export Controls
    'nuclearsuppliersgroup.org',  # Nuclear Suppliers Group
    'australiagroup.net',  # Australia Group (chemical/biological weapons)
    'mtcr.info',           # Missile Technology Control Regime
    'opanal.org',          # OPANAL - Nuclear Weapons Prohibition (Latin America)
    'apminebanconvention.org',   # Anti-Personnel Mine Ban Convention
    'clusterconvention.org',     # Convention on Cluster Munitions
    'brsmeas.org',         # Basel/Rotterdam/Stockholm Conventions Secretariat

    # ===================================================================
    # International Science & Research
    # ===================================================================
    'cern.ch',
    'home.cern',
    'iter.org',
    'esrf.eu',
    'embl.org',
    'eso.org',
    'cgiar.org',
    'irena.org',
    'ipcc.ch',             # Intergovernmental Panel on Climate Change
    'xfel.eu',             # European XFEL (12 participating countries)
    'ill.eu',              # Institut Laue-Langevin (intergovernmental, Grenoble)
    'euro-fusion.org',     # EUROfusion (European fusion research)
    'sesame.org.jo',       # SESAME Synchrotron (8 member states)
    'icgeb.org',           # International Centre for Genetic Engineering & Biotech
    'isolaralliance.org',  # International Solar Alliance (120+ member states)

    # ===================================================================
    # Environment & Climate Organizations
    # ===================================================================
    'thegef.org',          # Global Environment Facility (186 member countries)
    'greenclimate.fund',   # Green Climate Fund
    'adaptation-fund.org', # Adaptation Fund (Kyoto Protocol)
    'cif.org',             # Climate Investment Funds
    'ramsar.org',          # Ramsar Convention on Wetlands
    'cites.org',           # CITES (Endangered Species Trade Convention)
    'iucn.org',            # IUCN (government + civil society, intergovernmental status)

    # ===================================================================
    # Red Cross / Red Crescent (Geneva Convention status)
    # ===================================================================
    'icrc.org',
    'ifrc.org',

    # ===================================================================
    # Migration, Humanitarian & Cultural Heritage
    # ===================================================================
    'icmpd.org',           # International Centre for Migration Policy Development
    'iccrom.org',          # International Centre for Conservation (Rome)
    'gichd.org',           # Geneva Centre for Humanitarian Demining
    'dcaf.ch',             # Geneva Centre for Security Sector Governance

    # ===================================================================
    # River Basin & Navigation Commissions
    # ===================================================================
    'mrcmekong.org',       # Mekong River Commission
    'nilebasin.org',       # Nile Basin Initiative
    'danubecommission.org',  # Danube Commission (since 1948)
    'icpdr.org',           # International Commission for Danube River Protection
    'ccr-zkr.org',         # Central Commission for Navigation of the Rhine (since 1815)

    # ===================================================================
    # Sport Governance (intergovernmental)
    # ===================================================================
    'wada-ama.org',        # World Anti-Doping Agency
    'tas-cas.org',         # Court of Arbitration for Sport

    # ===================================================================
    # Standards, Metrology & Other Intergovernmental Bodies
    # ===================================================================
    'oecd.org',
    'g20.org',
    'pca-cpa.org',
    'hcch.net',
    'unidroit.org',
    'wco.org',
    'wcoomd.org',          # World Customs Organization (main domain)
    'oiml.org',
    'bipm.org',
    'iso.org',
    'iec.ch',
    'iea.org',
    'icglr.org',
    'isa.org.jm',          # International Seabed Authority
    'gggi.org',            # Global Green Growth Institute
})


def _normalize_domain(raw: str) -> str:
    """Lowercase, strip protocol/path/port/whitespace."""
    d = raw.strip().lower()
    # Strip protocol
    for prefix in ('https://', 'http://'):
        if d.startswith(prefix):
            d = d[len(prefix):]
    # Strip path
    d = d.split('/')[0]
    # Strip port
    d = d.split(':')[0]
    # Strip trailing dot (FQDN notation)
    d = d.rstrip('.')
    return d


def is_hard_blocked(domain: str) -> tuple[bool, str]:
    """Deterministic check: is this domain a government/public institution?

    Returns (blocked, reason).  Does NOT depend on LLM, network, or settings.
    For IP mode targets, callers should skip this check (IPs are not hard-blocked).
    """
    if not domain:
        return False, ''

    d = _normalize_domain(domain)
    if not d:
        return False, ''

    # Exact match (intergovernmental orgs on generic TLDs)
    if d in _EXACT_BLOCKED_DOMAINS:
        return True, (
            f"'{d}' is a protected intergovernmental organization domain. "
            "Scanning government and public institutional websites is permanently blocked."
        )

    # Also check if the domain is a subdomain of an exact-blocked domain
    for blocked in _EXACT_BLOCKED_DOMAINS:
        if d.endswith('.' + blocked):
            return True, (
                f"'{d}' is a subdomain of the protected domain '{blocked}'. "
                "Scanning government and public institutional websites is permanently blocked."
            )

    # TLD suffix match
    if _COMPILED_TLD_RE.search(d):
        return True, (
            f"'{d}' belongs to a government, military, educational, or international "
            "organization TLD. Scanning these targets is permanently blocked."
        )

    return False, ''
