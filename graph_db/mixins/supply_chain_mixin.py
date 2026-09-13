"""Supply-chain graph writer (plan Phase 2/4 graph model).

Writes the two node types shared by BOTH L1 (standalone repo/SBOM scan) and L2
(live-target recon harvest), so a repo scan and a live scan of the same project
dedup automatically:

  Package            - a discovered dependency. MERGE key (purl, user_id, project_id).
  MalPackageFinding  - a verdict about a package. MERGE key (finding_id, user_id,
                       project_id) where finding_id = sha256(purl:advisory)[:16].

Relationships:
  (GithubRepository|BaseURL)-[:DEPENDS_ON]->(Package)   (L1 uses the repo, L2 the BaseURL)
  (Package)-[:FLAGGED_AS]->(MalPackageFinding)

Rules (plan section 4):
  - All writes MERGE (ON CREATE SET first_seen; unconditional SET last_seen).
  - Only OSV MAL- hits are verdict=malicious. CVE-/GHSA- (vulnerable) are NOT
    written as MalPackageFinding here; they stay in the raw JSON output. GuardDog
    hits are verdict=suspicious.
  - Tenant isolation: every MERGE key includes user_id + project_id (S10).

The caller passes an ALREADY-VALIDATED artifact (see
supply_chain_common.security.validate_artifact); this writer never sees raw
tool bytes.
"""

import re
import hashlib


def _finding_id(purl, advisory):
    raw = "{}:{}".format(purl or "", advisory or "")
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


# A finding's title is what the graph viewer shows as the node NAME (it has no
# `name` property, so webapp/src/app/api/graph/format.ts falls back to `title`).
# It must stay a short label.
_MAX_TITLE = 120


def _finding_title(finding, advisory):
    """Short, human label for a finding node.

    The advisory/rule id is preferred over the message because GuardDog
    findings carry NO title and their `message` is the full evidence dump - for
    npm `metadata_mismatch` that is a multi-line manifest diff over a thousand
    characters long, which then became the node's displayed name. The evidence
    still ships, in `detail`.
    """
    explicit = (finding.get("title") or "").strip()
    if explicit and len(explicit) <= _MAX_TITLE and "\n" not in explicit:
        return explicit
    if advisory:
        return advisory
    if explicit:
        # No advisory to fall back to: use the first line, truncated.
        first = explicit.splitlines()[0].strip()
        return first[:_MAX_TITLE - 1] + "…" if len(first) > _MAX_TITLE else first
    message = (finding.get("message") or "").strip()
    if message:
        first = message.splitlines()[0].strip()
        return first[:_MAX_TITLE - 1] + "…" if len(first) > _MAX_TITLE else first
    return "finding"


# Incident context (B): the seven properties the supplychainattack.org catalog
# contributes to a finding that ALREADY EXISTS. They are attached upstream by
# supply_chain_common.intel.enrich_findings, which runs after the last artifact
# validation, so this layer only reads optional keys and never requires them.
#
# graph_db must NOT import supply_chain_common: graph_db is COPY-baked into the
# agent image while supply_chain_common is bind-mounted at scan spawn and is
# absent there. The field list is therefore duplicated, and a test asserts the
# two never drift.
_INCIDENT_PROPS = ("incident_id", "incident_url", "incident_summary",
                   "incident_blast_radius", "incident_remediation",
                   "incident_status", "incident_feed_revised")


# Which tool produced a `suspicious` finding. This used to be hardcoded to
# "guarddog" for every one of them, which was true when GuardDog was the only
# producer and became wrong the moment typosquat detection started writing here:
# a typosquat finding reached the graph claiming GuardDog found it, and the SCA
# table (which reads source_tool to word the verdict) then labelled it a
# behavioural hit. Anything unrecognised still maps to guarddog so existing rows
# and existing rules keep their meaning.
_SUSPICIOUS_TOOL_BY_RULE = {
    "typosquat": "typosquat",
}


def _suspicious_tool(finding):
    rule = (finding.get("rule") or "").strip().lower()
    return _SUSPICIOUS_TOOL_BY_RULE.get(rule, "guarddog")


def _incident_params(finding):
    """Cypher params for the incident properties; None when never enriched.

    A remediation list is capped and stringified here as well as upstream: this
    mixin is also reachable from an artifact that came off disk (a re-import, a
    restored snapshot), where the upstream cap cannot be assumed.
    """
    params = {}
    for prop in _INCIDENT_PROPS:
        value = finding.get(prop)
        if prop == "incident_remediation":
            if isinstance(value, list):
                value = [str(v) for v in value[:20]]
            elif value:
                value = [str(value)]
            else:
                value = None
        elif value is not None and not isinstance(value, str):
            value = str(value)
        # "" reads as "present but empty" in the UI; absent is the honest state.
        params[prop] = value or None
    return params


# The Vulnerability node's severity enum is critical|high|medium|low|info -
# there is no "unknown". An ungraded advisory lands at info so it does not
# inflate the alert stream.
_GRAPH_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _vuln_severity(value):
    v = (value or "").strip().lower()
    return v if v in _GRAPH_SEVERITIES else "info"


#: A CVE id, as OSV writes them in an advisory's `aliases`.
_CVE_ALIAS_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)


def _cve_aliases(vul: dict) -> list:
    """The CVE ids an OSV advisory is also known by.

    K3: OSV ids are GHSA or PYSEC, and the CVE aliases were not stored at all.
    Nothing downstream could reach them, so the whole CVE intelligence layer
    (CISA KEV, EPSS, public proof of concept) was unreachable for 94% of the
    findings in a real graph. Only real CVE ids are kept, so a malformed alias
    cannot end up being sent to an external lookup.
    """
    seen, out = set(), []
    for candidate in (vul.get("aliases") or []) + [vul.get("cve_id")]:
        text = str(candidate or "").strip().upper()
        if _CVE_ALIAS_RE.match(text) and text not in seen:
            seen.add(text)
            out.append(text)
    return sorted(out)


# Evidence strength per harvest source, used to stop a weaker sighting from
# overwriting a stronger one on the shared Package node (L1 and L2 dedup by
# purl into ONE node, by design).
#
# The ordering is about REACHABILITY, not tool quality: something observed
# being served by the live target is stronger evidence than something read out
# of a manifest a human uploaded. A lockfile can list a dependency that is
# never shipped to a browser; retire.js matching bytes the target actually
# served cannot.
#
#   40  live target, name AND version   (retire.js, wappalyzer)
#   30  live target, name only          (source maps, JS imports)
#   10  manifest / SBOM                 (osv, lockfile, sbom, dir)
#    0  synthesised to hang a finding on (has no discovery evidence at all)
_SOURCE_RANK = {
    "retirejs": 40,
    "wappalyzer": 40,
    "sourcemap": 30,
    "import": 30,
    "osv": 10,
    "sbom": 10,
    "lockfile": 10,
    "dir": 10,
    "finding": 0,
}
# An unrecognised source sits with the manifest tier: strong enough to replace
# a placeholder, never strong enough to erase live-target evidence.
_DEFAULT_SOURCE_RANK = 10


def _overridable_sources(source):
    """Sources a package discovered via `source` is allowed to overwrite.

    Equal rank is included so a re-scan by the same source refreshes normally.
    A source not in the table is left alone rather than clobbered - unknown
    provenance is still provenance.
    """
    rank = _SOURCE_RANK.get(source, _DEFAULT_SOURCE_RANK)
    return [name for name, r in _SOURCE_RANK.items() if r <= rank]


class SupplyChainMixin:
    """Mixin adding supply-chain graph writes to the Neo4jClient."""

    def update_graph_from_supply_chain(self, data, user_id, project_id, *,
                                       anchor_label=None, anchor_key=None,
                                       anchor_value=None):
        """MERGE Package + MalPackageFinding nodes from a validated artifact.

        anchor_label: "GithubRepository" (L1 repo), "BaseURL" (L2 live target),
                      or None (e.g. an uploaded SBOM has no graph parent). When
                      None, packages/findings are still created, just without a
                      DEPENDS_ON edge.
        anchor_key:   the anchor node's identity property ("id" or "url").
        anchor_value: its value. The DEPENDS_ON edge is created only when the
                      anchor node already exists (we never invent target nodes).

        Returns a stats dict.
        """
        has_anchor = anchor_label is not None
        if has_anchor and anchor_label not in ("GithubRepository", "BaseURL", "SbomDocument"):
            raise ValueError("unsupported anchor_label: {}".format(anchor_label))
        # L2-4: anchor_key is string-interpolated into the Cypher (labels/keys
        # can't be parameterized), so whitelist it too, not just anchor_label.
        if has_anchor and anchor_key not in ("id", "url"):
            raise ValueError("unsupported anchor_key: {}".format(anchor_key))
        if has_anchor and anchor_value is None:
            raise ValueError("anchor_value required with anchor_label")

        stats = {"packages_merged": 0, "malicious_merged": 0,
                 "suspicious_merged": 0, "vulnerabilities_merged": 0,
                 "relationships_created": 0, "errors": []}

        packages = data.get("packages") or []
        # Map malicious (OSV MAL-) and suspicious findings into one list.
        findings = []
        for m in data.get("malicious") or []:
            findings.append(("malicious", "osv", m.get("advisory_id"), m))
        for s in data.get("suspicious") or []:
            findings.append(("suspicious", _suspicious_tool(s), s.get("rule"), s))

        with self.driver.session() as session:
            for pkg in packages:
                purl = pkg.get("purl")
                if not purl:
                    continue
                try:
                    session.run(
                        """
                        MERGE (p:Package {purl: $purl, user_id: $uid, project_id: $pid})
                        ON CREATE SET p.first_seen = datetime()
                        SET p.ecosystem = $ecosystem, p.name = $name,
                            p.version = $version,
                            p.source = CASE
                                WHEN p.source IS NULL OR p.source IN $overridable
                                THEN $source ELSE p.source END,
                            p.source_path = coalesce($source_path, p.source_path),
                            p.last_seen = datetime(),
                            p.updated_at = datetime()
                        """,
                        purl=purl, uid=user_id, pid=project_id,
                        ecosystem=pkg.get("ecosystem"), name=pkg.get("name"),
                        version=pkg.get("version"), source=pkg.get("source"),
                        # L1 and L2 dedup into ONE node per purl (intentional),
                        # but `source` was SET unconditionally, so whichever
                        # scan ran last won. Upload a package-lock.json after a
                        # recon scan and lodash@4.17.4 - which retire.js read
                        # out of the bytes the target actually served - started
                        # claiming it came from a file someone uploaded.
                        #
                        # That field answers "is this dependency really being
                        # served, or did it just appear in a manifest?", which
                        # is the difference between a reachable finding and a
                        # theoretical one. So a WEAKER source may no longer
                        # overwrite a stronger one; see _overridable_sources.
                        overridable=_overridable_sources(pkg.get("source")),
                        # Which manifest inside a scanned tree the package came
                        # from - the only way to tell, on an L1 repo scan that
                        # walked 12 lockfiles, WHICH one carries the malware.
                        # coalesce so a later L2 sighting (no path) cannot erase
                        # what the repo scan established.
                        source_path=pkg.get("source_path"),
                    )
                    stats["packages_merged"] += 1
                except Exception as exc:  # keep going; one bad row is not fatal
                    stats["errors"].append("package {}: {}".format(purl, exc))
                    continue

                # DEPENDS_ON edge: only when an anchor is given AND it already
                # exists (an uploaded SBOM has no anchor -> packages float).
                if not has_anchor:
                    continue
                try:
                    res = session.run(
                        """
                        MATCH (a:%s {%s: $anchor_value, user_id: $uid, project_id: $pid})
                        MATCH (p:Package {purl: $purl, user_id: $uid, project_id: $pid})
                        MERGE (a)-[:DEPENDS_ON]->(p)
                        RETURN count(*) AS c
                        """ % (anchor_label, anchor_key),
                        anchor_value=anchor_value, purl=purl,
                        uid=user_id, pid=project_id,
                    )
                    rec = res.single()
                    if rec and rec.get("c"):
                        stats["relationships_created"] += 1
                except Exception as exc:
                    stats["errors"].append("depends_on {}: {}".format(purl, exc))

            for verdict, source_tool, advisory, f in findings:
                purl = f.get("purl")
                if not purl:
                    # A finding without a purl (e.g. GuardDog by name) still needs
                    # a package to attach to; build a name-only purl fallback.
                    name = f.get("name")
                    eco = f.get("ecosystem")
                    if name and eco:
                        purl = "pkg:{}/{}".format(eco, name)
                    else:
                        continue
                fid = _finding_id(purl, advisory)
                try:
                    # MERGE (not MATCH) the Package so a finding whose package is
                    # not in `packages` (e.g. a GuardDog name-only hit) still
                    # attaches instead of leaving an orphaned MalPackageFinding.
                    # Existing packages keep their richer props; only a brand-new
                    # one is seeded from the finding's fields.
                    session.run(
                        """
                        MERGE (mf:MalPackageFinding {finding_id: $fid, user_id: $uid, project_id: $pid})
                        ON CREATE SET mf.first_seen = datetime()
                        SET mf.verdict = $verdict, mf.source_tool = $source_tool,
                            mf.advisory_id = $advisory, mf.severity = $severity,
                            mf.confidence = $confidence, mf.title = $title,
                            mf.detail = $detail, mf.soft_error = $soft_error,
                            mf.aliases = $aliases, mf.last_seen = datetime(),
                            mf.incident_id = $incident_id,
                            mf.incident_url = $incident_url,
                            mf.incident_summary = $incident_summary,
                            mf.incident_blast_radius = $incident_blast_radius,
                            mf.incident_remediation = $incident_remediation,
                            mf.incident_status = $incident_status,
                            mf.incident_feed_revised = $incident_feed_revised
                        SET mf.updated_at = datetime()
                        WITH mf
                        MERGE (p:Package {purl: $purl, user_id: $uid, project_id: $pid})
                        ON CREATE SET p.first_seen = datetime(), p.name = $pname,
                                      p.ecosystem = $peco, p.source = 'finding'
                        SET p.last_seen = datetime()
                        SET p.updated_at = datetime()
                        MERGE (p)-[:FLAGGED_AS]->(mf)
                        """,
                        fid=fid, uid=user_id, pid=project_id, purl=purl,
                        pname=f.get("name"), peco=f.get("ecosystem"),
                        verdict=verdict, source_tool=source_tool,
                        advisory=advisory, severity=f.get("severity"),
                        confidence=f.get("confidence") or verdict,
                        title=_finding_title(f, advisory),
                        # THE difference between "GuardDog analysed this and
                        # found nothing bad" and "GuardDog never ran". The flag
                        # exists in the artifact for exactly that reason; not
                        # persisting it made every soft error read, in the UI,
                        # as an ordinary low-severity suspicious finding.
                        soft_error=bool(f.get("soft_error")),
                        # OSV alias ids (a MAL- advisory often also has a GHSA-).
                        aliases=[str(a) for a in (f.get("aliases") or [])][:50],
                        # None, not "": an absent detail should be an absent
                        # property, not an empty string that reads as present.
                        detail=f.get("detail") or f.get("message") or None,
                        # Incident context (B). Optional keys: the enrichment
                        # step is a local dictionary join that may not have run
                        # (never-synced volume, air-gapped deploy), so these are
                        # read with .get and land as None rather than failing the
                        # write. NOTE these deliberately do NOT touch `title` -
                        # that is the graph viewer's node name, guarded at 120
                        # chars, and incident titles would blow past it.
                        **_incident_params(f),
                    )
                    if verdict == "malicious":
                        stats["malicious_merged"] += 1
                    else:
                        stats["suspicious_merged"] += 1
                except Exception as exc:
                    stats["errors"].append("finding {}: {}".format(fid, exc))

            # ---- CVE/GHSA -> the EXISTING Vulnerability model --------------
            # These are known-vulnerable, NOT malicious, so they must never become
            # MalPackageFinding. They used to go nowhere at all: a package with 9
            # advisories rendered as a clean node while the JSON artifact listed
            # them. Reuse the Vulnerability node (no new label), exactly as the
            # cache-poisoning and takeover modules do.
            for vul in data.get("vulnerable") or []:
                purl = vul.get("purl")
                advisory = vul.get("advisory_id")
                if not purl or not advisory:
                    continue
                try:
                    session.run(
                        """
                        // ONE NODE PER PACKAGE AND ADVISORY, not one per advisory.
                        //
                        // Keyed on the advisory alone, a single advisory node
                        // hung off up to ELEVEN packages in the dev graph. That
                        // made it impossible to say anything true about it: its
                        // reachability was whichever package was looked at
                        // first, muting it muted the advisory on every package
                        // at once, and one remediation stood for eleven
                        // different upgrades. Grouping puts them back together
                        // deliberately, under `pkg:<purl>`.
                        MERGE (v:Vulnerability {id: $vuln_id, user_id: $uid,
                                                project_id: $pid})
                        ON CREATE SET v.first_seen = datetime()
                        SET v.source = 'osv',
                            v.name = $name,
                            v.description = $description,
                            v.severity = $severity,
                            v.cvss_metrics = $cvss,
                            v.advisory_id = $advisory,
                            // K3: the CVE aliases, so CVE intelligence (KEV,
                            // EPSS, public PoC) can reach an advisory at all.
                            // A GHSA id matches nothing in NVD.
                            v.cve_ids = $aliases,
                            v.aliases = $aliases,
                            // The version that fixes it, so the fix item can
                            // say "upgrade to X" instead of "upgrade".
                            v.fixed_version = $fixed_version,
                            v.package_version = $package_version,
                            v.purl = $purl,
                            v.updated_at = datetime()
                        WITH v
                        MERGE (p:Package {purl: $purl, user_id: $uid, project_id: $pid})
                        ON CREATE SET p.first_seen = datetime(), p.name = $pname,
                                      p.ecosystem = $peco, p.source = 'finding'
                        SET p.last_seen = datetime()
                        SET p.updated_at = datetime()
                        MERGE (p)-[:HAS_VULNERABILITY]->(v)
                        """,
                        vuln_id=f"osv:{purl}:{advisory}",
                        advisory=advisory, uid=user_id, pid=project_id, purl=purl,
                        # The runner emits `summary` and `summary_detail`;
                        # `title`/`detail` were read but never written, so every
                        # advisory reached the graph named after its own id with
                        # no description at all.
                        name=(vul.get("summary") or vul.get("title")
                              or advisory)[:300],
                        description=(vul.get("summary_detail") or vul.get("detail")
                                     or vul.get("summary") or "")[:4000],
                        # The graph enum has no "unknown"; an advisory we cannot
                        # grade lands at info so it stays out of the alert stream
                        # rather than inflating it (same convention the takeover
                        # module uses for manual_review).
                        severity=_vuln_severity(vul.get("severity")),
                        cvss=vul.get("cvss_vector"),
                        aliases=_cve_aliases(vul),
                        fixed_version=vul.get("fixed_version") or "",
                        package_version=vul.get("version") or "",
                        pname=vul.get("name"), peco=vul.get("ecosystem"),
                    )
                    stats["vulnerabilities_merged"] += 1
                except Exception as exc:
                    stats["errors"].append("vulnerability {}: {}".format(advisory, exc))

        return stats

    def _link_anchor_to_domain(self, session, user_id, project_id, label, node_id, rel):
        """Attach an L1 anchor to the project's Domain, the graph's root.

        Anchoring packages to a file or a repository stopped them from floating
        INDIVIDUALLY, but left the anchor itself parentless - so the whole L1
        scan hung in the view as one detached island, exactly what a GitHub
        Secret Hunt avoids by linking `Domain -[:HAS_GITHUB_HUNT]-> GithubHunt`.
        This is that same link for the supply-chain anchors.

        `label` and `rel` are internal constants, never caller/user input, so
        interpolating them into the query is safe (Cypher cannot parameterise a
        label or a relationship type).

        Returns True when a Domain existed to link to. A project with no Domain
        node yet is NOT an error and must not fail the scan: the graph write is
        still correct, the anchor simply stays a root until recon creates one.
        We never invent a Domain here - fabricating a target the operator never
        scanned would be worse than a detached node.
        """
        try:
            rec = session.run(
                """
                MATCH (dom:Domain {{user_id: $uid, project_id: $pid}})
                MATCH (n:{label} {{id: $nid}})
                MERGE (dom)-[:{rel}]->(n)
                RETURN count(*) AS linked
                """.format(label=label, rel=rel),
                uid=user_id, pid=project_id, nid=node_id).single()
            linked = bool(rec and rec["linked"])
            if not linked:
                print("[!][graph-db] no Domain for user_id={} project_id={}; "
                      "{} stays a graph root".format(user_id, project_id, label))
            return linked
        except Exception as exc:
            print("[!][graph-db] could not link {} to Domain: {}".format(label, exc))
            return False

    def ensure_github_repository(self, user_id, project_id, repo_slug):
        """MERGE the GithubRepository anchor for an L1 repo scan, return its id.

        update_graph_from_supply_chain only MATCHes an anchor (it must never
        invent a target node), so a repo that no other scan has seen would
        leave every package floating. A repository the operator explicitly
        pointed the scanner at is not an invented node, so creating it here is
        correct - and it is the SAME id format the GitHub secret hunter uses,
        so scanning a repo both ways attaches to one node instead of two.
        """
        repo_id = "github-repo-{}-{}-{}".format(user_id, project_id, repo_slug)
        with self.driver.session() as session:
            session.run(
                """
                MERGE (gr:GithubRepository {id: $id, user_id: $uid,
                                            project_id: $pid})
                ON CREATE SET gr.first_seen = datetime()
                SET gr.name = $name, gr.user_id = $uid, gr.project_id = $pid,
                    gr.updated_at = datetime()
                """,
                id=repo_id, name=repo_slug, uid=user_id, pid=project_id)
            self._link_anchor_to_domain(session, user_id, project_id,
                                        "GithubRepository", repo_id, "HAS_REPOSITORY")
        return repo_id

    def ensure_sbom_document(self, user_id, project_id, filename):
        """MERGE the SbomDocument anchor for an UPLOADED SBOM/lockfile.

        Without it the packages from an upload had no parent at all and sat in
        the graph as an island - a Package plus its Vulnerabilities, reachable
        from nothing. That contradicts the schema's own rule (GRAPH.SCHEMA.md,
        "No Isolated Nodes") and it is visibly odd next to a repo scan, which
        anchors to GithubRepository.

        An uploaded file has no target to hang off, so the file ITSELF is the
        parent: it is what the operator supplied and what the packages were
        read out of. It also recovers information that was previously lost -
        every upload collapsed into an indistinguishable pile of source='osv'
        packages, with no way to tell which file contributed which.
        """
        doc_id = "sbom-{}-{}-{}".format(user_id, project_id, filename)
        with self.driver.session() as session:
            session.run(
                """
                MERGE (d:SbomDocument {id: $id, user_id: $uid,
                                       project_id: $pid})
                ON CREATE SET d.first_seen = datetime()
                SET d.name = $name, d.user_id = $uid, d.project_id = $pid,
                    d.updated_at = datetime()
                """,
                id=doc_id, name=filename, uid=user_id, pid=project_id)
            self._link_anchor_to_domain(session, user_id, project_id,
                                        "SbomDocument", doc_id, "HAS_SBOM_DOCUMENT")
        return doc_id

    def update_graph_from_supply_chain_recon(self, combined_result, user_id, project_id):
        """L2 pipeline graph-write entry point (matches the _graph_update_bg
        signature). Reads combined_result['supply_chain_recon'] {artifact,
        base_urls} and MERGEs, anchoring packages to each target BaseURL that
        already exists. Falls back to a floating write when no BaseURL is known.
        """
        block = (combined_result or {}).get("supply_chain_recon") or {}
        artifact = block.get("artifact")
        if not artifact:
            return {"skipped": "no supply_chain_recon artifact"}
        base_urls = block.get("base_urls") or []

        if not base_urls:
            return self.update_graph_from_supply_chain(artifact, user_id, project_id)

        # Write the NODES once, then attach the per-BaseURL edges.
        #
        # This used to call update_graph_from_supply_chain once per BaseURL,
        # which re-wrote the ENTIRE artifact every time. A scan with 122
        # packages and 2 BaseURLs issued ~500 Cypher round-trips where ~250
        # were needed, and reported packages_merged=244 for 122 actual nodes -
        # the counts a reader trusts were simply wrong. A target with 10
        # BaseURLs (multiple ports/subdomains is normal) paid 10x.
        #
        # The data was never wrong - MERGE is idempotent - so this is about
        # cost and about the numbers meaning what they say.
        stats = self.update_graph_from_supply_chain(artifact, user_id, project_id)
        stats["relationships_created"] = 0

        purls = [p["purl"] for p in (artifact.get("packages") or []) if p.get("purl")]
        if purls:
            for url in base_urls:
                try:
                    stats["relationships_created"] += self._anchor_packages_to(
                        "BaseURL", "url", url, purls, user_id, project_id)
                except Exception as exc:
                    stats["errors"].append("depends_on {}: {}".format(url, exc))

        # A2: malicious-host correlations, written in the same pass.
        try:
            istats = self.update_graph_from_sca_intel(
                block.get("intel_correlation"), user_id, project_id)
            stats["intel_pulses_merged"] = istats.get("pulses_merged", 0)
            stats["relationships_created"] += istats.get("relationships_created", 0)
            stats["errors"].extend(istats.get("errors", []))
        except Exception as exc:
            stats["errors"].append("sca intel correlation: {}".format(exc))
        return stats

    def update_graph_from_sca_intel(self, correlation, user_id, project_id):
        """MERGE a ThreatPulse per matched incident + CONTACTS_MALICIOUS_HOST.

        The BaseURL is MATCHed FIRST and the pulse MERGEd after it. Cypher runs
        left to right, so ordering it the other way created the ThreatPulse and
        only then discovered there was nothing to attach it to - leaving an
        orphan node that renders as a floating node in the graph view, counts
        against the 20,000-node read cap, and is never cleaned up. With the match
        first, no anchor means no row to carry forward and nothing is written.

        REUSES ThreatPulse rather than adding a label: RedAmon already models
        "a named threat report listing indicators, attached to a discovered
        asset" (OTX enrichment writes exactly that). The 20,000-node graph read
        cap is another reason not to add a per-finding node here.

        The EDGE is deliberately NOT `APPEARS_IN_PULSE`. That edge means "this
        asset of mine is named in the report", which is false here: the attacker
        host is a third party the target CONTACTS, not the target's own domain.
        Reusing it would inject these into the Red Zone Domain/IP arms and the
        report's OTX section, where they would read as "your host is a known
        threat indicator".

        `adversary` is left UNSET: the feed has no threat-actor field (0 of
        3,595 incidents), and both the Red Zone route and the report collect
        pulse.adversary into an adversary list, so a fabricated value would
        propagate into a headline.
        """
        stats = {"pulses_merged": 0, "relationships_created": 0, "errors": []}
        correlations = ((correlation or {}).get("correlations") or [])
        if not correlations:
            return stats

        with self.driver.session() as session:
            for hit in correlations:
                inc = hit.get("incident") or {}
                incident_id = inc.get("incident_id")
                base_url = hit.get("base_url")
                if not incident_id or not base_url:
                    continue
                try:
                    res = session.run(
                        """
                        MATCH (u:BaseURL {url: $base_url, user_id: $uid, project_id: $pid})
                        WITH u
                        MERGE (tp:ThreatPulse {pulse_id: $pulse_id, user_id: $uid, project_id: $pid})
                        ON CREATE SET tp.created_at = datetime()
                        SET tp.name         = $name,
                            tp.tags         = $tags,
                            tp.author_name  = 'supplychainattack.org',
                            tp.modified     = $modified,
                            tp.sca_incident_id   = $incident_id,
                            tp.sca_incident_url  = $url,
                            tp.sca_status        = $status,
                            tp.sca_summary       = $summary,
                            tp.sca_blast_radius  = $blast_radius,
                            tp.sca_remediation   = $remediation,
                            tp.sca_feed_revised  = $feed_revised,
                            tp.updated_at   = datetime()
                        WITH u, tp
                        MERGE (u)-[c:CONTACTS_MALICIOUS_HOST {matched_host: $matched_host}]->(tp)
                        SET c.evidence     = $evidence,
                            c.source_url   = $source_url,
                            c.updated_at   = datetime()
                        RETURN count(c) AS linked
                        """,
                        pulse_id="sca-{}".format(incident_id),
                        uid=user_id, pid=project_id,
                        incident_id=incident_id,
                        name=inc.get("title") or incident_id,
                        tags=[str(t) for t in (inc.get("attack_vectors") or [])][:20],
                        modified=inc.get("last_updated") or "",
                        url=inc.get("url") or "",
                        status=inc.get("status") or "",
                        summary=inc.get("summary") or "",
                        blast_radius=inc.get("blast_radius") or "",
                        remediation=[str(r) for r in (inc.get("remediation") or [])][:20],
                        feed_revised=inc.get("feed_revised") or "",
                        base_url=base_url,
                        # The attacker host lives on the RELATIONSHIP, and it is
                        # part of that relationship's IDENTITY. One incident
                        # commonly lists several attacker domains, and a target
                        # can contact more than one: keyed on the two nodes
                        # alone, the second host MERGEd the SAME edge and
                        # overwrote the first, so the table showed one contacted
                        # host and silently lost the rest of the evidence.
                        # Merging it as a NODE is still forbidden - that would
                        # put a host the target does not own into its attack
                        # surface.
                        matched_host=hit.get("matched_host") or "",
                        evidence=hit.get("evidence") or "graph-host-match",
                        source_url=hit.get("source_url") or "",
                    )
                    row = res.single()
                    if row and row.get("linked"):
                        stats["pulses_merged"] += 1
                        stats["relationships_created"] += 1
                except Exception as exc:
                    stats["errors"].append(
                        "sca intel {}: {}".format(incident_id, exc))
        return stats

    def _anchor_packages_to(self, anchor_label, anchor_key, anchor_value,
                            purls, user_id, project_id):
        """MERGE DEPENDS_ON from one anchor to many packages in ONE query.

        UNWIND rather than a query per package: this is the only part that has
        to repeat per BaseURL, so it is the part worth batching.

        The anchor is MATCHed, never created - inventing a BaseURL the scan did
        not actually observe would put a fabricated target in the graph.
        """
        if anchor_label not in ("GithubRepository", "BaseURL", "SbomDocument"):
            raise ValueError("unsupported anchor_label: {}".format(anchor_label))
        if anchor_key not in ("id", "url"):
            raise ValueError("unsupported anchor_key: {}".format(anchor_key))

        with self.driver.session() as session:
            res = session.run(
                """
                MATCH (a:%s {%s: $anchor_value, user_id: $uid, project_id: $pid})
                UNWIND $purls AS purl
                MATCH (p:Package {purl: purl, user_id: $uid, project_id: $pid})
                MERGE (a)-[:DEPENDS_ON]->(p)
                RETURN count(*) AS c
                """ % (anchor_label, anchor_key),
                anchor_value=anchor_value, purls=purls,
                uid=user_id, pid=project_id)
            rec = res.single()
            return (rec and rec.get("c")) or 0
