"""
BaseMixin: Neo4j connection lifecycle and project-level data cleanup.

Provides:
- Driver initialization and context manager support
- Schema initialization (called once at startup)
- clear_project_data: wipe all data for a project
- clear_gvm_data: selective GVM data cleanup
"""

import os
import re
from pathlib import Path

from datetime import datetime, timezone

from neo4j import GraphDatabase
from dotenv import load_dotenv

from graph_db.schema import (init_schema, GLOBAL_REFERENCE_LABELS,
                            NON_RECON_LABELS, NON_RECON_SOURCES)
from graph_db.node_filters.guards import GUARD_KEEP_CHECK

# Load environment variables from local .env file
load_dotenv(Path(__file__).parent.parent / ".env")

#: `n:CVE OR n:Capec OR n:MitreData`, built once from the tenant filter's list
#: (through graph_db.schema) so a label added there is covered here too.
_REFERENCE_LABEL_PREDICATE = " OR ".join(
    f"n:`{label}`" for label in GLOBAL_REFERENCE_LABELS)
_REFERENCE_LABEL_PREDICATE_X = " OR ".join(
    f"x:`{label}`" for label in GLOBAL_REFERENCE_LABELS)

#: Longest path inside the reference catalogue itself:
#: CVE -> MitreData -> Capec. The orphan sweep looks this far for a
#: non-reference anchor, so a node deeper in a longer chain would be kept
#: rather than wrongly deleted.
_REFERENCE_CHAIN_DEPTH = 3

#: Every label a recon clear must leave standing: the other scanners' own, plus
#: the global reference nodes.
_PRESERVED_LABEL_PREDICATE = " OR ".join(
    f"n:`{label}`" for label in tuple(NON_RECON_LABELS) + tuple(GLOBAL_REFERENCE_LABELS))

#: Labels an operator can mute, judge, or have a fix item written for. These
#: carry state a PERSON put there, so they are the ones ingest-then-prune
#: protects. Kept in step with MUTEABLE_LABELS in the triage mixin.
FINDING_LABELS = (
    "Vulnerability", "JsReconFinding", "Secret", "MultiscannerFinding",
    "GithubSecret", "GithubSensitiveFile", "MalPackageFinding", "ExploitGvm",
)

_FINDING_LABEL_PREDICATE = " OR ".join(f"n:`{label}`" for label in FINDING_LABELS)

#: Every property a recon finding writer uses to say which host it is about.
#: No field is shared: nuclei's `host` may be a bare host, host:port or a URL;
#: security checks use `url`/`matched_at`/`hostname`; js_recon and jsluice
#: `source_url`/`base_url`; graphql and cache poisoning `endpoint`; nmap_nse
#: `ip_address`. ai_surface_recon stores none, so its skips are source-level.
#: GVM's Vulnerability and ExploitGvm use `target_ip`/`target_hostname`, which
#: no other finding label carries, so they change no other source's prune.
#: `domain` is the org of a security_check DNS finding (SPF, DMARC, DNSSEC,
#: zone transfer), its only host field; no other finding stores it.
_KEEP_HOST_FIELDS = (
    "host", "hostname", "ip", "ip_address", "matched_ip",
    "url", "matched_at", "base_url", "source_url", "endpoint", "probe_url",
    "target_ip", "target_hostname", "domain",
)

#: What a hostname in `keep_hosts` must look like before it is regex-escaped:
#: a DNS name, or an IPv6 literal without brackets. Underscores are allowed
#: because real hostnames carry them (`_dmarc.`, `my_host.`) and dropping one
#: here would let the prune delete a skipped host's findings.
_KEEP_HOST_CHARS = re.compile(r"^[a-z0-9._\-]+$|^[0-9a-f:]+$")

#: Hosts per regex, so a run that skipped hundreds builds several short
#: patterns rather than one enormous alternation.
_KEEP_HOSTS_PER_PATTERN = 100

#: `n.updated_at` as a DateTime when it is stored as an ISO string, else null.
#: A project export and a scan-version snapshot flatten DateTimes to strings,
#: and a restore before R-38 wrote them back as such; against a DateTime a
#: string compares as null, so those findings were never pruned nor revived.
#: Shape-checked first because one value datetime() cannot parse would fail
#: the whole prune; an unreadable one keeps its finding instead.
_ISO_DATETIME = (
    "[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]"
    "(:[0-5][0-9]([.][0-9]{1,9})?)?(Z|[+-][0-9]{2}(:?[0-9]{2})?)?")
_RESTORED_UPDATED_AT = (
    f"CASE WHEN n.updated_at IS :: STRING AND n.updated_at =~ '{_ISO_DATETIME}' "
    "THEN datetime(n.updated_at) END")

_HOST_FIELD_VALUES = ", ".join(f"toLower(toStringOrNull(n.{f}))" for f in _KEEP_HOST_FIELDS)

#: Positive coverage (D1): only findings about a host the source re-checked.
#: Each host field is read the way keep_host_patterns reads one (a bare host,
#: host:port, [v6]:port, or a URL whose authority is the host, userinfo only
#: after a scheme) and its hostname is looked up in $only_hosts. An exact
#: lookup, not the keep regexes: the checked set is the whole scanned surface,
#: and a regex per hundred hosts per field per candidate measured 10.8 s for
#: 2,000 stale findings over 3,000 hosts, against 0.5 s for the lookup. A
#: value it cannot read names no host, so its finding is kept.
_ONLY_HOSTS_CLAUSE = f"""
        WITH n, [v IN [{_HOST_FIELD_VALUES}] WHERE v IS NOT NULL |
                 CASE WHEN v =~ '[a-z][a-z0-9+.-]*://.*'
                      THEN {{scheme: true, rest: substring(v, size(split(v, '://')[0]) + 3)}}
                      ELSE {{scheme: false, rest: v}} END] AS parsed
        WITH n, [p IN parsed | {{scheme: p.scheme,
                 authority: split(split(split(p.rest, '/')[0], '?')[0], '#')[0]}}] AS authorities
        WITH n, [a IN authorities |
                 CASE WHEN NOT a.authority CONTAINS '@' THEN a.authority
                      WHEN a.scheme AND size(split(a.authority, '@')) = 2
                           THEN split(a.authority, '@')[1] END] AS hostports
        WHERE any(hp IN hostports WHERE hp IS NOT NULL AND
                  CASE WHEN hp STARTS WITH '[' THEN substring(split(hp, ']')[0], 1)
                       WHEN size(split(hp, ':')) = 2 AND split(hp, ':')[1] =~ '[0-9]+'
                            THEN split(hp, ':')[0]
                       ELSE hp END IN $only_hosts)"""


def _keep_host_name(host) -> str:
    """A keep_hosts entry as findings store it: lowercased, and without the
    trailing dot of a fully-qualified name, which no finding writer keeps."""
    if not host:
        return ""
    name = str(host).strip().lower()
    return name[:-1] if name.endswith(".") else name


def _host_names(hosts) -> list:
    """The entries of `keep_hosts` / `only_hosts` that are hostnames, as findings store them."""
    return sorted({n for n in (_keep_host_name(h) for h in hosts or ())
                   if _KEEP_HOST_CHARS.match(n)})


def keep_host_patterns(keep_hosts) -> list:
    """Anchored regexes matching a skipped host however a finding stores it.

    Each matches the whole value when it is the bare host, host:port, or a
    URL whose authority is the host (scheme and userinfo optional, IPv6
    brackets allowed). Hostnames are validated against a strict character
    set and `re.escape`d, and the patterns travel as query parameters - never
    concatenated into the Cypher text.
    """
    names = _host_names(keep_hosts)
    patterns = []
    for i in range(0, len(names), _KEEP_HOSTS_PER_PATTERN):
        alternation = "|".join(re.escape(n) for n in names[i:i + _KEEP_HOSTS_PER_PATTERN])
        patterns.append(
            r"^(?:[a-z][a-z0-9+.\-]*://(?:[^/@]*@)?)?\[?(?:" + alternation
            + r")\]?(?::[0-9]+)?(?:[/?#].*)?$")
    return patterns


def run_timestamp() -> str:
    """The moment a scan started, for `prune_unseen_findings`.

    Taken BEFORE the ingest, never after: everything the ingest writes then has
    a later `updated_at` and survives the prune. Taken after, the prune would
    delete the results the scan had just produced.

    Module level rather than a method: it needs no state, and a caller that
    mixes in only one mixin still has to be able to reach it.
    """
    return datetime.now(timezone.utc).isoformat()


class BaseMixin:
    def _sweep_orphan_reference_nodes(self, session) -> int:
        """Delete global reference nodes nothing points at any more.

        The reference labels are deliberately excluded from every project-scoped
        delete: one CVE node is shared by every project that finds it, so
        removing it with a project would take the other projects' links down too
        (observed live: 4 CVEs stamped with one project, linked from a second).

        Excluding them alone would leak, so this is the other half: a node no
        project can reach any more is safe to drop, and the next scan re-MERGEs
        it from its own feed.

        REACHABILITY, not degree. "No relationships at all" never becomes true,
        because the catalogue is internally linked as
        `CVE -[:HAS_CWE]-> MitreData -[:HAS_CAPEC]-> Capec`: an unreferenced CVE
        still holds its CWE, and that CWE still holds its CAPEC, so a
        degree-zero test kept all three forever. Nor is "no non-reference
        NEIGHBOUR" enough — that would delete a MitreData whose CVE is still
        live. The test is therefore whether any non-reference node sits within
        the chain's depth.
        """
        try:
            record = session.run(
                f"""
                MATCH (n) WHERE ({_REFERENCE_LABEL_PREDICATE})
                  AND NOT EXISTS {{
                    MATCH (n)-[*1..{_REFERENCE_CHAIN_DEPTH}]-(x)
                    WHERE NOT ({_REFERENCE_LABEL_PREDICATE_X})
                  }}
                DETACH DELETE n
                RETURN count(n) AS deleted
                """
            ).single()
            return record["deleted"] if record else 0
        except Exception as e:
            print(f"[!][graph-db] reference-node orphan sweep failed: {e}")
            return 0

    def __init__(self, uri=None, user=None, password=None):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER")
        self.password = password or os.getenv("NEO4J_PASSWORD")
        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        with self.driver.session() as session:
            init_schema(session)

    def close(self):
        self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def verify_connection(self):
        """Verify the connection to Neo4j is working."""
        try:
            with self.driver.session() as session:
                result = session.run("RETURN 1 AS test")
                return result.single()["test"] == 1
        except Exception as e:
            print(f"[!][graph-db] Neo4j connection failed: {e}")
            return False

    def clear_project_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete all nodes and relationships for a specific project.

        This should be called before re-running a recon scan to ensure
        old data is removed and replaced with fresh results.

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted nodes and relationships
        """
        stats = {"nodes_deleted": 0, "relationships_deleted": 0,
                 "reference_nodes_swept": 0}

        with self.driver.session() as session:
            # Delete all nodes and relationships for this project
            # DETACH DELETE removes the node and all its relationships
            result = session.run(
                f"""
                MATCH (n)
                WHERE n.user_id = $user_id AND n.project_id = $project_id
                  AND NOT ({_REFERENCE_LABEL_PREDICATE})
                DETACH DELETE n
                RETURN count(n) as deleted_count
                """,
                user_id=user_id, project_id=project_id
            )
            record = result.single()
            if record:
                stats["nodes_deleted"] = record["deleted_count"]

            stats["reference_nodes_swept"] = self._sweep_orphan_reference_nodes(session)

            print(f"[*][graph-db] Cleared project data: {stats['nodes_deleted']} nodes deleted")

        return stats

    def prune_unseen_findings(self, user_id: str, project_id: str,
                              sources, run_started_at: str, keep_hosts=(), *,
                              only_hosts=None, types=None, exclude_types=None) -> dict:
        """Ingest-then-prune: remove a source's findings it stopped reporting.

        WHY THIS REPLACED CLEAR-THEN-INGEST
        Every scanner used to DELETE its findings up front and re-create them.
        That deleted the operator's work with them: the mute they applied, the
        verdict they recorded, the AI's cached review, the link from a fix item
        back to the finding. Re-muting the same noise after every scan was the
        visible symptom; the invisible one was a fix item pointing at a finding
        id that no longer existed.

        So a scan now MERGEs its findings (which refreshes `updated_at`), and
        afterwards this removes the ones it did not touch. `updated_at` is
        already stamped by every node write and is already tested as universal,
        so "not seen in this run" is just "older than the run started".

        TWO RULES THAT MAKE IT SAFE
        1. A finding a PERSON touched is never deleted. Findings an operator
           muted and human-judged findings are kept and stamped `stale_since`
           instead, so the board can show them as resolved and an operator can
           see that the scanner stopped reporting something they had suppressed.
           A mute a node-filter RULE applied (`muted_by` starting `rule:`) is not
           a person's decision about that finding, so it is pruned like any
           other stale finding; the operator's exemptions live in Postgres and
           need no node to survive.
        2. CALL THIS ONLY AFTER A SUCCESSFUL INGEST. A scan that failed halfway
           reported nothing, and pruning on that would delete the entire
           project's findings. The caller owns that decision; this method
           cannot tell.

        `keep_hosts` are hostnames a degraded run skipped as unreachable: every
        finding about one of them is left exactly as it is (neither deleted
        nor stamped stale), since the run never re-checked it. Per host rather
        than per source, so one permanently dead host cannot keep a whole
        source unpruned for ever. With it empty the query is unchanged.

        `only_hosts` is the positive-coverage rule (design decision D1): when
        given, only findings about one of these hostnames (the hosts the
        sources re-checked this run, `CoverageReport.checked_hostnames`) are
        deleted or stamped stale, and every other finding of the sources is
        left as it is. Empty, nothing is pruned; the revive still runs.
        `keep_hosts` still wins over it, finding by finding. `types` narrows
        the prune to findings whose `type` is one of these, for a source that
        records coverage per check type (`security_check`). With both None the
        query is the older, source-level one.

        `exclude_types` leaves findings of these types out: the source-level
        rule for the types such a source did not record, so a check that has
        not adopted D1, or is switched off, prunes exactly as before while the
        recorded types prune on their own hosts. None changes nothing.
        """
        sources = [s for s in (sources or []) if s]
        if not sources or not run_started_at:
            return {"pruned": 0, "stale": 0}

        keep_patterns = keep_host_patterns(keep_hosts)
        keep_clause = ""
        if keep_patterns:
            checks = " OR ".join(
                f"coalesce(toLower(toStringOrNull(n.{f})), '') =~ rx" for f in _KEEP_HOST_FIELDS)
            keep_clause = f"\n          AND NOT any(rx IN $keep_patterns WHERE {checks})"
        only = None if only_hosts is None else _host_names(only_hosts)
        types = None if types is None else sorted({str(t) for t in types if t})
        types_clause = "" if types is None else "\n          AND coalesce(n.type, '') IN $types"
        excluded = None if exclude_types is None else sorted({str(t) for t in exclude_types if t})
        if excluded:
            types_clause += "\n          AND NOT coalesce(n.type, '') IN $exclude_types"
        only_clause = "" if only is None else _ONLY_HOSTS_CLAUSE
        prunes_something = only != [] and types != []

        query = f"""
        MATCH (n)
        WHERE n.user_id = $uid AND n.project_id = $pid
          AND ({_FINDING_LABEL_PREDICATE})
          AND coalesce(n.source, '') IN $sources
          AND (n.updated_at IS NULL OR n.updated_at < datetime($since)
               OR {_RESTORED_UPDATED_AT} < datetime($since)){keep_clause}{types_clause}{only_clause}
        // The write lock BEFORE `keep` reads n:Muted: a mute that committed
        // first is then kept, and one that starts later waits for the delete
        // and matches nothing. Without it a mute can land between the read
        // and the DETACH DELETE and be deleted with the node.
        SET n._prune_lock = true
        REMOVE n._prune_lock
        // Keep = an operator's own mute, OR any guard that spares a finding from
        // a rule-mute (person judged it, agent proved it). Sourced from
        // node_filters/guards.py so the prune and the mute guards never drift:
        // deleting an agent-confirmed candidate because a later run stopped
        // reporting it would destroy proof (plan §5.6-A, §12-A).
        WITH n,
             ((n:Muted AND NOT coalesce(n.muted_by, '') STARTS WITH 'rule:')
              OR ({GUARD_KEEP_CHECK})) AS keep
        // Kept: stamped rather than deleted, so it shows as resolved and the
        // person who judged it can see what happened to it.
        FOREACH (_ IN CASE WHEN keep THEN [1] ELSE [] END |
          SET n.stale_since = coalesce(n.stale_since, datetime()))
        WITH collect(CASE WHEN keep THEN NULL ELSE n END) AS candidates,
             count(CASE WHEN keep THEN 1 END) AS stale
        WITH [c IN candidates WHERE c IS NOT NULL] AS doomed, stale
        FOREACH (d IN doomed | DETACH DELETE d)
        RETURN size(doomed) AS pruned, stale
        """

        # A kept finding the scanner reports AGAIN is alive again. Nothing else
        # ever clears `stale_since` (the ingest MERGE only refreshes
        # `updated_at`), so without this a human-confirmed finding that came
        # back would stay "Resolved" on the board for ever.
        revive = f"""
        MATCH (n)
        WHERE n.user_id = $uid AND n.project_id = $pid
          AND ({_FINDING_LABEL_PREDICATE})
          AND coalesce(n.source, '') IN $sources
          AND n.stale_since IS NOT NULL
          AND (n.updated_at >= datetime($since)
               OR {_RESTORED_UPDATED_AT} >= datetime($since))
        REMOVE n.stale_since
        RETURN count(n) AS revived
        """

        with self.driver.session() as session:
            revived = session.run(
                revive, uid=user_id, pid=project_id, sources=sources,
                since=run_started_at,
            ).single()
            params = {"uid": user_id, "pid": project_id, "sources": sources,
                      "since": run_started_at}
            if keep_patterns:
                params["keep_patterns"] = keep_patterns
            if only is not None:
                params["only_hosts"] = only
            if types is not None:
                params["types"] = types
            if excluded:
                params["exclude_types"] = excluded
            record = session.run(query, **params).single() if prunes_something else None

        stats = {
            "pruned": int((record["pruned"] if record else 0) or 0),
            "stale": int((record["stale"] if record else 0) or 0),
            "revived": int((revived["revived"] if revived else 0) or 0),
        }
        scope = "" if only is None else f" on {len(only)} re-checked host(s)"
        print(f"[*][graph-db] Pruned {stats['pruned']} findings no longer "
              f"reported by {', '.join(sources)}{scope}; kept {stats['stale']} muted "
              f"or human-judged as stale; revived {stats['revived']}")
        return stats

    def clear_recon_data(self, user_id: str, project_id: str) -> dict:
        """Delete the RECON pipeline's own nodes for a project, and nothing else.

        Recon re-runs used to call `clear_project_data`, a bare
        `MATCH (n) WHERE n.user_id AND n.project_id DETACH DELETE n`. That is
        every node in the project, so a recon scan silently deleted the GitHub
        Secret Hunt, the Secret Multiscanner findings, the supply-chain packages
        (1638 OSV vulnerabilities on this box alone), the GVM results and the
        agent's attack chains. Every other scanner had already been given a
        scoped clear; recon was the last one still wiping the lot.

        Two exclusions, because ownership shows up two ways:
          - by LABEL, for the subsystems with labels of their own
            (`NON_RECON_LABELS`), and
          - by SOURCE, for the labels recon shares — Vulnerability above all,
            which GVM, the supply-chain scanner and the AI attack-surface
            scanner all write into (`NON_RECON_SOURCES`).

        Technology is kept whenever GVM has also detected it: recon re-MERGEs the
        node on the next pass anyway, and deleting it here would orphan the GVM
        vulnerabilities hanging off it. That mirrors clear_gvm_data, which strips
        GVM's enrichment off a shared Technology rather than deleting it.
        """
        stats = {"nodes_deleted": 0, "reference_nodes_swept": 0}

        with self.driver.session() as session:
            result = session.run(
                f"""
                MATCH (n)
                WHERE n.user_id = $uid AND n.project_id = $pid
                  AND NOT ({_PRESERVED_LABEL_PREDICATE})
                  // X7: findings are pruned AFTER a successful ingest, not
                  // deleted before one. Deleting them here took the operator's
                  // mutes and verdicts with them, every scan.
                  AND NOT ({_FINDING_LABEL_PREDICATE})
                  AND NOT coalesce(n.source, '') IN $keep_sources
                  AND coalesce(n.ai_attack_synthetic, false) = false
                  AND NOT (n:Technology AND coalesce(n.detected_by, '') CONTAINS 'gvm')
                  AND NOT (n:Certificate AND any(o IN coalesce(n.observed_by, []) WHERE o IN $keep_sources))
                DETACH DELETE n
                RETURN count(n) AS deleted
                """,
                uid=user_id, pid=project_id, keep_sources=list(NON_RECON_SOURCES)
            )
            record = result.single()
            if record:
                stats["nodes_deleted"] = record["deleted"]

            stats["reference_nodes_swept"] = self._sweep_orphan_reference_nodes(session)

            print(f"[*][graph-db] Cleared recon data: {stats['nodes_deleted']} nodes "
                  f"deleted (other scanners' findings preserved)")

        return stats

    def clear_gvm_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete only GVM-specific nodes and relationships for a project.

        Preserves all recon data (Domain, Subdomain, IP, Port, BaseURL,
        Endpoint, Parameter, Service, etc.). Only removes:
        - Vulnerability nodes with source='gvm'
        - GVM-only CVE nodes (not shared with recon)
        - GVM-only Technology nodes (detected_by='gvm')
        - GVM enrichments on shared Technology nodes (CPE data)
        - USES_TECHNOLOGY relationships with detected_by='gvm'
        - Domain node GVM metadata properties

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted/cleaned items
        """
        stats = {
            "vulnerabilities_deleted": 0,
            "cves_deleted": 0,
            "technologies_deleted": 0,
            "technologies_cleaned": 0,
            "traceroutes_deleted": 0,
            "certificates_deleted": 0,
            "exploits_gvm_deleted": 0,
            "relationships_deleted": 0,
        }

        with self.driver.session() as session:
            # Every delete below takes the node's write lock BEFORE reading
            # n:Muted (the prune's idiom), so a mute committing mid-statement is
            # kept rather than deleted with the node.
            #
            # 1. GVM's Vulnerability findings are NO LONGER deleted here (X7).
            # Deleting them deleted the operator's mutes and verdicts with them,
            # every scan. They are pruned after a successful ingest instead.
            # Only ones a previous run left with no host attached are swept,
            # because nothing will ever re-MERGE those.
            result = session.run(
                """
                MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
                WHERE v.source = 'gvm'
                  AND NOT (v)<-[:HAS_VULNERABILITY]-()
                SET v._prune_lock = true
                REMOVE v._prune_lock
                WITH v
                WHERE NOT v:Muted
                  AND coalesce(v.triage_source, '') <> 'human'
                DETACH DELETE v
                RETURN count(v) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["vulnerabilities_deleted"] = record["deleted"]

            # 1b. Delete Traceroute nodes
            result = session.run(
                """
                MATCH (tr:Traceroute {user_id: $uid, project_id: $pid})
                DETACH DELETE tr
                RETURN count(tr) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["traceroutes_deleted"] = record["deleted"]

            # 1c. Delete Certificate nodes observed ONLY by GVM. A certificate
            # httpx/tlsx/OSINT also observed carries their name in observed_by and
            # is preserved — source alone is whoever wrote last and cannot answer
            # "does another scanner still need this".
            result = session.run(
                """
                MATCH (c:Certificate {user_id: $uid, project_id: $pid})
                WHERE coalesce(c.observed_by, []) = ['gvm']
                   OR (coalesce(c.observed_by, []) = [] AND c.source = 'gvm')
                DETACH DELETE c
                RETURN count(c) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["certificates_deleted"] = record["deleted"]

            # 1d. ExploitGvm is a FINDING too, and the strongest one the
            # product has: it is what makes something "proven" on the board.
            # Same rule (X7): a person's decision on one survives.
            result = session.run(
                """
                MATCH (e:ExploitGvm {user_id: $uid, project_id: $pid})
                SET e._prune_lock = true
                REMOVE e._prune_lock
                WITH e
                WHERE NOT e:Muted
                  AND coalesce(e.triage_source, '') <> 'human'
                DETACH DELETE e
                RETURN count(e) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["exploits_gvm_deleted"] = record["deleted"]

            # 2. CVE is a GLOBAL reference node shared by every project that
            #    finds it, so it cannot be deleted by project. Removing the
            #    ExploitGvm nodes above already dropped this scan's
            #    EXPLOITED_CVE edges; the sweep collects only the CVEs that are
            #    now referenced by nothing at all, in any project.
            stats["cves_deleted"] = self._sweep_orphan_reference_nodes(session)

            # 3. Delete GVM-only Technology nodes (detected_by exactly 'gvm')
            result = session.run(
                """
                MATCH (t:Technology {user_id: $uid, project_id: $pid})
                WHERE t.detected_by = 'gvm'
                DETACH DELETE t
                RETURN count(t) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["technologies_deleted"] = record["deleted"]

            # 4. Clean shared Technology nodes (strip GVM enrichment)
            result = session.run(
                """
                MATCH (t:Technology {user_id: $uid, project_id: $pid})
                WHERE t.detected_by CONTAINS ',gvm'
                SET t.detected_by = replace(t.detected_by, ',gvm', ''),
                    t.cpe = null, t.cpe_vendor = null, t.cpe_product = null
                RETURN count(t) as cleaned
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["technologies_cleaned"] = record["cleaned"]

            # 5. Delete GVM USES_TECHNOLOGY relationships (Port→Tech and IP→Tech)
            result = session.run(
                """
                MATCH ({user_id: $uid, project_id: $pid})-[r:USES_TECHNOLOGY]->()
                WHERE r.detected_by = 'gvm'
                DELETE r
                RETURN count(r) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["relationships_deleted"] = record["deleted"]

            # 6. Clear Domain node GVM metadata properties
            session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                WHERE d.gvm_scan_timestamp IS NOT NULL
                REMOVE d.gvm_scan_timestamp, d.gvm_total_vulnerabilities,
                       d.gvm_critical, d.gvm_high, d.gvm_medium, d.gvm_low
                """,
                uid=user_id, pid=project_id
            )

            total = (stats["vulnerabilities_deleted"] + stats["cves_deleted"] +
                     stats["technologies_deleted"] + stats["traceroutes_deleted"] +
                     stats["certificates_deleted"] + stats["exploits_gvm_deleted"] +
                     stats["relationships_deleted"])
            print(f"[*][graph-db] Cleared GVM data: {total} items removed, "
                  f"{stats['technologies_cleaned']} shared technologies cleaned")

        return stats
