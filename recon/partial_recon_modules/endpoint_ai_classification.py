"""Partial recon for the Endpoint AI Classifier.

Re-classifies the Endpoints and Parameters already in the graph without
re-running the URL-discovery tools (Katana / Hakrawler / GAU / FFuf /
ParamSpider / Arjun / Kiterunner / jsluice). Use cases:

  * Operator updated the AI signal catalogue and wants existing endpoints
    re-tagged.
  * A new lap of AI annotations shipped (new path patterns, new param
    names) and the operator wants the graph back-filled without burning
    a full crawl.
  * Toggle was off during the original scan and operator wants to turn
    classification on now.

Reads:  the Endpoints + Parameters + BaseURLs on the hosts this run covers
        (its scan roots and groups, minus the RoE exclusions).
Writes: Endpoint.ai_interface_type, Endpoint.is_ai_rag_ingest,
        Parameter.is_ai_prompt_injectable, and nothing else.

No new traffic to the target. Pure pattern matching over data the graph
already holds.
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.graph_builders import graph_url_scope, url_host
from recon.partial_recon_modules.helpers import partial_settings, scope_roots


def run_endpoint_ai_classifier(config: dict):
    """Re-run the AI endpoint/parameter classifier over the existing graph.

    config keys used:
      - user_id / project_id (also pulled from env as fallback)
      - domains / domain_groups (the run's scope, from _prepare_scope)
      - include_graph_targets (ignored — this tool only reads from graph)
      - settings_overrides (rarely used)

    Returns None, or {root: status} when the graph write failed. Prints a
    one-line summary to stdout.
    """
    from recon.main_recon_modules.resource_enum import _annotate_ai_endpoint_classifier
    from graph_db.neo4j_client import Neo4jClient

    user_id = os.environ.get("USER_ID", "") or config.get("user_id", "")
    project_id = os.environ.get("PROJECT_ID", "") or config.get("project_id", "")

    if not (user_id and project_id):
        print("[!][ResourceEnum-AI] Missing USER_ID or PROJECT_ID — refusing to run")
        return

    print(f"\n{'=' * 50}")
    print(f"[*][ResourceEnum-AI] Partial recon: Endpoint AI Classifier")
    print(f"[*][ResourceEnum-AI] Project: {project_id}")
    print(f"{'=' * 50}\n")

    settings = partial_settings(config)

    # Force the master toggle on for the partial run — the operator explicitly
    # asked for it. Sub-toggles still honour whatever the project settings say.
    settings["RESOURCE_ENUM_AI_CLASSIFIER_ENABLED"] = True

    # Build a synthetic organized_data dict by reading existing Endpoints +
    # Parameters from Neo4j. We need:
    #   organized_data = {
    #     "by_base_url": {
    #       <base_url>: {
    #         "endpoints": {
    #           <path>: {"parameters": {"query": [...], "body": [...], "path": [...]},
    #                    "methods": [...]}
    #         }
    #       }
    #     }
    #   }
    roots = scope_roots(config)
    client = Neo4jClient()
    organized_data: dict = {"by_base_url": {}}

    with client.driver.session() as session:
        # Endpoints are read project-wide; a host this run does not cover (another
        # group's root, an unticked root) or the RoE excludes is left as it is.
        keep = graph_url_scope(session, user_id, project_id, roots,
                               config.get("domain_groups"), apex_filter=False)

        def in_run(base_url) -> bool:
            host = url_host(base_url) if base_url else ""
            return bool(host) and keep(host)

        # The methods are kept so the write matches each Endpoint on its full
        # (path, method, baseurl) key.
        ep_rows = session.run(
            """
            MATCH (e:Endpoint {user_id:$u, project_id:$p})
            RETURN e.baseurl AS baseurl, e.path AS path, e.method AS method
            """,
            u=user_id, p=project_id,
        )
        ep_total = skipped = 0
        for row in ep_rows:
            base, path = row["baseurl"], row["path"]
            if not path or not in_run(base):
                skipped += 1
                continue
            ep_total += 1
            method = row["method"] or "GET"
            by_base = organized_data["by_base_url"].setdefault(base, {"endpoints": {}})
            ep = by_base["endpoints"].setdefault(
                path,
                {"parameters": {"query": [], "body": [], "path": []}, "methods": []},
            )
            if method not in ep["methods"]:
                ep["methods"].append(method)

        # Attach parameters (one row per parameter, whatever the number of
        # methods sharing its path).
        param_rows = session.run(
            """
            MATCH (e:Endpoint {user_id:$u, project_id:$p})-[:HAS_PARAMETER]->(p:Parameter)
            RETURN DISTINCT e.baseurl AS baseurl, e.path AS path,
                   p.name AS name, p.position AS position
            """,
            u=user_id, p=project_id,
        )
        param_total = 0
        for row in param_rows:
            base = row["baseurl"]
            name = row["name"]
            position = row["position"] or "query"
            ep = (organized_data["by_base_url"].get(base) or {}).get("endpoints", {}).get(row["path"])
            if not ep or not name:
                continue
            param_total += 1
            ep["parameters"].setdefault(position, []).append({"name": name})

    print(f"[*][ResourceEnum-AI] Loaded {ep_total} endpoint(s) + {param_total} parameter(s) from graph")
    if skipped:
        print(f"[*][ResourceEnum-AI] Left {skipped} endpoint(s) on hosts outside this run untouched")

    if ep_total == 0:
        print("[-][ResourceEnum-AI] No endpoints in graph — nothing to classify")
        client.close()
        return

    # Build a minimal recon_data so _build_parent_ai_map can read http_probe.by_url.
    # Pull existing AI tags from BaseURL→Endpoint paths to determine parent-AI.
    recon_data: dict = {"http_probe": {"by_url": {}}}
    with client.driver.session() as session:
        ai_rows = session.run(
            """
            MATCH (b:BaseURL {user_id:$u, project_id:$p})-[:HAS_ENDPOINT]->(e:Endpoint)
            WHERE e.is_ai_framework_detected = true
            RETURN b.url AS base_url
            """,
            u=user_id, p=project_id,
        )
        for row in ai_rows:
            base = row["base_url"]
            if base and base in organized_data["by_base_url"]:
                recon_data["http_probe"]["by_url"][base + "/"] = {"is_ai_framework_detected": True}

    summary = _annotate_ai_endpoint_classifier(organized_data, settings, recon_data)
    print(
        f"[+][ResourceEnum-AI] Classified — "
        f"paths={summary.get('paths', 0)}, "
        f"rag={summary.get('rag_paths', 0)}, "
        f"prompt-params={summary.get('prompt_params', 0)}"
    )

    # Only the AI fields go back (D5): the full resource_enum writer would also
    # set what a crawl measures (urls_found, source, counts, sample values) from
    # this dict, which holds none of it.
    stats = client.update_graph_from_endpoint_ai_classifier(
        organized_data["by_base_url"], user_id, project_id)
    client.close()

    if stats.get("errors"):
        for error in stats["errors"]:
            print(f"[!][ResourceEnum-AI] {error}")
        return {root: "failed: graph write" for root in roots}
    print(f"[+][ResourceEnum-AI] Partial classification complete — "
          f"{stats.get('endpoints_annotated', 0)} endpoint(s), "
          f"{stats.get('parameters_annotated', 0)} parameter(s) annotated")
