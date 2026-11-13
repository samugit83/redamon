# Neo4j Graph Database for RedAmon

## Quick Start

```bash
cd graph_db
docker compose up -d
```

## Endpoints

- **Browser UI**: http://localhost:7474
- **Bolt (Python driver)**: bolt://localhost:7687

## Credentials

Configured via root `.env` file:
- `NEO4J_URI` - Bolt connection URI (default: `bolt://localhost:7687`)
- `NEO4J_USER` - Username (default: `neo4j`)
- `NEO4J_PASSWORD` - Your password

## The schema

This file covers running Neo4j. What the graph CONTAINS - every node label,
its properties, and the relationships between them - is declared once, in
[graph_db/schema_sections.md](../../graph_db/schema_sections.md).

```bash
# the whole schema, as the agent is served it
python3 -c "from graph_db.schema_render import render_schema; print(render_schema())"

# one label
python3 -c "from graph_db.schema_render import render_label; print(render_label('Subdomain'))"
```

Constraints and indexes are generated from
[graph_db/schema_keys.py](../../graph_db/schema_keys.py) and applied by
`init_schema` on every container spawn, so a fresh database needs no manual DDL.

After editing the schema, re-seed the catalog:

```bash
python3 tooling/scripts/seed_schema_catalog.py
```

[GRAPH.SCHEMA.md](GRAPH.SCHEMA.md) explains WHY the graph is shaped this way -
the tenancy model, the `Muted` label, Scan Timeline. It deliberately lists no
labels.

### Moving a project to another owner

`TenancyMixin.retenant_project(project_id, from_user_id, to_user_id)` ([graph_db/mixins/tenancy_mixin.py](../../graph_db/mixins/tenancy_mixin.py), RBAC step 5.12) changes the tenant key of every node of one project, in batches: every label keyed on `(user_id, project_id)` or indexed so (41, checked against the schema catalog), then a label-free sweep for labels an older release wrote, then relationships stamped with the tenant; only `user_id` changes, node ids stay (Postgres rows reference them). A key collision with a node the new owner already holds is refused before any write (`retenant_conflict`); a failed write moves back what it moved (`retenant_failed`); a failed move back raises `retenant_rollback_failed` with what moved, and the same call again completes it. The agent's `POST /graph/retenant` (master key) runs it for an ownership transfer; `tests/rbac_retenant_live.sh` runs it on a live database.

## Configuration

The graph is automatically populated after each recon scan phase completes. Graph updates are controlled by the `UPDATE_GRAPH_DB` setting in the project configuration. GitHub Secret Hunt results are also ingested into the graph after scan completion.

## Docker Commands

```bash
# Start Neo4j
cd graph_db && docker compose up -d

# Stop Neo4j
docker compose down

# Stop and remove all data (fresh start)
docker compose down -v

# View logs
docker compose logs -f

# View last 50 lines of logs
docker compose logs --tail 50

# Check container status
docker compose ps

# Restart Neo4j
docker compose restart

# Enter container shell
docker exec -it redamon-neo4j bash
```

## Cypher Queries

Run these in the Neo4j Browser at http://localhost:7474

Queries sent through the AI agent, the MCP server or a saved graph view are
tenant-scoped before they run, and they refuse variable-length paths and namespaced
function calls ([graph_db/tenant_filter.py](../../graph_db/tenant_filter.py),
[injectProjectFilter.ts](../../webapp/src/app/api/graph-views/execute/injectProjectFilter.ts);
rules in the [MCP Server wiki page](../../redamon.wiki/MCP-Server.md)). A saved view
is stricter: it runs read-only and accepts only Neo4j's built-in functions, ASCII
outside strings, `:Label` node patterns and the `$projectId` parameter (the
[Attack Surface Graph wiki page](../../redamon.wiki/Attack-Surface-Graph.md)). To read an
attack chain's steps there, match `(s:ChainStep {chain_id: $chain_id})`: `HAS_STEP`
links only the first step, and a `NEXT_STEP*` walk is refused.

### View All Data

```cypher
-- Show all nodes and relationships
MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN n, r, m

-- Show all nodes (browser auto-draws relationships)
MATCH (n) RETURN n

-- Count all nodes by type
MATCH (n) RETURN labels(n) AS type, count(n) AS count
```

### Query by Project

```cypher
-- Show all nodes and relationships for a project
MATCH (n {project_id: "first_test"})
OPTIONAL MATCH (n)-[r]->(m)
RETURN n, r, m

-- Filter by both user_id and project_id
MATCH (n {user_id: "samgiam", project_id: "first_test"})
OPTIONAL MATCH (n)-[r]->(m)
RETURN n, r, m
```

### Delete Data

```cypher
-- Delete all nodes and relationships (clear database)
MATCH (n) DETACH DELETE n

-- Delete all data for a specific project
MATCH (n {project_id: "first_test"})
DETACH DELETE n

-- Delete by user_id and project_id
MATCH (n {user_id: "samgiam", project_id: "first_test"})
DETACH DELETE n
```