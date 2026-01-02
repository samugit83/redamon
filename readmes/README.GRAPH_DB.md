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

## Configuration

Set `UPDATE_GRAPH_DB = True` in `params.py` to automatically populate the graph after `domain_discovery` module completes.

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

## Automatic Integration

When `UPDATE_GRAPH_DB = True`, the graph is automatically populated after `domain_discovery` with:

- **Domain** node (root) with WHOIS data
- **Subdomain** nodes
- **IP** nodes (from DNS resolution)
- **DNSRecord** nodes (TXT, MX, NS, etc.)
- All relationships between them

## Manual Usage

```python
from graph_db import Neo4jClient

with Neo4jClient() as client:
    # Load existing recon data
    import json
    with open("recon/output/recon_example.com.json") as f:
        recon_data = json.load(f)

    # Initialize graph
    stats = client.update_graph_from_domain_discovery(recon_data, "user_id", "project_id")
    print(stats)
```

## Standalone Graph Update Script

Use `update_graph_from_json.py` to run graph updates independently from the main pipeline:

```bash
# Run from project root
cd "/home/samuele/Progetti didattici/RedAmon"
python -m graph_db.update_graph_from_json

# Or run directly
python graph_db/update_graph_from_json.py
```

### Configuration

Edit the script to select which modules to run:

```python
# Run all modules (default)
UPDATE_MODULES = []

# Run specific modules only
UPDATE_MODULES = ["vuln_scan"]
UPDATE_MODULES = ["http_probe", "vuln_scan"]
UPDATE_MODULES = ["domain_discovery", "port_scan", "http_probe", "vuln_scan"]
```

### Available Update Modules

| Module | Creates | Relationships |
|--------|---------|---------------|
| `domain_discovery` | Domain, Subdomain, IP, DNSRecord | HAS_SUBDOMAIN, RESOLVES_TO, HAS_DNS_RECORD |
| `port_scan` | Port, Service | HAS_PORT, RUNS_SERVICE |
| `http_probe` | BaseURL, Technology, Header | SERVES_URL, USES_TECHNOLOGY, HAS_HEADER |
| `vuln_scan` | Endpoint, Parameter, Vulnerability | HAS_ENDPOINT, HAS_PARAMETER, HAS_VULNERABILITY, FOUND_AT, AFFECTS_PARAMETER |

### Use Cases

- Re-import data after schema changes
- Update graph from existing JSON without re-running scans
- Run specific updates (e.g., only vuln_scan after adding new findings)
- Debug/test graph update functions

## Graph Schema

See [GRAPH.SCHEMA.md](../readmes/GRAPH.SCHEMA.md) for the complete schema documentation.

```
(Domain) <-[:BELONGS_TO]- (Subdomain) -[:RESOLVES_TO]-> (IP)
                               |
                        [:HAS_DNS_RECORD]
                               |
                               v
                         (DNSRecord)
```

## Troubleshooting

```bash
# Check if Neo4j is running
docker compose ps

# Check logs for errors
docker compose logs --tail 100

# Verify connection from Python
python -c "from graph_db import Neo4jClient; c = Neo4jClient(); print('OK' if c.verify_connection() else 'FAIL'); c.close()"

# Reset database (delete all data)
docker compose down -v && docker compose up -d
```

## Requirements

```bash
pip install neo4j
```
