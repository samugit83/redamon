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