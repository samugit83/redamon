"""Normalize legacy project-scoped recon seen timestamp strings."""

import json

from graph_db import Neo4jClient


def main() -> int:
    client = None
    try:
        client = Neo4jClient()
        result = client.normalize_recon_seen_timestamps()
        print(json.dumps(result, sort_keys=True))
        return 0
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
