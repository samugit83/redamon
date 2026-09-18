"""RESOLVES_TO must be identified by its endpoints, not its property map."""

import re
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
PROPERTY_MERGE = re.compile(
    r"MERGE\s*\([^\n)]*\)\s*-\[[^\]\n]*:RESOLVES_TO\s*\{"
)


class TestResolvesToWriterIdentity(unittest.TestCase):
    def test_production_writers_do_not_merge_on_relationship_properties(self):
        offenders = []
        for root in (REPO_ROOT / "graph_db", REPO_ROOT / "recon" / "partial_recon_modules"):
            for path in root.rglob("*.py"):
                text = path.read_text(encoding="utf-8")
                for match in PROPERTY_MERGE.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{line}")

        self.assertEqual(offenders, [], "property-bearing RESOLVES_TO MERGE: " + ", ".join(offenders))


if __name__ == "__main__":
    unittest.main()
