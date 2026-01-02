# RedAmon - MITRE CWE/CAPEC Enrichment Module

## Complete Technical Documentation

> **Module:** `recon/add_mitre.py` (automatically called by `vuln_scan`)
> **Purpose:** Enrich CVE data with CWE weaknesses and CAPEC attack patterns
> **Author:** RedAmon Security Suite

**Note:** MITRE CWE/CAPEC enrichment is automatically integrated into the `vuln_scan` module.
When you run `vuln_scan`, all discovered CVEs are automatically enriched with CWE weaknesses and CAPEC attack patterns.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [The Enrichment Chain](#the-enrichment-chain)
4. [Configuration Parameters](#configuration-parameters)
5. [Data Sources](#data-sources)
6. [Output Data Structure](#output-data-structure)
7. [Usage Examples](#usage-examples)
8. [Database Management](#database-management)
9. [Understanding CWE and CAPEC](#understanding-cwe-and-capec)
10. [Integration with Pipeline](#integration-with-pipeline)

---

## Overview

The `add_mitre.py` module enriches discovered CVEs with MITRE CWE and CAPEC intelligence. This transforms raw vulnerability data into actionable security intelligence by mapping:

- **CVEs** → What's vulnerable
- **CWEs** → Why it's vulnerable (weakness type)
- **CAPECs** → How attackers exploit it (attack patterns)

### Why CWE/CAPEC Enrichment?

| Without Enrichment | With Enrichment |
|-------------------|-----------------|
| CVE-2021-44228 | CVE-2021-44228 |
| CVSS: 10.0 | CVSS: 10.0 |
| "Log4j vulnerability" | **CWE:** CWE-502 - Deserialization of Untrusted Data |
| | **CAPEC:** CAPEC-586 - Object Injection |
| | **Attack Pattern:** How adversaries inject malicious objects |

### Why NOT ATT&CK Techniques?

> **Important:** This module intentionally does NOT include MITRE ATT&CK techniques or D3FEND defenses.

The CVE2CAPEC database maps CVEs through the CWE hierarchy to ATT&CK techniques. However, these mappings often come from **generic parent CWEs**, not the specific vulnerability. This leads to inaccurate, overly broad technique associations.

**Example Problem:**
```
CVE-2019-9641 (PHP EXIF uninitialized read)
  → CWE-908 (most specific - Uninitialized Resource)
  → CWE-665 (parent - Improper Initialization)
  → CWE-664 (grandparent - Improper Control of a Resource)

From CWE-664, the database inherits CAPECs like:
  - CAPEC-61 Session Fixation      ← NOT RELEVANT
  - CAPEC-62 Cross Site Request Forgery  ← NOT RELEVANT

These inherited CAPECs then link to ATT&CK techniques that have nothing to do
with the actual memory corruption vulnerability.
```

**Our Solution:** Only use **direct CAPEC mappings** from the **most specific CWE** for each CVE. If the specific CWE has no direct CAPECs, we don't show any (rather than showing inaccurate inherited ones).

### How It Works

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        MITRE CWE/CAPEC ENRICHMENT FLOW                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   CVE-2021-3618                                                                 │
│        │                                                                        │
│        ▼                                                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │  cwe_hierarchy (nested parent→child structure)                          │  │
│   │                                                                         │  │
│   │  CWE-284 (Pillar, DISCOURAGED)                                         │  │
│   │    └── CWE-287 (Class, DISCOURAGED)                                    │  │
│   │          └── CWE-295 (Base, ALLOWED) ← Rich details + CAPECs           │  │
│   │                • name, description, consequences                        │  │
│   │                • mitigations, detection_methods                         │  │
│   │                • observed_examples, platforms                           │  │
│   │                • related_capec: [CAPEC-475, CAPEC-459]                  │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│   Data Sources:                                                                 │
│   • CVE2CAPEC (github.com/Galeax/CVE2CAPEC) - CVE→CWE mappings                 │
│   • Official MITRE CWE XML - metadata (name, abstraction, mapping, details)     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **CWE Hierarchy** | Nested parent→child structure showing weakness lineage |
| **CWE Metadata** | Name, abstraction level (Pillar/Class/Base/Variant), mapping status |
| **Rich Details** | For ALLOWED CWEs: descriptions, consequences, mitigations, detection methods |
| **Real Examples** | Observed CVE examples demonstrating each weakness |
| **Platform Info** | Affected languages and technologies |
| **CAPEC Patterns** | Direct attack patterns embedded in ALLOWED CWEs only |
| **Accurate Mappings** | Only includes CAPECs from appropriate CWEs (not inherited from parents) |
| **Auto-Update Database** | Automatically downloads and caches CVE2CAPEC + official CWE metadata |
| **Offline Mode** | Works with cached data when auto-update is disabled |
| **GVM Support** | Enriches both recon output and GVM/OpenVAS scan results |

---

## The Enrichment Chain

### CVE → CWE Hierarchy

**What:** A nested structure showing the weakness hierarchy from most abstract (Pillar) to most specific (Base/Variant).

The enrichment builds a **hierarchical chain** of CWEs:

```
CVE-2021-3618 → cwe_hierarchy:
    CWE-284 (Pillar, DISCOURAGED)
        └── CWE-287 (Class, DISCOURAGED)
              └── CWE-295 (Base, ALLOWED) ← Rich details + CAPECs here
```

| Abstraction | Example | Mapping | Gets CAPECs? |
|-------------|---------|---------|--------------|
| Pillar | CWE-284: Improper Access Control | DISCOURAGED | ❌ |
| Class | CWE-287: Improper Authentication | DISCOURAGED | ❌ |
| Base | CWE-295: Improper Certificate Validation | ALLOWED | ✅ |
| Variant | CWE-297: Improper Validation of Host Certificate | ALLOWED | ✅ |

### CWE (ALLOWED) → CAPEC

**What:** Attack patterns are only embedded in CWEs with `mapping: ALLOWED`.

**Key:** CAPECs come from ALLOWED CWEs, not inherited from DISCOURAGED parents.

```
CWE-295 (Base, ALLOWED) → related_capec: [CAPEC-475, CAPEC-459] ✓
CWE-284 (Pillar, DISCOURAGED) → no CAPECs shown ✓
```

| Example CAPECs | Description |
|----------------|-------------|
| CAPEC-66 | SQL Injection |
| CAPEC-86 | XSS Through HTTP Headers |
| CAPEC-586 | Object Injection |
| CAPEC-88 | OS Command Injection |
| CAPEC-540 | Overread Buffers |
| CAPEC-664 | Server Side Request Forgery |
| CAPEC-475 | Signature Spoofing by Improper Validation |

---

## Configuration Parameters

All parameters are configured in `params.py`:

```python
# =============================================================================
# MITRE CWE/CAPEC Enrichment Configuration
# =============================================================================

# Auto-update MITRE database when running enrichment
# If True, downloads latest CVE2CAPEC data before enrichment (respects TTL cache)
# If False, uses existing cached database only
MITRE_AUTO_UPDATE_DB = True

# Include CWE (Common Weakness Enumeration) information
# Shows the weakness type that enabled the vulnerability
MITRE_INCLUDE_CWE = True

# Include CAPEC (Common Attack Pattern Enumeration) information
# Shows the attack patterns directly associated with the specific CWE
MITRE_INCLUDE_CAPEC = True

# Which scan outputs to enrich with MITRE data
MITRE_ENRICH_RECON = True    # Enrich recon output (vuln_scan + technology_cves)
MITRE_ENRICH_GVM = True      # Enrich GVM/OpenVAS output

# Local database cache settings
MITRE_DATABASE_PATH = "recon/data/mitre_db"  # Where to store the database
MITRE_CACHE_TTL_HOURS = 24                    # How long before checking for updates
```

### Parameter Details

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `MITRE_AUTO_UPDATE_DB` | bool | `True` | Auto-download database updates (respects TTL) |
| `MITRE_INCLUDE_CWE` | bool | `True` | Add CWE weakness mappings with hierarchy |
| `MITRE_INCLUDE_CAPEC` | bool | `True` | Add CAPEC attack patterns (direct only) |
| `MITRE_ENRICH_RECON` | bool | `True` | Enrich recon scan results |
| `MITRE_ENRICH_GVM` | bool | `True` | Enrich GVM scan results |
| `MITRE_DATABASE_PATH` | str | `recon/data/mitre_db` | Database cache location |
| `MITRE_CACHE_TTL_HOURS` | int | `24` | Hours before database refresh |

---

## Data Sources

### CVE2CAPEC Database

**Source:** [github.com/Galeax/CVE2CAPEC](https://github.com/Galeax/CVE2CAPEC)

The CVE2CAPEC project provides daily-updated mappings from CVEs to CWE and CAPEC.

### Official MITRE CWE Data

**Source:** [cwe.mitre.org](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip)

Official CWE XML data provides detailed metadata (name, abstraction, mapping status, descriptions, mitigations, etc.)

### Official MITRE CAPEC Data

**Source:** [capec.mitre.org](https://capec.mitre.org/data/xml/capec_latest.xml)

Official CAPEC XML data provides detailed attack pattern information (descriptions, severity, execution flow, examples, prerequisites)

**Files Downloaded:**

| File | Purpose | Size |
|------|---------|------|
| `capec_db.json` | CAPEC patterns with names (from CVE2CAPEC) | ~80KB |
| `cwe_db.json` | CWE hierarchy, relationships, and direct CAPEC mappings | ~130KB |
| `cwe_metadata.json` | CWE names, abstraction, mapping status, descriptions, mitigations | ~15MB |
| `capec_metadata.json` | CAPEC descriptions, severity, execution flow, examples | ~4MB |
| `CVE-{year}.jsonl` | CVE → CWE mappings (per year) | ~2-40MB each |

---

## Output Data Structure

### Enriched CVE Format

Each CVE in the output receives a `mitre_attack` field with a hierarchical CWE structure:

```json
{
  "id": "CVE-2021-3618",
  "description": "ALPACA is an application layer protocol content confusion attack...",
  "cvss": 7.4,
  "severity": "HIGH",
  "mitre_attack": {
    "enriched": true,
    "enrichment_timestamp": "2026-01-01T23:04:14",
    "source": "CVE2CAPEC",
    
    "cwe_hierarchy": {
      "id": "CWE-284",
      "url": "https://cwe.mitre.org/data/definitions/284.html",
      "name": "Improper Access Control",
      "abstraction": "Pillar",
      "mapping": "DISCOURAGED",
      "child": {
        "id": "CWE-287",
        "url": "https://cwe.mitre.org/data/definitions/287.html",
        "name": "Improper Authentication",
        "abstraction": "Class",
        "mapping": "DISCOURAGED",
        "child": {
          "id": "CWE-295",
          "url": "https://cwe.mitre.org/data/definitions/295.html",
          "name": "Improper Certificate Validation",
          "abstraction": "Base",
          "mapping": "ALLOWED",
          "structure": "Simple",
          "description": "The product does not validate, or incorrectly validates, a certificate.",
          "consequences": [
            {
              "scope": ["Integrity", "Authentication"],
              "impact": ["Bypass Protection Mechanism", "Gain Privileges or Assume Identity"]
            }
          ],
          "mitigations": [
            {
              "description": "Certificates should be carefully managed and checked...",
              "phase": ["Architecture and Design", "Implementation"]
            }
          ],
          "detection_methods": [
            {"method": "Automated Static Analysis - Binary or Bytecode"},
            {"method": "Dynamic Analysis with Automated Results Interpretation"}
          ],
          "observed_examples": [
            {"cve": "CVE-2014-1266", "description": "Apple 'goto fail' bug..."}
          ],
          "platforms": {
            "languages": ["Not Language-Specific"],
            "technologies": ["Web Based", "Mobile"]
          },
          "related_capec": [
            {
              "id": "CAPEC-459",
              "url": "https://capec.mitre.org/data/definitions/459.html",
              "name": "Creating a Rogue Certification Authority Certificate",
              "description": "An adversary exploits a weakness resulting from using a hashing algorithm with weak collision resistance...",
              "likelihood": "Medium",
              "severity": "Very High",
              "prerequisites": ["Certification Authority is using a hash function with insufficient collision resistance..."],
              "execution_flow": [
                {"step": "1", "phase": "Experiment", "description": "Craft two different, but valid X.509 certificates..."},
                {"step": "2", "phase": "Experiment", "description": "Send CSR to Certificate Authority..."},
                {"step": "3", "phase": "Exploit", "description": "Insert Signed Blob into Unsigned Certificate..."}
              ],
              "examples": ["The Windows CryptoAPI (Crypt32.dll) was shown to be vulnerable..."],
              "related_cwes": ["CWE-327", "CWE-295", "CWE-290"]
            }
          ]
        }
      }
    }
  }
}
```

### CWE Hierarchy Structure

The `cwe_hierarchy` is a nested object representing the parent→child chain from the broadest category to the most specific weakness.

| Field | Type | Description | Present In |
|-------|------|-------------|------------|
| `id` | string | CWE ID (e.g., "CWE-295") | All CWEs |
| `url` | string | Link to official MITRE CWE page | All CWEs |
| `name` | string | Human-readable weakness name | All CWEs |
| `abstraction` | string | Level: Pillar, Class, Base, or Variant | All CWEs |
| `mapping` | string | ALLOWED, DISCOURAGED, or PROHIBITED | All CWEs |
| `child` | object | Nested child CWE (if any) | Non-leaf CWEs |
| `related_capec` | array | Direct CAPEC attack patterns | ALLOWED CWEs only |

### Additional Fields for ALLOWED CWEs

CWEs with `mapping: ALLOWED` include rich security intelligence:

| Field | Type | Description |
|-------|------|-------------|
| `structure` | string | Simple or Composite |
| `description` | string | Full description of the weakness |
| `consequences` | array | Security impact (scope + impact) |
| `mitigations` | array | How to fix (description + phase) |
| `detection_methods` | array | How to detect this weakness |
| `observed_examples` | array | Real CVEs demonstrating this weakness |
| `platforms` | object | Affected languages and technologies |

### CAPEC Object (in `related_capec`)

Each CAPEC entry includes comprehensive attack pattern intelligence from official MITRE data:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | CAPEC ID (e.g., "CAPEC-459") |
| `url` | string | Link to official MITRE CAPEC page |
| `name` | string | Human-readable attack pattern name |
| `description` | string | Full description of the attack pattern |
| `likelihood` | string | Likelihood of attack: Low, Medium, High |
| `severity` | string | Typical severity: Low, Medium, High, Very High |
| `prerequisites` | array | Conditions required for the attack to succeed |
| `execution_flow` | array | Step-by-step attack methodology (step, phase, description) |
| `examples` | array | Real-world attack scenarios and instances |
| `related_cwes` | array | Associated CWE weaknesses (e.g., ["CWE-327", "CWE-295"]) |

### CWE Abstraction Levels

| Level | Description | Example |
|-------|-------------|---------|
| **Pillar** | Highest-level category (most abstract) | CWE-284: Improper Access Control |
| **Class** | Abstract, language-independent weakness | CWE-287: Improper Authentication |
| **Base** | Abstract, detection-capable weakness | CWE-295: Improper Certificate Validation |
| **Variant** | Most specific, low-level weakness | CWE-297: Improper Validation of Host-specific Certificate Data |

### CWE Mapping Status

| Status | Meaning | CAPEC Included? |
|--------|---------|-----------------|
| **ALLOWED** | Suitable for mapping vulnerabilities | ✅ Yes - full details |
| **DISCOURAGED** | Too abstract for direct mapping | ❌ No |
| **PROHIBITED** | Should not be used for mapping | ❌ No |

### When `related_capec` Is Empty

Some ALLOWED CWEs may have `related_capec: []`. This happens when:
1. The CWE has no direct CAPEC mappings in the MITRE database
2. The CWE is too new or specific to have documented attack patterns

This is **correct behavior** - we don't show inherited CAPECs from parent CWEs that aren't relevant to the specific weakness.

---

## Usage Examples

### Automatic Integration with vuln_scan

MITRE enrichment is automatically included when running `vuln_scan`:

```python
# params.py
SCAN_MODULES = ["domain_discovery", "port_scan", "http_probe", "vuln_scan"]
# ↑ vuln_scan automatically includes MITRE CWE/CAPEC enrichment
```

### CWE Only (No CAPEC)

```python
# params.py
MITRE_INCLUDE_CAPEC = False  # Only show CWE weaknesses
```

### Offline Mode (No Internet)

```python
# params.py
MITRE_AUTO_UPDATE_DB = False  # Use cached database only
```

---

## Database Management

### Database Location

```
recon/data/mitre_db/
├── resources/
│   ├── capec_db.json               # CAPEC patterns with names (from CVE2CAPEC)
│   ├── cwe_db.json                 # CWE hierarchy and relationships
│   ├── cwe_metadata.json           # CWE metadata (name, abstraction, mapping, descriptions, mitigations)
│   └── capec_metadata.json         # CAPEC metadata (descriptions, severity, execution flow, examples)
├── database/
│   ├── CVE-2020.jsonl              # CVE mappings for 2020
│   ├── CVE-2021.jsonl              # CVE mappings for 2021
│   ├── CVE-2022.jsonl              # CVE mappings for 2022
│   ├── CVE-2023.jsonl              # CVE mappings for 2023
│   ├── CVE-2024.jsonl              # CVE mappings for 2024
│   └── CVE-2025.jsonl              # CVE mappings for 2025
└── .last_update                    # Timestamp of last update
```

### Cache TTL

The database is refreshed when:
- More than `MITRE_CACHE_TTL_HOURS` hours have passed since last update
- The `.last_update` file doesn't exist
- Required files are missing

### Manual Database Update

To force a database update, delete the `.last_update` file:

```bash
rm recon/data/mitre_db/.last_update
```

Or set a shorter TTL:

```python
MITRE_CACHE_TTL_HOURS = 1  # Check for updates every hour
```

---

## Understanding CWE and CAPEC

### CWE Categories

| Category | Example CWEs | Description |
|----------|--------------|-------------|
| **Injection** | CWE-79, CWE-89, CWE-78 | Code/data injection vulnerabilities |
| **Memory Safety** | CWE-119, CWE-125, CWE-908 | Buffer overflows, uninitialized memory |
| **Authentication** | CWE-287, CWE-306, CWE-798 | Authentication bypass, hardcoded credentials |
| **Access Control** | CWE-284, CWE-639, CWE-862 | Improper access control |
| **Cryptography** | CWE-327, CWE-328, CWE-330 | Weak cryptography |
| **Input Validation** | CWE-20, CWE-113, CWE-117 | Improper input handling |

### CAPEC Categories

| Category | Example CAPECs | Description |
|----------|----------------|-------------|
| **Injection** | CAPEC-66, CAPEC-88 | SQL injection, command injection |
| **Data Manipulation** | CAPEC-586, CAPEC-664 | Object injection, SSRF |
| **Resource Consumption** | CAPEC-125, CAPEC-147 | DoS attacks |
| **Credential Attacks** | CAPEC-16, CAPEC-49 | Brute force, credential stuffing |
| **Session Attacks** | CAPEC-61, CAPEC-62 | Session fixation, CSRF |

### CWE Hierarchy Example

```
cwe_hierarchy for a certificate validation CVE:

{
  "id": "CWE-284", "abstraction": "Pillar", "mapping": "DISCOURAGED",
  "child": {
    "id": "CWE-287", "abstraction": "Class", "mapping": "DISCOURAGED",
    "child": {
      "id": "CWE-295", "abstraction": "Base", "mapping": "ALLOWED",
      "description": "The product does not validate, or incorrectly validates, a certificate.",
      "mitigations": [...],
      "related_capec": [{"id": "CAPEC-475", "name": "Signature Spoofing..."}]
    }
  }
}

Key points:
- CWE-295 is the "most specific" ALLOWED CWE (leaf node)
- Rich details (description, mitigations, etc.) only on ALLOWED CWEs
- CAPECs only on ALLOWED CWEs, not inherited from parents
```

---

## Integration with Pipeline

### Automatic Integration with vuln_scan

MITRE CWE/CAPEC enrichment is **automatically included** in the `vuln_scan` module. No separate configuration is needed.

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           vuln_scan MODULE                                  │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌─────────────┐     ┌─────────────┐     ┌──────────────────────────────┐ │
│  │  Nuclei +   │────▶│  CVE List   │────▶│  MITRE Enrichment            │ │
│  │  NVD lookup │     │             │     │  (automatic)                 │ │
│  │             │     │ CVE-2021-44228  │                              │ │
│  │ Finds CVEs  │     │ CVE-2022-22965  │ Adds:                        │ │
│  │             │     │ CVE-2023-12345  │ • cwe_hierarchy              │ │
│  └─────────────┘     └─────────────┘     │ • CWE metadata              │ │
│                                          │ • Mitigations, consequences │ │
│                                          │ • related_capec (ALLOWED)   │ │
│                                          └──────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────┘
```

### What Gets Enriched

| Source | Field | What's Added |
|--------|-------|--------------|
| `vuln_scan` | `all_cves` | `mitre_attack.cwe_hierarchy` with full metadata |
| `technology_cves` | `by_technology.<tech>.cves[]` | `mitre_attack.cwe_hierarchy` with full metadata |
| `gvm_scan` | `unique_cves_enriched` | `mitre_attack.cwe_hierarchy` with full metadata |

### Pipeline Order

MITRE enrichment runs automatically after vulnerability scanning as part of `vuln_scan`:

```python
SCAN_MODULES = [
    "domain_discovery",  # 1. Find subdomains, IPs
    "port_scan",         # 2. Find open ports
    "http_probe",        # 3. Probe HTTP, detect tech
    "vuln_scan",         # 4. Find vulnerabilities (CVEs) + MITRE enrichment ← INCLUDED
    "github"             # 5. Hunt for secrets
]
```

---

## Troubleshooting

### Database Download Issues

**Problem:** Database download fails or times out

**Solutions:**
1. Check internet connectivity
2. Try again later (GitHub might be rate-limited)
3. Use offline mode with existing cache:
   ```python
   MITRE_AUTO_UPDATE_DB = False
   ```

### CVE Not Enriched

**Problem:** A CVE shows `"enriched": false`

**Causes:**
- The CVE is too new and not yet in CVE2CAPEC database
- The CVE has no known CWE mappings
- The CVE year database file is missing

**Solution:** Database updates daily. Wait for next update or check if the CVE has mappings at [cve2capec.github.io](https://cve2capec.github.io/).

### No CAPECs Shown

**Problem:** CVE has CWE hierarchy but `related_capec: []` is empty

**Cause:** The ALLOWED CWE(s) in the hierarchy have no direct CAPEC mappings. This is intentional - we don't show inherited CAPECs from DISCOURAGED parent CWEs.

**Solution:** This is expected behavior. The CWE hierarchy still provides valuable context:
- Weakness type and abstraction level
- Description and consequences
- Mitigations and detection methods
- Observed examples from other CVEs

---

## References

- **CWE:** [cwe.mitre.org](https://cwe.mitre.org/)
- **CAPEC:** [capec.mitre.org](https://capec.mitre.org/)
- **CVE2CAPEC Database:** [github.com/Galeax/CVE2CAPEC](https://github.com/Galeax/CVE2CAPEC)
- **MITRE ATT&CK:** [attack.mitre.org](https://attack.mitre.org/) (for reference only)
- **MITRE D3FEND:** [d3fend.mitre.org](https://d3fend.mitre.org/) (for reference only)
