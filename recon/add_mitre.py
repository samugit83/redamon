"""
RedAmon - MITRE CWE/CAPEC Enrichment Module
===========================================
Enriches CVE data with CWE weaknesses and CAPEC attack patterns.

Uses the CVE2CAPEC database (https://github.com/Galeax/CVE2CAPEC) which provides:
- CVE → CWE mappings
- CWE → CAPEC mappings (direct mappings from most specific CWEs only)

Note: ATT&CK techniques and D3FEND defenses are NOT included because
CVE2CAPEC's mappings are inherited from generic parent CWEs (inaccurate).
Only direct CWE→CAPEC mappings provide relevant attack patterns.

The database is updated daily via GitHub Actions.

Enriches:
- recon output: vuln_scan.all_cves and technology_cves.by_technology.<tech>.cves
- gvm_scan output: scans[].unique_cves
"""

import json
import os
import sys
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import requests

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from params import (
    MITRE_AUTO_UPDATE_DB,
    MITRE_ENRICH_RECON,
    MITRE_ENRICH_GVM,
    MITRE_DATABASE_PATH,
    MITRE_CACHE_TTL_HOURS,
    MITRE_INCLUDE_CWE,
    MITRE_INCLUDE_CAPEC,
)

# =============================================================================
# Constants
# =============================================================================

CVE2CAPEC_REPO = "https://github.com/Galeax/CVE2CAPEC.git"
CVE2CAPEC_RAW_BASE = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main"

# Official MITRE CWE data (for names, abstraction, mapping status)
CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

# Official MITRE CAPEC data (for detailed attack pattern information)
CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"

# Resource files needed from CVE2CAPEC
# Only CWE and CAPEC data - ATT&CK techniques and D3FEND are NOT used
RESOURCE_FILES = [
    "resources/capec_db.json",           # CAPEC patterns with names
    "resources/cwe_db.json",             # CWE hierarchy and direct CAPEC mappings
]

# Database files (by year) - we'll download only needed years
DATABASE_YEARS = list(range(1999, datetime.now().year + 1))


# =============================================================================
# Database Management
# =============================================================================

def ensure_database_directory() -> Path:
    """Ensure the MITRE database directory exists."""
    db_path = Path(MITRE_DATABASE_PATH)
    db_path.mkdir(parents=True, exist_ok=True)
    (db_path / "resources").mkdir(parents=True, exist_ok=True)
    (db_path / "database").mkdir(parents=True, exist_ok=True)
    return db_path


def is_database_fresh() -> bool:
    """Check if database was updated recently (within TTL)."""
    db_path = Path(MITRE_DATABASE_PATH)
    marker_file = db_path / ".last_update"

    if not marker_file.exists():
        return False

    try:
        last_update = datetime.fromisoformat(marker_file.read_text().strip())
        age_hours = (datetime.now() - last_update).total_seconds() / 3600
        return age_hours < MITRE_CACHE_TTL_HOURS
    except Exception:
        return False


def mark_database_updated():
    """Mark database as freshly updated."""
    db_path = Path(MITRE_DATABASE_PATH)
    marker_file = db_path / ".last_update"
    marker_file.write_text(datetime.now().isoformat())


def download_file(url: str, dest_path: Path) -> bool:
    """Download a file from URL to destination path."""
    try:
        print(f"    Downloading: {dest_path.name}...", end=" ", flush=True)
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        dest_path.write_bytes(response.content)
        print("OK")
        return True
    except Exception as e:
        print(f"FAILED ({e})")
        return False


def download_resource_files(db_path: Path) -> bool:
    """Download resource files from CVE2CAPEC repository."""
    print("[*] Downloading MITRE resource files...")

    success = True
    for resource in RESOURCE_FILES:
        url = f"{CVE2CAPEC_RAW_BASE}/{resource}"
        dest = db_path / resource
        dest.parent.mkdir(parents=True, exist_ok=True)

        if not download_file(url, dest):
            success = False

    return success


def download_cwe_metadata(db_path: Path) -> bool:
    """
    Download and parse official MITRE CWE data for comprehensive weakness information.
    Creates cwe_metadata.json with full details for ALLOWED CWEs.
    """
    import zipfile
    import io
    import xml.etree.ElementTree as ET

    dest_file = db_path / "resources" / "cwe_metadata.json"

    # Check if we already have it and it's recent
    if dest_file.exists():
        try:
            mtime = datetime.fromtimestamp(dest_file.stat().st_mtime)
            if (datetime.now() - mtime).total_seconds() / 3600 < MITRE_CACHE_TTL_HOURS:
                print("    CWE metadata: cached (skipping download)")
                return True
        except Exception:
            pass

    print("    Downloading official MITRE CWE data...", end=" ", flush=True)

    try:
        # Download the ZIP file
        response = requests.get(CWE_XML_URL, timeout=180)
        response.raise_for_status()

        # Extract XML from ZIP
        with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
            xml_files = [f for f in zf.namelist() if f.endswith('.xml')]
            if not xml_files:
                print("FAILED (no XML in ZIP)")
                return False
            xml_content = zf.read(xml_files[0])

        # Parse XML
        root = ET.fromstring(xml_content)
        ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}

        def get_text(element, path):
            """Helper to get text from XML path."""
            el = element.find(path, ns)
            if el is not None and el.text:
                return el.text.strip()
            return None

        def get_all_text(element, path):
            """Helper to get all text from multiple elements."""
            results = []
            for el in element.findall(path, ns):
                if el.text and el.text.strip():
                    results.append(el.text.strip())
            return results if results else None

        cwe_metadata = {}

        # Find all Weakness elements
        for weakness in root.findall('.//cwe:Weakness', ns):
            cwe_id = weakness.get('ID')
            if not cwe_id:
                continue

            # Basic attributes (always included)
            entry = {
                "name": weakness.get('Name', ''),
                "abstraction": weakness.get('Abstraction', ''),
            }

            # Get mapping status
            mapping = 'ALLOWED'  # Default
            mapping_notes = weakness.find('.//cwe:Mapping_Notes/cwe:Usage', ns)
            if mapping_notes is not None and mapping_notes.text:
                mapping = mapping_notes.text.upper()
            entry["mapping"] = mapping

            # Additional fields (for detailed info on ALLOWED CWEs)
            # Structure attribute
            structure = weakness.get('Structure', '')
            if structure:
                entry["structure"] = structure

            # Description
            desc = get_text(weakness, './/cwe:Description')
            if desc:
                entry["description"] = desc

            # Extended Description
            ext_desc = get_text(weakness, './/cwe:Extended_Description')
            if ext_desc:
                # Truncate if too long
                if len(ext_desc) > 500:
                    ext_desc = ext_desc[:500] + "..."
                entry["extended_description"] = ext_desc

            # Likelihood of Exploit
            likelihood = get_text(weakness, './/cwe:Likelihood_Of_Exploit')
            if likelihood:
                entry["likelihood_of_exploit"] = likelihood

            # Common Consequences (CIA impact)
            consequences = []
            for conseq in weakness.findall('.//cwe:Common_Consequences/cwe:Consequence', ns):
                scope = get_all_text(conseq, './/cwe:Scope')
                impact = get_all_text(conseq, './/cwe:Impact')
                if scope or impact:
                    conseq_entry = {}
                    if scope:
                        conseq_entry["scope"] = scope
                    if impact:
                        conseq_entry["impact"] = impact
                    consequences.append(conseq_entry)
            if consequences:
                entry["consequences"] = consequences

            # Potential Mitigations
            mitigations = []
            for mitigation in weakness.findall('.//cwe:Potential_Mitigations/cwe:Mitigation', ns):
                phase = get_all_text(mitigation, './/cwe:Phase')
                desc = get_text(mitigation, './/cwe:Description')
                if desc:
                    mit_entry = {"description": desc[:300] + "..." if len(desc) > 300 else desc}
                    if phase:
                        mit_entry["phase"] = phase
                    mitigations.append(mit_entry)
            if mitigations:
                entry["mitigations"] = mitigations[:3]  # Limit to top 3

            # Detection Methods
            detections = []
            for detection in weakness.findall('.//cwe:Detection_Methods/cwe:Detection_Method', ns):
                method = get_text(detection, './/cwe:Method')
                desc = get_text(detection, './/cwe:Description')
                if method:
                    det_entry = {"method": method}
                    if desc:
                        det_entry["description"] = desc[:200] + "..." if len(desc) > 200 else desc
                    detections.append(det_entry)
            if detections:
                entry["detection_methods"] = detections[:3]  # Limit to top 3

            # Observed Examples (real CVEs)
            examples = []
            for example in weakness.findall('.//cwe:Observed_Examples/cwe:Observed_Example', ns):
                ref = get_text(example, './/cwe:Reference')
                desc = get_text(example, './/cwe:Description')
                if ref:
                    ex_entry = {"cve": ref}
                    if desc:
                        ex_entry["description"] = desc[:150] + "..." if len(desc) > 150 else desc
                    examples.append(ex_entry)
            if examples:
                entry["observed_examples"] = examples[:5]  # Limit to top 5

            # Applicable Platforms
            platforms = {}
            for lang in weakness.findall('.//cwe:Applicable_Platforms/cwe:Language', ns):
                lang_name = lang.get('Name') or lang.get('Class')
                if lang_name:
                    if "languages" not in platforms:
                        platforms["languages"] = []
                    platforms["languages"].append(lang_name)
            for tech in weakness.findall('.//cwe:Applicable_Platforms/cwe:Technology', ns):
                tech_name = tech.get('Name') or tech.get('Class')
                if tech_name:
                    if "technologies" not in platforms:
                        platforms["technologies"] = []
                    platforms["technologies"].append(tech_name)
            if platforms:
                entry["platforms"] = platforms

            cwe_metadata[cwe_id] = entry

        # Save parsed data
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_file, 'w') as f:
            json.dump(cwe_metadata, f)

        print(f"OK ({len(cwe_metadata)} CWEs)")
        return True

    except Exception as e:
        print(f"FAILED ({e})")
        return False


def download_capec_metadata(db_path: Path) -> bool:
    """
    Download and parse official MITRE CAPEC data for comprehensive attack pattern information.
    Creates capec_metadata.json with full details for each CAPEC.
    """
    import xml.etree.ElementTree as ET

    dest_file = db_path / "resources" / "capec_metadata.json"

    # Check if we already have it and it's recent
    if dest_file.exists():
        try:
            mtime = datetime.fromtimestamp(dest_file.stat().st_mtime)
            if (datetime.now() - mtime).total_seconds() / 3600 < MITRE_CACHE_TTL_HOURS:
                print("    CAPEC metadata: cached (skipping download)")
                return True
        except Exception:
            pass

    print("    Downloading official MITRE CAPEC data...", end=" ", flush=True)

    try:
        # Download the XML file
        response = requests.get(CAPEC_XML_URL, timeout=180)
        response.raise_for_status()

        # Parse XML
        root = ET.fromstring(response.content)
        ns = {'capec': 'http://capec.mitre.org/capec-3'}

        def get_text(element, path):
            """Helper to get text from XML path."""
            el = element.find(path, ns)
            if el is not None and el.text:
                return el.text.strip()
            return None

        def get_all_text(element, path):
            """Helper to get all text from multiple elements."""
            results = []
            for el in element.findall(path, ns):
                if el.text and el.text.strip():
                    results.append(el.text.strip())
            return results if results else None

        capec_metadata = {}

        # Find all Attack_Pattern elements
        for ap in root.findall('.//capec:Attack_Pattern', ns):
            capec_id = ap.get('ID')
            if not capec_id:
                continue

            entry = {
                "name": ap.get('Name', ''),
                "abstraction": ap.get('Abstraction', ''),
                "status": ap.get('Status', ''),
            }

            # Description
            desc = get_text(ap, 'capec:Description')
            if desc:
                # Truncate if too long
                if len(desc) > 500:
                    desc = desc[:500] + "..."
                entry["description"] = desc

            # Likelihood of Attack
            likelihood = get_text(ap, 'capec:Likelihood_Of_Attack')
            if likelihood:
                entry["likelihood"] = likelihood

            # Typical Severity
            severity = get_text(ap, 'capec:Typical_Severity')
            if severity:
                entry["severity"] = severity

            # Prerequisites
            prerequisites = []
            for prereq in ap.findall('.//capec:Prerequisite', ns):
                if prereq.text and prereq.text.strip():
                    prereq_text = prereq.text.strip()
                    if len(prereq_text) > 200:
                        prereq_text = prereq_text[:200] + "..."
                    prerequisites.append(prereq_text)
            if prerequisites:
                entry["prerequisites"] = prerequisites

            # Execution Flow (Attack Steps)
            execution_flow = []
            for step in ap.findall('.//capec:Attack_Step', ns):
                step_num = get_text(step, 'capec:Step')
                phase = get_text(step, 'capec:Phase')
                step_desc = get_text(step, 'capec:Description')
                if step_num or phase or step_desc:
                    step_entry = {}
                    if step_num:
                        step_entry["step"] = step_num
                    if phase:
                        step_entry["phase"] = phase
                    if step_desc:
                        if len(step_desc) > 200:
                            step_desc = step_desc[:200] + "..."
                        step_entry["description"] = step_desc
                    execution_flow.append(step_entry)
            if execution_flow:
                entry["execution_flow"] = execution_flow

            # Example Instances
            examples = []
            for example in ap.findall('.//capec:Example', ns):
                if example.text and example.text.strip():
                    ex_text = example.text.strip()
                    if len(ex_text) > 300:
                        ex_text = ex_text[:300] + "..."
                    examples.append(ex_text)
            if examples:
                entry["examples"] = examples[:3]  # Limit to 3 examples

            # Related Weaknesses (CWEs)
            related_cwes = []
            for cwe in ap.findall('.//capec:Related_Weakness', ns):
                cwe_id = cwe.get('CWE_ID')
                if cwe_id:
                    related_cwes.append(f"CWE-{cwe_id}")
            if related_cwes:
                entry["related_cwes"] = related_cwes

            capec_metadata[capec_id] = entry

        # Save parsed data
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_file, 'w') as f:
            json.dump(capec_metadata, f)

        print(f"OK ({len(capec_metadata)} CAPECs)")
        return True

    except Exception as e:
        print(f"FAILED ({e})")
        return False


def download_cve_database_year(db_path: Path, year: int) -> bool:
    """Download CVE database for a specific year."""
    filename = f"CVE-{year}.jsonl"
    url = f"{CVE2CAPEC_RAW_BASE}/database/{filename}"
    dest = db_path / "database" / filename
    return download_file(url, dest)


def get_needed_years(cve_ids: List[str]) -> set:
    """Extract unique years from CVE IDs."""
    years = set()
    for cve_id in cve_ids:
        # CVE format: CVE-YYYY-NNNNN
        try:
            parts = cve_id.split("-")
            if len(parts) >= 2:
                year = int(parts[1])
                if 1999 <= year <= datetime.now().year:
                    years.add(year)
        except (ValueError, IndexError):
            continue
    return years


def update_database(cve_ids: List[str] = None, force: bool = False) -> bool:
    """
    Update the CVE2CAPEC database.

    Args:
        cve_ids: List of CVE IDs to determine which year files to download
        force: Force update even if cache is fresh

    Returns:
        True if database is ready for use
    """
    db_path = ensure_database_directory()

    # Check if update is needed
    if not force and is_database_fresh():
        print("[*] MITRE database is up to date (within TTL)")
        return True

    print("\n" + "=" * 60)
    print("MITRE ATT&CK Database Update")
    print("=" * 60)
    print(f"    Source: CVE2CAPEC (github.com/Galeax/CVE2CAPEC)")
    print(f"    Cache path: {db_path}")

    # Download resource files (always needed)
    if not download_resource_files(db_path):
        print("[!] Failed to download some resource files")
        return False

    # Download official MITRE CWE metadata (names, abstraction, mapping status)
    download_cwe_metadata(db_path)

    # Download official MITRE CAPEC metadata (descriptions, severity, execution flow)
    download_capec_metadata(db_path)

    # Download CVE database files for needed years
    if cve_ids:
        years = get_needed_years(cve_ids)
        print(f"[*] Downloading CVE database for years: {sorted(years)}")
        for year in sorted(years):
            db_file = db_path / "database" / f"CVE-{year}.jsonl"
            if not db_file.exists() or force:
                download_cve_database_year(db_path, year)
    else:
        # Download recent years by default (last 10 years)
        current_year = datetime.now().year
        print(f"[*] Downloading CVE database for recent years...")
        for year in range(current_year - 10, current_year + 1):
            db_file = db_path / "database" / f"CVE-{year}.jsonl"
            if not db_file.exists() or force:
                download_cve_database_year(db_path, year)

    mark_database_updated()
    print("[+] Database update complete")
    print("=" * 60)

    return True


# =============================================================================
# Database Loading
# =============================================================================

class MITREDatabase:
    """Handles loading and querying the CVE2CAPEC database for CWE/CAPEC enrichment."""

    def __init__(self, db_path: Path = None):
        self.db_path = Path(db_path or MITRE_DATABASE_PATH)
        self.capec_db: Dict = {}             # capec_id -> {name, techniques, ...}
        self.cwe_db: Dict = {}               # cwe_id -> {parent CWEs, related CAPECs}
        self.cwe_metadata: Dict = {}         # cwe_id -> {name, abstraction, mapping}
        self.capec_metadata: Dict = {}       # capec_id -> {description, severity, etc.}
        self.cve_cache: Dict = {}            # year -> {cve_id -> data}
        self._loaded = False

    def load_resources(self) -> bool:
        """Load CWE and CAPEC resource files into memory."""
        try:
            # Load CAPEC database (capec_id -> pattern info with names)
            capec_file = self.db_path / "resources" / "capec_db.json"
            if capec_file.exists():
                self.capec_db = json.loads(capec_file.read_text())
                print(f"    Loaded {len(self.capec_db)} CAPEC patterns")

            # Load CWE database (cwe_id -> hierarchy and related CAPECs)
            cwe_file = self.db_path / "resources" / "cwe_db.json"
            if cwe_file.exists():
                self.cwe_db = json.loads(cwe_file.read_text())
                print(f"    Loaded {len(self.cwe_db)} CWE entries")

            # Load CWE metadata (name, abstraction, mapping status from official MITRE data)
            metadata_file = self.db_path / "resources" / "cwe_metadata.json"
            if metadata_file.exists():
                self.cwe_metadata = json.loads(metadata_file.read_text())
                print(f"    Loaded {len(self.cwe_metadata)} CWE metadata entries")

            # Load CAPEC metadata (description, severity, execution flow from official MITRE data)
            capec_metadata_file = self.db_path / "resources" / "capec_metadata.json"
            if capec_metadata_file.exists():
                self.capec_metadata = json.loads(capec_metadata_file.read_text())
                print(f"    Loaded {len(self.capec_metadata)} CAPEC metadata entries")

            self._loaded = True
            return True

        except Exception as e:
            print(f"[!] Error loading resources: {e}")
            return False

    def load_cve_year(self, year: int) -> Dict:
        """Load CVE data for a specific year."""
        if year in self.cve_cache:
            return self.cve_cache[year]

        cve_file = self.db_path / "database" / f"CVE-{year}.jsonl"
        if not cve_file.exists():
            print(f"    [!] CVE database for {year} not found")
            return {}

        year_data = {}
        try:
            with open(cve_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            # Format is {"CVE-XXXX-YYYY": {"CWE": [...], "CAPEC": [...], "TECHNIQUES": [...]}}
                            # The CVE ID is the key, not a field value
                            for cve_id, cve_data in entry.items():
                                if cve_id.upper().startswith("CVE-"):
                                    year_data[cve_id.upper()] = cve_data
                        except json.JSONDecodeError:
                            continue

            self.cve_cache[year] = year_data
            print(f"    Loaded {len(year_data)} CVEs from {year}")

        except Exception as e:
            print(f"    [!] Error loading {year}: {e}")

        return year_data

    def get_cve_data(self, cve_id: str) -> Optional[Dict]:
        """Get data for a specific CVE ID."""
        cve_id = cve_id.upper()

        # Extract year from CVE ID
        try:
            parts = cve_id.split("-")
            year = int(parts[1])
        except (ValueError, IndexError):
            return None

        # Load year data if not cached
        year_data = self.load_cve_year(year)
        return year_data.get(cve_id)


# =============================================================================
# CVE Enrichment
# =============================================================================

def enrich_cve(cve_data: Dict, mitre_db: MITREDatabase,
               include_cwe: bool = True, include_capec: bool = True) -> Dict:
    """
    Enrich a single CVE entry with MITRE CWE and CAPEC data.

    Args:
        cve_data: Original CVE data dictionary
        mitre_db: Loaded MITRE database
        include_cwe: Include CWE information
        include_capec: Include CAPEC information

    Returns:
        Enriched CVE dictionary with mitre_attack field added
    
    Note:
        ATT&CK techniques and D3FEND defenses are NOT included because
        CVE2CAPEC's mappings are inherited from generic parent CWEs (inaccurate).
        Only CWE and CAPEC data is reliable.
    """
    cve_id = cve_data.get("id", "")
    if not cve_id:
        return cve_data

    # Get CVE data from CVE2CAPEC database
    cve2capec_data = mitre_db.get_cve_data(cve_id)

    # Initialize MITRE enrichment structure
    mitre_enrichment = {
        "enriched": False,
        "enrichment_timestamp": datetime.now().isoformat(),
        "source": "CVE2CAPEC",
    }

    if cve2capec_data:
        mitre_enrichment["enriched"] = True

        # Get all CWEs for this CVE
        # CVE2CAPEC format: "CWE": ["193", "682"] - just numbers without "CWE-" prefix
        cwes = cve2capec_data.get("CWE", []) or cve2capec_data.get("cwe", [])
        cwes = [str(c) for c in cwes]
        cwes_set = set(cwes)  # For quick lookup

        if cwes and include_cwe:
            # Find the most specific CWEs (leaf nodes - those that are NOT parents of other CWEs in the list)
            parent_cwe_nums = set()
            for cwe_num in cwes:
                cwe_info = mitre_db.cwe_db.get(cwe_num, {})
                if isinstance(cwe_info, dict):
                    for parent in cwe_info.get("ChildOf", []):
                        parent_cwe_nums.add(str(parent))

            # Most specific CWEs = CWEs that are not parent of any other CWE in the list
            leaf_cwe_nums = [c for c in cwes if c not in parent_cwe_nums]

            # Helper function to build CAPEC list for a CWE
            def build_capec_list(cwe_num):
                capec_list = []
                if include_capec:
                    cwe_info = mitre_db.cwe_db.get(cwe_num, {})
                    if isinstance(cwe_info, dict):
                        for capec_num in cwe_info.get("RelatedAttackPatterns", []):
                            capec_num = str(capec_num)
                            capec_entry = {
                                "id": f"CAPEC-{capec_num}",
                                "url": f"https://capec.mitre.org/data/definitions/{capec_num}.html",
                            }
                            # Get basic name from CVE2CAPEC db
                            capec_info = mitre_db.capec_db.get(capec_num, {})
                            if isinstance(capec_info, dict) and capec_info.get("name"):
                                capec_entry["name"] = capec_info["name"]

                            # Get detailed info from official MITRE CAPEC metadata
                            capec_meta = mitre_db.capec_metadata.get(capec_num, {})
                            if capec_meta:
                                # Description
                                if capec_meta.get("description"):
                                    capec_entry["description"] = capec_meta["description"]
                                # Likelihood of Attack
                                if capec_meta.get("likelihood"):
                                    capec_entry["likelihood"] = capec_meta["likelihood"]
                                # Typical Severity
                                if capec_meta.get("severity"):
                                    capec_entry["severity"] = capec_meta["severity"]
                                # Prerequisites
                                if capec_meta.get("prerequisites"):
                                    capec_entry["prerequisites"] = capec_meta["prerequisites"]
                                # Execution Flow
                                if capec_meta.get("execution_flow"):
                                    capec_entry["execution_flow"] = capec_meta["execution_flow"]
                                # Example Instances
                                if capec_meta.get("examples"):
                                    capec_entry["examples"] = capec_meta["examples"]
                                # Related CWEs
                                if capec_meta.get("related_cwes"):
                                    capec_entry["related_cwes"] = capec_meta["related_cwes"]

                            capec_list.append(capec_entry)
                return capec_list

            # Helper function to build CWE node with metadata
            def build_cwe_node(cwe_num, is_leaf=False):
                node = {
                    "id": f"CWE-{cwe_num}",
                    "url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                }
                # Add metadata from official MITRE CWE data
                metadata = mitre_db.cwe_metadata.get(cwe_num, {})
                if metadata.get("name"):
                    node["name"] = metadata["name"]
                if metadata.get("abstraction"):
                    node["abstraction"] = metadata["abstraction"]
                mapping_status = metadata.get("mapping", "")
                if mapping_status:
                    node["mapping"] = mapping_status

                # Add related_capec and detailed fields ONLY for ALLOWED CWEs
                if mapping_status == "ALLOWED":
                    node["related_capec"] = build_capec_list(cwe_num)
                    # Add structure
                    if metadata.get("structure"):
                        node["structure"] = metadata["structure"]

                    # Add description
                    if metadata.get("description"):
                        node["description"] = metadata["description"]

                    # Add extended description
                    if metadata.get("extended_description"):
                        node["extended_description"] = metadata["extended_description"]

                    # Add likelihood of exploit
                    if metadata.get("likelihood_of_exploit"):
                        node["likelihood_of_exploit"] = metadata["likelihood_of_exploit"]

                    # Add consequences (CIA impact)
                    if metadata.get("consequences"):
                        node["consequences"] = metadata["consequences"]

                    # Add mitigations
                    if metadata.get("mitigations"):
                        node["mitigations"] = metadata["mitigations"]

                    # Add detection methods
                    if metadata.get("detection_methods"):
                        node["detection_methods"] = metadata["detection_methods"]

                    # Add observed examples (real CVEs)
                    if metadata.get("observed_examples"):
                        node["observed_examples"] = metadata["observed_examples"]

                    # Add applicable platforms
                    if metadata.get("platforms"):
                        node["platforms"] = metadata["platforms"]

                return node

            # Helper function to build hierarchical CWE chain from leaf to root
            def build_cwe_hierarchy(leaf_num):
                # Build chain from leaf up to root (only CWEs in our CVE's list)
                chain = []
                current = leaf_num
                visited = set()
                
                while current and current not in visited:
                    visited.add(current)
                    chain.append(current)
                    # Find parent that's also in our CVE's CWE list
                    cwe_info = mitre_db.cwe_db.get(current, {})
                    if isinstance(cwe_info, dict):
                        parents = cwe_info.get("ChildOf", [])
                        # Find a parent that's in our CVE's CWE list
                        next_parent = None
                        for p in parents:
                            if str(p) in cwes_set:
                                next_parent = str(p)
                                break
                        current = next_parent
                    else:
                        break
                
                # Reverse to get root -> leaf order
                chain.reverse()
                
                # Build nested hierarchy object
                if not chain:
                    return None
                
                # Start from root (first in chain)
                root_num = chain[0]
                is_only_one = len(chain) == 1
                hierarchy = build_cwe_node(root_num, is_leaf=is_only_one)
                
                # Build nested structure
                current_node = hierarchy
                for i, cwe_num in enumerate(chain[1:], 1):
                    is_leaf = (i == len(chain) - 1)
                    child_node = build_cwe_node(cwe_num, is_leaf=is_leaf)
                    current_node["child"] = child_node
                    current_node = child_node
                
                return hierarchy

            # Build hierarchy for primary leaf CWE
            if leaf_cwe_nums:
                primary_hierarchy = build_cwe_hierarchy(leaf_cwe_nums[0])
                if primary_hierarchy:
                    mitre_enrichment["cwe_hierarchy"] = primary_hierarchy

                # If there are multiple leaf CWEs, add additional hierarchies
                if len(leaf_cwe_nums) > 1:
                    additional_hierarchies = []
                    for extra_leaf in leaf_cwe_nums[1:]:
                        extra_hierarchy = build_cwe_hierarchy(extra_leaf)
                        if extra_hierarchy:
                            additional_hierarchies.append(extra_hierarchy)
                    if additional_hierarchies:
                        mitre_enrichment["additional_cwe_hierarchies"] = additional_hierarchies

        # NOTE: ATT&CK techniques and D3FEND defenses are NOT included because:
        # - CVE2CAPEC's technique mappings are inherited from generic parent CWEs (inaccurate)
        # - MITRE's official CAPEC→ATT&CK mappings only cover ~32 CAPECs
        # Only CWE and CAPEC data from the most specific (leaf) CWE is reliable

    # Add enrichment to CVE data
    enriched_cve = cve_data.copy()
    enriched_cve["mitre_attack"] = mitre_enrichment

    return enriched_cve


def enrich_cve_list(cve_list: List[Dict], mitre_db: MITREDatabase,
                    include_cwe: bool = True, include_capec: bool = True) -> List[Dict]:
    """
    Enrich a list of CVEs with MITRE CWE and CAPEC data.

    Args:
        cve_list: List of CVE dictionaries
        mitre_db: Loaded MITRE database
        include_cwe: Include CWE information
        include_capec: Include CAPEC information

    Returns:
        List of enriched CVE dictionaries
    """
    enriched_list = []
    enriched_count = 0

    for cve in cve_list:
        enriched_cve = enrich_cve(cve, mitre_db, include_cwe, include_capec)
        enriched_list.append(enriched_cve)

        if enriched_cve.get("mitre_attack", {}).get("enriched"):
            enriched_count += 1

    return enriched_list, enriched_count


# =============================================================================
# Main Enrichment Functions
# =============================================================================

def enrich_recon_data(recon_data: Dict, mitre_db: MITREDatabase) -> Dict:
    """
    Enrich reconnaissance data with MITRE ATT&CK information.

    Enriches:
    - vuln_scan.all_cves
    - technology_cves.all_cves

    Args:
        recon_data: Reconnaissance data dictionary
        mitre_db: Loaded MITRE database

    Returns:
        Enriched recon data
    """
    total_enriched = 0
    total_cves = 0

    # Enrich vuln_scan.all_cves (Nuclei findings)
    vuln_scan = recon_data.get("vuln_scan", {})
    if vuln_scan and vuln_scan.get("all_cves"):
        all_cves = vuln_scan["all_cves"]
        total_cves += len(all_cves)
        print(f"    Enriching vuln_scan.all_cves ({len(all_cves)} CVEs)...")

        enriched_cves, count = enrich_cve_list(
            all_cves, mitre_db,
            include_cwe=MITRE_INCLUDE_CWE,
            include_capec=MITRE_INCLUDE_CAPEC,
        )
        recon_data["vuln_scan"]["all_cves"] = enriched_cves
        total_enriched += count
        print(f"    -> Enriched {count}/{len(all_cves)} CVEs with CWE/CAPEC data")

    # Enrich technology_cves.by_technology.<tech>.cves (NVD lookup)
    # CVEs are stored directly inside each technology entry
    tech_cves = recon_data.get("technology_cves", {})
    by_technology = tech_cves.get("by_technology", {})
    if by_technology:
        tech_cve_count = 0
        tech_enriched_count = 0
        for tech_name, tech_data in by_technology.items():
            cves = tech_data.get("cves", [])
            if cves:
                tech_cve_count += len(cves)
                enriched_cves, count = enrich_cve_list(
                    cves, mitre_db,
                    include_cwe=MITRE_INCLUDE_CWE,
                    include_capec=MITRE_INCLUDE_CAPEC,
                )
                recon_data["technology_cves"]["by_technology"][tech_name]["cves"] = enriched_cves
                tech_enriched_count += count

        if tech_cve_count > 0:
            total_cves += tech_cve_count
            total_enriched += tech_enriched_count
            print(f"    Enriching technology_cves.by_technology ({tech_cve_count} CVEs across {len(by_technology)} technologies)...")
            print(f"    -> Enriched {tech_enriched_count}/{tech_cve_count} CVEs with CWE/CAPEC data")

    # Add enrichment metadata
    if "metadata" not in recon_data:
        recon_data["metadata"] = {}

    recon_data["metadata"]["mitre_enrichment"] = {
        "timestamp": datetime.now().isoformat(),
        "total_cves_processed": total_cves,
        "total_cves_enriched": total_enriched,
        "include_cwe": MITRE_INCLUDE_CWE,
        "include_capec": MITRE_INCLUDE_CAPEC,
        "source": "CVE2CAPEC",
    }

    return recon_data


def enrich_gvm_data(gvm_data: Dict, mitre_db: MITREDatabase) -> Dict:
    """
    Enrich GVM scan data with MITRE ATT&CK information.

    Enriches:
    - scans[].unique_cves

    Args:
        gvm_data: GVM scan data dictionary
        mitre_db: Loaded MITRE database

    Returns:
        Enriched GVM data
    """
    total_enriched = 0
    total_cves = 0

    scans = gvm_data.get("scans", [])
    for i, scan in enumerate(scans):
        unique_cves = scan.get("unique_cves", [])
        if unique_cves:
            total_cves += len(unique_cves)
            print(f"    Enriching scan[{i}].unique_cves ({len(unique_cves)} CVEs)...")

            # GVM CVEs are just IDs, convert to dict format
            cve_dicts = []
            for cve_id in unique_cves:
                if isinstance(cve_id, str):
                    cve_dicts.append({"id": cve_id})
                elif isinstance(cve_id, dict):
                    cve_dicts.append(cve_id)

            enriched_cves, count = enrich_cve_list(
                cve_dicts, mitre_db,
                include_cwe=MITRE_INCLUDE_CWE,
                include_capec=MITRE_INCLUDE_CAPEC,
            )

            # Update the scan data
            gvm_data["scans"][i]["unique_cves_enriched"] = enriched_cves
            total_enriched += count
            print(f"    -> Enriched {count}/{len(unique_cves)} CVEs with CWE/CAPEC data")

    # Add enrichment metadata
    if "metadata" not in gvm_data:
        gvm_data["metadata"] = {}

    gvm_data["metadata"]["mitre_enrichment"] = {
        "timestamp": datetime.now().isoformat(),
        "total_cves_processed": total_cves,
        "total_cves_enriched": total_enriched,
        "include_cwe": MITRE_INCLUDE_CWE,
        "include_capec": MITRE_INCLUDE_CAPEC,
        "source": "CVE2CAPEC",
    }

    return gvm_data


def run_mitre_enrichment(recon_data: Dict = None, output_file: Path = None) -> Dict:
    """
    Run MITRE CWE/CAPEC enrichment on recon data.

    This is the main entry point called from main.py pipeline.

    Args:
        recon_data: Reconnaissance data dictionary
        output_file: Path to save results

    Returns:
        Enriched recon data
    """
    print("\n" + "=" * 60)
    print("         RedAmon - MITRE CWE/CAPEC Enrichment")
    print("=" * 60)
    print(f"    Include CWE: {MITRE_INCLUDE_CWE}")
    print(f"    Include CAPEC: {MITRE_INCLUDE_CAPEC}")
    print(f"    Enrich Recon: {MITRE_ENRICH_RECON}")
    print(f"    Enrich GVM: {MITRE_ENRICH_GVM}")
    print(f"    Auto Update DB: {MITRE_AUTO_UPDATE_DB}")

    # Collect all CVE IDs to download only needed years
    all_cve_ids = []

    if recon_data and MITRE_ENRICH_RECON:
        # From vuln_scan
        vuln_cves = recon_data.get("vuln_scan", {}).get("all_cves", [])
        all_cve_ids.extend([c.get("id", "") for c in vuln_cves if isinstance(c, dict)])

        # From technology_cves.by_technology.<tech>.cves
        by_technology = recon_data.get("technology_cves", {}).get("by_technology", {})
        for tech_data in by_technology.values():
            for cve in tech_data.get("cves", []):
                if isinstance(cve, dict) and cve.get("id"):
                    all_cve_ids.append(cve["id"])

    print(f"    Total CVEs to enrich: {len(all_cve_ids)}")
    print("=" * 60)

    # Update database with needed years (if auto-update enabled)
    if MITRE_AUTO_UPDATE_DB:
        if not update_database(all_cve_ids):
            print("[!] Failed to update MITRE database")
            return recon_data
    else:
        print("[*] Auto-update disabled, using cached database")

    # Load database
    print("\n[*] Loading MITRE database...")
    mitre_db = MITREDatabase()
    if not mitre_db.load_resources():
        print("[!] Failed to load MITRE database resources")
        return recon_data

    # Enrich recon data
    if recon_data and MITRE_ENRICH_RECON:
        print("\n[*] Enriching reconnaissance data...")
        recon_data = enrich_recon_data(recon_data, mitre_db)

        # Save if output file provided
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2)
            print(f"\n[+] Saved enriched data to: {output_file}")

    # Print summary
    metadata = recon_data.get("metadata", {}).get("mitre_enrichment", {})
    print(f"\n{'=' * 60}")
    print(f"[+] MITRE ENRICHMENT COMPLETE")
    print(f"[+] CVEs processed: {metadata.get('total_cves_processed', 0)}")
    print(f"[+] CVEs enriched: {metadata.get('total_cves_enriched', 0)}")
    print(f"{'=' * 60}")

    return recon_data


def enrich_gvm_file(gvm_file: Path) -> Dict:
    """
    Enrich a GVM scan output file with MITRE ATT&CK data.

    Args:
        gvm_file: Path to GVM JSON file

    Returns:
        Enriched GVM data
    """
    if not MITRE_ENRICH_GVM:
        print("[*] GVM MITRE enrichment disabled in params")
        return None

    if not gvm_file.exists():
        print(f"[!] GVM file not found: {gvm_file}")
        return None

    print("\n" + "=" * 60)
    print("         RedAmon - MITRE CWE/CAPEC Enrichment (GVM)")
    print("=" * 60)
    print(f"    File: {gvm_file}")
    print(f"    Auto Update DB: {MITRE_AUTO_UPDATE_DB}")

    # Load GVM data
    with open(gvm_file, 'r') as f:
        gvm_data = json.load(f)

    # Collect all CVE IDs
    all_cve_ids = []
    for scan in gvm_data.get("scans", []):
        for cve in scan.get("unique_cves", []):
            if isinstance(cve, str):
                all_cve_ids.append(cve)
            elif isinstance(cve, dict):
                all_cve_ids.append(cve.get("id", ""))

    print(f"    Total CVEs to enrich: {len(all_cve_ids)}")
    print("=" * 60)

    # Update database (if auto-update enabled)
    if MITRE_AUTO_UPDATE_DB:
        if not update_database(all_cve_ids):
            print("[!] Failed to update MITRE database")
            return gvm_data
    else:
        print("[*] Auto-update disabled, using cached database")

    # Load database
    print("\n[*] Loading MITRE database...")
    mitre_db = MITREDatabase()
    if not mitre_db.load_resources():
        print("[!] Failed to load MITRE database resources")
        return gvm_data

    # Enrich GVM data
    print("\n[*] Enriching GVM scan data...")
    gvm_data = enrich_gvm_data(gvm_data, mitre_db)

    # Save enriched data
    with open(gvm_file, 'w') as f:
        json.dump(gvm_data, f, indent=2)
    print(f"\n[+] Saved enriched data to: {gvm_file}")

    # Print summary
    metadata = gvm_data.get("metadata", {}).get("mitre_enrichment", {})
    print(f"\n{'=' * 60}")
    print(f"[+] GVM MITRE ENRICHMENT COMPLETE")
    print(f"[+] CVEs processed: {metadata.get('total_cves_processed', 0)}")
    print(f"[+] CVEs enriched: {metadata.get('total_cves_enriched', 0)}")
    print(f"{'=' * 60}")

    return gvm_data
