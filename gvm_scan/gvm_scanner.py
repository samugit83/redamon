"""
RedAmon - GVM/OpenVAS Vulnerability Scanner
============================================
Connects to GVM via python-gvm to run vulnerability scans.
Extracts targets from recon JSON data and saves results as JSON.

This module uses the Greenbone Management Protocol (GMP) to:
- Create scan targets from recon data
- Launch vulnerability scan tasks
- Monitor scan progress
- Extract and format results to JSON
"""

import json
import os
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from xml.etree import ElementTree as ET
import sys

# XML to dict conversion for complete data extraction
try:
    import xmltodict
    XMLTODICT_AVAILABLE = True
except ImportError:
    XMLTODICT_AVAILABLE = False
    print("[!] xmltodict not installed. Run: pip install xmltodict")

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# GVM project settings (fetched from webapp API or defaults)
try:
    from gvm_scan.project_settings import get_setting
except ImportError:
    from project_settings import get_setting

# Runtime parameters from environment variables (set by orchestrator)
USER_ID = os.environ.get("USER_ID", "")
PROJECT_ID = os.environ.get("PROJECT_ID", "")

# GVM connection settings (from environment, set by orchestrator)
GVM_SOCKET_PATH = os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock")
GVM_USERNAME = os.environ.get("GVM_USERNAME", "admin")
GVM_PASSWORD = os.environ.get("GVM_PASSWORD", "admin")

# GVM imports (handled gracefully if not installed)
try:
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp, GMPv227
    from gvm.protocols.gmp.requests.v224._targets import AliveTest
    from gvm.transforms import EtreeTransform
    from gvm.errors import GvmError
    GVM_AVAILABLE = True
except ImportError:
    GVM_AVAILABLE = False
    GvmError = Exception  # Fallback
    AliveTest = None
    print("[!] python-gvm not installed. Run: pip install python-gvm")


class GVMScanner:
    """
    GVM/OpenVAS vulnerability scanner using python-gvm.
    
    Connects to gvmd via Unix socket and executes vulnerability scans
    against targets extracted from RedAmon recon data.
    """
    
    def __init__(
        self,
        socket_path: str = None,
        username: str = None,
        password: str = None,
        scan_config: str = None,
        task_timeout: int = None,
        poll_interval: int = None,
    ):
        """
        Initialize GVM scanner.

        Args:
            socket_path: Path to gvmd Unix socket (default: from env)
            username: GVM username (default: from env)
            password: GVM password (default: from env)
            scan_config: Name of scan configuration to use (default: from project settings)
            task_timeout: Maximum time to wait for scan completion (default: from project settings)
            poll_interval: Seconds between status checks (default: from project settings)
        """
        if not GVM_AVAILABLE:
            raise RuntimeError("python-gvm library not installed")

        self.socket_path = socket_path or GVM_SOCKET_PATH
        self.username = username or GVM_USERNAME
        self.password = password or GVM_PASSWORD
        self.scan_config_name = scan_config or get_setting('SCAN_CONFIG', 'Full and fast')
        self.task_timeout = task_timeout if task_timeout is not None else get_setting('TASK_TIMEOUT', 14400)
        self.poll_interval = poll_interval if poll_interval is not None else get_setting('POLL_INTERVAL', 30)
        
        # Connection state
        self._connection = None
        self.gmp = None
        self.connected = False
        
        # Cached IDs
        self.scanner_id: Optional[str] = None
        self.config_id: Optional[str] = None
        self.xml_format_id: Optional[str] = None
        self.port_list_id: Optional[str] = None
    
    def connect(self, max_retries: int = 60, retry_interval: int = 30) -> bool:
        """
        Establish connection to GVMD with retry logic.

        Waits for gvmd to be fully ready (feeds imported, scan configs loaded).
        On first boot this can take 20-30 minutes.

        Args:
            max_retries: Maximum number of connection attempts (default: 30)
            retry_interval: Seconds between retries (default: 30)

        Returns:
            True if connected successfully
        """
        for attempt in range(1, max_retries + 1):
            try:
                # Clean up any previous failed connection
                if self._connection:
                    try:
                        self._connection.disconnect()
                    except Exception:
                        pass
                    self._connection = None
                    self.gmp = None

                # Create and establish connection
                self._connection = UnixSocketConnection(path=self.socket_path)
                self._connection.connect()

                # Create GMP protocol handler (use version-specific class with authenticate)
                transform = EtreeTransform()
                self.gmp = GMPv227(connection=self._connection, transform=transform)

                # Authenticate with GVM
                self.gmp.authenticate(self.username, self.password)

                # Cache commonly needed IDs
                self._cache_scanner_id()
                self._cache_config_id()
                self._cache_report_format_id()
                self._cache_port_list_id()

                self.connected = True
                print(f"[+] Connected to GVM at {self.socket_path}")
                return True

            except Exception as e:
                error_msg = str(e)

                if attempt < max_retries:
                    # Determine a user-friendly reason
                    if "Connection refused" in error_msg or "No such file" in error_msg:
                        reason = "gvmd socket not available yet"
                    elif "not found" in error_msg.lower() and "config" in error_msg.lower():
                        reason = "scan configs not loaded yet (feed sync in progress)"
                    elif "not found" in error_msg.lower() and "scanner" in error_msg.lower():
                        reason = "OpenVAS scanner not registered yet"
                    elif "Authentication failed" in error_msg:
                        reason = "admin user not created yet"
                    else:
                        reason = error_msg

                    print(
                        f"[*] Waiting for GVM to be ready... "
                        f"(attempt {attempt}/{max_retries}, {reason})"
                    )
                    print(
                        f"    Retrying in {retry_interval}s... "
                        f"(first boot takes ~10-15 min for feed sync)"
                    )
                    time.sleep(retry_interval)
                else:
                    print(f"[!] Failed to connect to GVM after {max_retries} attempts: {error_msg}")
                    self.connected = False
                    return False

        return False
    
    def disconnect(self):
        """Close connection to GVMD."""
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                pass
        self._connection = None
        self.connected = False
        self.gmp = None
    
    def _cache_scanner_id(self):
        """Get and cache OpenVAS scanner ID."""
        scanners = self.gmp.get_scanners()
        for scanner in scanners.findall('.//scanner'):
            name = scanner.find('name')
            if name is not None and 'OpenVAS' in name.text:
                self.scanner_id = scanner.get('id')
                return
        raise RuntimeError("OpenVAS scanner not found in GVM")
    
    def _cache_config_id(self):
        """Get and cache scan config ID."""
        configs = self.gmp.get_scan_configs()
        for config in configs.findall('.//config'):
            name = config.find('name')
            if name is not None and self.scan_config_name in name.text:
                self.config_id = config.get('id')
                return
        
        # List available configs for debugging
        available = [c.find('name').text for c in configs.findall('.//config') 
                     if c.find('name') is not None]
        raise RuntimeError(
            f"Scan config '{self.scan_config_name}' not found. "
            f"Available: {available}"
        )
    
    def _cache_report_format_id(self):
        """Get and cache XML report format ID."""
        formats = self.gmp.get_report_formats()
        for fmt in formats.findall('.//report_format'):
            name = fmt.find('name')
            if name is not None and name.text == "XML":
                self.xml_format_id = fmt.get('id')
                return
        # Default XML format UUID
        self.xml_format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"
    
    def _cache_port_list_id(self):
        """Get and cache port list ID (All IANA assigned TCP and UDP)."""
        port_lists = self.gmp.get_port_lists()
        # Prefer "All IANA assigned TCP and UDP" for comprehensive scanning
        preferred_lists = [
            "All IANA assigned TCP and UDP",
            "All IANA assigned TCP",
            "All TCP and Nmap top 1000 UDP",
        ]
        
        for preferred in preferred_lists:
            for pl in port_lists.findall('.//port_list'):
                name = pl.find('name')
                if name is not None and name.text == preferred:
                    self.port_list_id = pl.get('id')
                    print(f"    [+] Using port list: {preferred}")
                    return
        
        # Fallback: use first available port list
        first_pl = port_lists.find('.//port_list')
        if first_pl is not None:
            self.port_list_id = first_pl.get('id')
            name = first_pl.find('name')
            print(f"    [+] Using port list: {name.text if name is not None else 'default'}")
            return
            
        # Default UUID for "All IANA assigned TCP and UDP"
        self.port_list_id = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
    
    def create_target(self, name: str, hosts: List[str], comment: str = "") -> str:
        """
        Create a scan target in GVM.
        
        Args:
            name: Target name
            hosts: List of IPs or hostnames
            comment: Optional description
            
        Returns:
            Target ID
        """
        # Use CONSIDER_ALIVE to skip ICMP ping check (cloud providers block ICMP)
        response = self.gmp.create_target(
            name=name,
            hosts=hosts,
            port_list_id=self.port_list_id,
            alive_test=AliveTest.CONSIDER_ALIVE,
            comment=comment or f"RedAmon auto-generated - {datetime.now().isoformat()}"
        )
        # Extract ID from XML response (attribute on root element)
        target_id = response.get('id') if hasattr(response, 'get') else None
        if target_id is None and hasattr(response, 'attrib'):
            target_id = response.attrib.get('id')
        
        # Check response status
        status = response.get('status') if hasattr(response, 'get') else None
        if status and status != '201':
            status_text = response.get('status_text', 'Unknown error')
            raise RuntimeError(f"Failed to create target: {status_text}")
        
        if not target_id:
            raise RuntimeError(f"Failed to create target '{name}': No ID returned")
            
        print(f"    [+] Created target '{name}': {target_id}")
        return target_id
    
    def create_task(self, name: str, target_id: str, comment: str = "") -> str:
        """
        Create a scan task in GVM.
        
        Args:
            name: Task name
            target_id: ID of target to scan
            comment: Optional description
            
        Returns:
            Task ID
        """
        if not target_id:
            raise ValueError("create_task requires a target_id argument")
            
        response = self.gmp.create_task(
            name=name,
            config_id=self.config_id,
            target_id=target_id,
            scanner_id=self.scanner_id,
            comment=comment or f"RedAmon scan - {datetime.now().isoformat()}"
        )
        # Extract ID from XML response
        task_id = response.get('id') if hasattr(response, 'get') else None
        if task_id is None and hasattr(response, 'attrib'):
            task_id = response.attrib.get('id')
            
        # Check response status
        status = response.get('status') if hasattr(response, 'get') else None
        if status and status != '201':
            status_text = response.get('status_text', 'Unknown error')
            raise RuntimeError(f"Failed to create task: {status_text}")
            
        if not task_id:
            raise RuntimeError(f"Failed to create task '{name}': No ID returned")
            
        print(f"    [+] Created task '{name}': {task_id}")
        return task_id
    
    def start_task(self, task_id: str) -> str:
        """
        Start a scan task.
        
        Args:
            task_id: Task ID to start
            
        Returns:
            Report ID for the running task
        """
        response = self.gmp.start_task(task_id)
        report_id = response.find('.//report_id')
        report_id_str = report_id.text if report_id is not None else None
        print(f"    [+] Started task {task_id}")
        return report_id_str
    
    def wait_for_task(self, task_id: str) -> Tuple[str, str]:
        """
        Wait for task completion.
        
        Args:
            task_id: Task ID to wait for
            
        Returns:
            Tuple of (status, report_id)
            
        Raises:
            TimeoutError: If task exceeds timeout
            RuntimeError: If task fails
        """
        print(f"    [⏳] Waiting for task {task_id}...")
        start_time = time.time()
        progress_note_shown = False

        while True:
            elapsed = time.time() - start_time
            
            if self.task_timeout > 0 and elapsed > self.task_timeout:
                raise TimeoutError(
                    f"Task {task_id} exceeded timeout of {self.task_timeout}s"
                )
            
            task = self.gmp.get_task(task_id)
            status = task.find('.//status')
            status_text = status.text if status is not None else "Unknown"
            
            progress = task.find('.//progress')
            progress_text = progress.text if progress is not None else "0"
            
            # Get report ID
            report = task.find('.//report')
            report_id = report.get('id') if report is not None else None
            
            if progress_text in ("0", "-1"):
                print(f"        Status: {status_text} | Scanning... | "
                      f"Elapsed: {int(elapsed)}s")
            else:
                print(f"        Status: {status_text} | Progress: {progress_text}% | "
                      f"Elapsed: {int(elapsed)}s")

            if not progress_note_shown and status_text == "Running" and progress_text in ("0", "-1") and elapsed > 60:
                print("        [i] GVM is running thousands of vulnerability checks. "
                      "This may take 15-45 minutes per target.")
                progress_note_shown = True
            
            if status_text == "Done":
                return status_text, report_id
            elif status_text in ("Stopped", "Stop Requested"):
                raise RuntimeError(f"Task was stopped: {status_text}")
            elif status_text == "Interrupted":
                raise RuntimeError(
                    f"Task was interrupted by GVM (likely resource exhaustion "
                    f"after previous scan). Elapsed: {int(elapsed)}s"
                )
            elif "Error" in status_text:
                raise RuntimeError(f"Task failed: {status_text}")
            
            time.sleep(self.poll_interval)
    
    def get_report(self, report_id: str) -> Dict:
        """
        Fetch and parse a scan report with full details.

        Args:
            report_id: Report ID to fetch

        Returns:
            Parsed report as dictionary with enhanced data including:
            - Full raw XML converted to JSON (raw_data)
            - Computed/enriched fields (severity_class, unique_cves, etc.)
        """
        # Request report with full details including notes and overrides
        report_xml = self.gmp.get_report(
            report_id=report_id,
            report_format_id=self.xml_format_id,
            ignore_pagination=True,
            details=True
        )
        return self._parse_report_full(report_xml)
    
    def _parse_report_full(self, report_xml: ET.Element) -> Dict:
        """
        Parse GVM XML report using xmltodict for complete data extraction,
        then enrich with computed fields.

        Args:
            report_xml: XML Element from GVM

        Returns:
            Complete report with:
            - raw_data: Full XML converted to JSON (no data loss)
            - Computed summary fields for easy access
            - Enriched vulnerability list with severity classifications
        """
        # Convert XML to string for xmltodict
        xml_string = ET.tostring(report_xml, encoding='unicode')

        # Convert to dict using xmltodict - captures ALL fields
        if XMLTODICT_AVAILABLE:
            raw_data = xmltodict.parse(xml_string, attr_prefix='@', cdata_key='#text')
        else:
            # Fallback: use basic ElementTree conversion
            raw_data = self._element_to_dict(report_xml)

        # Extract the report from response wrapper
        report_data = self._extract_report_data(raw_data)

        # Compute enriched summary fields
        summary = self._compute_summary(report_data)

        return {
            # Metadata
            "report_id": summary.get("report_id"),
            "scan_start": summary.get("scan_start"),
            "scan_end": summary.get("scan_end"),
            "scan_run_status": summary.get("scan_run_status"),

            # Computed statistics
            "hosts_scanned": summary.get("hosts_scanned", 0),
            "vulnerability_count": summary.get("vulnerability_count", 0),
            "severity_summary": summary.get("severity_summary", {}),
            "unique_cves": summary.get("unique_cves", []),
            "unique_cve_count": summary.get("unique_cve_count", 0),
            "ports_affected": summary.get("ports_affected", []),

            # Enriched vulnerabilities with severity_class
            "vulnerabilities": summary.get("vulnerabilities", []),

            # Complete raw data - ALL GVM fields preserved
            "raw_data": report_data
        }

    def _extract_report_data(self, raw_data: Dict) -> Dict:
        """
        Extract the report data from GMP response wrapper.

        Args:
            raw_data: Full xmltodict output

        Returns:
            The actual report data
        """
        # Navigate through possible wrapper structures
        if 'get_reports_response' in raw_data:
            response = raw_data['get_reports_response']
            if 'report' in response:
                report_wrapper = response['report']
                # Handle nested report structure
                if isinstance(report_wrapper, dict) and 'report' in report_wrapper:
                    return report_wrapper
                return {'report': report_wrapper}
        elif 'get_report_response' in raw_data:
            response = raw_data['get_report_response']
            if 'report' in response:
                return response
        # Return as-is if structure not recognized
        return raw_data

    def _compute_summary(self, report_data: Dict) -> Dict:
        """
        Compute summary statistics and enrich vulnerabilities.

        Args:
            report_data: Extracted report data

        Returns:
            Summary dictionary with computed fields
        """
        summary = {
            "report_id": None,
            "scan_start": None,
            "scan_end": None,
            "scan_run_status": None,
            "hosts_scanned": 0,
            "vulnerability_count": 0,
            "severity_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "log": 0},
            "unique_cves": [],
            "unique_cve_count": 0,
            "ports_affected": [],
            "vulnerabilities": []
        }

        # Navigate to the inner report
        report = report_data.get('report', {})
        if isinstance(report, dict) and 'report' in report:
            inner_report = report.get('report', {})
        else:
            inner_report = report

        # Extract metadata
        summary["report_id"] = report.get('@id') or self._safe_get(report, 'id')
        summary["scan_start"] = self._safe_get(inner_report, 'scan_start')
        summary["scan_end"] = self._safe_get(inner_report, 'scan_end')
        summary["scan_run_status"] = self._safe_get(inner_report, 'scan_run_status')

        # Get hosts count
        hosts_data = self._safe_get(inner_report, 'hosts')
        if isinstance(hosts_data, dict):
            summary["hosts_scanned"] = self._safe_int(hosts_data.get('count', 0))

        # Extract and enrich results
        results_data = self._safe_get(inner_report, 'results', {})
        results_list = self._safe_get(results_data, 'result', [])

        # Ensure results_list is a list
        if isinstance(results_list, dict):
            results_list = [results_list]
        elif not isinstance(results_list, list):
            results_list = []

        unique_cves = set()
        ports_affected = set()
        enriched_vulns = []

        for result in results_list:
            if not isinstance(result, dict):
                continue

            # Get severity and classify
            severity = self._safe_float(self._safe_get(result, 'severity', 0))
            severity_class = self._classify_severity(severity)
            summary["severity_summary"][severity_class] += 1

            # Extract CVEs
            cves = self._extract_cves_from_dict(result)
            unique_cves.update(cves)

            # Extract port
            port = self._safe_get(result, 'port')
            if port:
                ports_affected.add(port)

            # Create enriched vulnerability entry
            enriched_vuln = {
                **result,  # Keep all original fields
                "severity_float": severity,
                "severity_class": severity_class,
                "cves_extracted": cves,
            }
            enriched_vulns.append(enriched_vuln)

        # Sort by severity (highest first)
        enriched_vulns.sort(key=lambda x: x.get('severity_float', 0), reverse=True)

        summary["vulnerability_count"] = len(enriched_vulns)
        summary["vulnerabilities"] = enriched_vulns
        summary["unique_cves"] = sorted(list(unique_cves))
        summary["unique_cve_count"] = len(unique_cves)
        summary["ports_affected"] = sorted(list(ports_affected))

        return summary

    def _extract_cves_from_dict(self, result: Dict) -> List[str]:
        """
        Extract CVE identifiers from a result dictionary.

        Args:
            result: Result dictionary from xmltodict

        Returns:
            List of CVE identifiers
        """
        cves = []

        # Check nvt/refs/ref structure
        nvt = self._safe_get(result, 'nvt', {})
        refs = self._safe_get(nvt, 'refs', {})
        ref_list = self._safe_get(refs, 'ref', [])

        if isinstance(ref_list, dict):
            ref_list = [ref_list]

        for ref in ref_list:
            if isinstance(ref, dict):
                ref_type = ref.get('@type', '')
                ref_id = ref.get('@id', '')
                if ref_type.lower() == 'cve' and ref_id:
                    cves.append(ref_id)

        return cves

    def _element_to_dict(self, element: ET.Element) -> Dict:
        """
        Fallback: Convert ElementTree element to dict (basic conversion).

        Args:
            element: XML Element

        Returns:
            Dictionary representation
        """
        result = {}

        # Add attributes
        if element.attrib:
            result['@attributes'] = dict(element.attrib)

        # Add text content
        if element.text and element.text.strip():
            result['#text'] = element.text.strip()

        # Add children
        for child in element:
            child_dict = self._element_to_dict(child)
            if child.tag in result:
                # Convert to list if multiple same-named children
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_dict)
            else:
                result[child.tag] = child_dict

        return result if result else (element.text.strip() if element.text else None)

    @staticmethod
    def _safe_get(data: Any, key: str, default: Any = None) -> Any:
        """Safely get a key from dict-like data."""
        if isinstance(data, dict):
            return data.get(key, default)
        return default

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        """Safely convert value to int."""
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        """Safely convert value to float."""
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    def _classify_severity(self, severity: float) -> str:
        """Classify severity score into category."""
        if severity >= 9.0:
            return "critical"
        elif severity >= 7.0:
            return "high"
        elif severity >= 4.0:
            return "medium"
        elif severity > 0.0:
            return "low"
        return "log"

    def delete_target(self, target_id: str):
        """Delete a target from GVM."""
        try:
            self.gmp.delete_target(target_id, ultimate=True)
            print(f"    [+] Deleted target {target_id}")
        except Exception as e:
            print(f"    [!] Failed to delete target {target_id}: {e}")
    
    def delete_task(self, task_id: str):
        """Delete a task from GVM."""
        try:
            self.gmp.delete_task(task_id, ultimate=True)
            print(f"    [+] Deleted task {task_id}")
        except Exception as e:
            print(f"    [!] Failed to delete task {task_id}: {e}")
    
    def scan_targets(
        self,
        targets: List[str],
        target_name: str,
        cleanup: Optional[bool] = None
    ) -> Dict:
        """
        Run a complete vulnerability scan on targets.
        
        Args:
            targets: List of IPs or hostnames to scan
            target_name: Name for the scan target/task
            cleanup: Delete target and task after scan
            
        Returns:
            Scan results dictionary
        """
        if cleanup is None:
            cleanup = get_setting('CLEANUP_AFTER_SCAN', True)

        if not targets:
            return {"error": "No targets provided", "vulnerabilities": []}

        print(f"\n[*] Scanning {len(targets)} targets: {target_name}")
        print(f"    Targets: {', '.join(targets[:5])}{'...' if len(targets) > 5 else ''}")
        
        target_id = None
        task_id = None
        
        try:
            # Create target
            target_id = self.create_target(
                name=f"RedAmon_{target_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                hosts=targets
            )
            
            # Create and start task
            task_id = self.create_task(
                name=f"RedAmon_Scan_{target_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                target_id=target_id
            )
            self.start_task(task_id)
            
            # Wait for completion
            status, report_id = self.wait_for_task(task_id)
            
            # Get results
            if report_id:
                results = self.get_report(report_id)
                results["scan_name"] = target_name
                results["targets"] = targets
                results["status"] = status
                print(f"    [+] Scan complete: {results['vulnerability_count']} vulnerabilities found")
                return results
            else:
                return {
                    "scan_name": target_name,
                    "targets": targets,
                    "status": status,
                    "error": "No report generated",
                    "vulnerabilities": []
                }
                
        except Exception as e:
            print(f"    [!] Scan failed: {e}")
            return {
                "scan_name": target_name,
                "targets": targets,
                "status": "error",
                "error": str(e),
                "vulnerabilities": []
            }
            
        finally:
            if cleanup:
                if task_id:
                    self.delete_task(task_id)
                if target_id:
                    self.delete_target(target_id)


def extract_targets_from_recon(recon_data: Dict) -> Tuple[Set[str], Set[str]]:
    """
    Extract unique IPs and hostnames from recon JSON data.
    
    Respects SUBDOMAIN_LIST filtering:
    - Only includes root domain if it has DNS records (was resolved during scan)
    - Only includes subdomains that have DNS records
    
    Args:
        recon_data: RedAmon recon JSON data
        
    Returns:
        Tuple of (ips_set, hostnames_set)
    """
    ips = set()
    hostnames = set()
    
    dns_data = recon_data.get("dns", {})
    if not dns_data:
        return ips, hostnames
    
    # Root domain - only include if it has DNS records (respects SUBDOMAIN_LIST filtering)
    domain = recon_data.get("metadata", {}).get("root_domain", "") or recon_data.get("domain", "")
    domain_dns = dns_data.get("domain", {})
    
    if domain and domain_dns and domain_dns.get("has_records"):
        # Root domain was resolved (included in scan via "." in SUBDOMAIN_LIST or full discovery)
        hostnames.add(domain)
        domain_ips = domain_dns.get("ips", {})
        ips.update(domain_ips.get("ipv4", []))
        ips.update(domain_ips.get("ipv6", []))
    
    # Subdomains - only include those with DNS records
    for subdomain, subdomain_data in dns_data.get("subdomains", {}).items():
        if subdomain_data and subdomain_data.get("has_records"):
            hostnames.add(subdomain)
            subdomain_ips = subdomain_data.get("ips", {})
            ips.update(subdomain_ips.get("ipv4", []))
            ips.update(subdomain_ips.get("ipv6", []))
    
    # Filter empty values
    ips = {ip for ip in ips if ip}
    hostnames = {h for h in hostnames if h}
    
    return ips, hostnames


def load_recon_file(project_id: str, recon_dir: Path = None) -> Dict:
    """
    Load recon JSON file for a project.

    Args:
        project_id: Project ID used in the filename
        recon_dir: Directory containing recon files

    Returns:
        Recon data dictionary
    """
    if recon_dir is None:
        recon_dir = PROJECT_ROOT / "recon" / "output"

    recon_file = recon_dir / f"recon_{project_id}.json"

    if not recon_file.exists():
        raise FileNotFoundError(f"Recon file not found: {recon_file}")

    with open(recon_file, 'r') as f:
        return json.load(f)


def save_vuln_results(
    results: Dict,
    project_id: str,
    output_dir: Path = None
) -> Path:
    """
    Save vulnerability scan results to JSON file.

    Args:
        results: Scan results dictionary
        project_id: Project ID used in the filename
        output_dir: Output directory

    Returns:
        Path to saved file
    """
    if output_dir is None:
        output_dir = PROJECT_ROOT / "gvm_scan" / "output"

    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"gvm_{project_id}.json"

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"[+] Results saved to: {output_file}")
    return output_file


def update_graph_from_gvm_results(
    gvm_data: Dict,
    user_id: str = None,
    project_id: str = None
) -> Dict:
    """
    Update Neo4j graph database with GVM scan results.

    This function creates/updates:
    - Vulnerability nodes (from GVM findings with source="gvm")
    - Links to existing IP and Subdomain nodes
    - CVE nodes extracted from GVM findings
    - CVE -> CWE -> CAPEC enrichment chain

    Args:
        gvm_data: GVM scan results dictionary
        user_id: User identifier (defaults to USER_ID from params)
        project_id: Project identifier (defaults to PROJECT_ID from params)

    Returns:
        Dictionary with statistics about created/updated nodes
    """
    from graph_db import Neo4jClient

    user_id = user_id or USER_ID
    project_id = project_id or PROJECT_ID

    print("\n" + "=" * 50)
    print("[*] Updating Neo4j graph with GVM results...")
    print("=" * 50)

    try:
        with Neo4jClient() as client:
            if not client.verify_connection():
                print("[!] Failed to connect to Neo4j")
                return {"error": "Neo4j connection failed"}

            stats = client.update_graph_from_gvm_scan(
                gvm_data=gvm_data,
                user_id=user_id,
                project_id=project_id
            )

            print("[+] Graph update completed successfully")
            return stats

    except Exception as e:
        print(f"[!] Graph update failed: {e}")
        return {"error": str(e)}

