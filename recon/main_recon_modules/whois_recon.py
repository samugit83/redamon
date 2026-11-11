"""
OSINT Module - WHOIS Information Gathering
This module provides comprehensive WHOIS lookup capabilities for domain reconnaissance.
Output is saved as structured JSON to the output folder.
"""

import ipaddress
import json
import re
import time
import whois
from typing import Any, Optional
from datetime import datetime
from pathlib import Path

# Output directory for JSON results
OUTPUT_DIR = Path(__file__).parent / "output"

# Default for WHOIS retries (used when no settings provided)
DEFAULT_WHOIS_MAX_RETRIES = 6


class WhoisUnavailable(Exception):
    """WHOIS is paused or stopped for this run: the `whois` circuit breaker is open."""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


#: The keys a regional registry names an address block's holder with, most
#: specific first: ARIN's OrgName, RIPE's and AFRINIC's org-name, LACNIC's
#: owner, then the free-text descr RIPE, APNIC and AFRINIC all carry.
_ORG_KEYS = ("orgname", "org-name", "owner", "descr")
_FIELD = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*$")
#: The only servers an ARIN referral is followed to: the other regional
#: registries. An rwhois:// referral names an ISP's own server.
_REGISTRY_SERVERS = frozenset({
    "whois.ripe.net", "whois.apnic.net", "whois.lacnic.net", "whois.afrinic.net", "whois.registro.br",
})


def registry_fields(text: str) -> dict:
    """{"org", "country"} from a registry's WHOIS answer, each only when found.

    python-whois's generic parser knows none of the registries' keys, so an
    IP's answer parsed empty. The first value of the first organisation key
    present wins, and the first country.
    """
    fields: dict = {}
    for line in (text or "").splitlines():
        if line.lstrip().startswith(("%", "#")):
            continue
        match = _FIELD.match(line)
        if match and match.group(2):
            fields.setdefault(match.group(1).lower(), match.group(2))
    out = {}
    org = next((fields[k] for k in _ORG_KEYS if k in fields), None)
    if org:
        out["org"] = org
    if fields.get("country"):
        out["country"] = fields["country"]
    return out


def _referral(text: str):
    """The regional registry ARIN refers the block to, or None."""
    for line in (text or "").splitlines():
        match = _FIELD.match(line)
        if match and match.group(1).lower() == "referralserver":
            server = match.group(2).lower()
            host = server[len("whois://"):].split(":", 1)[0].strip("/") if server.startswith("whois://") else ""
            return host if host in _REGISTRY_SERVERS else None
    return None


def _ip_whois(address: str) -> dict:
    """IP WHOIS at the registries, asked with the address itself.

    python-whois 0.9.6 resolves an address's PTR with socket.gethostbyaddr
    before asking, then queries the PTR name's registered domain: a hidden
    lookup outside the resolver breakers, which IP only must not send (I-7),
    and an answer about a domain's registrant instead of the address block.
    ARIN answers for every address (IPv6 too, for which the library finds no
    server) and refers a block another registry holds; only that registry's
    answer is read. The library's own recursion would append it to ARIN's,
    whose first OrgName is then the registry itself.
    """
    from whois.exceptions import WhoisError
    from whois.whois import NICClient

    client = NICClient()
    text = client.whois(address, NICClient.ANICHOST, 0,
                        quiet=True, ignore_socket_errors=False, timeout=10)
    if not text:
        raise WhoisError("Whois command returned no output")
    server = _referral(text)
    if server:
        text = client.whois(address, server, 0, quiet=True, ignore_socket_errors=False, timeout=10)
    return registry_fields(text)


def _query(domain: str, is_ip: bool):
    """One WHOIS call, typed: (result, outcome, detail, retry_once_only).

    python-whois defaults to ignore_socket_errors=True, which turns a dead
    server into the text "Socket not responding: ..." that parses as an empty
    entry, so a dead server looked exactly like "no data". Asking it to raise
    keeps the two apart.
    """
    from recon.helpers.circuit_breaker import Outcome
    from whois.exceptions import (
        WhoisDomainNotFoundError, WhoisError, WhoisQuotaExceededError,
    )
    try:
        if is_ip:
            fields = _ip_whois(domain)
            return fields, (Outcome.OK if fields else Outcome.NO_DATA), ("" if fields else "empty record"), False
        w = whois.whois(domain, ignore_socket_errors=False, quiet=True)
    except WhoisQuotaExceededError:
        return None, Outcome.FATAL, "quota exceeded", False
    except WhoisDomainNotFoundError:
        return {}, Outcome.NO_DATA, "no record", False
    except WhoisError as e:
        # The message is read to classify, never logged.
        if "no output" in str(e).lower():
            if is_ip:
                return {}, Outcome.NO_DATA, "no output", False
            return None, Outcome.TRANSIENT, "no output", True
        return None, Outcome.TRANSIENT, type(e).__name__, False
    except Exception as e:  # noqa: BLE001 - socket errors and timeouts
        return None, Outcome.TRANSIENT, type(e).__name__, False
    if w and (w.domain_name or w.registrar or w.creation_date):
        return w, Outcome.OK, "", False
    # An empty parse is a permanent answer (typical for an IP without reverse
    # DNS): returned as-is, never retried.
    return (w if w is not None else {}), Outcome.NO_DATA, "empty record", False


def get_whois_data(domain: str, max_retries: int = None, settings: Optional[dict] = None):
    """
    Get WHOIS information for a domain or an IP.

    An empty answer is an answer and comes back at once: a parse with no
    domain_name/registrar/creation_date, an unknown domain, or (for an IP) no
    output at all. Only socket errors and timeouts are retried, with
    exponential backoff, and only while the process-wide ``whois`` circuit
    breaker is closed: three consecutive failures stop WHOIS for the run. A
    domain that returns no output gets one short retry.

    Args:
        domain: The domain or IP to look up (e.g., "example.com")
        max_retries: Maximum attempts (overrides settings if provided)
        settings: Settings dict from project_settings.get_settings()

    Returns:
        Tuple of (whois_result_dict_like_object, domain_string).

    Raises:
        WhoisUnavailable: the whois breaker is open.
        Exception: no answer was obtained (the message carries no server text).
    """
    if max_retries is None:
        if settings:
            max_retries = settings.get('WHOIS_MAX_RETRIES', DEFAULT_WHOIS_MAX_RETRIES)
        else:
            max_retries = DEFAULT_WHOIS_MAX_RETRIES
    attempts = max(1, int(max_retries or 1))

    from recon.helpers import circuit_breaker as cb
    breaker = cb.get_breaker("whois", label="WHOIS", threshold=cb.INTERNAL_THRESHOLD)
    is_ip = _is_ip(domain)
    last_detail = "no answer"
    short_retry_used = False

    for attempt in range(attempts):
        if not breaker.allow():
            raise WhoisUnavailable(f"WHOIS paused for this run ({breaker.detail})")
        epoch = breaker.epoch()
        result, outcome, detail, retry_once_only = _query(domain, is_ip)
        breaker.record(outcome, detail, epoch=epoch)
        if outcome in (cb.Outcome.OK, cb.Outcome.NO_DATA):
            return result, domain
        if outcome is cb.Outcome.FATAL:
            raise Exception(f"WHOIS lookup refused for {domain}: {detail}")
        last_detail = detail
        if retry_once_only:
            if short_retry_used:
                break
            short_retry_used = True
        if attempt >= attempts - 1 or breaker.is_open:
            break
        delay = 1 if retry_once_only else 2 ** attempt
        print(f"[!][WHOIS] {detail}, retrying in {delay}s... (attempt {attempt + 1}/{attempts})")
        time.sleep(delay)

    raise Exception(f"WHOIS lookup failed for {domain}: {last_detail}")


def _serialize_for_json(value: Any) -> Any:
    """
    Serialize a value for JSON output, handling datetime objects.
    
    Args:
        value: The value to serialize.
        
    Returns:
        JSON-serializable value.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [_serialize_for_json(item) for item in value]
    if isinstance(value, dict):
        return {k: _serialize_for_json(v) for k, v in value.items()}
    return value


def whois_to_dict(whois_result: Any, domain: str) -> dict:
    """
    Convert whois library result to a structured dictionary with all fields.
    Uses the library's dict-like interface to capture all available fields.
    
    Args:
        whois_result: The whois.whois() result (dict-like object).
        domain: The domain that was queried.
        
    Returns:
        Structured dictionary ready for JSON serialization with all fields.
    """
    # Convert whois result to dict (captures ALL fields automatically)
    whois_dict = dict(whois_result)
    
    # Serialize datetime objects and structure the output
    serialized_data = _serialize_for_json(whois_dict)
    
    # Structure the output nicely, while preserving all fields
    result = {
        "metadata": {
            "scan_type": "whois",
            "scan_timestamp": datetime.now().isoformat(),
            "target_domain": domain
        },
        "whois_data": serialized_data
    }
    
    return result


def save_json_report(data: dict, domain: str, output_dir: Path = OUTPUT_DIR) -> str:
    """
    Save WHOIS information as a structured JSON file.
    
    Args:
        data: Dictionary containing WHOIS data.
        domain: Domain name for filename.
        output_dir: Directory to save the JSON file.
        
    Returns:
        Path to the saved JSON file.
    """
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate filename
    filename = f"whois_{domain}.json"
    filepath = output_dir / filename
    
    # Save the structured data
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    return str(filepath)


def print_whois_settings(settings: Optional[dict]) -> None:
    if settings:
        from recon.helpers import print_effective_settings
        print_effective_settings(
            "WHOIS",
            settings,
            keys=[
                ("WHOIS_MAX_RETRIES", "Retry policy"),
            ],
        )


def whois_lookup(domain: str, save_output: bool = True, settings: Optional[dict] = None,
                 print_settings: bool = True) -> dict:
    """
    Main function to perform a WHOIS lookup and save results as JSON.

    Args:
        domain: The domain to lookup (e.g., "example.com")
        save_output: Whether to save the JSON report to file.
        settings: Settings dict from project_settings.get_settings()
        print_settings: Print the settings banner. A caller looping over many
            targets prints it once itself and passes False.

    Returns:
        Dictionary containing all WHOIS data with metadata.
    """
    if print_settings:
        print_whois_settings(settings)

    whois_result, domain = get_whois_data(domain, settings=settings)
    result = whois_to_dict(whois_result, domain)

    if save_output:
        filepath = save_json_report(result, domain)
        print(f"[✓][WHOIS] Report saved to: {filepath}")

    return result

