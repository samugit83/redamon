"""
IANA Service Name and Port Number Registry Lookup

Provides service name lookups from the official IANA registry.
CSV source: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv

The CSV is bundled in recon/data/iana-services.csv for offline use.
"""

import csv
from pathlib import Path
from typing import Dict, Tuple

# Cache for loaded IANA data: {(port, protocol): service_name}
_IANA_CACHE: Dict[Tuple[int, str], str] = {}
_CACHE_LOADED = False

# Path to the IANA CSV file
IANA_CSV_PATH = Path(__file__).parent.parent / "data" / "iana-services.csv"


def _load_iana_cache() -> None:
    """Load IANA services CSV into memory cache."""
    global _IANA_CACHE, _CACHE_LOADED

    if _CACHE_LOADED:
        return

    if not IANA_CSV_PATH.exists():
        print(f"[!][IANA] IANA services CSV not found at {IANA_CSV_PATH}")
        _CACHE_LOADED = True
        return

    try:
        with open(IANA_CSV_PATH, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                service_name = row.get('Service Name', '').strip()
                port_str = row.get('Port Number', '').strip()
                protocol = row.get('Transport Protocol', '').strip().lower()

                # Skip empty entries, reserved, or unassigned
                if not service_name or not port_str or not protocol:
                    continue

                # Handle port ranges (e.g., "49152-65535")
                if '-' in port_str:
                    continue  # Skip ranges, too broad

                try:
                    port = int(port_str)
                except ValueError:
                    continue

                # Store first service name for each port/protocol combo
                # (IANA may have multiple entries, we take the first)
                key = (port, protocol)
                if key not in _IANA_CACHE:
                    _IANA_CACHE[key] = service_name

        _CACHE_LOADED = True

    except Exception as e:
        print(f"[!][IANA] Error loading IANA services: {e}")
        _CACHE_LOADED = True


def get_service_name(port: int, protocol: str = "tcp") -> str:
    """
    Get service name from IANA registry.

    Args:
        port: Port number
        protocol: Transport protocol (tcp, udp, sctp, dccp). Default: tcp

    Returns:
        Service name or "unknown" if not found

    Examples:
        >>> get_service_name(22)
        'ssh'
        >>> get_service_name(80)
        'http'
        >>> get_service_name(53, 'udp')
        'domain'
    """
    _load_iana_cache()

    protocol = protocol.lower()
    return _IANA_CACHE.get((port, protocol), "unknown")


def get_service_info(port: int, protocol: str = "tcp") -> Dict:
    """
    Get detailed service info from IANA registry.

    Returns dict with service name and whether it was found.
    """
    _load_iana_cache()

    protocol = protocol.lower()
    service = _IANA_CACHE.get((port, protocol))

    return {
        "port": port,
        "protocol": protocol,
        "service": service or "unknown",
        "found_in_iana": service is not None
    }


def get_all_services_for_port(port: int) -> Dict[str, str]:
    """
    Get all services registered for a port across all protocols.

    Returns:
        Dict mapping protocol to service name

    Example:
        >>> get_all_services_for_port(53)
        {'tcp': 'domain', 'udp': 'domain'}
    """
    _load_iana_cache()

    result = {}
    for (p, proto), svc in _IANA_CACHE.items():
        if p == port:
            result[proto] = svc

    return result


def get_cache_stats() -> Dict:
    """Get statistics about the loaded IANA cache."""
    _load_iana_cache()

    protocols = {}
    for (port, proto), service in _IANA_CACHE.items():
        protocols[proto] = protocols.get(proto, 0) + 1

    return {
        "total_entries": len(_IANA_CACHE),
        "by_protocol": protocols,
        "cache_loaded": _CACHE_LOADED,
        "csv_path": str(IANA_CSV_PATH),
        "csv_exists": IANA_CSV_PATH.exists()
    }


# Common port overrides for clarity (IANA names can be cryptic)
# These take precedence over IANA when more descriptive
_FRIENDLY_NAMES = {
    # Web
    (80, "tcp"): "http",
    (443, "tcp"): "https",
    (8080, "tcp"): "http-proxy",
    (8443, "tcp"): "https-alt",
    (8000, "tcp"): "http-alt",
    (8888, "tcp"): "http-alt",
    # Remote access
    (3389, "tcp"): "rdp",
    (5900, "tcp"): "vnc",
    (5901, "tcp"): "vnc",
    # Databases
    (27017, "tcp"): "mongodb",
    (6379, "tcp"): "redis",
    (9200, "tcp"): "elasticsearch",
    (9300, "tcp"): "elasticsearch-cluster",
    (5984, "tcp"): "couchdb",
    (7474, "tcp"): "neo4j-http",
    (7687, "tcp"): "neo4j-bolt",
    (8086, "tcp"): "influxdb",
    (9042, "tcp"): "cassandra",
    (11211, "tcp"): "memcached",
    # Monitoring/Observability
    (5601, "tcp"): "kibana",
    (9090, "tcp"): "prometheus",
    (3000, "tcp"): "grafana",
    (5044, "tcp"): "logstash",
    (9100, "tcp"): "node-exporter",
    (8125, "udp"): "statsd",
    # Message queues
    (5672, "tcp"): "rabbitmq",
    (15672, "tcp"): "rabbitmq-mgmt",
    (9092, "tcp"): "kafka",
    (2181, "tcp"): "zookeeper",
    (1883, "tcp"): "mqtt",
    (8883, "tcp"): "mqtt-tls",
    (4222, "tcp"): "nats",
    # Containers/Orchestration
    (2375, "tcp"): "docker",
    (2376, "tcp"): "docker-tls",
    (6443, "tcp"): "kubernetes-api",
    (10250, "tcp"): "kubelet",
    (2379, "tcp"): "etcd",
    (8500, "tcp"): "consul",
    (8600, "tcp"): "consul-dns",
    # CI/CD
    (50000, "tcp"): "jenkins-agent",
    (8081, "tcp"): "nexus",
    (9000, "tcp"): "sonarqube",
    # App servers
    (8009, "tcp"): "ajp",
    (7001, "tcp"): "weblogic",
    (4848, "tcp"): "glassfish",
}


def get_service_name_friendly(port: int, protocol: str = "tcp") -> str:
    """
    Get service name with friendly overrides for common services.

    Falls back to IANA registry if no friendly name defined.
    """
    protocol = protocol.lower()

    # Check friendly overrides first
    friendly = _FRIENDLY_NAMES.get((port, protocol))
    if friendly:
        return friendly

    # Fall back to IANA
    return get_service_name(port, protocol)
