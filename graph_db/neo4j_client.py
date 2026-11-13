"""
Neo4j Graph Database Client for RedAmon Reconnaissance Data

Usage:
    from graph_db import Neo4jClient
    with Neo4jClient() as client:
        client.update_graph_from_domain_discovery(recon_data, user_id, project_id)

All methods are provided by the mixin classes combined via multiple inheritance.
MRO: BaseMixin → ReconMixin → GvmMixin → SecretMixin → OsintMixin → GraphQLMixin → CacheMixin
     → SupplyChainMixin → NodeFilterMixin → TenancyMixin
"""

from graph_db.mixins.base_mixin import BaseMixin
from graph_db.mixins.recon_mixin import ReconMixin
from graph_db.mixins.gvm_mixin import GvmMixin
from graph_db.mixins.secret_mixin import SecretMixin
from graph_db.mixins.osint_mixin import OsintMixin
from graph_db.mixins.graphql_mixin import GraphQLMixin
from graph_db.mixins.cache_mixin import CacheMixin
from graph_db.mixins.supply_chain_mixin import SupplyChainMixin
from graph_db.mixins.node_filter_mixin import NodeFilterMixin
from graph_db.mixins.tenancy_mixin import TenancyMixin


class Neo4jClient(BaseMixin, ReconMixin, GvmMixin, SecretMixin, OsintMixin, GraphQLMixin, CacheMixin,
                  SupplyChainMixin, NodeFilterMixin, TenancyMixin):
    """
    Public Neo4j client for RedAmon. All methods provided by mixins.

    Connection lifecycle and schema initialization: BaseMixin
    Core recon pipeline (domain, IP, port, HTTP, vuln, resource): ReconMixin
    GVM vulnerability scanner integration: GvmMixin
    Secret detection (GitHub hunt, TruffleHog): SecretMixin
    OSINT enrichment (Shodan, Censys, FOFA, OTX, etc.): OsintMixin
    GraphQL security scanning integration: GraphQLMixin
    Web cache poisoning scanning integration: CacheMixin
    Rule-based mutes (node filters): NodeFilterMixin
    Moving a project to a new owner (ownership transfer): TenancyMixin
    """
    pass
