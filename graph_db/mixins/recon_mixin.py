"""
ReconMixin: core reconnaissance pipeline graph operations.

After the split, this module is a thin combinator. All methods are provided
by per-topic sub-mixins in the graph_db.mixins.recon package:

    DomainMixin    -> domain discovery + IP recon
    PortMixin      -> port scan + nmap
    HttpMixin      -> HTTP probe
    VulnMixin      -> vulnerability scan (Vuln, CVE, CWE, CAPEC, Exploit, MitreData)
    ResourceMixin  -> resource enumeration (Endpoint, Parameter)
    JsReconMixin   -> JS recon (JsReconFinding, Secret)
    TriageMixin    -> finding triage verdicts + mute/unmute suppression
    UserInputMixin -> user input nodes + partial discovery + tool input gathering
    OpenApiMixin   -> target-scoped OpenAPI operation declarations

The public surface is unchanged: Neo4jClient(... ReconMixin ...) resolves
every original method via MRO.
"""

from graph_db.mixins.recon.domain_mixin import DomainMixin
from graph_db.mixins.recon.port_mixin import PortMixin
from graph_db.mixins.recon.http_mixin import HttpMixin
from graph_db.mixins.recon.vuln_mixin import VulnMixin
from graph_db.mixins.recon.resource_mixin import ResourceMixin
from graph_db.mixins.recon.js_recon_mixin import JsReconMixin
from graph_db.mixins.recon.user_input_mixin import UserInputMixin
from graph_db.mixins.recon.takeover_mixin import TakeoverMixin
from graph_db.mixins.recon.vhost_sni_mixin import VhostSniMixin
from graph_db.mixins.recon.ai_surface_recon_mixin import AiSurfaceReconMixin
from graph_db.mixins.recon.openapi_mixin import OpenApiMixin
from graph_db.mixins.recon.triage_mixin import TriageMixin



class ReconMixin(
    DomainMixin,
    PortMixin,
    HttpMixin,
    VulnMixin,
    ResourceMixin,
    JsReconMixin,
    UserInputMixin,
    TakeoverMixin,
    VhostSniMixin,
    AiSurfaceReconMixin,
    OpenApiMixin,
    TriageMixin,

):
    pass
