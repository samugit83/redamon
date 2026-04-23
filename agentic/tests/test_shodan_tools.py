"""
Unit tests for unified Shodan OSINT tool (ShodanToolManager, PhaseAwareToolExecutor integration).

Run with: python -m pytest tests/test_shodan_tools.py -v
"""
import asyncio
import json
import sys
import os
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

# Add parent dir to path so we can import from agentic modules
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# Stub out heavy dependencies that aren't installed in the local venv
# (they exist only inside the Docker container).
_stubs = {}
for mod_name in [
    'langchain_core', 'langchain_core.tools', 'langchain_core.language_models',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client',
    'langchain_neo4j',
]:
    if mod_name not in sys.modules:
        _stubs[mod_name] = MagicMock()
        sys.modules[mod_name] = _stubs[mod_name]

# Provide a real-ish @tool decorator stub: it should return the function
# with a .name attribute matching the function name, and an .ainvoke method
# that accepts a dict of kwargs (matching LangChain's ainvoke behavior).
import functools

def _fake_tool(fn):
    """Minimal stub for langchain_core.tools.tool decorator."""
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        return await fn(*args, **kwargs)
    wrapper.name = fn.__name__
    wrapper.ainvoke = lambda args_dict: fn(**args_dict)
    return wrapper

sys.modules['langchain_core.tools'].tool = _fake_tool


class TestShodanToolManager(unittest.TestCase):
    """Tests for ShodanToolManager class."""

    def test_no_api_key_returns_none(self):
        """get_tools() returns None when no API key is configured."""
        from tools import ShodanToolManager
        manager = ShodanToolManager()
        tool = manager.get_tool()
        self.assertIsNone(tool)

    def test_no_api_key_empty_string_returns_none(self):
        """get_tools() returns None when API key is empty string."""
        from tools import ShodanToolManager
        manager = ShodanToolManager(api_key='')
        tool = manager.get_tool()
        self.assertIsNone(tool)

    def test_with_api_key_returns_tool(self):
        """get_tools() returns a callable tool when API key is set."""
        from tools import ShodanToolManager
        manager = ShodanToolManager(api_key='test-key-123')
        tool = manager.get_tool()
        self.assertIsNotNone(tool)
        self.assertEqual(tool.name, 'shodan')

    def test_api_key_update(self):
        """Manager can have its key updated and return new tool."""
        from tools import ShodanToolManager
        manager = ShodanToolManager()
        self.assertEqual(manager.api_key, '')
        tool = manager.get_tool()
        self.assertIsNone(tool)

        manager.api_key = 'new-key'
        tool = manager.get_tool()
        self.assertIsNotNone(tool)


class TestShodanUnknownAction(unittest.TestCase):
    """Tests for unknown action handling."""

    def setUp(self):
        from tools import ShodanToolManager
        self.manager = ShodanToolManager(api_key='test-key')
        self.tool = self.manager.get_tool()

    def test_unknown_action(self):
        """Unknown action returns error with valid actions list."""
        result = asyncio.run(self.tool.ainvoke({"action": "foobar"}))
        self.assertIn("Unknown action", result)
        self.assertIn("foobar", result)
        self.assertIn("search", result)
        self.assertIn("host", result)
        self.assertIn("dns_reverse", result)

    def test_missing_required_param_search(self):
        """action=search without query returns error."""
        result = asyncio.run(self.tool.ainvoke({"action": "search"}))
        self.assertIn("'query' parameter is required", result)

    def test_missing_required_param_host(self):
        """action=host without ip returns error."""
        result = asyncio.run(self.tool.ainvoke({"action": "host"}))
        self.assertIn("'ip' parameter is required", result)

    def test_missing_required_param_dns_reverse(self):
        """action=dns_reverse without ip returns error."""
        result = asyncio.run(self.tool.ainvoke({"action": "dns_reverse"}))
        self.assertIn("'ip' parameter is required", result)

    def test_missing_required_param_dns_domain(self):
        """action=dns_domain without domain returns error."""
        result = asyncio.run(self.tool.ainvoke({"action": "dns_domain"}))
        self.assertIn("'domain' parameter is required", result)

    def test_missing_required_param_count(self):
        """action=count without query returns error."""
        result = asyncio.run(self.tool.ainvoke({"action": "count"}))
        self.assertIn("'query' parameter is required", result)


def _mock_httpx_client(mock_client_cls, response=None, side_effect=None):
    """Helper to set up a mocked httpx.AsyncClient context manager."""
    mock_client = AsyncMock()
    if side_effect:
        mock_client.get = AsyncMock(side_effect=side_effect)
    else:
        mock_client.get = AsyncMock(return_value=response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client
    return mock_client


def _mock_response(json_data):
    """Helper to create a mock HTTP response."""
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.raise_for_status = MagicMock()
    return resp


class TestActionSearch(unittest.TestCase):
    """Tests for action=search."""

    def setUp(self):
        from tools import ShodanToolManager
        self.tool = ShodanToolManager(api_key='test-key').get_tool()

    @patch('tools.httpx.AsyncClient')
    def test_search_success(self, mock_client_cls):
        """action=search returns formatted results on success."""
        resp = _mock_response({
            "total": 2,
            "matches": [
                {
                    "ip_str": "1.2.3.4", "port": 80, "org": "TestOrg",
                    "product": "Apache", "version": "2.4.49",
                    "hostnames": ["test.example.com"],
                    "vulns": {"CVE-2021-41773": {}}, "transport": "tcp",
                },
                {
                    "ip_str": "5.6.7.8", "port": 443, "org": "OtherOrg",
                    "product": "nginx", "version": "1.21",
                    "hostnames": [], "vulns": {}, "transport": "tcp",
                },
            ],
        })
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "search", "query": "hostname:example.com"}))
        self.assertIn("2 total results", result)
        self.assertIn("1.2.3.4:80/tcp", result)
        self.assertIn("org=TestOrg", result)
        self.assertIn("svc=Apache 2.4.49", result)
        self.assertIn("CVE-2021-41773", result)
        self.assertIn("5.6.7.8:443/tcp", result)

    @patch('tools.httpx.AsyncClient')
    def test_search_no_results(self, mock_client_cls):
        """action=search returns 'No results' when matches is empty."""
        resp = _mock_response({"total": 0, "matches": []})
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "search", "query": "nonexistent"}))
        self.assertIn("No Shodan results", result)

    @patch('tools.httpx.AsyncClient')
    def test_search_401_error(self, mock_client_cls):
        """action=search returns auth error on 401."""
        import httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        _mock_httpx_client(mock_client_cls, side_effect=httpx.HTTPStatusError("401", request=MagicMock(), response=mock_resp))

        result = asyncio.run(self.tool.ainvoke({"action": "search", "query": "test"}))
        self.assertIn("Invalid API key", result)

    @patch('tools.httpx.AsyncClient')
    def test_search_403_error(self, mock_client_cls):
        """action=search returns paid-key-required error on 403."""
        import httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        _mock_httpx_client(mock_client_cls, side_effect=httpx.HTTPStatusError("403", request=MagicMock(), response=mock_resp))

        result = asyncio.run(self.tool.ainvoke({"action": "search", "query": "test"}))
        self.assertIn("requires a paid Shodan API key", result)

    @patch('tools.httpx.AsyncClient')
    def test_search_429_rate_limit(self, mock_client_cls):
        """action=search returns rate limit error on 429."""
        import httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        _mock_httpx_client(mock_client_cls, side_effect=httpx.HTTPStatusError("429", request=MagicMock(), response=mock_resp))

        result = asyncio.run(self.tool.ainvoke({"action": "search", "query": "test"}))
        self.assertIn("Rate limit", result)

    @patch('tools.httpx.AsyncClient')
    def test_search_caps_at_20_results(self, mock_client_cls):
        """Only shows max 20 results even if more returned."""
        matches = [{"ip_str": f"10.0.0.{i}", "port": 80, "transport": "tcp"} for i in range(30)]
        resp = _mock_response({"total": 30, "matches": matches})
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "search", "query": "port:80"}))
        self.assertIn("[20]", result)
        self.assertNotIn("[21]", result)

    @patch('tools.httpx.AsyncClient')
    def test_search_without_optional_fields(self, mock_client_cls):
        """Handles matches missing optional fields (product, vulns, hostnames)."""
        resp = _mock_response({
            "total": 1,
            "matches": [{"ip_str": "1.2.3.4", "port": 22, "transport": "tcp"}],
        })
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "search", "query": "port:22"}))
        self.assertIn("1.2.3.4:22/tcp", result)
        self.assertNotIn("org=", result)
        self.assertNotIn("svc=", result)
        self.assertNotIn("vulns=", result)


class TestActionHost(unittest.TestCase):
    """Tests for action=host."""

    def setUp(self):
        from tools import ShodanToolManager
        self.tool = ShodanToolManager(api_key='test-key').get_tool()

    @patch('tools.httpx.AsyncClient')
    def test_host_info_success(self, mock_client_cls):
        """action=host returns formatted host details."""
        resp = _mock_response({
            "ip_str": "1.2.3.4",
            "hostnames": ["web.example.com", "api.example.com"],
            "os": "Linux 5.4",
            "org": "Example Inc", "isp": "CloudProvider",
            "country_name": "United States", "city": "New York",
            "ports": [22, 80, 443],
            "vulns": ["CVE-2021-44228", "CVE-2021-41773"],
            "data": [
                {"port": 80, "transport": "tcp", "product": "Apache", "version": "2.4.49",
                 "data": "HTTP/1.1 200 OK\nServer: Apache/2.4.49"},
                {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.21",
                 "data": "HTTP/1.1 301 Moved"},
            ],
        })
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "host", "ip": "1.2.3.4"}))
        self.assertIn("Shodan Host: 1.2.3.4", result)
        self.assertIn("web.example.com", result)
        self.assertIn("OS: Linux 5.4", result)
        self.assertIn("Org: Example Inc", result)
        self.assertIn("ISP: CloudProvider", result)
        self.assertIn("New York, United States", result)
        self.assertIn("22, 80, 443", result)
        self.assertIn("CVE-2021-44228", result)
        self.assertIn("Apache 2.4.49", result)
        self.assertIn("banner:", result)

    @patch('tools.httpx.AsyncClient')
    def test_host_info_404(self, mock_client_cls):
        """action=host returns 'no info' message on 404."""
        import httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        _mock_httpx_client(mock_client_cls, side_effect=httpx.HTTPStatusError("404", request=MagicMock(), response=mock_resp))

        result = asyncio.run(self.tool.ainvoke({"action": "host", "ip": "10.0.0.1"}))
        self.assertIn("No information available", result)
        self.assertIn("10.0.0.1", result)

    @patch('tools.httpx.AsyncClient')
    def test_host_info_minimal_data(self, mock_client_cls):
        """action=host handles hosts with minimal data gracefully."""
        resp = _mock_response({"ip_str": "10.0.0.5", "hostnames": [], "ports": [22], "data": []})
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "host", "ip": "10.0.0.5"}))
        self.assertIn("Shodan Host: 10.0.0.5", result)
        self.assertIn("22", result)
        self.assertNotIn("Hostnames:", result)
        self.assertNotIn("OS:", result)


class TestActionDnsReverse(unittest.TestCase):
    """Tests for action=dns_reverse."""

    def setUp(self):
        from tools import ShodanToolManager
        self.tool = ShodanToolManager(api_key='test-key').get_tool()

    @patch('tools.httpx.AsyncClient')
    def test_dns_reverse_success(self, mock_client_cls):
        """action=dns_reverse returns hostnames for an IP."""
        resp = _mock_response({"8.8.8.8": ["dns.google"]})
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "dns_reverse", "ip": "8.8.8.8"}))
        self.assertIn("Reverse DNS for 8.8.8.8", result)
        self.assertIn("dns.google", result)

    @patch('tools.httpx.AsyncClient')
    def test_dns_reverse_no_records(self, mock_client_cls):
        """action=dns_reverse returns message when no records found."""
        resp = _mock_response({"10.0.0.1": []})
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "dns_reverse", "ip": "10.0.0.1"}))
        self.assertIn("No reverse DNS records", result)

    @patch('tools.httpx.AsyncClient')
    def test_dns_reverse_multiple_hostnames(self, mock_client_cls):
        """action=dns_reverse returns multiple hostnames."""
        resp = _mock_response({"1.2.3.4": ["host1.example.com", "host2.example.com"]})
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "dns_reverse", "ip": "1.2.3.4"}))
        self.assertIn("host1.example.com", result)
        self.assertIn("host2.example.com", result)


class TestActionDnsDomain(unittest.TestCase):
    """Tests for action=dns_domain."""

    def setUp(self):
        from tools import ShodanToolManager
        self.tool = ShodanToolManager(api_key='test-key').get_tool()

    @patch('tools.httpx.AsyncClient')
    def test_dns_domain_success(self, mock_client_cls):
        """action=dns_domain returns subdomains and records."""
        resp = _mock_response({
            "domain": "example.com",
            "subdomains": ["www", "api", "mail"],
            "data": [
                {"type": "A", "subdomain": "www", "value": "1.2.3.4"},
                {"type": "MX", "subdomain": "", "value": "mail.example.com"},
            ],
        })
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "dns_domain", "domain": "example.com"}))
        self.assertIn("DNS for example.com", result)
        self.assertIn("Subdomains (3)", result)
        self.assertIn("www", result)
        self.assertIn("api", result)
        self.assertIn("A  www.example.com -> 1.2.3.4", result)
        self.assertIn("MX  example.com -> mail.example.com", result)

    @patch('tools.httpx.AsyncClient')
    def test_dns_domain_403(self, mock_client_cls):
        """action=dns_domain returns paid-key-required error on 403."""
        import httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        _mock_httpx_client(mock_client_cls, side_effect=httpx.HTTPStatusError("403", request=MagicMock(), response=mock_resp))

        result = asyncio.run(self.tool.ainvoke({"action": "dns_domain", "domain": "example.com"}))
        self.assertIn("requires a paid Shodan API key", result)

    @patch('tools.httpx.AsyncClient')
    def test_dns_domain_more_flag(self, mock_client_cls):
        """action=dns_domain shows note when more results are available."""
        resp = _mock_response({
            "domain": "example.com",
            "subdomains": ["www"],
            "data": [{"type": "A", "subdomain": "www", "value": "1.2.3.4"}],
            "more": True,
        })
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "dns_domain", "domain": "example.com"}))
        self.assertIn("Additional results available", result)

    @patch('tools.httpx.AsyncClient')
    def test_dns_domain_no_data(self, mock_client_cls):
        """action=dns_domain handles empty results."""
        resp = _mock_response({"domain": "example.com", "subdomains": [], "data": []})
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "dns_domain", "domain": "example.com"}))
        self.assertIn("No DNS data found", result)


class TestActionCount(unittest.TestCase):
    """Tests for action=count."""

    def setUp(self):
        from tools import ShodanToolManager
        self.tool = ShodanToolManager(api_key='test-key').get_tool()

    @patch('tools.httpx.AsyncClient')
    def test_count_success(self, mock_client_cls):
        """action=count returns total count."""
        resp = _mock_response({"total": 42, "facets": {}})
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "count", "query": "hostname:example.com"}))
        self.assertIn("42 hosts", result)
        self.assertIn("hostname:example.com", result)

    @patch('tools.httpx.AsyncClient')
    def test_count_with_facets(self, mock_client_cls):
        """action=count includes facet breakdown if present."""
        resp = _mock_response({
            "total": 100,
            "facets": {
                "port": [
                    {"value": 80, "count": 60},
                    {"value": 443, "count": 40},
                ],
            },
        })
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "count", "query": "org:Google"}))
        self.assertIn("100 hosts", result)
        self.assertIn("port:", result)
        self.assertIn("80: 60", result)
        self.assertIn("443: 40", result)

    @patch('tools.httpx.AsyncClient')
    def test_count_zero_results(self, mock_client_cls):
        """action=count handles zero results."""
        resp = _mock_response({"total": 0, "facets": {}})
        _mock_httpx_client(mock_client_cls, response=resp)

        result = asyncio.run(self.tool.ainvoke({"action": "count", "query": "nonexistent"}))
        self.assertIn("0 hosts", result)


class TestToolRegistryEntries(unittest.TestCase):
    """Tests for TOOL_REGISTRY entries."""

    def test_shodan_in_registry(self):
        """shodan entry exists with required fields."""
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("shodan", TOOL_REGISTRY)
        entry = TOOL_REGISTRY["shodan"]
        self.assertIn("purpose", entry)
        self.assertIn("when_to_use", entry)
        self.assertIn("args_format", entry)
        self.assertIn("description", entry)
        self.assertIn("action", entry["args_format"])

    def test_shodan_positioned_after_web_search(self):
        """shodan comes after web_search in registry order."""
        from prompts.tool_registry import TOOL_REGISTRY
        keys = list(TOOL_REGISTRY.keys())
        ws_idx = keys.index("web_search")
        sh_idx = keys.index("shodan")
        self.assertEqual(sh_idx, ws_idx + 1)

    def test_old_tool_names_not_in_registry(self):
        """Old shodan_search and shodan_host_info should not exist."""
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertNotIn("shodan_search", TOOL_REGISTRY)
        self.assertNotIn("shodan_host_info", TOOL_REGISTRY)


class TestProjectSettings(unittest.TestCase):
    """Tests for project_settings.py changes."""

    def test_shodan_enabled_default(self):
        """SHODAN_ENABLED defaults to True."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        self.assertIn('SHODAN_ENABLED', DEFAULT_AGENT_SETTINGS)
        self.assertTrue(DEFAULT_AGENT_SETTINGS['SHODAN_ENABLED'])

    def test_shodan_in_phase_map(self):
        """Unified shodan tool is in TOOL_PHASE_MAP with all phases."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        all_phases = ['informational', 'exploitation', 'post_exploitation']

        self.assertIn('shodan', phase_map)
        self.assertEqual(phase_map['shodan'], all_phases)

    def test_old_tool_names_not_in_phase_map(self):
        """Old shodan_search and shodan_host_info not in phase map."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertNotIn('shodan_search', phase_map)
        self.assertNotIn('shodan_host_info', phase_map)

    def test_phase_check_functions(self):
        """is_tool_allowed_in_phase works for unified shodan tool."""
        from project_settings import is_tool_allowed_in_phase
        self.assertTrue(is_tool_allowed_in_phase('shodan', 'informational'))
        self.assertTrue(is_tool_allowed_in_phase('shodan', 'exploitation'))
        self.assertTrue(is_tool_allowed_in_phase('shodan', 'post_exploitation'))


class TestPhaseAwareToolExecutor(unittest.TestCase):
    """Tests for PhaseAwareToolExecutor Shodan integration."""

    def test_executor_accepts_shodan_tool(self):
        """PhaseAwareToolExecutor registers shodan tool in __init__."""
        from tools import ShodanToolManager, PhaseAwareToolExecutor, MCPToolsManager

        shodan_mgr = ShodanToolManager(api_key='test')
        shodan_tool = shodan_mgr.get_tool()

        mcp_mgr = MagicMock(spec=MCPToolsManager)
        executor = PhaseAwareToolExecutor(mcp_mgr, None, None, shodan_tool=shodan_tool)

        self.assertIn("shodan", executor._all_tools)

    def test_executor_without_shodan_tool(self):
        """PhaseAwareToolExecutor works fine without shodan tool."""
        from tools import PhaseAwareToolExecutor, MCPToolsManager

        mcp_mgr = MagicMock(spec=MCPToolsManager)
        executor = PhaseAwareToolExecutor(mcp_mgr, None, None)

        self.assertNotIn("shodan", executor._all_tools)

    def test_update_shodan_tool_add(self):
        """update_shodan_tool adds tool to executor."""
        from tools import ShodanToolManager, PhaseAwareToolExecutor, MCPToolsManager

        mcp_mgr = MagicMock(spec=MCPToolsManager)
        executor = PhaseAwareToolExecutor(mcp_mgr, None, None)
        self.assertNotIn("shodan", executor._all_tools)

        shodan_mgr = ShodanToolManager(api_key='test')
        shodan_tool = shodan_mgr.get_tool()
        executor.update_shodan_tool(shodan_tool)

        self.assertIn("shodan", executor._all_tools)

    def test_update_shodan_tool_remove(self):
        """update_shodan_tool(None) removes tool from executor."""
        from tools import ShodanToolManager, PhaseAwareToolExecutor, MCPToolsManager

        shodan_mgr = ShodanToolManager(api_key='test')
        shodan_tool = shodan_mgr.get_tool()

        mcp_mgr = MagicMock(spec=MCPToolsManager)
        executor = PhaseAwareToolExecutor(mcp_mgr, None, None, shodan_tool=shodan_tool)
        self.assertIn("shodan", executor._all_tools)

        executor.update_shodan_tool(None)
        self.assertNotIn("shodan", executor._all_tools)

    def test_execute_shodan_dispatch(self):
        """execute() dispatches shodan tool with full tool_args dict."""
        from tools import ShodanToolManager, PhaseAwareToolExecutor, MCPToolsManager

        shodan_mgr = ShodanToolManager(api_key='test')
        shodan_tool = shodan_mgr.get_tool()

        mcp_mgr = MagicMock(spec=MCPToolsManager)
        executor = PhaseAwareToolExecutor(mcp_mgr, None, None, shodan_tool=shodan_tool)

        tool_args = {"action": "host", "ip": "1.2.3.4"}
        with patch.object(shodan_tool, 'ainvoke', new_callable=AsyncMock, return_value="mock result") as mock_invoke:
            result = asyncio.run(executor.execute("shodan", tool_args, "informational"))
            mock_invoke.assert_called_once_with(tool_args)
            self.assertTrue(result["success"])
            self.assertEqual(result["output"], "mock result")


if __name__ == '__main__':
    unittest.main()
