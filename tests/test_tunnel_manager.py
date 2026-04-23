"""
Unit tests for tunnel_manager.py

Tests the HTTP server logic, process management, and configure/status endpoints.
Run with: python -m pytest tests/test_tunnel_manager.py -v
"""
import json
import subprocess
import threading
import time
import urllib.request
import urllib.error
import sys
import os

# Add the MCP servers directory to path so we can import tunnel_manager
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'mcp', 'servers'))

import pytest


class TestTunnelManagerLogic:
    """Test the core logic functions without starting the HTTP server."""

    def setup_method(self):
        """Reset module state before each test."""
        import tunnel_manager
        # Reset global state
        tunnel_manager._ngrok_proc = None
        tunnel_manager._chisel_proc = None

    def test_get_status_no_tunnels(self):
        import tunnel_manager
        status = tunnel_manager.get_status()
        assert status["ngrok"]["active"] is False
        assert status["chisel"]["active"] is False

    def test_configure_empty_config(self):
        """Empty config should stop any running tunnels and not start new ones."""
        import tunnel_manager
        result = tunnel_manager.configure_tunnels({})
        assert result["status"] == "ok"
        assert result["ngrok"] is False
        assert result["chisel"] is False

    def test_configure_empty_strings(self):
        """Config with empty strings should behave like empty config."""
        import tunnel_manager
        result = tunnel_manager.configure_tunnels({
            "ngrokAuthtoken": "",
            "chiselServerUrl": "",
            "chiselAuth": "",
        })
        assert result["status"] == "ok"
        assert result["ngrok"] is False
        assert result["chisel"] is False

    def test_kill_process_none(self):
        """Killing None process should not raise."""
        import tunnel_manager
        tunnel_manager._kill_process(None, "test")  # Should not raise

    def test_kill_process_already_dead(self):
        """Killing an already-terminated process should not raise."""
        import tunnel_manager
        # Create a process that exits immediately
        proc = subprocess.Popen(["true"])
        proc.wait()
        tunnel_manager._kill_process(proc, "test")  # Should not raise

    def test_status_after_dead_process(self):
        """Status should report inactive for a process that has exited."""
        import tunnel_manager
        proc = subprocess.Popen(["true"])
        proc.wait()
        tunnel_manager._ngrok_proc = proc
        status = tunnel_manager.get_status()
        assert status["ngrok"]["active"] is False
        assert status["ngrok"]["pid"] == proc.pid


class TestTunnelManagerHTTP:
    """Test the HTTP server endpoints."""

    @pytest.fixture(autouse=True)
    def start_server(self):
        """Start tunnel_manager HTTP server on a test port."""
        import tunnel_manager

        # Reset state
        tunnel_manager._ngrok_proc = None
        tunnel_manager._chisel_proc = None

        # Use a different port to avoid conflicts
        test_port = 18015
        tunnel_manager.PORT = test_port
        from http.server import HTTPServer
        server = HTTPServer(("127.0.0.1", test_port), tunnel_manager.TunnelHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        self.base_url = f"http://127.0.0.1:{test_port}"

        yield

        server.shutdown()

    def _get(self, path: str) -> tuple[int, dict]:
        req = urllib.request.Request(f"{self.base_url}{path}")
        try:
            resp = urllib.request.urlopen(req, timeout=5)
            return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def _post(self, path: str, data: dict) -> tuple[int, dict]:
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req, timeout=5)
            return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_health_endpoint(self):
        status, body = self._get("/health")
        assert status == 200
        assert body["status"] == "ok"

    def test_status_endpoint_initial(self):
        status, body = self._get("/tunnel/status")
        assert status == 200
        assert body["ngrok"]["active"] is False
        assert body["chisel"]["active"] is False

    def test_configure_empty(self):
        status, body = self._post("/tunnel/configure", {})
        assert status == 200
        assert body["status"] == "ok"
        assert body["ngrok"] is False
        assert body["chisel"] is False

    def test_configure_empty_strings(self):
        status, body = self._post("/tunnel/configure", {
            "ngrokAuthtoken": "",
            "chiselServerUrl": "",
            "chiselAuth": "",
        })
        assert status == 200
        assert body["ngrok"] is False
        assert body["chisel"] is False

    def test_configure_invalid_json(self):
        """POST with invalid JSON should return 400."""
        body = b"not json"
        req = urllib.request.Request(
            f"{self.base_url}/tunnel/configure",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req, timeout=5)
            status = resp.status
            data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            status = e.code
            data = json.loads(e.read())
        assert status == 400
        assert "error" in data

    def test_404_on_unknown_path(self):
        status, body = self._get("/unknown")
        assert status == 404

    def test_status_reflects_configure(self):
        """After configure with empty, status should show no tunnels."""
        self._post("/tunnel/configure", {"ngrokAuthtoken": "", "chiselServerUrl": ""})
        status, body = self._get("/tunnel/status")
        assert body["ngrok"]["active"] is False
        assert body["chisel"]["active"] is False


class TestSettingsFieldConsistency:
    """Verify field names are consistent across the stack."""

    def test_prisma_fields_match_api_fields(self):
        """Check that the Prisma schema UserSettings fields match what the API expects."""
        schema_path = os.path.join(
            os.path.dirname(__file__), '..', 'webapp', 'prisma', 'schema.prisma'
        )
        with open(schema_path) as f:
            content = f.read()

        # Extract UserSettings model fields
        in_model = False
        prisma_fields = set()
        for line in content.split('\n'):
            if 'model UserSettings' in line:
                in_model = True
                continue
            if in_model and line.strip().startswith('}'):
                break
            if in_model and '@map(' in line:
                # Extract field name (first word after whitespace)
                field = line.strip().split()[0]
                if field and not field.startswith('//') and not field.startswith('@@'):
                    prisma_fields.add(field)

        expected_settings_fields = {
            'id', 'userId', 'user',
            'tavilyApiKey', 'shodanApiKey', 'serpApiKey', 'nvdApiKey',
            'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth',
            'createdAt', 'updatedAt',
        }

        # All expected fields should be in Prisma schema
        for field in ['nvdApiKey', 'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth']:
            assert field in prisma_fields, f"Field '{field}' missing from Prisma UserSettings model"

    def test_api_route_fields_array(self):
        """Check the settings API route handles all 7 user-configurable fields."""
        route_path = os.path.join(
            os.path.dirname(__file__), '..', 'webapp', 'src', 'app', 'api',
            'users', '[id]', 'settings', 'route.ts'
        )
        with open(route_path) as f:
            content = f.read()

        expected_fields = [
            'tavilyApiKey', 'shodanApiKey', 'serpApiKey', 'nvdApiKey',
            'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth',
        ]
        for field in expected_fields:
            assert field in content, f"Field '{field}' missing from settings API route"

    def test_tunnel_config_route_exists(self):
        """Check the global tunnel-config route file exists."""
        route_path = os.path.join(
            os.path.dirname(__file__), '..', 'webapp', 'src', 'app', 'api',
            'global', 'tunnel-config', 'route.ts'
        )
        assert os.path.exists(route_path), "tunnel-config route.ts does not exist"

        with open(route_path) as f:
            content = f.read()
        for field in ['ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth']:
            assert field in content, f"Field '{field}' missing from tunnel-config route"

    def test_frontend_settings_interface(self):
        """Check the frontend UserSettings interface has all fields."""
        page_path = os.path.join(
            os.path.dirname(__file__), '..', 'webapp', 'src', 'app',
            'settings', 'page.tsx'
        )
        with open(page_path) as f:
            content = f.read()

        expected_fields = [
            'tavilyApiKey', 'shodanApiKey', 'serpApiKey', 'nvdApiKey',
            'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth',
        ]
        for field in expected_fields:
            assert field in content, f"Field '{field}' missing from settings page.tsx"

    def test_no_env_var_reads_for_migrated_vars(self):
        """Ensure no code still reads the 4 migrated variables from environment."""
        import re

        # Patterns that indicate reading from env
        patterns = [
            r'os\.(environ|getenv).*NVD_API_KEY',
            r'os\.(environ|getenv).*NGROK_AUTHTOKEN',
            r'os\.(environ|getenv).*CHISEL_SERVER_URL',
            r'os\.(environ|getenv).*CHISEL_AUTH',
        ]

        # Directories to scan (Python source code)
        scan_dirs = [
            os.path.join(os.path.dirname(__file__), '..', 'agentic'),
            os.path.join(os.path.dirname(__file__), '..', 'recon_orchestrator'),
        ]

        violations = []
        for scan_dir in scan_dirs:
            if not os.path.isdir(scan_dir):
                continue
            for root, dirs, files in os.walk(scan_dir):
                for fname in files:
                    if not fname.endswith('.py'):
                        continue
                    fpath = os.path.join(root, fname)
                    with open(fpath) as f:
                        content = f.read()
                    for pattern in patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            violations.append(f"{fpath}: still reads env var matching {pattern}")

        assert not violations, f"Found env var reads that should be removed:\n" + "\n".join(violations)

    def test_docker_compose_no_migrated_env_vars(self):
        """Ensure docker-compose.yml no longer references the 4 migrated variables."""
        compose_path = os.path.join(
            os.path.dirname(__file__), '..', 'docker-compose.yml'
        )
        with open(compose_path) as f:
            content = f.read()

        for var in ['NVD_API_KEY', 'NGROK_AUTHTOKEN', 'CHISEL_SERVER_URL', 'CHISEL_AUTH']:
            assert var not in content, f"docker-compose.yml still references ${var}"

    def test_env_example_deleted(self):
        """Ensure .env.example no longer exists."""
        env_example = os.path.join(os.path.dirname(__file__), '..', '.env.example')
        assert not os.path.exists(env_example), ".env.example should have been deleted"

    def test_recon_project_settings_no_env_fallback(self):
        """Ensure recon project_settings.py no longer falls back to NVD_API_KEY env var."""
        settings_path = os.path.join(
            os.path.dirname(__file__), '..', 'recon', 'project_settings.py'
        )
        with open(settings_path) as f:
            content = f.read()
        assert "os.getenv('NVD_API_KEY'" not in content, \
            "recon/project_settings.py still has os.getenv('NVD_API_KEY') fallback"

    def test_vuln_scan_passes_nvd_api_key(self):
        """Ensure vuln_scan.py passes nvd_api_key to run_cve_lookup."""
        vuln_path = os.path.join(
            os.path.dirname(__file__), '..', 'recon', 'vuln_scan.py'
        )
        with open(vuln_path) as f:
            content = f.read()
        assert 'nvd_api_key=NVD_API_KEY' in content, \
            "vuln_scan.py does not pass nvd_api_key to run_cve_lookup()"

    def test_orchestrator_no_load_dotenv(self):
        """Ensure agentic/orchestrator.py no longer calls load_dotenv()."""
        orch_path = os.path.join(
            os.path.dirname(__file__), '..', 'agentic', 'orchestrator.py'
        )
        with open(orch_path) as f:
            content = f.read()
        assert 'load_dotenv' not in content, \
            "orchestrator.py still references load_dotenv"

    def test_agent_behaviour_section_no_dotenv_reference(self):
        """Ensure AgentBehaviourSection.tsx no longer references .env."""
        section_path = os.path.join(
            os.path.dirname(__file__), '..', 'webapp', 'src', 'components',
            'projects', 'ProjectForm', 'sections', 'AgentBehaviourSection.tsx'
        )
        with open(section_path) as f:
            content = f.read()
        # Should reference Global Settings, not .env
        assert 'in .env' not in content, \
            "AgentBehaviourSection.tsx still references '.env'"
        assert 'Global Settings' in content, \
            "AgentBehaviourSection.tsx should reference 'Global Settings'"
