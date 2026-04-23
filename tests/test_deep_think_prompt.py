"""
Unit tests for Deep Think prompt enrichment.

Validates that the DEEP_THINK_PROMPT template receives all required context
(tunnel/session config, RoE, attack path behavior, phase definitions,
objective history, todo list) and renders correctly.

Run with: python -m pytest tests/test_deep_think_prompt.py -v
"""
import sys
import os
import importlib
from unittest.mock import patch, MagicMock

# Add the agentic directory to path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'agentic'))

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_settings(**overrides):
    """Build a settings dict with sensible defaults, applying overrides."""
    defaults = {
        'LHOST': '10.0.0.1',
        'LPORT': 4444,
        'BIND_PORT_ON_TARGET': None,
        'PAYLOAD_USE_HTTPS': False,
        'NGROK_TUNNEL_ENABLED': False,
        'CHISEL_TUNNEL_ENABLED': False,
        'POST_EXPL_PHASE_TYPE': 'statefull',
        'MAX_ITERATIONS': 100,
        'ROE_ENABLED': False,
        'DEEP_THINK_ENABLED': True,
        'ACTIVATE_POST_EXPL_PHASE': True,
        'STEALTH_MODE': False,
        'TOOL_OUTPUT_MAX_CHARS': 20000,
    }
    defaults.update(overrides)
    return defaults


@pytest.fixture(autouse=True)
def mock_project_settings():
    """Mock project_settings.get_setting everywhere it's imported."""
    settings = _make_settings()
    getter = lambda k, d=None: settings.get(k, d)
    # Patch in both the source module and any module that did 'from project_settings import get_setting'
    with patch('project_settings.get_setting', side_effect=getter), \
         patch('utils.get_setting', side_effect=getter):
        yield settings


# ---------------------------------------------------------------------------
# 1. Template renders without KeyError
# ---------------------------------------------------------------------------

class TestDeepThinkTemplateRendering:
    """Verify the DEEP_THINK_PROMPT template accepts all new fields."""

    def test_template_renders_with_all_fields(self):
        from prompts.base import DEEP_THINK_PROMPT
        result = DEEP_THINK_PROMPT.format(
            current_phase="exploitation",
            objective="Exploit CVE-2021-41773",
            attack_path_type="cve_exploit",
            attack_path_behavior="In informational phase: Gather target info.",
            phase_definitions="### Phase Definitions\n**INFORMATIONAL**...",
            iteration=5,
            max_iterations=100,
            target_info='{"ip": "10.0.0.1"}',
            chain_context="Step 1: Nmap scan completed.",
            trigger_reason="Phase transition to exploitation",
            todo_list="1. [ ] Run exploit",
            objective_history="No previous objectives completed.",
            session_config="",
            roe_section="",
        )
        assert "exploitation" in result
        assert "CVE-2021-41773" in result
        assert "Gather target info" in result
        assert "Phase Definitions" in result
        assert "Run exploit" in result
        assert "situation_assessment" in result  # JSON schema still present

    def test_template_renders_with_session_config(self):
        from prompts.base import DEEP_THINK_PROMPT
        session_block = "\n### Pre-Configured Payload Settings\n**Chisel Tunnel: ACTIVE** — handler 1.2.3.4:4444\n"
        result = DEEP_THINK_PROMPT.format(
            current_phase="exploitation",
            objective="Test",
            attack_path_type="cve_exploit",
            attack_path_behavior="Gather info.",
            phase_definitions="Phases...",
            iteration=1,
            max_iterations=100,
            target_info="{}",
            chain_context="None",
            trigger_reason="First iteration",
            todo_list="No tasks.",
            objective_history="None.",
            session_config=session_block,
            roe_section="",
        )
        assert "Chisel Tunnel: ACTIVE" in result
        assert "1.2.3.4:4444" in result

    def test_template_renders_with_roe(self):
        from prompts.base import DEEP_THINK_PROMPT
        roe_block = "\n## RULES OF ENGAGEMENT (MANDATORY)\n**Client:** Acme Corp\n"
        result = DEEP_THINK_PROMPT.format(
            current_phase="exploitation",
            objective="Test",
            attack_path_type="cve_exploit",
            attack_path_behavior="Gather info.",
            phase_definitions="Phases...",
            iteration=1,
            max_iterations=100,
            target_info="{}",
            chain_context="None",
            trigger_reason="First iteration",
            todo_list="No tasks.",
            objective_history="None.",
            session_config="",
            roe_section=roe_block,
        )
        assert "RULES OF ENGAGEMENT" in result
        assert "Acme Corp" in result

    def test_template_renders_empty_optional_sections(self):
        """Empty session_config and roe_section should not break rendering."""
        from prompts.base import DEEP_THINK_PROMPT
        result = DEEP_THINK_PROMPT.format(
            current_phase="informational",
            objective="Recon target",
            attack_path_type="cve_exploit",
            attack_path_behavior="Gather info.",
            phase_definitions="Phases...",
            iteration=1,
            max_iterations=100,
            target_info="{}",
            chain_context="None",
            trigger_reason="First iteration",
            todo_list="No tasks.",
            objective_history="No previous objectives completed.",
            session_config="",
            roe_section="",
        )
        assert "## Your Task" in result
        assert "situation_assessment" in result

    def test_template_missing_field_raises_keyerror(self):
        """Omitting a required field should raise KeyError."""
        from prompts.base import DEEP_THINK_PROMPT
        with pytest.raises(KeyError):
            DEEP_THINK_PROMPT.format(
                current_phase="exploitation",
                objective="Test",
                # missing attack_path_type and others
            )


# ---------------------------------------------------------------------------
# 2. build_attack_path_behavior returns meaningful content
# ---------------------------------------------------------------------------

class TestAttackPathBehavior:
    """Verify build_attack_path_behavior returns content for each path type."""

    def test_cve_exploit(self):
        from prompts.base import build_attack_path_behavior
        result = build_attack_path_behavior("cve_exploit")
        assert "informational" in result.lower()
        assert len(result) > 20

    def test_brute_force(self):
        from prompts.base import build_attack_path_behavior
        result = build_attack_path_behavior("brute_force_credential_guess")
        assert "brute force" in result.lower() or "wordlist" in result.lower()

    def test_denial_of_service(self):
        from prompts.base import build_attack_path_behavior
        result = build_attack_path_behavior("denial_of_service")
        assert "dos" in result.lower() or "denial" in result.lower()

    def test_unknown_path_returns_string(self):
        from prompts.base import build_attack_path_behavior
        result = build_attack_path_behavior("unknown_path")
        assert isinstance(result, str)

    def test_empty_path_returns_string(self):
        from prompts.base import build_attack_path_behavior
        result = build_attack_path_behavior("")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# 3. build_phase_definitions returns expected content
# ---------------------------------------------------------------------------

class TestPhaseDefinitions:
    """Verify phase definitions include all 3 phases."""

    def test_all_phases_present(self):
        from prompts.base import build_phase_definitions
        result = build_phase_definitions()
        assert "INFORMATIONAL" in result
        assert "EXPLOITATION" in result
        assert "POST-EXPLOITATION" in result

    def test_returns_string(self):
        from prompts.base import build_phase_definitions
        assert isinstance(build_phase_definitions(), str)


# ---------------------------------------------------------------------------
# 4. Session config gating logic
# ---------------------------------------------------------------------------

class TestSessionConfigGating:
    """Verify session config is only injected when appropriate."""

    def test_exploitation_statefull_needs_session(self):
        phase = "exploitation"
        is_statefull = True
        attack_path = "cve_exploit"
        needs_session = (
            (phase == "exploitation" and is_statefull)
            or attack_path == "phishing_social_engineering"
        )
        assert needs_session is True

    def test_informational_does_not_need_session(self):
        phase = "informational"
        is_statefull = True
        attack_path = "cve_exploit"
        needs_session = (
            (phase == "exploitation" and is_statefull)
            or attack_path == "phishing_social_engineering"
        )
        assert needs_session is False

    def test_phishing_any_phase_needs_session(self):
        for phase in ["informational", "exploitation", "post_exploitation"]:
            attack_path = "phishing_social_engineering"
            is_statefull = False
            needs_session = (
                (phase == "exploitation" and is_statefull)
                or attack_path == "phishing_social_engineering"
            )
            assert needs_session is True, f"phishing should need session in {phase}"

    def test_exploitation_stateless_no_session(self):
        phase = "exploitation"
        is_statefull = False
        attack_path = "cve_exploit"
        needs_session = (
            (phase == "exploitation" and is_statefull)
            or attack_path == "phishing_social_engineering"
        )
        assert needs_session is False

    def test_post_exploitation_no_session(self):
        phase = "post_exploitation"
        is_statefull = True
        attack_path = "cve_exploit"
        needs_session = (
            (phase == "exploitation" and is_statefull)
            or attack_path == "phishing_social_engineering"
        )
        assert needs_session is False


# ---------------------------------------------------------------------------
# 5. get_session_config_prompt content validation
# ---------------------------------------------------------------------------

class TestSessionConfigContent:
    """Verify get_session_config_prompt returns correct tunnel info."""

    @patch('utils._query_ngrok_tunnel', return_value=None)
    @patch('utils._query_chisel_tunnel', return_value=None)
    def test_reverse_mode_no_tunnel(self, mock_chisel, mock_ngrok):
        """With LHOST/LPORT set and no tunnel, should show reverse mode."""
        from utils import get_session_config_prompt
        result = get_session_config_prompt()
        assert "REVERSE" in result
        assert "10.0.0.1" in result

    @patch('utils._query_chisel_tunnel', return_value={'host': '18.102.183.71', 'port': 4444, 'srv_port': 8080})
    @patch('utils._query_ngrok_tunnel', return_value=None)
    def test_chisel_active(self, mock_ngrok, mock_chisel):
        """With chisel enabled and active, should show chisel tunnel info."""
        settings = _make_settings(CHISEL_TUNNEL_ENABLED=True)
        getter = lambda k, d=None: settings.get(k, d)
        with patch('project_settings.get_setting', side_effect=getter), \
             patch('utils.get_setting', side_effect=getter):
            from utils import get_session_config_prompt
            result = get_session_config_prompt()
            assert "Chisel Tunnel: ACTIVE" in result
            assert "18.102.183.71" in result
            assert "4444" in result

    @patch('utils._query_ngrok_tunnel', return_value={'host': '0.tcp.ngrok.io', 'port': 12345})
    @patch('utils._query_chisel_tunnel', return_value=None)
    def test_ngrok_active(self, mock_chisel, mock_ngrok):
        """With ngrok enabled and active, should show ngrok tunnel info."""
        settings = _make_settings(NGROK_TUNNEL_ENABLED=True)
        getter = lambda k, d=None: settings.get(k, d)
        with patch('project_settings.get_setting', side_effect=getter), \
             patch('utils.get_setting', side_effect=getter):
            from utils import get_session_config_prompt
            result = get_session_config_prompt()
            assert "ngrok Tunnel: ACTIVE" in result
            assert "0.tcp.ngrok.io" in result

    @patch('utils._query_ngrok_tunnel', return_value=None)
    @patch('utils._query_chisel_tunnel', return_value=None)
    def test_no_lhost_no_lport_ask_mode(self, mock_chisel, mock_ngrok):
        """With no LHOST/LPORT/BIND, should return ask mode or not-configured."""
        settings = _make_settings(LHOST='', LPORT=None)
        getter = lambda k, d=None: settings.get(k, d)
        with patch('project_settings.get_setting', side_effect=getter), \
             patch('utils.get_setting', side_effect=getter):
            from utils import get_session_config_prompt
            result = get_session_config_prompt()
            # Should NOT be reverse mode (no LHOST)
            assert "Mode: REVERSE" not in result


# ---------------------------------------------------------------------------
# 6. RoE section gating
# ---------------------------------------------------------------------------

class TestRoEGating:
    """Verify RoE is only injected when enabled."""

    def test_roe_disabled_returns_empty(self):
        from prompts.base import build_roe_prompt_section
        result = build_roe_prompt_section()
        assert result == ""

    def test_roe_enabled_returns_content(self):
        settings = _make_settings(
            ROE_ENABLED=True,
            ROE_CLIENT_NAME='TestCorp',
            ROE_CLIENT_CONTACT_NAME='',
            ROE_CLIENT_CONTACT_EMAIL='',
            ROE_CLIENT_CONTACT_PHONE='',
            ROE_EMERGENCY_CONTACT='',
            ROE_ENGAGEMENT_START_DATE='2026-01-01',
            ROE_ENGAGEMENT_END_DATE='2026-12-31',
            ROE_ENGAGEMENT_TYPE='external',
            ROE_EXCLUDED_HOSTS='',
            ROE_EXCLUDED_PORTS='',
            ROE_ALLOW_DOS=False,
            ROE_ALLOW_SOCIAL_ENGINEERING=False,
            ROE_ALLOW_PHYSICAL_ACCESS=False,
            ROE_ALLOW_ACCOUNT_LOCKOUT=False,
            ROE_ALLOW_PRODUCTION_DISRUPTION=False,
            ROE_CUSTOM_CONSTRAINTS='',
        )
        getter = lambda k, d=None: settings.get(k, d)
        with patch('project_settings.get_setting', side_effect=getter), \
             patch('utils.get_setting', side_effect=getter):
            from prompts.base import build_roe_prompt_section
            result = build_roe_prompt_section()
            assert "RULES OF ENGAGEMENT" in result
            assert "TestCorp" in result


# ---------------------------------------------------------------------------
# 7. Format helpers produce safe strings (skip if pydantic unavailable)
# ---------------------------------------------------------------------------

class TestFormatHelpers:
    """Verify format helpers don't produce strings that break .format()."""

    @pytest.fixture(autouse=True)
    def check_pydantic(self):
        """Skip these tests if pydantic is not installed (runs inside Docker)."""
        try:
            import pydantic
        except ImportError:
            pytest.skip("pydantic not available outside Docker")

    def test_format_todo_list_empty(self):
        from state import format_todo_list
        result = format_todo_list([])
        assert isinstance(result, str)
        assert "No tasks" in result

    def test_format_todo_list_with_items(self):
        from state import format_todo_list
        todos = [
            {"description": "Run nmap scan", "status": "completed", "priority": "high"},
            {"description": "Exploit CVE-2021-41773", "status": "pending", "priority": "high"},
        ]
        result = format_todo_list(todos)
        assert "nmap" in result.lower()
        assert "Exploit" in result

    def test_format_objective_history_empty(self):
        from state import format_objective_history
        result = format_objective_history([])
        assert isinstance(result, str)
        assert "No previous" in result

    def test_format_objective_history_with_items(self):
        from state import format_objective_history
        history = [
            {
                "objective": {"content": "Scan target ports"},
                "success": True,
                "findings": ["Found port 80 open"],
            },
        ]
        result = format_objective_history(history)
        assert "Scan target" in result
        assert "Success" in result or "✓" in result


# ---------------------------------------------------------------------------
# 8. Full prompt assembly integration test
# ---------------------------------------------------------------------------

class TestFullPromptAssembly:
    """Test that the full deep think prompt assembles without errors."""

    @patch('utils._query_chisel_tunnel', return_value={'host': '18.102.183.71', 'port': 4444, 'srv_port': 8080})
    @patch('utils._query_ngrok_tunnel', return_value=None)
    def test_full_assembly_with_chisel(self, mock_ngrok, mock_chisel):
        """Simulate full deep think prompt assembly with chisel active."""
        from prompts.base import (
            DEEP_THINK_PROMPT,
            build_phase_definitions,
            build_attack_path_behavior,
        )

        settings = _make_settings(CHISEL_TUNNEL_ENABLED=True, LHOST='', LPORT=None)
        getter = lambda k, d=None: settings.get(k, d)
        with patch('project_settings.get_setting', side_effect=getter), \
             patch('utils.get_setting', side_effect=getter):
            from utils import get_session_config_prompt

            phase = "exploitation"
            _attack_path = "cve_exploit"
            _is_statefull = True
            _needs_session = (phase == "exploitation" and _is_statefull)

            _session_config = ""
            if _needs_session:
                _sc = get_session_config_prompt()
                if _sc:
                    _session_config = f"\n{_sc}\n"

            _roe_section = ""

            result = DEEP_THINK_PROMPT.format(
                current_phase=phase,
                objective="Exploit CVE-2021-41773 on Apache 2.4.49",
                attack_path_type=_attack_path,
                attack_path_behavior=build_attack_path_behavior(_attack_path),
                phase_definitions=build_phase_definitions(),
                iteration=5,
                max_iterations=100,
                target_info='{"ip": "15.160.68.117", "ports": [8080, 22]}',
                chain_context="Found Apache 2.4.49 on port 8080. CVE confirmed by nuclei.",
                trigger_reason="Phase transition to exploitation — re-evaluating strategy",
                todo_list="1. [ ] Exploit Apache CVE",
                objective_history="No previous objectives completed.",
                session_config=_session_config,
                roe_section=_roe_section,
            )

            assert "exploitation" in result
            assert "CVE-2021-41773" in result
            assert "18.102.183.71" in result
            assert "Chisel Tunnel: ACTIVE" in result
            assert "REVERSE" in result
            assert "INFORMATIONAL" in result
            assert "Exploit Apache CVE" in result
            assert "## Your Task" in result
            assert "situation_assessment" in result

    def test_full_assembly_informational_no_tunnel(self):
        """Informational phase should NOT include tunnel config."""
        from prompts.base import (
            DEEP_THINK_PROMPT,
            build_phase_definitions,
            build_attack_path_behavior,
        )

        phase = "informational"
        _attack_path = "cve_exploit"
        _is_statefull = True
        _needs_session = (phase == "exploitation" and _is_statefull)

        assert _needs_session is False

        result = DEEP_THINK_PROMPT.format(
            current_phase=phase,
            objective="Gather intel on target",
            attack_path_type=_attack_path,
            attack_path_behavior=build_attack_path_behavior(_attack_path),
            phase_definitions=build_phase_definitions(),
            iteration=1,
            max_iterations=100,
            target_info='{"domain": "example.com"}',
            chain_context="No steps yet.",
            trigger_reason="First iteration — establishing initial strategy",
            todo_list="No tasks defined yet.",
            objective_history="No previous objectives completed.",
            session_config="",
            roe_section="",
        )

        assert "Chisel" not in result
        assert "ngrok" not in result
        assert "informational" in result
        assert "## Your Task" in result


# ---------------------------------------------------------------------------
# 9. Verify no format brace collisions
# ---------------------------------------------------------------------------

class TestBraceCollisions:
    """Ensure substituted values with braces don't break .format()."""

    def test_session_config_with_code_blocks(self):
        """Session config contains ``` code blocks with special chars — should not break."""
        from prompts.base import DEEP_THINK_PROMPT
        session_config = """
### Pre-Configured Payload Settings

**Mode: REVERSE**

```
set PAYLOAD windows/meterpreter_reverse_tcp
set LHOST 18.102.183.71
set LPORT 4444
```
"""
        result = DEEP_THINK_PROMPT.format(
            current_phase="exploitation",
            objective="Test",
            attack_path_type="cve_exploit",
            attack_path_behavior="Gather info.",
            phase_definitions="Phases...",
            iteration=1,
            max_iterations=100,
            target_info="{}",
            chain_context="None",
            trigger_reason="Test",
            todo_list="No tasks.",
            objective_history="None.",
            session_config=session_config,
            roe_section="",
        )
        assert "set PAYLOAD" in result
        assert "18.102.183.71" in result

    def test_roe_with_special_characters(self):
        """RoE section with special characters should not break .format()."""
        from prompts.base import DEEP_THINK_PROMPT
        roe = "\n## RULES OF ENGAGEMENT\n**Excluded:** 10.0.0.{1-254} range\n"
        # This should NOT raise — braces in substituted values are safe
        result = DEEP_THINK_PROMPT.format(
            current_phase="exploitation",
            objective="Test",
            attack_path_type="cve_exploit",
            attack_path_behavior="Gather info.",
            phase_definitions="Phases...",
            iteration=1,
            max_iterations=100,
            target_info="{}",
            chain_context="None",
            trigger_reason="Test",
            todo_list="No tasks.",
            objective_history="None.",
            session_config="",
            roe_section=roe,
        )
        assert "10.0.0.{1-254}" in result
