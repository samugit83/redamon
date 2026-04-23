"""Load CypherFix settings from the webapp API."""

import httpx
import logging
import os

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")
INTERNAL_HEADERS = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}


async def load_cypherfix_settings(project_id: str) -> dict:
    """Fetch cypherfix settings from webapp API, including user LLM providers."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{WEBAPP_API_URL}/api/projects/{project_id}", headers=INTERNAL_HEADERS)
            resp.raise_for_status()
            project = resp.json()

            settings = {
                "github_token": project.get("cypherfixGithubToken", ""),
                "default_repo": project.get("cypherfixDefaultRepo", ""),
                "default_branch": project.get("cypherfixDefaultBranch", "main"),
                "branch_prefix": project.get("cypherfixBranchPrefix", "cypherfix/"),
                "require_approval": project.get("cypherfixRequireApproval", True),
                "llm_model": project.get("cypherfixLlmModel", "") or project.get("agentOpenaiModel", ""),
            }

            # Fetch user LLM providers for key resolution
            user_id = project.get("userId", "")
            if user_id:
                try:
                    prov_resp = await client.get(
                        f"{WEBAPP_API_URL}/api/users/{user_id}/llm-providers",
                        params={"internal": "true"},
                        headers=INTERNAL_HEADERS,
                    )
                    if prov_resp.status_code == 200:
                        settings["user_llm_providers"] = prov_resp.json()

                    us_resp = await client.get(
                        f"{WEBAPP_API_URL}/api/users/{user_id}/settings",
                        params={"internal": "true"},
                        headers=INTERNAL_HEADERS,
                    )
                    if us_resp.status_code == 200:
                        settings["user_settings"] = us_resp.json()
                except Exception as e2:
                    logger.warning(f"Failed to fetch user providers for cypherfix: {e2}")

            # Resolve custom LLM config if model starts with custom/
            model = settings["llm_model"]
            if model.startswith("custom/") and settings.get("user_llm_providers"):
                config_id = model[len("custom/"):]
                for p in settings["user_llm_providers"]:
                    if p.get("id") == config_id:
                        settings["custom_llm_config"] = p
                        break

            return settings
    except Exception as e:
        logger.error(f"Failed to load cypherfix settings: {e}")
        return {}
