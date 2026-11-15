"""The per-user model each AI feature runs on ("Models by feature").

Mirror of the webapp registry `webapp/src/lib/llmFeatures.ts`. The value lives
in `UserSettings.featureModels`, a JSON object keyed by these ids, and is read
from the settings of the user the feature runs FOR: the effective user for a
browser-started feature, the project owner for triage and CodeFix. It is never
taken from a request body, so a client cannot pick a model the user never chose.

A feature with no model has none: there is no fallback to the project's agent
model, the agent's shared LLM or a default id, because each of those can belong
to another user or name a provider this user has no key for.
"""

from __future__ import annotations

FEATURE_IDS = (
    "roe_parse",
    "preset_generator",
    "triage",
    "codefix",
    "command_whisperer",
    "tradecraft_section_picker",
    "report_narratives",
    "multi_mute",
    "skill_metadata",
    "navigator",
)


def feature_model(user_settings, feature_id: str) -> str:
    """The saved model id for `feature_id`, or "" when unset, unknown or malformed."""
    if feature_id not in FEATURE_IDS or not isinstance(user_settings, dict):
        return ""
    models = user_settings.get("featureModels")
    if not isinstance(models, dict):
        return ""
    value = models.get(feature_id)
    return value.strip() if isinstance(value, str) else ""
