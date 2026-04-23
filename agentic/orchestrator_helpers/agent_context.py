"""Agent attribution context helper.

Resolves (agent_id, agent_name, fireteam_id) from either an AgentState
(root agent) or a FireteamMemberState (fireteam member) so that every
downstream write (Neo4j, Postgres, streaming) carries consistent
attribution without the caller having to know which state shape it holds.
"""

from typing import Mapping, Any


def get_agent_context(state: Mapping[str, Any]) -> dict:
    """Return attribution dict: {agent_id, agent_name, fireteam_id}.

    A FireteamMemberState is identified by presence of "member_id" in state.
    Every other state shape is treated as the root agent.
    """
    # Fireteam member: state was built by fireteam_deploy_node._build_member_state
    if state.get("member_id"):
        return {
            "agent_id": state["member_id"],
            "agent_name": state.get("member_name") or state["member_id"],
            "fireteam_id": state.get("fireteam_id"),
        }

    # Root agent
    return {
        "agent_id": "root",
        "agent_name": "root",
        "fireteam_id": state.get("_fireteam_id"),
    }
