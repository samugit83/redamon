"""LoopChatModel: a LangChain chat model whose answers come from a driver.

Each ``ainvoke`` opens a step in the broker and awaits the driver's answer.
Identity comes from the live run scope of the session, never from the tenant
ContextVars: initialize_node makes the guardrail and classifier calls before
any node sets current_user_id / current_project_id, so those are empty for the
first two steps of every run. A call with no live loop scope fails at once.
"""
from __future__ import annotations

from typing import Any, ClassVar, Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from agent_context import current_llm_purpose, current_log_session_id

from . import LOOP_MODEL_ID, is_loop_llm  # noqa: F401  (re-exported)
from .broker import get_broker
from .errors import LoopModelOutsideRun
from .prompt_doc import last_instruction, to_parts
from .purpose import answer_format

_ZERO_USAGE = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}


class LoopChatModel(BaseChatModel):
    model_name: str = LOOP_MODEL_ID
    is_agent_in_the_loop: ClassVar[bool] = True

    @property
    def _llm_type(self) -> str:
        return "agent-in-the-loop"

    def _generate(self, messages: list[BaseMessage], stop: Optional[list[str]] = None,
                  run_manager: Any = None, **kwargs: Any) -> ChatResult:
        raise NotImplementedError("Agent in the Loop is async only")

    async def _agenerate(self, messages: list[BaseMessage], stop: Optional[list[str]] = None,
                         run_manager: Any = None, **kwargs: Any) -> ChatResult:
        broker = get_broker()
        scope = broker.scope_for_session(current_log_session_id.get())
        if scope is None:
            raise LoopModelOutsideRun()
        label = dict(current_llm_purpose.get())
        purpose = label.pop("purpose", "other")
        rendered = to_parts(messages)
        step = broker.new_step(scope, purpose=purpose, meta=label, messages=rendered,
                               answer_format=answer_format(purpose),
                               last_instruction=last_instruction(rendered))
        await broker.open_step(step, scope)
        text = await broker.await_answer(step)
        metadata = {"loop_step_id": step.id}
        if step.answered_by:
            metadata["answered_by"] = dict(step.answered_by)
        message = AIMessage(content=text, usage_metadata=dict(_ZERO_USAGE),
                            response_metadata=metadata)
        return ChatResult(generations=[ChatGeneration(message=message)])

    # RedAmon spends no tokens on a loop step; the base class would load a
    # GPT-2 tokenizer (the Fireteam member falls back to it when usage is 0).
    def get_num_tokens(self, text: str) -> int:
        return 0

    def get_num_tokens_from_messages(self, messages: list[BaseMessage], tools: Any = None) -> int:
        return 0
