"""Capabilities both session agents (tester, reviewer) share for talking to the model (PLAN §9, #209)."""

from typing import Any

from pydantic_ai.capabilities import AgentCapability, Caching, RetryOnModelErrors
from pydantic_ai_harness.repair_tool_arguments import RepairToolArguments

# Prompt caching: instructions, tool schemas and the whole history are resent every turn, so a cache hit is
# most of the input cost of a long session. Retry: transient provider errors (rate limit, overload, 5xx,
# connection) wait and retry the same model instead of ending the operator's session. Repair: smaller models
# emit malformed tool-call JSON; it is repaired before schema validation, which (and every scope gate) still runs.
# The one-shot search agent takes none of these: a single request has nothing to cache or repair.
MODEL_CAPABILITIES: tuple[AgentCapability[Any], ...] = (Caching(), RetryOnModelErrors(), RepairToolArguments())
