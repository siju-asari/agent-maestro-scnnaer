""""Blind" discovery: probe an agent that exposes no metadata endpoint at all.

Some deployments (e.g. a proprietary gateway with a single
``POST .../run_streamed``-style invoke route) publish neither an A2A agent
card nor an OpenAPI spec. There is nothing to passively discover -- the only
way to learn anything about the agent is to actually invoke it once with a
benign message and see what its response leaks.

This module POSTs a single probe message to an invoke endpoint, parses a
Server-Sent-Events (or plain JSON) response, and normalizes whatever
metadata it can extract (model identity, internal agent/node graph, leaked
chain-of-thought/reasoning) into the same :class:`AgentCard` shape used
elsewhere, stashing the extracted signals under ``card.raw["blind_probe"]``
for the dedicated rules in :mod:`a2a_maestro.analyzer` to inspect.

This performs a real invocation with real side effects (LLM calls, any
tools the agent is wired to) -- only point it at a target you're authorized
to run against.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

from .models import AgentCard, DiscoveredAgent, Skill

DEFAULT_TIMEOUT = 30.0
DEFAULT_PROBE_MESSAGE = "hi"

_TELEMETRY_KEYS = ("run_id", "thread_id", "agentId", "parent_ids", "invocationId")
_REASONING_KEYS = ("reasoning", "reasoning_content", "chain_of_thought")


def _parse_sse(raw: bytes) -> list[dict]:
    """Parse a text/event-stream body into a list of decoded `data:` payloads."""
    text = raw.decode("utf-8", errors="replace")
    events: list[dict] = []
    for block in text.split("\n\n"):
        data_lines = [line[len("data:") :].strip() for line in block.splitlines() if line.startswith("data:")]
        if not data_lines:
            continue
        payload = "\n".join(data_lines)
        try:
            events.append(json.loads(payload))
        except json.JSONDecodeError:
            continue
    return events


def _find_values(obj, keys: tuple[str, ...], found: dict[str, list]) -> None:
    """Recursively collect values for any of `keys` anywhere in a nested dict/list."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and v not in (None, "", [], {}):
                found.setdefault(k, []).append(v)
            _find_values(v, keys, found)
    elif isinstance(obj, list):
        for item in obj:
            _find_values(item, keys, found)


def _extract_signals(events: list[dict]) -> dict:
    telemetry: dict[str, list] = {}
    reasoning: dict[str, list] = {}
    agent_names: set[str] = set()
    node_names: set[str] = set()
    model_names: set[str] = set()
    model_providers: set[str] = set()
    tool_calls: set[str] = set()
    final_text = ""

    for evt in events:
        _find_values(evt, _TELEMETRY_KEYS, telemetry)
        _find_values(evt, _REASONING_KEYS, reasoning)

        found_agent: dict[str, list] = {}
        _find_values(evt, ("agentName",), found_agent)
        agent_names.update(str(v) for v in found_agent.get("agentName", []))

        found_node: dict[str, list] = {}
        _find_values(evt, ("nodeName",), found_node)
        node_names.update(str(v) for v in found_node.get("nodeName", []))

        found_model: dict[str, list] = {}
        _find_values(evt, ("model_name",), found_model)
        model_names.update(str(v) for v in found_model.get("model_name", []))
        found_provider: dict[str, list] = {}
        _find_values(evt, ("model_provider",), found_provider)
        model_providers.update(str(v) for v in found_provider.get("model_provider", []))

        found_tools: dict[str, list] = {}
        _find_values(evt, ("tool_calls",), found_tools)
        for call_list in found_tools.get("tool_calls", []):
            if isinstance(call_list, list):
                for call in call_list:
                    if isinstance(call, dict) and call.get("name"):
                        tool_calls.add(str(call["name"]))

        found_content: dict[str, list] = {}
        _find_values(evt, ("content",), found_content)
        for c in found_content.get("content", []):
            if isinstance(c, str) and len(c) > len(final_text):
                final_text = c

    # Different frameworks reuse "reasoning" for a full string, a streamed
    # token-count, or a structured object -- only real text counts as a leak.
    reasoning_sample = ""
    full_strings = [v for v in reasoning.get("reasoning", []) if isinstance(v, str) and v.strip()]
    if full_strings:
        reasoning_sample = max(full_strings, key=len)
    if not reasoning_sample:
        chunks = [v for v in reasoning.get("reasoning_content", []) if isinstance(v, str)]
        reasoning_sample = "".join(chunks)
    if not reasoning_sample:
        full_strings = [v for v in reasoning.get("chain_of_thought", []) if isinstance(v, str) and v.strip()]
        if full_strings:
            reasoning_sample = max(full_strings, key=len)
    reasoning_sample = reasoning_sample.strip()[:400]

    return {
        "telemetry_leaked": bool(telemetry),
        "telemetry_fields_seen": sorted(telemetry.keys()),
        "reasoning_leaked": bool(reasoning_sample),
        "reasoning_sample": reasoning_sample,
        "agent_graph_nodes": sorted(agent_names | node_names),
        "model_name": next(iter(model_names), ""),
        "model_provider": next(iter(model_providers), ""),
        "tool_calls_seen": sorted(tool_calls),
        "final_text_sample": final_text[:300],
    }


def discover_blind_agent(
    invoke_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
    probe_message: str = DEFAULT_PROBE_MESSAGE,
) -> DiscoveredAgent:
    """POST a single benign message to `invoke_url` and analyze the response."""
    body = json.dumps({"messages": [{"role": "user", "content": probe_message}]}).encode("utf-8")
    req_headers = {"Content-Type": "application/json", "Accept": "text/event-stream, application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(invoke_url, data=body, headers=req_headers, method="POST")

    try:
        with urllib.request.urlopen(  # noqa: S310 (user-directed URL, explicit blind-invoke mode)
            req, timeout=timeout, context=ssl_context
        ) as resp:
            raw = resp.read()
            content_type = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        return DiscoveredAgent(
            source_url=invoke_url,
            reachable=False,
            error=f"HTTP {exc.code}: {exc.read()[:200]!r}",
            source_format="blind",
        )
    except urllib.error.URLError as exc:
        return DiscoveredAgent(
            source_url=invoke_url, reachable=False, error=f"unreachable: {exc.reason}", source_format="blind"
        )

    if "text/event-stream" in content_type or raw.lstrip().startswith(b"event:") or raw.lstrip().startswith(b"data:"):
        events = _parse_sse(raw)
    else:
        try:
            parsed = json.loads(raw)
            events = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            events = []

    signals = _extract_signals(events)

    skills = [
        Skill(id=n, name=n, description=f"Observed agent/node in execution graph: {n}", tags=["blind-probe"])
        for n in signals["agent_graph_nodes"]
    ] + [
        Skill(id=t, name=t, description=f"Tool invoked during probe run: {t}", tags=["blind-probe", "tool"])
        for t in signals["tool_calls_seen"]
    ]

    card = AgentCard(
        url=invoke_url,
        name=signals["agent_graph_nodes"][0] if signals["agent_graph_nodes"] else "",
        description=f"Blind-probed via a single invocation; no discoverable metadata endpoint existed. "
        f"Sample response: {signals['final_text_sample']!r}",
        version="",
        provider={"model_provider": signals["model_provider"]} if signals["model_provider"] else None,
        capabilities={"streaming": "event-stream" in content_type},
        security_schemes={"bearer": {"type": "http", "scheme": "bearer"}} if headers else {},
        security=[{"bearer": []}] if headers else [],
        skills=skills,
        raw={"blind_probe": signals},
    )
    return DiscoveredAgent(source_url=invoke_url, reachable=True, card=card, source_format="blind")
