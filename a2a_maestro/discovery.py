"""A2A agent discovery.

Implements client-side discovery per the A2A protocol's Agent Card mechanism:
each agent is expected to publish a JSON document describing its identity,
capabilities and skills at a well-known path. This module probes candidate
base URLs for that document and parses whatever it finds, without assuming
any particular agent framework is on the other end.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from .blind_discovery import discover_blind_agent
from .models import AgentCard, DiscoveredAgent
from .openapi_discovery import discover_openapi_agent

# Current A2A spec path first, legacy path as a fallback for older agents.
WELL_KNOWN_PATHS = (
    "/.well-known/agent-card.json",
    "/.well-known/agent.json",
)

DEFAULT_TIMEOUT = 3.0

PROTOCOLS = ("auto", "a2a", "openapi", "blind")


def _fetch_json(
    url: str,
    timeout: float,
    headers: dict[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> dict:
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(  # noqa: S310 (local/user-directed URLs only)
        req, timeout=timeout, context=ssl_context
    ) as resp:
        raw = resp.read()
    return json.loads(raw)


def discover_a2a_agent(
    base_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> DiscoveredAgent:
    """Probe a single base URL for an A2A agent card."""
    base_url = base_url.rstrip("/")
    last_error: str | None = None
    for path in WELL_KNOWN_PATHS:
        url = f"{base_url}{path}"
        try:
            data = _fetch_json(url, timeout, headers, ssl_context)
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code} at {path}"
            continue
        except urllib.error.URLError as exc:
            last_error = f"unreachable: {exc.reason}"
            continue
        except (TimeoutError, json.JSONDecodeError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            continue

        card = AgentCard.from_dict(data)
        if not card.url:
            card = replace(card, url=base_url)
        return DiscoveredAgent(
            source_url=base_url, reachable=True, card=card, well_known_path=path, source_format="a2a"
        )

    return DiscoveredAgent(source_url=base_url, reachable=False, error=last_error, source_format="a2a")


def discover_agent(
    base_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    protocol: str = "auto",
    headers: dict[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
    probe_message: str | None = None,
) -> DiscoveredAgent:
    """Probe a single base URL, trying the requested protocol(s).

    ``protocol="auto"`` tries A2A's agent card first and falls back to
    OpenAPI/Swagger if no agent card is found, so a mixed fleet of A2A and
    plain-REST services can be scanned in one pass. ``headers`` (e.g. an
    ``Authorization`` bearer token) are sent on every discovery request.

    ``protocol="blind"`` is never tried by "auto" -- it performs a real
    invocation of the target (side effects included), so it must be
    requested explicitly.
    """
    if protocol not in PROTOCOLS:
        raise ValueError(f"unknown protocol {protocol!r}, expected one of {PROTOCOLS}")

    if protocol == "a2a":
        return discover_a2a_agent(base_url, timeout, headers, ssl_context)
    if protocol == "openapi":
        return discover_openapi_agent(base_url, timeout, headers, ssl_context)
    if protocol == "blind":
        kwargs = {"probe_message": probe_message} if probe_message else {}
        return discover_blind_agent(base_url, timeout, headers, ssl_context, **kwargs)

    result = discover_a2a_agent(base_url, timeout, headers, ssl_context)
    if result.reachable:
        return result
    return discover_openapi_agent(base_url, timeout, headers, ssl_context)


def discover_many(
    base_urls: list[str],
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = 8,
    protocol: str = "auto",
    headers: dict[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
    probe_message: str | None = None,
) -> list[DiscoveredAgent]:
    """Probe multiple base URLs concurrently."""
    if not base_urls:
        return []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(base_urls))) as pool:
        return list(
            pool.map(
                lambda u: discover_agent(u, timeout, protocol, headers, ssl_context, probe_message),
                base_urls,
            )
        )


def local_port_range_targets(
    host: str, port_start: int, port_end: int, scheme: str = "http"
) -> list[str]:
    """Build candidate base URLs for a localhost port range.

    Intentionally scoped to loopback-style discovery of a local simulated
    environment rather than arbitrary network scanning.
    """
    return [f"{scheme}://{host}:{p}" for p in range(port_start, port_end + 1)]
