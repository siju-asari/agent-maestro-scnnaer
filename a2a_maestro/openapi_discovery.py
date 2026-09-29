"""OpenAPI/Swagger discovery for non-A2A REST services.

Plenty of "agents" in the wild are just a REST API with no A2A agent card
at all. This module fetches a service's OpenAPI/Swagger document (OpenAPI
3.x or Swagger 2.0) and normalizes it into the same :class:`AgentCard`
shape the A2A pipeline produces:

- ``info.title/description/version``      -> name/description/version
- each path+method operation               -> one Skill (id, description, tags)
- ``components.securitySchemes``/``securityDefinitions`` -> security_schemes
- top-level ``security``                   -> security

Once normalized, the existing MAESTRO rules in :mod:`a2a_maestro.analyzer`
(missing auth, dangerous-keyword skills, missing provenance, ...) run
against it unchanged -- no OpenAPI-specific rules needed.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

from .models import AgentCard, DiscoveredAgent, Skill

# Common locations services publish their spec at. Tried in order.
OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/openapi/v1.json",
)

DEFAULT_TIMEOUT = 3.0

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")


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
        return json.loads(resp.read())


def _security_schemes(spec: dict) -> dict:
    schemes = (spec.get("components") or {}).get("securitySchemes")
    if schemes:
        return schemes
    return spec.get("securityDefinitions") or {}  # Swagger 2.0


def _provider_from_info(info: dict) -> dict | None:
    contact = info.get("contact") or {}
    if contact.get("name") or contact.get("url"):
        return {"organization": contact.get("name", ""), "url": contact.get("url", "")}
    return None


def _skills_from_paths(spec: dict) -> list[Skill]:
    skills: list[Skill] = []
    for path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            op_id = op.get("operationId") or f"{method.upper()} {path}"
            skills.append(
                Skill(
                    id=op_id,
                    name=op.get("summary", "") or op_id,
                    description=op.get("description", "") or op.get("summary", ""),
                    tags=list(op.get("tags", []) or []) + [method.lower(), path],
                )
            )
    return skills


def discover_openapi_agent(
    base_url: str,
    timeout: float = DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> DiscoveredAgent:
    """Probe a single base URL for an OpenAPI/Swagger document."""
    base_url = base_url.rstrip("/")
    last_error: str | None = None
    for path in OPENAPI_PATHS:
        url = f"{base_url}{path}"
        try:
            spec = _fetch_json(url, timeout, headers, ssl_context)
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code} at {path}"
            continue
        except urllib.error.URLError as exc:
            last_error = f"unreachable: {exc.reason}"
            continue
        except (TimeoutError, json.JSONDecodeError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            continue

        if "openapi" not in spec and "swagger" not in spec:
            last_error = f"{path} did not look like an OpenAPI/Swagger document"
            continue

        info = spec.get("info") or {}
        card = AgentCard(
            url=base_url,
            name=info.get("title", ""),
            description=info.get("description", ""),
            version=info.get("version", ""),
            provider=_provider_from_info(info),
            capabilities={},
            security_schemes=_security_schemes(spec),
            security=list(spec.get("security", []) or []),
            skills=_skills_from_paths(spec),
            supports_authenticated_extended_card=False,
            default_input_modes=["application/json"],
            default_output_modes=["application/json"],
            raw=spec,
        )
        return DiscoveredAgent(
            source_url=base_url,
            reachable=True,
            card=card,
            well_known_path=path,
            source_format="openapi",
        )

    return DiscoveredAgent(
        source_url=base_url, reachable=False, error=last_error, source_format="openapi"
    )
