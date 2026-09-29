"""Data model for A2A Agent Cards and discovery results.

Mirrors the fields of the A2A protocol's Agent Card (as served from
``/.well-known/agent-card.json``) that matter for threat analysis, without
requiring the full A2A SDK as a dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Skill:
    id: str
    name: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Skill":
        return cls(
            id=str(data.get("id", "")),
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            tags=list(data.get("tags", []) or []),
        )


@dataclass
class AgentCard:
    url: str
    name: str = ""
    description: str = ""
    version: str = ""
    provider: dict[str, Any] | None = None
    capabilities: dict[str, Any] = field(default_factory=dict)
    security_schemes: dict[str, Any] = field(default_factory=dict)
    security: list[Any] = field(default_factory=list)
    skills: list[Skill] = field(default_factory=list)
    supports_authenticated_extended_card: bool = False
    default_input_modes: list[str] = field(default_factory=list)
    default_output_modes: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentCard":
        return cls(
            url=str(data.get("url", "")),
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            version=str(data.get("version", "")),
            provider=data.get("provider"),
            capabilities=dict(data.get("capabilities", {}) or {}),
            security_schemes=dict(data.get("securitySchemes", {}) or {}),
            security=list(data.get("security", []) or []),
            skills=[Skill.from_dict(s) for s in data.get("skills", []) or []],
            supports_authenticated_extended_card=bool(
                data.get("supportsAuthenticatedExtendedCard", False)
            ),
            default_input_modes=list(data.get("defaultInputModes", []) or []),
            default_output_modes=list(data.get("defaultOutputModes", []) or []),
            raw=data,
        )


@dataclass
class DiscoveredAgent:
    source_url: str
    reachable: bool
    card: AgentCard | None = None
    well_known_path: str | None = None
    error: str | None = None
    source_format: str = "a2a"  # "a2a" | "openapi"
