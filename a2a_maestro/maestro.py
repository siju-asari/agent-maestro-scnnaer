"""MAESTRO threat modeling framework primitives.

MAESTRO (Multi-Agent Environment, Security, Threat, Risk, and Outcome), from
the Cloud Security Alliance, structures agentic-AI threats across seven
layers. This module defines those layers and the severity scale used to
score findings; :mod:`a2a_maestro.analyzer` maps discovered agent
capabilities onto them.
"""

from __future__ import annotations

from enum import IntEnum


class MaestroLayer:
    L1_FOUNDATION_MODELS = "L1: Foundation Models"
    L2_DATA_OPERATIONS = "L2: Data Operations"
    L3_AGENT_FRAMEWORKS = "L3: Agent Frameworks"
    L4_DEPLOYMENT_INFRASTRUCTURE = "L4: Deployment & Infrastructure"
    L5_EVALUATION_OBSERVABILITY = "L5: Evaluation & Observability"
    L6_SECURITY_COMPLIANCE = "L6: Security & Compliance"
    L7_AGENT_ECOSYSTEM = "L7: Agent Ecosystem"

    ORDER = (
        L1_FOUNDATION_MODELS,
        L2_DATA_OPERATIONS,
        L3_AGENT_FRAMEWORKS,
        L4_DEPLOYMENT_INFRASTRUCTURE,
        L5_EVALUATION_OBSERVABILITY,
        L6_SECURITY_COMPLIANCE,
        L7_AGENT_ECOSYSTEM,
    )


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class Finding:
    __slots__ = (
        "agent_url",
        "agent_name",
        "layer",
        "severity",
        "title",
        "description",
        "evidence",
        "recommendation",
    )

    def __init__(
        self,
        *,
        agent_url: str,
        agent_name: str,
        layer: str,
        severity: Severity,
        title: str,
        description: str,
        evidence: str = "",
        recommendation: str = "",
    ) -> None:
        self.agent_url = agent_url
        self.agent_name = agent_name
        self.layer = layer
        self.severity = severity
        self.title = title
        self.description = description
        self.evidence = evidence
        self.recommendation = recommendation

    def to_dict(self) -> dict:
        return {
            "agent_url": self.agent_url,
            "agent_name": self.agent_name,
            "layer": self.layer,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
