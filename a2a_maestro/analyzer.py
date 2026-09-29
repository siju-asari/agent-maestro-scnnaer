"""Rule-based MAESTRO threat analysis over discovered A2A agent cards.

Each rule inspects an :class:`~a2a_maestro.models.AgentCard` and yields zero
or more :class:`~a2a_maestro.maestro.Finding` objects. Rules are heuristic,
not a formal proof of exploitability — they flag patterns that are worth a
human security review (missing auth, over-broad tool access, unrestricted
orchestration of other agents, etc.), the same categories MAESTRO calls out
per layer.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from .maestro import Finding, MaestroLayer, Severity
from .models import AgentCard, DiscoveredAgent

Rule = Callable[[AgentCard], list[Finding]]


def _keyword_matches(haystack: str, keyword: str) -> bool:
    """Word-boundary match so 'exec' doesn't hit 'execution', 'sql' doesn't hit 'sqlite', etc."""
    return re.search(rf"\b{re.escape(keyword)}\b", haystack) is not None


_DANGEROUS_SKILL_KEYWORDS = {
    "shell": Severity.CRITICAL,
    "exec": Severity.CRITICAL,
    "subprocess": Severity.CRITICAL,
    "eval": Severity.CRITICAL,
    "system": Severity.HIGH,
    "filesystem": Severity.HIGH,
    "file_system": Severity.HIGH,
    "database": Severity.HIGH,
    "sql": Severity.HIGH,
    "admin": Severity.HIGH,
    "delete": Severity.MEDIUM,
    "network": Severity.MEDIUM,
    "pii": Severity.MEDIUM,
    "credential": Severity.CRITICAL,
    "secret": Severity.CRITICAL,
}

_ORCHESTRATION_KEYWORDS = ("orchestrat", "delegate", "multi-agent", "multi_agent", "spawn")

_UNRESTRICTED_PHRASES = ("no restrictions", "full access", "unrestricted", "trusted implicitly")


def _has_security(card: AgentCard) -> bool:
    return bool(card.security) or bool(card.security_schemes)


def rule_missing_authentication(card: AgentCard) -> list[Finding]:
    if _has_security(card):
        return []
    return [
        Finding(
            agent_url=card.url,
            agent_name=card.name or card.url,
            layer=MaestroLayer.L6_SECURITY_COMPLIANCE,
            severity=Severity.HIGH,
            title="Agent card declares no authentication scheme",
            description=(
                "The agent card has no `securitySchemes`/`security` entries, so "
                "any caller that can reach the endpoint can invoke it directly, "
                "with no identity verification."
            ),
            evidence="securitySchemes={} security=[]",
            recommendation=(
                "Require an auth scheme (OAuth2, API key, mTLS) in the agent "
                "card and enforce it on every skill invocation, not just on "
                "the extended card."
            ),
        )
    ]


def rule_dangerous_skills(card: AgentCard) -> list[Finding]:
    findings: list[Finding] = []
    for skill in card.skills:
        haystack = " ".join(
            [skill.id, skill.name, skill.description, " ".join(skill.tags)]
        ).lower()
        matched = [kw for kw in _DANGEROUS_SKILL_KEYWORDS if _keyword_matches(haystack, kw)]
        if not matched:
            continue
        severity = max(_DANGEROUS_SKILL_KEYWORDS[kw] for kw in matched)
        auth_note = (
            "no authentication is required to call it"
            if not _has_security(card)
            else "authentication is declared, but verify it is actually enforced per-skill"
        )
        findings.append(
            Finding(
                agent_url=card.url,
                agent_name=card.name or card.url,
                layer=MaestroLayer.L3_AGENT_FRAMEWORKS,
                severity=severity,
                title=f"High-impact skill exposed: {skill.id or skill.name}",
                description=(
                    f"Skill '{skill.id or skill.name}' matches sensitive "
                    f"capability keyword(s) {matched}, and {auth_note}. "
                    "Skills with system, data-store, or credential access are "
                    "prime targets for tool-injection and privilege-escalation "
                    "attacks against agentic systems."
                ),
                evidence=f"skill.tags={skill.tags!r} skill.description={skill.description!r}",
                recommendation=(
                    "Scope this skill to least privilege, sandbox/execute it "
                    "out-of-process, and require step-up authorization for "
                    "any request that reaches it."
                ),
            )
        )
    return findings


def rule_streaming_or_push_without_auth(card: AgentCard) -> list[Finding]:
    if _has_security(card):
        return []
    findings: list[Finding] = []
    if card.capabilities.get("pushNotifications"):
        findings.append(
            Finding(
                agent_url=card.url,
                agent_name=card.name or card.url,
                layer=MaestroLayer.L4_DEPLOYMENT_INFRASTRUCTURE,
                severity=Severity.MEDIUM,
                title="Push notifications enabled without authentication",
                description=(
                    "The agent accepts webhook/push-notification callbacks "
                    "(`capabilities.pushNotifications`) but declares no auth. "
                    "A malicious caller can register an arbitrary callback URL, "
                    "turning the agent into an SSRF/exfiltration relay."
                ),
                evidence="capabilities.pushNotifications=true",
                recommendation=(
                    "Authenticate callback registration and allow-list or "
                    "validate destination URLs before sending push callbacks."
                ),
            )
        )
    if card.capabilities.get("streaming"):
        findings.append(
            Finding(
                agent_url=card.url,
                agent_name=card.name or card.url,
                layer=MaestroLayer.L4_DEPLOYMENT_INFRASTRUCTURE,
                severity=Severity.LOW,
                title="Streaming interface exposed without authentication",
                description=(
                    "`capabilities.streaming` is enabled with no auth scheme, "
                    "allowing any caller to open long-lived streamed "
                    "interactions and consume resources or observe outputs."
                ),
                evidence="capabilities.streaming=true",
                recommendation="Gate streaming sessions behind the same auth as regular invocation.",
            )
        )
    return findings


def rule_orchestration_reach(card: AgentCard) -> list[Finding]:
    findings: list[Finding] = []
    for skill in card.skills:
        haystack = " ".join([skill.id, skill.name, skill.description, " ".join(skill.tags)]).lower()
        if not any(kw in haystack for kw in _ORCHESTRATION_KEYWORDS):
            continue
        findings.append(
            Finding(
                agent_url=card.url,
                agent_name=card.name or card.url,
                layer=MaestroLayer.L7_AGENT_ECOSYSTEM,
                severity=Severity.HIGH if not _has_security(card) else Severity.MEDIUM,
                title=f"Agent can delegate/orchestrate other agents: {skill.id or skill.name}",
                description=(
                    "This agent's skills include orchestration/delegation of "
                    "other agents. Compromising it (via prompt injection or "
                    "unauthenticated invocation) can cascade into every agent "
                    "it can call — a rogue-orchestrator / cascading-trust "
                    "scenario that MAESTRO flags at the ecosystem layer."
                ),
                evidence=f"skill.id={skill.id!r} tags={skill.tags!r}",
                recommendation=(
                    "Apply per-hop authorization on delegated calls (don't "
                    "just trust the orchestrator's identity transitively), "
                    "and log/attest the delegation chain."
                ),
            )
        )
    return findings


def rule_unrestricted_language(card: AgentCard) -> list[Finding]:
    findings: list[Finding] = []
    text_fields = [card.description] + [s.description for s in card.skills]
    for text in text_fields:
        lowered = text.lower()
        for phrase in _UNRESTRICTED_PHRASES:
            if phrase in lowered:
                findings.append(
                    Finding(
                        agent_url=card.url,
                        agent_name=card.name or card.url,
                        layer=MaestroLayer.L6_SECURITY_COMPLIANCE,
                        severity=Severity.CRITICAL,
                        title="Agent card advertises unrestricted trust/access",
                        description=(
                            f"Card text contains the phrase '{phrase}', suggesting "
                            "the agent was designed with no authorization boundary. "
                            "This is a direct violation of least-privilege and "
                            "typically indicates the agent will execute requests "
                            "from any caller without policy checks."
                        ),
                        evidence=f"matched phrase: {phrase!r} in {text!r}",
                        recommendation=(
                            "Remove blanket-trust behavior; add explicit "
                            "authorization checks per skill and per caller."
                        ),
                    )
                )
                break
    return findings


def rule_missing_provenance(card: AgentCard) -> list[Finding]:
    if card.provider and card.version:
        return []
    missing = []
    if not card.provider:
        missing.append("provider")
    if not card.version:
        missing.append("version")
    return [
        Finding(
            agent_url=card.url,
            agent_name=card.name or card.url,
            layer=MaestroLayer.L7_AGENT_ECOSYSTEM,
            severity=Severity.LOW,
            title="Agent card missing provenance metadata",
            description=(
                f"Card omits {', '.join(missing)}, making it harder to verify "
                "the agent's origin, pin a known-good version, or detect a "
                "swapped/impersonating agent presenting a similar name."
            ),
            evidence=f"missing fields: {missing}",
            recommendation="Publish provider identity and semantic version in every agent card.",
        )
    ]


def rule_reasoning_disclosure(card: AgentCard) -> list[Finding]:
    probe = card.raw.get("blind_probe")
    if not probe or not probe.get("reasoning_leaked"):
        return []
    return [
        Finding(
            agent_url=card.url,
            agent_name=card.name or card.url,
            layer=MaestroLayer.L1_FOUNDATION_MODELS,
            severity=Severity.MEDIUM,
            title="Model internal reasoning/chain-of-thought exposed to the caller",
            description=(
                "The invoke response includes a raw reasoning/chain-of-thought "
                "field alongside the visible reply. This can leak system-prompt "
                "paraphrases, internal policy logic, or decision rationale an "
                "attacker can use to craft more effective prompt-injection or "
                "jailbreak attempts against this agent."
            ),
            evidence=f"reasoning sample: {probe['reasoning_sample']!r}",
            recommendation=(
                "Strip reasoning/chain-of-thought fields from any externally "
                "facing API response; keep them server-side/observability-only."
            ),
        )
    ]


def rule_verbose_execution_telemetry(card: AgentCard) -> list[Finding]:
    probe = card.raw.get("blind_probe")
    if not probe or not probe.get("telemetry_leaked"):
        return []
    return [
        Finding(
            agent_url=card.url,
            agent_name=card.name or card.url,
            layer=MaestroLayer.L5_EVALUATION_OBSERVABILITY,
            severity=Severity.MEDIUM,
            title="Internal multi-agent execution graph exposed in API response",
            description=(
                "The response stream exposes internal run/thread/agent identifiers "
                f"and execution graph nodes ({', '.join(probe['agent_graph_nodes']) or 'unnamed'}). "
                "This gives an external caller a map of the system's internal "
                "architecture (sub-agent names, orchestration structure) useful "
                "for reconnaissance ahead of a targeted attack, and may leak "
                "correlation identifiers across sessions/tenants."
            ),
            evidence=f"telemetry fields seen: {probe['telemetry_fields_seen']}",
            recommendation=(
                "Return only the final output to external callers; keep "
                "step-by-step execution traces (run_id, thread_id, node "
                "names) in server-side observability tooling, not the API "
                "response body."
            ),
        )
    ]


def rule_model_fingerprint_disclosure(card: AgentCard) -> list[Finding]:
    probe = card.raw.get("blind_probe")
    if not probe or not probe.get("model_name"):
        return []
    return [
        Finding(
            agent_url=card.url,
            agent_name=card.name or card.url,
            layer=MaestroLayer.L1_FOUNDATION_MODELS,
            severity=Severity.LOW,
            title="Underlying foundation model identity disclosed",
            description=(
                f"The response discloses the specific model in use "
                f"({probe['model_name']} via {probe['model_provider'] or 'unknown provider'}). "
                "Knowing the exact model lets an attacker target known "
                "jailbreaks, context-length quirks, or safety-filter gaps "
                "specific to that model."
            ),
            evidence=f"model_name={probe['model_name']!r} model_provider={probe['model_provider']!r}",
            recommendation="Omit model identity/provider fields from externally facing responses.",
        )
    ]


def rule_unreachable(discovered: DiscoveredAgent) -> list[Finding]:
    if discovered.reachable:
        return []
    return [
        Finding(
            agent_url=discovered.source_url,
            agent_name=discovered.source_url,
            layer=MaestroLayer.L5_EVALUATION_OBSERVABILITY,
            severity=Severity.INFO,
            title="Target did not expose a discoverable A2A agent card",
            description=(
                "No A2A agent card or OpenAPI/Swagger document was found at any "
                f"known path. Detail: {discovered.error or 'no response'}."
            ),
            evidence=discovered.error or "",
            recommendation="Informational only — confirm this target is expected to run an A2A agent.",
        )
    ]


CARD_RULES: tuple[Rule, ...] = (
    rule_missing_authentication,
    rule_dangerous_skills,
    rule_streaming_or_push_without_auth,
    rule_orchestration_reach,
    rule_unrestricted_language,
    rule_missing_provenance,
    rule_reasoning_disclosure,
    rule_verbose_execution_telemetry,
    rule_model_fingerprint_disclosure,
)


def analyze_agent(discovered: DiscoveredAgent) -> list[Finding]:
    findings: list[Finding] = list(rule_unreachable(discovered))
    if discovered.card is not None:
        for rule in CARD_RULES:
            findings.extend(rule(discovered.card))
    return findings


def analyze_many(discovered: Iterable[DiscoveredAgent]) -> list[Finding]:
    findings: list[Finding] = []
    for agent in discovered:
        findings.extend(analyze_agent(agent))
    return findings
