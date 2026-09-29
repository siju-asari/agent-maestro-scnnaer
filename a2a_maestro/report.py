"""Render discovery + MAESTRO analysis results as Markdown or JSON."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from .maestro import Finding, MaestroLayer, Severity
from .models import DiscoveredAgent

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
    Severity.INFO: "⬜",
}


def render_json(discovered: list[DiscoveredAgent], findings: list[Finding]) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "framework": "MAESTRO",
        "agents": [
            {
                "source_url": d.source_url,
                "source_format": d.source_format,
                "reachable": d.reachable,
                "well_known_path": d.well_known_path,
                "name": d.card.name if d.card else None,
                "error": d.error,
            }
            for d in discovered
        ],
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total_agents": len(discovered),
            "reachable_agents": sum(1 for d in discovered if d.reachable),
            "total_findings": len(findings),
            "by_severity": {
                sev.name: sum(1 for f in findings if f.severity == sev)
                for sev in _SEVERITY_ORDER
            },
        },
    }
    return json.dumps(payload, indent=2)


def render_markdown(discovered: list[DiscoveredAgent], findings: list[Finding]) -> str:
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append("# A2A Discovery + MAESTRO Threat Analysis")
    lines.append("")
    lines.append(f"Generated {now}")
    lines.append("")

    lines.append("## Discovered agents")
    lines.append("")
    lines.append("| Agent | Source | Format | Reachable | Skills |")
    lines.append("|---|---|---|---|---|")
    for d in discovered:
        name = d.card.name if d.card and d.card.name else "—"
        skills = ", ".join(s.id or s.name for s in d.card.skills) if d.card else "—"
        lines.append(
            f"| {name} | {d.source_url} | {d.source_format} | {'yes' if d.reachable else 'no'} | {skills or '—'} |"
        )
    lines.append("")

    sev_counts = Counter(f.severity for f in findings)
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {_SEVERITY_EMOJI[sev]} {sev.name} | {sev_counts.get(sev, 0)} |")
    lines.append("")
    lines.append(f"**Total findings:** {len(findings)} across {len(discovered)} discovered target(s).")
    lines.append("")

    lines.append("## Findings by MAESTRO layer")
    lines.append("")
    for layer in MaestroLayer.ORDER:
        layer_findings = sorted(
            (f for f in findings if f.layer == layer),
            key=lambda f: _SEVERITY_ORDER.index(f.severity),
        )
        if not layer_findings:
            continue
        lines.append(f"### {layer}")
        lines.append("")
        for f in layer_findings:
            lines.append(f"- {_SEVERITY_EMOJI[f.severity]} **[{f.severity.name}] {f.title}** — `{f.agent_name}`")
            lines.append(f"  - {f.description}")
            if f.evidence:
                lines.append(f"  - Evidence: `{f.evidence}`")
            if f.recommendation:
                lines.append(f"  - Recommendation: {f.recommendation}")
        lines.append("")

    if not findings:
        lines.append("_No findings — all discovered agents passed the current rule set._")
        lines.append("")

    return "\n".join(lines)
