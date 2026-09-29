# a2a-maestro-scanner

Discovers agents — [A2A protocol](https://a2a-protocol.org/) agents via their
published Agent Card, or plain OpenAPI/Swagger REST services that don't speak
A2A at all — then runs a rule-based threat analysis against each one using
the [MAESTRO](https://cloudsecurityalliance.org/) framework (Multi-Agent
Environment, Security, Threat, Risk, and Outcome — CSA's 7-layer threat model
for agentic AI).

Zero third-party dependencies (stdlib only).

## How it works

1. **Discovery** — for each candidate base URL, probe for a machine-readable
   description of the service and normalize it into a common `AgentCard`:
   - `a2a_maestro/discovery.py`: A2A — fetch `/.well-known/agent-card.json`
     (falling back to the legacy `/.well-known/agent.json`).
   - `a2a_maestro/openapi_discovery.py`: OpenAPI/Swagger — fetch
     `/openapi.json`, `/swagger.json`, etc.; each path+method operation
     becomes a Skill, `components.securitySchemes`/`securityDefinitions`
     becomes the security info.
   - `a2a_maestro/blind_discovery.py`: **blind invoke** — for targets with
     *no* metadata endpoint at all (a bare proprietary invoke route). Sends
     one real request with a benign probe message and parses whatever the
     response leaks (model identity, internal agent/execution-graph names,
     chain-of-thought/reasoning fields) into the same `AgentCard` shape.
     This performs a genuine invocation with real side effects, so it's
     never tried by `auto` — only via `--protocol blind`, explicitly.
   - `--protocol auto` (default) tries A2A first and falls back to OpenAPI,
     so a mixed fleet of real A2A agents and plain REST services can be
     scanned in one pass; `--protocol a2a` / `--protocol openapi` / `--protocol blind` force one.
2. **Analysis** (`a2a_maestro/analyzer.py`) — the same rules run against any
   normalized `AgentCard` regardless of source protocol: missing
   authentication, high-impact skills/operations (shell/exec, database/SQL,
   credentials, destructive verbs), unauthenticated streaming/push-notification
   surfaces, orchestration/delegation reach into other agents, unrestricted-trust
   language, and missing provenance metadata. Blind-probed agents get three
   more: chain-of-thought/reasoning disclosure, foundation-model fingerprint
   disclosure, and verbose internal execution-graph/telemetry disclosure.
3. **Reporting** (`a2a_maestro/report.py`) — findings are grouped by MAESTRO
   layer and severity into a Markdown or JSON report.

Rules are heuristic red flags for a human reviewer, not proof of an
exploitable vulnerability.

## Local simulated environment

`a2a_maestro/sim/` ships a small local multi-agent environment: four real
HTTP servers on `127.0.0.1:9001-9004`, each serving a genuine A2A agent card,
with deliberately different security postures (a well-configured baseline,
an unauthenticated shell-execution agent, an unauthenticated PII/database
agent, and an orchestrator that can delegate to the others). It exercises
the exact same discovery/analysis code path you'd use against a real
deployment — only the "network" is local and synthetic.

## Usage

```bash
# Discover + list agent cards from the built-in sim, starting it for the duration of the command
python3 -m a2a_maestro.cli discover --sim --start-sim

# Run the full MAESTRO scan against the sim and print a Markdown report
python3 -m a2a_maestro.cli scan --sim --start-sim

# Same, but JSON, written to a file
python3 -m a2a_maestro.cli scan --sim --start-sim --format json --output report.json

# Run the sim as a standalone, long-lived environment (separate terminal)
python3 -m a2a_maestro.cli sim start

# Point the scanner at real targets instead of the sim (auto-detects A2A vs OpenAPI)
python3 -m a2a_maestro.cli scan --targets https://agent-one.internal,https://agent-two.internal

# Force OpenAPI-only discovery against a non-A2A REST service
python3 -m a2a_maestro.cli scan --targets https://legacy-api.internal --protocol openapi

# Authenticated target: send an API key as a Bearer token on every discovery request
python3 -m a2a_maestro.cli scan --targets https://secured-agent.internal --api-key "$MY_API_KEY"

# Or a custom header instead of Bearer auth (repeatable)
python3 -m a2a_maestro.cli scan --targets https://secured-agent.internal --header "X-Api-Key: $MY_API_KEY"

# Probe a local port range (loopback-scoped, not arbitrary network scanning)
python3 -m a2a_maestro.cli discover --local-range 127.0.0.1:9000-9010

# Internal/self-signed cert target: skip TLS verification for this scan
python3 -m a2a_maestro.cli scan --targets https://internal-agent.staging --api-key "$KEY" --insecure

# No metadata endpoint exists at all: actually invoke the agent once and analyze what it leaks
# (real side effects -- only for a target you're authorized to run against)
python3 -m a2a_maestro.cli scan --targets https://agent.internal/run \
  --protocol blind --api-key "$KEY" --probe-message "hi"
```

Or install it as a console script:

```bash
pip install -e .
a2a-maestro scan --sim --start-sim
```

## Extending

- New MAESTRO rules: add a function `AgentCard -> list[Finding]` to
  `a2a_maestro/analyzer.py` and register it in `CARD_RULES`.
- New mock agents for the sim: add an entry to
  `a2a_maestro/sim/agents.py::MOCK_AGENT_CARDS`.
