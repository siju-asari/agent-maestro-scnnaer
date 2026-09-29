"""A local, simulated multi-agent environment speaking real A2A discovery.

Each mock agent runs as a real HTTP server on localhost and serves an A2A
agent card at the standard well-known path, so the discovery/analysis code
paths exercised against it are the same ones you'd use against a real
deployment — only the network is local and synthetic.
"""

from .agents import DEFAULT_PORT_RANGE, MOCK_AGENT_CARDS

__all__ = ["MOCK_AGENT_CARDS", "DEFAULT_PORT_RANGE"]
