"""Mock A2A agent card fixtures for the local simulated environment.

Four agents with deliberately different security postures, so a scan
against the sim demonstrates the full severity range MAESTRO cares about:

- 9001 concierge-agent   : well-configured (baseline / should be mostly clean)
- 9002 shell-executor    : unauthenticated agent with raw command execution
- 9003 data-broker       : unauthenticated agent with direct DB/PII access
- 9004 fleet-orchestrator: can delegate to other agents, weak provenance
"""

from __future__ import annotations

DEFAULT_PORT_RANGE = (9001, 9004)

MOCK_AGENT_CARDS: dict[int, dict] = {
    9001: {
        "name": "concierge-agent",
        "description": "Answers user FAQs and books calendar appointments.",
        "version": "1.4.0",
        "provider": {"organization": "Acme Corp", "url": "https://acme.example/agents"},
        "url": "http://127.0.0.1:9001",
        "capabilities": {"streaming": True, "pushNotifications": False},
        "securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
        },
        "security": [{"bearer": []}],
        "supportsAuthenticatedExtendedCard": True,
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            {
                "id": "answer_faq",
                "name": "Answer FAQ",
                "description": "Answers common questions from a curated knowledge base.",
                "tags": ["faq", "support"],
            },
            {
                "id": "book_appointment",
                "name": "Book Appointment",
                "description": "Creates a calendar appointment for the authenticated user.",
                "tags": ["calendar", "scheduling"],
            },
        ],
    },
    9002: {
        "name": "shell-executor",
        "description": "Internal dev-tools agent. No restrictions, trusted implicitly by CI.",
        "version": "",
        "provider": None,
        "url": "http://127.0.0.1:9002",
        "capabilities": {"streaming": True, "pushNotifications": False},
        "securitySchemes": {},
        "security": [],
        "supportsAuthenticatedExtendedCard": False,
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            {
                "id": "run_shell_command",
                "name": "Run Shell Command",
                "description": "Executes an arbitrary shell command on the host via subprocess.",
                "tags": ["shell", "exec", "system"],
            }
        ],
    },
    9003: {
        "name": "data-broker",
        "description": "Looks up customer records for the sales team.",
        "version": "0.9.1",
        "provider": None,
        "url": "http://127.0.0.1:9003",
        "capabilities": {"streaming": False, "pushNotifications": True},
        "securitySchemes": {},
        "security": [],
        "supportsAuthenticatedExtendedCard": False,
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": "query_customer_database",
                "name": "Query Customer Database",
                "description": "Runs a SQL lookup against the customer PII database.",
                "tags": ["database", "sql", "pii"],
            }
        ],
    },
    9004: {
        "name": "fleet-orchestrator",
        "description": "Coordinates work across the internal agent fleet.",
        "version": "2.0.0",
        "provider": {"organization": "Acme Corp"},
        "url": "http://127.0.0.1:9004",
        "capabilities": {"streaming": True, "pushNotifications": True},
        "securitySchemes": {
            "apiKey": {"type": "apiKey", "in": "header", "name": "X-Api-Key"}
        },
        "security": [{"apiKey": []}],
        "supportsAuthenticatedExtendedCard": False,
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": "delegate_task_to_agent",
                "name": "Delegate Task",
                "description": "Selects and invokes another agent in the fleet to complete a subtask.",
                "tags": ["orchestration", "delegate", "multi-agent"],
            }
        ],
    },
}
