"""Command-line entry point: a2a-maestro."""

from __future__ import annotations

import argparse
import signal
import ssl
import sys
import time

from . import blind_discovery, discovery
from .analyzer import analyze_many
from .models import DiscoveredAgent
from .report import render_json, render_markdown
from .sim.agents import DEFAULT_PORT_RANGE
from .sim.launcher import start_all, stop_all


def _resolve_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []
    if args.targets:
        targets.extend(t.strip() for t in args.targets.split(",") if t.strip())
    if args.local_range:
        host, _, rng = args.local_range.partition(":")
        start_s, _, end_s = rng.partition("-")
        start, end = int(start_s), int(end_s or start_s)
        targets.extend(discovery.local_port_range_targets(host or "127.0.0.1", start, end))
    if args.sim:
        start, end = DEFAULT_PORT_RANGE
        targets.extend(discovery.local_port_range_targets("127.0.0.1", start, end))
    return targets


def _add_target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--targets",
        help="Comma-separated base URLs to probe for an A2A agent card, e.g. http://host:port,http://host2:port2",
    )
    p.add_argument(
        "--local-range",
        metavar="HOST:START-END",
        help="Probe every port in a range on a host, e.g. 127.0.0.1:9000-9010",
    )
    p.add_argument(
        "--sim",
        action="store_true",
        help="Include the built-in simulated agent environment's ports (starts it in-process if --start-sim is also given)",
    )
    p.add_argument(
        "--start-sim",
        action="store_true",
        help="Launch the local mock agent servers for the duration of this command (use with --sim)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=None,
        help=f"Per-target request timeout in seconds "
        f"[default: {discovery.DEFAULT_TIMEOUT}s, or {blind_discovery.DEFAULT_TIMEOUT}s for --protocol blind]",
    )
    p.add_argument(
        "--protocol",
        choices=list(discovery.PROTOCOLS),
        default="auto",
        help="Discovery protocol: 'a2a' (agent card only), 'openapi' (REST/Swagger only), "
        "'blind' (no metadata endpoint exists -- actually invoke the agent once and analyze "
        "what it leaks; never used by 'auto', real side effects), or 'auto' (A2A then OpenAPI) "
        "[default: auto]",
    )
    p.add_argument(
        "--probe-message",
        default=blind_discovery.DEFAULT_PROBE_MESSAGE,
        help="Message body sent to the agent for --protocol blind [default: %(default)r]",
    )
    p.add_argument(
        "--api-key",
        metavar="KEY",
        help="Send this as an 'Authorization: Bearer <KEY>' header on every discovery request",
    )
    p.add_argument(
        "--header",
        action="append",
        metavar="'Name: Value'",
        help="Extra raw header to send on every discovery request (repeatable), "
        "e.g. --header 'X-Api-Key: abc123'",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification (self-signed/internal CA targets only -- "
        "never use against untrusted hosts)",
    )


def _build_ssl_context(args: argparse.Namespace) -> ssl.SSLContext | None:
    if not args.insecure:
        return None
    print(
        "WARNING: --insecure is set, TLS certificate verification is disabled for this scan.",
        file=sys.stderr,
    )
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _build_headers(args: argparse.Namespace) -> dict[str, str]:
    headers: dict[str, str] = {}
    if args.api_key:
        headers["Authorization"] = f"Bearer {args.api_key}"
    for raw in args.header or []:
        name, sep, value = raw.partition(":")
        if not sep:
            print(f"Ignoring malformed --header {raw!r} (expected 'Name: Value')", file=sys.stderr)
            continue
        headers[name.strip()] = value.strip()
    return headers


def _discover(args: argparse.Namespace) -> list[DiscoveredAgent]:
    running = None
    try:
        if args.start_sim:
            running = start_all()
            time.sleep(0.2)  # let listener sockets come up
        targets = _resolve_targets(args)
        if not targets:
            print("No targets resolved. Use --targets, --local-range, or --sim.", file=sys.stderr)
            sys.exit(2)
        headers = _build_headers(args)
        ssl_context = _build_ssl_context(args)
        if args.timeout is not None:
            timeout = args.timeout
        elif args.protocol == "blind":
            timeout = blind_discovery.DEFAULT_TIMEOUT
        else:
            timeout = discovery.DEFAULT_TIMEOUT
        if args.protocol == "blind":
            print(
                f"WARNING: --protocol blind will actually invoke {len(targets)} target(s) with a "
                f"real request (probe message: {args.probe_message!r}). This has real side effects.",
                file=sys.stderr,
            )
        return discovery.discover_many(
            targets,
            timeout=timeout,
            protocol=args.protocol,
            headers=headers,
            ssl_context=ssl_context,
            probe_message=args.probe_message,
        )
    finally:
        if running:
            stop_all(running)


def cmd_discover(args: argparse.Namespace) -> None:
    discovered = _discover(args)
    for d in discovered:
        status = "OK" if d.reachable else f"UNREACHABLE ({d.error})"
        name = d.card.name if d.card else "-"
        print(f"{d.source_url:30s} {d.source_format:8s} {status:35s} {name}")


def cmd_scan(args: argparse.Namespace) -> None:
    discovered = _discover(args)
    findings = analyze_many(discovered)
    if args.format == "json":
        output = render_json(discovered, findings)
    else:
        output = render_markdown(discovered, findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)


def cmd_sim_start(args: argparse.Namespace) -> None:
    running = start_all(host=args.host)
    print("Local simulated A2A environment running:")
    for agent in running:
        print(f"  {agent.name:20s} {agent.url}")
    print("\nPress Ctrl+C to stop.")

    def _handle_sigint(signum, frame):  # noqa: ANN001
        print("\nStopping...")
        stop_all(running)
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_sigint)
    signal.pause()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="a2a-maestro", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_discover = sub.add_parser("discover", help="Discover A2A agents and print their cards")
    _add_target_args(p_discover)
    p_discover.set_defaults(func=cmd_discover)

    p_scan = sub.add_parser("scan", help="Discover agents and run the MAESTRO threat analysis")
    _add_target_args(p_scan)
    p_scan.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p_scan.add_argument("--output", help="Write the report to this file instead of stdout")
    p_scan.set_defaults(func=cmd_scan)

    p_sim = sub.add_parser("sim", help="Manage the local simulated agent environment")
    sim_sub = p_sim.add_subparsers(dest="sim_command", required=True)
    p_sim_start = sim_sub.add_parser("start", help="Start the mock agents and keep running")
    p_sim_start.add_argument("--host", default="127.0.0.1")
    p_sim_start.set_defaults(func=cmd_sim_start)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
