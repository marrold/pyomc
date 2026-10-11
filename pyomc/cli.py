"""Command-line parser and entry point for PyOMC."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import List, Optional

from .commands import (
    command_configure, command_provision, command_reconcile,
    command_reset, command_scan,
)
from .protocol import CONFIG_PARAMETERS, ProtocolError, normalize_mac
from .proxy import command_proxy


def mac_argument(value: str) -> str:
    """Argparse type for a MAC, preserving normalize_mac's specific messages."""
    try:
        return normalize_mac(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def add_network_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--interface",
        default="0.0.0.0",
        metavar="IP",
        help="local IPv4 address to bind (default: all interfaces)",
    )
    parser.add_argument(
        "--broadcast",
        default="255.255.255.255",
        metavar="IP",
        help="IPv4 broadcast address (default: 255.255.255.255)",
    )
    parser.add_argument("--timeout", type=float, default=2.0, help="seconds to await each response")
    parser.add_argument("--attempts", type=int, default=2, help="send attempts per operation")
    parser.add_argument(
        "--proxy",
        metavar="HOST",
        help="send OMC packets through this reachable proxy RFP",
    )
    # --scan-subnet selects L3 (targeted-unicast) discovery across a CIDR.
    # It is deliberately never aliased to --subnet, which configure and
    # provision use for the static netmask being written.
    parser.add_argument(
        "--scan-subnet",
        dest="scan_subnet",
        metavar="CIDR",
        help="discover by unicasting to each address in an IPv4 subnet",
    )


def add_credentials(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--username", help="OMM username; password is prompted if omitted")
    parser.add_argument(
        "--password",
        help="OMM password (prefer the OMM_PASSWORD environment variable or prompt)",
    )


def add_discovery_address(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--address",
        metavar="IP",
        help="discover and operate on only the RFP at this IPv4 address",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyomc",
        description="Discover, configure, and factory-reset SIP-DECT RFPs."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="discover RFPs and read their configuration")
    add_network_options(scan)
    add_discovery_address(scan)
    add_credentials(scan)
    scan.add_argument(
        "--interval",
        type=float,
        default=10.0,
        help="seconds between discovery passes (default: 10)",
    )
    scan.add_argument("--json", action="store_true", help="emit one JSON object per newly seen RFP")
    scan.set_defaults(handler=command_scan)

    proxy = subparsers.add_parser(
        "proxy",
        help="relay OMC proxy requests onto a local RFP broadcast domain",
    )
    proxy.add_argument(
        "--interface",
        default="0.0.0.0",
        metavar="IP",
        help="local IPv4 address on which to listen (default: all interfaces)",
    )
    proxy.add_argument(
        "--broadcast",
        default="255.255.255.255",
        metavar="IP",
        help="downstream RFP broadcast address (default: 255.255.255.255)",
    )
    proxy.add_argument(
        "--request-ttl",
        type=float,
        default=5.0,
        help="seconds to retain request/reply correlation (default: 5)",
    )
    proxy.add_argument("--quiet", action="store_true", help="suppress relay event logging")
    proxy.set_defaults(handler=command_proxy)

    configure = subparsers.add_parser("configure", help="set configuration on one MAC address")
    configure.add_argument("mac", type=mac_argument, help="target RFP MAC address")
    add_network_options(configure)
    add_discovery_address(configure)
    add_credentials(configure)
    for name in CONFIG_PARAMETERS:
        dashed = "--" + name.replace("_", "-")
        underscored = "--" + name
        spellings = (dashed, underscored) if dashed != underscored else (dashed,)
        configure.add_argument(*spellings, dest=name, metavar="VALUE", help="set OMC parameter %s" % name)
    configure.add_argument(
        "--set",
        dest="set_values",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="set an extra/firmware-specific parameter (repeatable)",
    )
    configure.add_argument(
        "--force", action="store_true", help="skip the confirmation prompt"
    )
    configure.set_defaults(handler=command_configure, username="omm")

    reset = subparsers.add_parser("reset", help="factory-reset every newly discovered RFP")
    add_network_options(reset)
    add_discovery_address(reset)
    add_credentials(reset)
    reset.add_argument(
        "--state",
        "--history",
        dest="state",
        type=Path,
        default=Path("rfp-provision-state.json"),
        help="shared reset and provisioning state (default: ./rfp-provision-state.json)",
    )
    reset.add_argument(
        "--legacy-reset-history",
        type=Path,
        default=Path("rfp-reset-history.json"),
        help=argparse.SUPPRESS,
    )
    reset.add_argument(
        "--force", action="store_true", help="skip the confirmation prompt"
    )
    reset.add_argument(
        "--secret",
        type=Path,
        metavar="FILE",
        help="use the raw 256-byte factory-reset secret instead of credentials",
    )
    reset.set_defaults(handler=command_reset, username="omm")

    provision = subparsers.add_parser(
        "provision",
        help="factory-reset new RFPs and assign persistent static configuration",
    )
    add_network_options(provision)
    add_discovery_address(provision)
    add_credentials(provision)
    provision.add_argument(
        "--state",
        type=Path,
        default=Path("rfp-provision-state.json"),
        help="assignment and progress file (default: ./rfp-provision-state.json)",
    )
    provision.add_argument(
        "--legacy-reset-history",
        "--reset-history",
        dest="legacy_reset_history",
        type=Path,
        default=Path("rfp-reset-history.json"),
        help="old reset-history file to import once (default: ./rfp-reset-history.json)",
    )
    provision.add_argument(
        "--secret",
        type=Path,
        metavar="FILE",
        help="use the raw 256-byte factory-reset secret instead of credentials",
    )
    provision.add_argument("--pool", help="IPv4 START-END range or CIDR; saved on first run")
    provision.add_argument("--subnet", help="static IPv4 netmask; saved on first run")
    provision.add_argument("--router", help="optional static IPv4 router")
    provision.add_argument("--ommip1", help="primary OMM address; saved on first run")
    provision.add_argument("--ommip2", help="optional standby OMM address")
    provision.add_argument("--dns", help="optional DNS server address")
    provision.add_argument("--siaddr", help="TFTP server address (default for new state: 0.0.0.0)")
    provision.add_argument("--boot-file", dest="boot_file", help="TFTP file (default: none)")
    provision.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="IP",
        help="exclude an address from allocation (repeatable)",
    )
    provision.add_argument(
        "--interval",
        type=float,
        default=10.0,
        help="seconds between discovery passes (default: 10)",
    )
    provision.add_argument(
        "--config-retry",
        type=float,
        default=60.0,
        help="seconds before retrying an acknowledged configuration (default: 60)",
    )
    provision.add_argument("--once", action="store_true", help="perform one discovery cycle and exit")
    provision.add_argument(
        "--force", action="store_true", help="skip the confirmation prompt"
    )
    provision.set_defaults(handler=command_provision, username="omm")

    reconcile = subparsers.add_parser(
        "reconcile",
        help="compare live RFP configuration with the provision state",
    )
    add_network_options(reconcile)
    add_discovery_address(reconcile)
    add_credentials(reconcile)
    reconcile.add_argument(
        "--state",
        type=Path,
        default=Path("rfp-provision-state.json"),
        help="assignment state file (default: ./rfp-provision-state.json)",
    )
    reconcile.add_argument(
        "--apply",
        action="store_true",
        help="write saved configuration to RFPs that have drifted",
    )
    reconcile.add_argument(
        "--force",
        action="store_true",
        help="skip the confirmation prompt shown by --apply",
    )
    reconcile.set_defaults(handler=command_reconcile, username="omm")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if hasattr(args, "timeout") and args.timeout <= 0:
        print("error: --timeout must be positive", file=sys.stderr)
        return 2
    if hasattr(args, "attempts") and args.attempts < 1:
        print("error: --attempts must be at least one", file=sys.stderr)
        return 2
    if args.command in ("scan", "provision") and args.interval < 0:
        print("error: --interval cannot be negative", file=sys.stderr)
        return 2
    if hasattr(args, "scan_subnet") and args.scan_subnet and args.proxy:
        print("error: --scan-subnet cannot be combined with --proxy", file=sys.stderr)
        return 2
    if hasattr(args, "address") and args.address and args.scan_subnet:
        print("error: --address cannot be combined with --scan-subnet", file=sys.stderr)
        return 2
    if hasattr(args, "address") and args.address and args.proxy:
        print("error: --address cannot be combined with --proxy", file=sys.stderr)
        return 2
    if args.command == "provision" and args.config_retry <= 0:
        print("error: --config-retry must be positive", file=sys.stderr)
        return 2
    if args.command == "proxy" and args.request_ttl <= 0:
        print("error: --request-ttl must be positive", file=sys.stderr)
        return 2
    try:
        return int(args.handler(args))
    except (OSError, ProtocolError, TimeoutError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

