"""Persistent state, address allocation, and configuration comparison helpers."""

from __future__ import annotations

import argparse
from collections import OrderedDict
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
from typing import List, Mapping, MutableMapping, Optional, Tuple

from .protocol import PROVISION_STATE_VERSION

def load_history(path: Path) -> MutableMapping[str, object]:
    if not path.exists():
        return {"version": 1, "reset": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read reset history %s: %s" % (path, exc)) from exc
    if not isinstance(value, dict) or not isinstance(value.get("reset"), dict):
        raise ValueError("reset history %s has an invalid format" % path)
    return value


def save_history(path: Path, history: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(history, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(str(temporary), str(path))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def seconds_since(timestamp: object) -> float:
    if not isinstance(timestamp, str):
        return float("inf")
    try:
        then = datetime.fromisoformat(timestamp)
    except ValueError:
        return float("inf")
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - then).total_seconds())


def parse_ipv4(value: str, label: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("%s must be a valid IPv4 address" % label) from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("%s must be an IPv4 address" % label)
    return str(address)


def parse_netmask(value: str) -> str:
    value = parse_ipv4(value, "--subnet")
    try:
        network = ipaddress.IPv4Network("0.0.0.0/" + value)
    except ValueError as exc:
        raise ValueError("--subnet must be a contiguous IPv4 netmask") from exc
    return str(network.netmask)


def parse_address_pool(value: str) -> List[str]:
    """Expand START-END or CIDR into an ordered list of usable IPv4 addresses."""
    try:
        if "-" in value:
            first_text, last_text = value.split("-", 1)
            first = ipaddress.IPv4Address(first_text.strip())
            last = ipaddress.IPv4Address(last_text.strip())
            if int(last) < int(first):
                raise ValueError("pool end precedes pool start")
            count = int(last) - int(first) + 1
            if count > 65536:
                raise ValueError("pool contains more than 65536 addresses")
            return [str(ipaddress.IPv4Address(number)) for number in range(int(first), int(last) + 1)]
        network = ipaddress.ip_network(value, strict=False)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("pool must use IPv4")
        if network.num_addresses > 65536:
            raise ValueError("pool contains more than 65536 addresses")
        return [str(address) for address in network.hosts()]
    except ipaddress.AddressValueError as exc:
        raise ValueError("invalid IPv4 pool %r" % value) from exc


def load_provision_state(path: Path) -> MutableMapping[str, object]:
    if not path.exists():
        return {
            "version": PROVISION_STATE_VERSION,
            "settings": {},
            "devices": {},
            "reset": {},
        }
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read provision state %s: %s" % (path, exc)) from exc
    if not isinstance(state, dict) or state.get("version") != PROVISION_STATE_VERSION:
        raise ValueError("provision state %s has an invalid or unsupported format" % path)
    # Normalize both older files: provision state lacked ``reset``, while the
    # standalone reset-history file lacked ``settings`` and ``devices``.
    state.setdefault("settings", {})
    state.setdefault("devices", {})
    state.setdefault("reset", {})
    if not all(isinstance(state.get(key), dict) for key in ("settings", "devices", "reset")):
        raise ValueError("provision state %s has an invalid or unsupported format" % path)
    # Provision records created by the two-file version contain a copy of the
    # old history entry.  Promote it so migration remains safe even when the
    # separate history file has already been removed.
    reset_records = state["reset"]
    devices = state["devices"]
    assert isinstance(reset_records, dict) and isinstance(devices, dict)
    for mac, record in devices.items():
        if mac in reset_records or not isinstance(record, dict):
            continue
        imported = record.get("imported_reset_history")
        if isinstance(imported, dict):
            reset_records[mac] = dict(imported)
        elif record.get("reset_attempted_at"):
            reset_records[mac] = {
                "reset_attempted_at": record["reset_attempted_at"],
                "status": "acknowledged" if record.get("reset_ack_at") else "attempted-by-provision",
            }
    return state


def save_provision_state(path: Path, state: Mapping[str, object]) -> None:
    save_history(path, state)


def import_legacy_reset_history(
    state: MutableMapping[str, object], path: Optional[Path]
) -> int:
    """Merge the old reset-only file into unified state without modifying it."""
    if path is None or not path.exists():
        return 0
    legacy = load_history(path)
    reset_records = state["reset"]
    assert isinstance(reset_records, dict)
    imported = 0
    for mac, record in legacy["reset"].items():
        if mac not in reset_records:
            reset_records[mac] = record
            imported += 1
    if imported:
        state["legacy_reset_history_imported_from"] = str(path)
    return imported


def provision_settings(args: argparse.Namespace, state: MutableMapping[str, object]) -> Mapping[str, object]:
    saved = state["settings"]
    assert isinstance(saved, dict)
    supplied = {
        "pool": args.pool,
        "subnet": args.subnet,
        "router": args.router,
        "ommip1": args.ommip1,
        "ommip2": args.ommip2,
        "dns": args.dns,
        "siaddr": args.siaddr,
        "boot_file": args.boot_file,
        "exclude": sorted(args.exclude or []),
    }
    if not saved:
        for required in ("pool", "subnet", "ommip1"):
            if not supplied[required]:
                raise ValueError("--%s is required when creating a provision state" % required)
        supplied["subnet"] = parse_netmask(str(supplied["subnet"]))
        supplied["ommip1"] = parse_ipv4(str(supplied["ommip1"]), "--ommip1")
        for optional in ("router", "ommip2", "dns", "siaddr"):
            if supplied[optional]:
                supplied[optional] = parse_ipv4(str(supplied[optional]), "--" + optional)
        supplied["siaddr"] = supplied["siaddr"] or "0.0.0.0"
        supplied["boot_file"] = supplied["boot_file"] or "none"
        supplied["exclude"] = [parse_ipv4(value, "--exclude") for value in supplied["exclude"]]
        pool = parse_address_pool(str(supplied["pool"]))
        network = ipaddress.IPv4Network((pool[0], str(supplied["subnet"])), strict=False)
        for address_text in pool:
            address = ipaddress.IPv4Address(address_text)
            if address not in network:
                raise ValueError("address pool crosses the configured subnet boundary")
            if address in (network.network_address, network.broadcast_address):
                raise ValueError("address pool includes subnet network/broadcast address %s" % address)
        if supplied["router"] and ipaddress.IPv4Address(str(supplied["router"])) not in network:
            raise ValueError("--router is outside the address pool's subnet")
        saved.update(supplied)
        return saved
    for key, value in supplied.items():
        if value not in (None, []) and value != saved.get(key):
            raise ValueError(
                "%s differs from the value stored in %s; omit it to resume or use another state file"
                % ("--" + key.replace("_", "-"), args.state)
            )
    return saved


def allocate_address(settings: Mapping[str, object], devices: Mapping[str, object]) -> str:
    used = {
        str(record.get("assigned_ip"))
        for record in devices.values()
        if isinstance(record, dict) and record.get("assigned_ip")
    }
    excluded = set(str(value) for value in settings.get("exclude", []))
    for key in ("router", "ommip1", "ommip2"):
        if settings.get(key):
            excluded.add(str(settings[key]))
    for address in parse_address_pool(str(settings["pool"])):
        if address not in used and address not in excluded:
            return address
    raise ValueError("address pool is exhausted")


def desired_configuration(settings: Mapping[str, object], assigned_ip: str) -> "OrderedDict[str, str]":
    values = OrderedDict(
        (
            ("use_local_cfg", "1"),
            ("ip", assigned_ip),
            ("subnet", str(settings["subnet"])),
        )
    )
    for key in ("router", "ommip1", "ommip2", "dns", "siaddr", "boot_file"):
        value = settings.get(key)
        if value:
            values[key] = str(value)
    values["stream"] = "SIP-DECT"
    return values


def configuration_drift(
    expected: Mapping[str, str], observed: Mapping[str, str]
) -> "OrderedDict[str, Tuple[str, Optional[str]]]":
    drift = OrderedDict()  # type: OrderedDict[str, Tuple[str, Optional[str]]]
    for key, wanted in expected.items():
        if key == "stream":
            continue
        actual = observed.get(key)
        if actual != wanted:
            drift[key] = (wanted, actual)
    return drift



