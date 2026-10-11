"""Implementations of PyOMC scan, configure, reset, provision, and reconcile commands."""

from __future__ import annotations

import argparse
from collections import OrderedDict
import getpass
import json
import os
from pathlib import Path
import sys
import time
from typing import Dict, Mapping, Optional, Tuple

from .client import OMCClient
from .protocol import (
    BACKDOOR, CONFIG_PARAMETERS, COOKIEREQ, FACTORY_SECRET_SIZE, LIST, RESET, SET,
    ProtocolError, derive_factory_key, encode_parameters, normalize_mac,
)
from .state import (
    allocate_address, configuration_drift, desired_configuration,
    import_legacy_reset_history, load_history, load_provision_state,
    provision_settings, save_provision_state, seconds_since, utc_now,
)

def credentials(args: argparse.Namespace) -> Tuple[Optional[str], Optional[str]]:
    username = args.username
    password = args.password
    if username and password is None:
        password = os.environ.get("OMM_PASSWORD")
    if username and password is None:
        password = getpass.getpass("OMM password: ")
    if password is not None and username is None:
        raise ValueError("--password/OMM_PASSWORD requires --username")
    return username, password


def client_from_args(args: argparse.Namespace) -> OMCClient:
    return OMCClient(args.interface, args.broadcast, args.timeout, args.attempts)


def confirm_write(args: argparse.Namespace, warning: str) -> bool:
    """Require interactive confirmation for a write operation unless --force.

    Returns True when the operation may proceed.  Confirmation is impossible
    in a non-interactive session, so the operation is refused there unless
    --force is supplied.
    """
    if getattr(args, "force", False):
        return True
    print(warning, flush=True)
    if not sys.stdin.isatty():
        print(
            "Refusing to proceed without confirmation; re-run with --force.",
            file=sys.stderr,
        )
        return False
    try:
        reply = input("Continue? [y/N] ").strip().lower()
    except EOFError:
        reply = ""
    if reply in ("y", "yes"):
        return True
    print("Aborted.")
    return False


def discover_devices(
    client: OMCClient,
    args: argparse.Namespace,
    attempts: Optional[int] = None,
) -> Dict[str, Dict[str, object]]:
    """Discover using the command's selected broadcast, proxy, or L3 route."""
    if getattr(args, "address", None):
        return client.discover_address(args.address, attempts=attempts)
    if args.scan_subnet:
        return client.discover_subnet(args.scan_subnet, attempts=attempts)
    return client.discover(attempts=attempts, proxy=args.proxy)


def _provision_target_mac(
    devices_state: Mapping[str, object],
    address: Optional[str],
) -> Optional[str]:
    """Recover an address-targeted provision run from its persistent state."""
    if not address:
        return None
    matches = []
    for mac, value in devices_state.items():
        if not isinstance(value, dict):
            continue
        known_addresses = {
            value.get("initial_address"),
            value.get("last_seen_address"),
            value.get("assigned_ip"),
        }
        if address in known_addresses:
            matches.append(mac)
    if len(matches) > 1:
        raise ValueError("--address matches more than one RFP in the provision state")
    return matches[0] if matches else None


def print_record(
    mac: str,
    record: Mapping[str, object],
    config: Optional[Mapping[str, str]],
    login: str,
    error: Optional[str] = None,
) -> None:
    if record.get("proxy"):
        route = "via-proxy=%s" % record["proxy"]
    else:
        route = str(record["address"])
    fields = [mac, route, "login=%s" % login]
    if config is not None:
        fields.extend("%s=%s" % (key, value) for key, value in config.items())
    if error:
        fields.append("error=%s" % error)
    print("  ".join(fields))


def command_scan(args: argparse.Namespace) -> int:
    username, password = credentials(args)
    seen = set()
    with client_from_args(args) as client:
        if not args.json:
            if args.address:
                print("Scanning for the RFP at %s; press Ctrl+C to stop." % args.address, flush=True)
            else:
                method = " by unicast" if args.scan_subnet else ""
                print("Scanning%s for new RFPs; press Ctrl+C to stop." % method, flush=True)
        try:
            while True:
                cycle_started = time.monotonic()
                # Continuous monitoring sends one discovery pass per cycle.
                # Retries remain available to finite configure/reset scans.
                devices = discover_devices(client, args, attempts=1)
                for mac in sorted(set(devices) - seen):
                    # Remember it before LIST so a device that requires credentials
                    # is still reported only once.
                    seen.add(mac)
                    record = devices[mac]
                    config = None
                    error = None
                    login = "unknown"
                    try:
                        config, authenticated = client.exchange_with_status(
                            str(record["address"] or args.proxy),
                            mac,
                            LIST,
                            username=username,
                            password=password,
                            proxy=args.proxy,
                        )
                        if authenticated:
                            login = "authenticated"
                        elif username is not None:
                            login = "not required (credentials not verified)"
                        else:
                            login = "not required"
                    except PermissionError as exc:
                        error = str(exc)
                        login = "failed" if username is not None else "credentials required"
                    except (TimeoutError, ProtocolError) as exc:
                        error = str(exc)
                    if args.json:
                        output = {
                            "mac": mac,
                            "address": record["address"],
                            "proxy": record.get("proxy"),
                            "login": login,
                            "config": config,
                            "error": error,
                        }
                        print(json.dumps(output), flush=True)
                    else:
                        print_record(mac, record, config, login, error)
                        sys.stdout.flush()
                # Targeted mode (--address) scans for one known RFP: report it
                # once it is found and exit, mirroring configure/reset.
                if args.address and seen:
                    return 0
                remaining = args.interval - (time.monotonic() - cycle_started)
                if remaining > 0:
                    time.sleep(remaining)
        except KeyboardInterrupt:
            if not args.json:
                print("\nStopped after discovering %d RFP(s)." % len(seen))
    return 0


def locate(client: OMCClient, mac: str, args: argparse.Namespace) -> str:
    """Resolve how to reach one MAC, honouring the command's discovery mode.

    Returns the proxy host in proxy mode (the proxy resolves the inner MAC
    itself), otherwise the IPv4 address found by broadcast, L3, or targeted
    discovery.  Targeted mode (``--address``) therefore confirms that the
    requested MAC is actually present at that address rather than writing to
    whatever happens to answer there.
    """
    if args.proxy:
        return args.proxy
    target = normalize_mac(mac)
    devices = discover_devices(client, args)
    if target not in devices:
        raise TimeoutError("RFP %s was not found by discovery" % target)
    return str(devices[target]["address"])


def command_configure(args: argparse.Namespace) -> int:
    username, password = credentials(args)
    values = OrderedDict()  # type: OrderedDict[str, str]
    for name in CONFIG_PARAMETERS:
        value = getattr(args, name)
        if value is not None:
            values[name] = value
    for assignment in args.set_values:
        if "=" not in assignment:
            raise ValueError("--set must be KEY=VALUE")
        key, value = assignment.split("=", 1)
        if not key or key in ("stream", "version_mismatch", "cookie"):
            raise ValueError("--set cannot write reserved key %r" % key)
        values[key] = value
    if not values:
        raise ValueError("configure requires at least one configuration option or --set KEY=VALUE")
    values["stream"] = "SIP-DECT"
    if not confirm_write(
        args, "WARNING: this will write new configuration to RFP %s." % normalize_mac(args.mac)
    ):
        return 1
    with client_from_args(args) as client:
        address = locate(client, args.mac, args)
        response = client.exchange(
            address,
            args.mac,
            SET,
            encode_parameters(values),
            username,
            password,
            args.proxy,
        )
        route = " via proxy %s" % args.proxy if args.proxy else " at %s" % address
        print("Configured %s%s" % (normalize_mac(args.mac), route))
        for key, value in response.items():
            print("  %s=%s" % (key, value))
    return 0


def factory_reset_one(
    client: OMCClient,
    address: str,
    mac: str,
    secret: Optional[bytes],
    username: Optional[str] = None,
    password: Optional[str] = None,
    proxy: Optional[str] = None,
) -> "OrderedDict[str, str]":
    if secret is None:
        if not username or password is None:
            raise ValueError("OMM credential-based factory reset requires a username and password")
        return client.exchange(
            address,
            mac,
            RESET,
            username=username,
            password=password,
            proxy=proxy,
        )
    cookie_reply = client.exchange(address, mac, COOKIEREQ, proxy=proxy)
    cookie_text = cookie_reply.get("cookie")
    if cookie_text is None:
        raise ProtocolError("cookie reply contains no cookie")
    compact_cookie = cookie_text.replace(":", "").replace("-", "").replace(" ", "")
    if len(compact_cookie) != 32:
        raise ProtocolError("cookie is not 16 bytes")
    try:
        cookie = bytes.fromhex(compact_cookie)
    except ValueError as exc:
        raise ProtocolError("cookie is not hexadecimal") from exc
    key = derive_factory_key(cookie, secret)
    return client.exchange(address, mac, BACKDOOR, key, proxy=proxy)


def command_reset(args: argparse.Namespace) -> int:
    if not confirm_write(
        args, "WARNING: this will FACTORY-RESET every discovered RFP, erasing its configuration."
    ):
        return 1
    state = load_provision_state(args.state)
    import_legacy_reset_history(state, args.legacy_reset_history)
    reset_records = state["reset"]
    assert isinstance(reset_records, dict)
    save_provision_state(args.state, state)
    secret = read_factory_secret(args.secret)
    if secret is None:
        username, password = credentials(args)
        reset_method = "credentials"
    else:
        username, password = None, None
        reset_method = "secret"
    failures = 0
    with client_from_args(args) as client:
        devices = discover_devices(client, args)
        if not devices:
            print("No RFPs found.")
            return 1
        for mac in sorted(devices):
            device_address = devices[mac]["address"]
            address = str(device_address or args.proxy)
            if mac in reset_records:
                print(
                    "SKIP  %s  already recorded in %s; remove its record to reset it again"
                    % (mac, args.state)
                )
                continue
            attempted_at = utc_now()
            reset_records[mac] = {
                "address": device_address,
                "proxy": args.proxy,
                "method": reset_method,
                "reset_attempted_at": attempted_at,
                "status": "attempted",
            }
            # Persist before sending: a timeout may mean the reset succeeded
            # and the device rebooted before its acknowledgement arrived.
            save_provision_state(args.state, state)
            try:
                response = factory_reset_one(
                    client,
                    address,
                    mac,
                    secret,
                    username,
                    password,
                    args.proxy,
                )
                reset_records[mac].update(
                    {
                        "reset_at": utc_now(),
                        "response": dict(response),
                        "status": "acknowledged",
                    }
                )
                save_provision_state(args.state, state)
                print("RESET %s  %s" % (mac, address))
            except (OSError, PermissionError, TimeoutError, ProtocolError, ValueError) as exc:
                reset_records[mac]["status"] = "uncertain"
                reset_records[mac]["error"] = str(exc)
                save_provision_state(args.state, state)
                failures += 1
                print("FAIL  %s  %s  %s" % (mac, address, exc), file=sys.stderr)
    return 1 if failures else 0


def read_factory_secret(path: Optional[Path]) -> Optional[bytes]:
    if path is None:
        return None
    secret = path.read_bytes()
    if len(secret) != FACTORY_SECRET_SIZE:
        raise ValueError(
            "factory-reset secret file %s contains %d bytes; expected 256" % (path, len(secret))
        )
    return secret


def command_provision(args: argparse.Namespace) -> int:
    if not confirm_write(
        args,
        "WARNING: this will FACTORY-RESET and reconfigure every new RFP it discovers.",
    ):
        return 1
    state = load_provision_state(args.state)
    import_legacy_reset_history(state, args.legacy_reset_history)
    settings = provision_settings(args, state)
    save_provision_state(args.state, state)
    devices_state = state["devices"]
    assert isinstance(devices_state, dict)
    previously_reset = state["reset"]
    assert isinstance(previously_reset, dict)
    secret = read_factory_secret(args.secret)
    username, password = credentials(args)
    announced_uncertain = set()
    # MACs whose reset or configuration failed this run; drives the exit code.
    failed = set()  # type: set
    target_mac = _provision_target_mac(devices_state, args.address)
    with client_from_args(args) as client:
        print("Provisioning RFPs; press Ctrl+C to stop.", flush=True)
        try:
            while True:
                cycle_started = time.monotonic()
                if args.address:
                    addresses = [args.address]
                    if target_mac:
                        target_record = devices_state.get(target_mac)
                        if isinstance(target_record, dict) and target_record.get("assigned_ip"):
                            addresses.append(str(target_record["assigned_ip"]))
                    discovered = client.discover_addresses(addresses, attempts=1)
                    if target_mac:
                        discovered = {
                            mac: live for mac, live in discovered.items() if mac == target_mac
                        }
                    elif discovered:
                        if len(discovered) > 1:
                            raise ValueError("--address discovery returned more than one RFP")
                        target_mac = next(iter(discovered))
                else:
                    discovered = discover_devices(client, args, attempts=1)
                for mac in sorted(discovered):
                    live = discovered[mac]
                    address = str(live["address"] or args.proxy)
                    record = devices_state.get(mac)
                    if not isinstance(record, dict):
                        assigned = allocate_address(settings, devices_state)
                        record = {
                            "assigned_ip": assigned,
                            "phase": "reset_complete" if mac in previously_reset else "allocated",
                            "created_at": utc_now(),
                        }
                        if args.address:
                            record["initial_address"] = args.address
                        if mac in previously_reset:
                            record["imported_reset_history"] = previously_reset[mac]
                        devices_state[mac] = record
                        save_provision_state(args.state, state)
                        event = "IMPORT-RESET" if mac in previously_reset else "ALLOCATE"
                        print("%s %s  ip=%s" % (event, mac, assigned), flush=True)
                    record["last_seen_at"] = utc_now()
                    record["last_seen_address"] = live["address"]
                    phase = record.get("phase")
                    if phase == "allocated":
                        # Persist before transmitting.  If the process dies or
                        # the ACK is lost, an automatic second factory reset is
                        # deliberately forbidden.
                        record["phase"] = "reset_attempted"
                        record["reset_attempted_at"] = utc_now()
                        record.pop("error", None)
                        save_provision_state(args.state, state)
                        previously_reset[mac] = {
                            "address": live["address"],
                            "proxy": args.proxy,
                            "method": "secret" if secret is not None else "credentials",
                            "reset_attempted_at": record["reset_attempted_at"],
                            "status": "attempted-by-provision",
                        }
                        save_provision_state(args.state, state)
                        try:
                            factory_reset_one(
                                client,
                                address,
                                mac,
                                secret,
                                username,
                                password,
                                args.proxy,
                            )
                        except (OSError, PermissionError, TimeoutError, ProtocolError, ValueError) as exc:
                            record["error"] = str(exc)
                            save_provision_state(args.state, state)
                            failed.add(mac)
                            print("RESET-UNCERTAIN %s  ip=%s  error=%s" % (mac, record["assigned_ip"], exc))
                        else:
                            record["phase"] = "reset_complete"
                            record["reset_ack_at"] = utc_now()
                            previously_reset[mac]["reset_at"] = record["reset_ack_at"]
                            previously_reset[mac]["status"] = "acknowledged"
                            save_provision_state(args.state, state)
                            failed.discard(mac)
                            print("RESET %s  assigned-ip=%s" % (mac, record["assigned_ip"]), flush=True)
                        continue
                    if phase == "reset_attempted":
                        if mac not in announced_uncertain:
                            print(
                                "HOLD %s  reset outcome uncertain; not resetting twice" % mac,
                                flush=True,
                            )
                            announced_uncertain.add(mac)
                        continue
                    expected = desired_configuration(settings, str(record["assigned_ip"]))
                    # Older versions incorrectly sent action 9 after SET.  The
                    # real OMC labels that operation as a factory reset, not a
                    # reboot.  Recover those records by applying their saved
                    # configuration again without repeating the key reset.
                    if phase in ("reset_complete", "reboot_attempted"):
                        try:
                            client.exchange(
                                address,
                                mac,
                                SET,
                                encode_parameters(expected),
                                username,
                                password,
                                args.proxy,
                            )
                        except (OSError, PermissionError, TimeoutError, ProtocolError, ValueError) as exc:
                            record["error"] = str(exc)
                            save_provision_state(args.state, state)
                            failed.add(mac)
                            print("CONFIG-FAIL %s  error=%s" % (mac, exc), flush=True)
                            continue
                        record["phase"] = "configuration_sent"
                        record["configured_at"] = utc_now()
                        record.pop("error", None)
                        failed.discard(mac)
                        save_provision_state(args.state, state)
                        print(
                            "CONFIGURED %s  awaiting-ip=%s  ommip1=%s"
                            % (mac, record["assigned_ip"], settings["ommip1"]),
                            flush=True,
                        )
                        continue
                    if phase == "configuration_sent":
                        # A direct discovery response from the assigned address
                        # proves that the new IPv4 setting has taken effect.  A
                        # LIST response may legitimately be empty on older RFPs.
                        address_matches = args.proxy is None and live["address"] == record["assigned_ip"]
                        verified = False
                        try:
                            observed = client.exchange(
                                address,
                                mac,
                                LIST,
                                username=username,
                                password=password,
                                proxy=args.proxy,
                            )
                            config_matches = bool(observed) and not configuration_drift(expected, observed)
                            if (address_matches and (not observed or config_matches)) or (
                                args.proxy is not None and config_matches
                            ):
                                record["phase"] = "complete"
                                record["completed_at"] = utc_now()
                                record["last_observed"] = dict(observed)
                                record.pop("error", None)
                                save_provision_state(args.state, state)
                                failed.discard(mac)
                                print("COMPLETE %s  ip=%s" % (mac, record["assigned_ip"]), flush=True)
                                verified = True
                        except (OSError, PermissionError, TimeoutError, ProtocolError, ValueError):
                            pass
                        if not verified and seconds_since(record.get("configured_at")) >= args.config_retry:
                            try:
                                client.exchange(
                                    address,
                                    mac,
                                    SET,
                                    encode_parameters(expected),
                                    username,
                                    password,
                                    args.proxy,
                                )
                            except (OSError, PermissionError, TimeoutError, ProtocolError, ValueError) as exc:
                                record["error"] = str(exc)
                                failed.add(mac)
                                print("CONFIG-RETRY-FAIL %s  error=%s" % (mac, exc), flush=True)
                            else:
                                record["configured_at"] = utc_now()
                                record["configuration_attempts"] = int(
                                    record.get("configuration_attempts", 1)
                                ) + 1
                                record.pop("error", None)
                                print(
                                    "CONFIG-RETRY %s  awaiting-ip=%s"
                                    % (mac, record["assigned_ip"]),
                                    flush=True,
                                )
                            save_provision_state(args.state, state)
                if args.once:
                    break
                remaining = args.interval - (time.monotonic() - cycle_started)
                if remaining > 0:
                    time.sleep(remaining)
        except KeyboardInterrupt:
            print("\nProvisioning stopped. State saved to %s." % args.state)
    return 1 if failed else 0


def format_drift(drift: Mapping[str, Tuple[str, Optional[str]]]) -> str:
    return ",".join(
        "%s:%s!=%s" % (key, actual if actual is not None else "<missing>", expected)
        for key, (expected, actual) in drift.items()
    )


def command_reconcile(args: argparse.Namespace) -> int:
    state = load_provision_state(args.state)
    settings = state["settings"]
    devices_state = state["devices"]
    assert isinstance(settings, dict) and isinstance(devices_state, dict)
    if not settings:
        raise ValueError("provision state contains no settings")
    if args.apply and not confirm_write(
        args, "WARNING: this will write saved configuration to RFPs that have drifted."
    ):
        return 1
    username, password = credentials(args)
    failures = 0
    repaired = 0
    with client_from_args(args) as client:
        discovered = discover_devices(client, args)
        for mac in sorted(set(discovered) - set(devices_state)):
            route = discovered[mac]["address"] or args.proxy
            print("UNTRACKED %s  address=%s" % (mac, route))
        selected_macs = set(devices_state)
        if args.address:
            selected_macs = set(discovered) & set(devices_state)
            if not selected_macs:
                state_match = _provision_target_mac(devices_state, args.address)
                if state_match:
                    selected_macs.add(state_match)
            if not selected_macs:
                raise ValueError("no tracked RFP matches --address %s" % args.address)
        for mac in sorted(selected_macs):
            record = devices_state[mac]
            if not isinstance(record, dict) or not record.get("assigned_ip"):
                print("INVALID %s  state record has no assigned IP" % mac)
                failures += 1
                continue
            live = discovered.get(mac)
            if live is not None:
                address = str(live["address"] or args.proxy)
            elif args.proxy:
                address = args.proxy
            else:
                address = str(record["assigned_ip"])
            expected = desired_configuration(settings, str(record["assigned_ip"]))
            try:
                observed = client.exchange(
                    address,
                    mac,
                    LIST,
                    username=username,
                    password=password,
                    proxy=args.proxy,
                )
            except (OSError, PermissionError, TimeoutError, ProtocolError, ValueError) as exc:
                print("UNREACHABLE %s  assigned-ip=%s  error=%s" % (mac, record["assigned_ip"], exc))
                failures += 1
                continue
            drift = configuration_drift(expected, observed)
            record["last_reconciled_at"] = utc_now()
            record["last_observed"] = dict(observed)
            if not drift:
                record["phase"] = "complete"
                record.pop("error", None)
                print("MATCH %s  ip=%s" % (mac, record["assigned_ip"]))
                continue
            print("DRIFT %s  %s" % (mac, format_drift(drift)))
            if not args.apply:
                # Reporting mode: drift is an unresolved problem.
                failures += 1
                continue
            try:
                client.exchange(
                    address,
                    mac,
                    SET,
                    encode_parameters(expected),
                    username,
                    password,
                    args.proxy,
                )
            except (OSError, PermissionError, TimeoutError, ProtocolError, ValueError) as exc:
                record["error"] = str(exc)
                failures += 1
                print("APPLY-FAIL %s  error=%s" % (mac, exc))
                continue
            record["phase"] = "configuration_sent"
            record["reconciled_at"] = utc_now()
            record.pop("error", None)
            # The SET was acknowledged but not re-verified: a new IPv4 address
            # only takes effect once the RFP re-initialises, so count the
            # device as repaired rather than silently converged.
            repaired += 1
            print("APPLIED %s  awaiting-ip=%s" % (mac, record["assigned_ip"]))
        save_provision_state(args.state, state)
    if repaired:
        print("Repaired %d device(s); re-run reconcile to confirm convergence." % repaired)
    return 1 if failures else 0



