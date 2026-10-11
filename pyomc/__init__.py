"""Importable Python API for SIP-DECT OMC operations."""

__version__ = "0.5.0"

from . import commands
from .client import OMCClient
from .commands import (
    client_from_args, command_configure, command_provision,
    command_reconcile, command_reset, command_scan, credentials, discover_devices,
    factory_reset_one, locate, print_record, read_factory_secret,
)
from .cli import build_parser, main
from .protocol import (
    BACKDOOR, BROADCAST_MAC, CONFIG_PARAMETERS, COOKIEREQ, FACTORY_SECRET_SIZE,
    LIST, LIST_V2, PORT, PROXY, RESET, RESET_V2, SCAN, SET, SET_V2, V2_ACTION,
    ProtocolError, add_crc, build_packet, check_crc, derive_factory_key,
    encapsulate_proxy, encode_parameters, format_mac, mac_bytes, normalize_mac,
    omc_md5crypt, parse_packet, parse_parameters, posix_cksum,
    parse_proxy_frame,
)
from .proxy import OMCProxy, PendingRequest, command_proxy
from .state import (
    PROVISION_STATE_VERSION, allocate_address, configuration_drift,
    desired_configuration, import_legacy_reset_history, load_history,
    load_provision_state, parse_address_pool, parse_ipv4, parse_netmask,
    provision_settings, save_history, save_provision_state, seconds_since, utc_now,
)

__all__ = [name for name in globals() if not name.startswith("_")]

