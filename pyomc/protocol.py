"""OMC wire-format constants, codecs, authentication, and proxy framing."""

from __future__ import annotations

from collections import OrderedDict
import hashlib
import struct
from typing import Mapping, Optional, Tuple

PORT = 64000
BROADCAST_MAC = b"\xff" * 6
FACTORY_SECRET_SIZE = 256
PROVISION_STATE_VERSION = 1

SET = 1
LIST = 2
SET_V2 = 3
LIST_V2 = 4
SCAN = 5
COOKIEREQ = 6
BACKDOOR = 7
PROXY = 8
RESET = 9
RESET_V2 = 10

V2_ACTION = {SET: SET_V2, LIST: LIST_V2, RESET: RESET_V2}

# ParamsEnum in OMC.  stream is intentionally not accepted from the command
# line: OMC itself always writes the fixed value SIP-DECT.
CONFIG_PARAMETERS = (
    "use_local_cfg",
    "ip",
    "subnet",
    "siaddr",
    "boot_file",
    "ommip1",
    "ommip2",
    "router",
    "syslgip",
    "syslgport",
    "dns",
    "tftp",
    "ipv6",
    "ipv6prefix_len",
    "ipv6_gateway",
    "eventmgrstart",
    "mosquittostart",
)

_ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


class ProtocolError(ValueError):
    """A received or requested packet is invalid."""


def normalize_mac(value: str) -> str:
    compact = value.replace(":", "").replace("-", "").replace(".", "").strip()
    if len(compact) != 12:
        raise ValueError("MAC address must contain 12 hexadecimal digits")
    try:
        raw = bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError("MAC address contains a non-hexadecimal character") from exc
    return ":".join("%02X" % octet for octet in raw)


def mac_bytes(value: str) -> bytes:
    return bytes.fromhex(normalize_mac(value).replace(":", ""))


def format_mac(value: bytes) -> str:
    if len(value) != 6:
        raise ProtocolError("a MAC address must be six bytes")
    return ":".join("%02X" % octet for octet in value)


def posix_cksum(data: bytes) -> int:
    """Return the CRC used by POSIX cksum (not zlib.crc32)."""
    crc = 0
    for octet in data:
        crc ^= octet << 24
        for _ in range(8):
            crc = ((crc << 1) ^ (0x04C11DB7 if crc & 0x80000000 else 0)) & 0xFFFFFFFF
    length = len(data)
    while length:
        crc ^= (length & 0xFF) << 24
        for _ in range(8):
            crc = ((crc << 1) ^ (0x04C11DB7 if crc & 0x80000000 else 0)) & 0xFFFFFFFF
        length >>= 8
    return (~crc) & 0xFFFFFFFF


def add_crc(data: bytes) -> bytes:
    return data + struct.pack(">I", posix_cksum(data))


def check_crc(packet: bytes) -> bool:
    return len(packet) >= 4 and struct.unpack(">I", packet[-4:])[0] == posix_cksum(packet[:-4])


def encapsulate_proxy(packet: bytes, response: bool = False) -> bytes:
    """Wrap a complete inner packet in an OMC proxy request or response."""
    if len(packet) < 13 or not check_crc(packet):
        raise ProtocolError("cannot proxy an invalid inner packet")
    action = PROXY | (0x10 if response else 0)
    return add_crc(packet[:2] + BROADCAST_MAC + bytes((action,)) + packet)


def parse_proxy_frame(packet: bytes) -> Tuple[int, int, bytes]:
    """Validate a proxy frame and return outer ident, action, and inner packet."""
    if len(packet) < 26 or not check_crc(packet):
        raise ProtocolError("proxy frame is invalid")
    ident = struct.unpack(">H", packet[:2])[0]
    action = packet[8]
    if action not in (PROXY, PROXY | 0x10):
        raise ProtocolError("packet is not a proxy frame")
    inner = packet[9:-4]
    parse_packet(inner, allow_proxy=False)
    return ident, action, inner


def _to64(value: int, count: int) -> str:
    result = []
    for _ in range(count):
        result.append(_ITOA64[value & 0x3F])
        value >>= 6
    return "".join(result)


def omc_md5crypt(password: str) -> str:
    """OMC's empty-salt $1$ password transform."""
    pw = password.encode("utf-8")
    magic = b"$1$"
    first = hashlib.md5(pw + pw).digest()
    ctx = hashlib.md5(pw + magic)
    remaining = len(pw)
    while remaining > 0:
        ctx.update(first[: min(remaining, 16)])
        remaining -= 16
    remaining = len(pw)
    while remaining:
        # This is the same odd bit-loop used by OMC's Java implementation.
        ctx.update(b"\x00" if remaining & 1 else pw[:1])
        remaining >>= 1
    digest = ctx.digest()
    for index in range(1000):
        ctx = hashlib.md5()
        ctx.update(pw if index & 1 else digest)
        if index % 3:
            pass  # The salt is empty.
        if index % 7:
            ctx.update(pw)
        ctx.update(digest if index & 1 else pw)
        digest = ctx.digest()
    encoded = []
    for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
        encoded.append(_to64((digest[a] << 16) | (digest[b] << 8) | digest[c], 4))
    encoded.append(_to64(digest[11], 2))
    return "$1$$" + "".join(encoded)


def derive_factory_key(cookie: bytes, secret: bytes) -> bytes:
    """Return the raw 16-byte BACKDOOR key for a cookie and reset secret."""
    if len(cookie) != 16:
        raise ValueError("factory-reset cookie must be 16 bytes")
    if len(secret) != FACTORY_SECRET_SIZE:
        raise ValueError("factory-reset secret file must contain exactly 256 bytes")
    return hashlib.md5(cookie + secret).digest()


def encode_parameters(parameters: Mapping[str, str]) -> bytes:
    return b"".join(
        ("%s=%s" % (key, value)).encode("utf-8") + b"\x00"
        for key, value in parameters.items()
    )


def parse_parameters(payload: bytes) -> "OrderedDict[str, str]":
    result = OrderedDict()  # type: OrderedDict[str, str]
    for item in payload.rstrip(b"\x00").split(b"\x00"):
        if not item or b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        result[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
    return result


def build_packet(
    ident: int,
    target_mac: bytes,
    action: int,
    payload: bytes = b"",
    username: Optional[str] = None,
    password: Optional[str] = None,
    challenge: Optional[bytes] = None,
) -> bytes:
    if not 0 <= ident <= 0xFF:
        raise ProtocolError("packet ident must fit in OMC's eight-bit counter")
    if len(target_mac) != 6:
        raise ProtocolError("target MAC must be six bytes")
    authenticated = challenge is not None
    if authenticated:
        if action not in V2_ACTION or username is None or password is None:
            raise ProtocolError("authenticated packet needs a supported action and OMM credentials")
        if len(challenge) != 16:
            raise ProtocolError("authentication challenge must be 16 bytes")
        action = V2_ACTION[action]
    body = struct.pack(">H", ident) + target_mac + bytes((action,)) + payload
    if authenticated:
        user = username[:8].encode("utf-8")
        if len(user) > 8:
            raise ProtocolError("username's first eight characters are not eight UTF-8 bytes")
        body += user.ljust(9, b"\x00")
        digest = hashlib.md5(body + omc_md5crypt(password).encode("ascii") + challenge).digest()
        body += digest
    return add_crc(body)


def parse_packet(packet: bytes, allow_proxy: bool = True) -> Tuple[int, str, int, bytes]:
    if len(packet) < 13:
        raise ProtocolError("packet is shorter than the 13-byte minimum")
    if not check_crc(packet):
        raise ProtocolError("packet CRC is invalid")
    ident = struct.unpack(">H", packet[:2])[0]
    action = packet[8]
    payload = packet[9:-4]
    if action in (PROXY, PROXY | 0x10):
        if not allow_proxy:
            raise ProtocolError("nested proxy packet is invalid")
        return parse_packet(payload, allow_proxy=False)
    return ident, format_mac(packet[2:8]), action, payload



