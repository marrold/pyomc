"""UDP transport and request/reply client for OMC-compatible RFPs."""

from __future__ import annotations

from collections import OrderedDict
import ipaddress
import select
import socket
import time
from typing import Dict, Iterable, Optional, Sequence, Tuple

from .protocol import (
    BROADCAST_MAC, PORT, PROXY, SCAN, V2_ACTION, ProtocolError, build_packet,
    encapsulate_proxy, mac_bytes, normalize_mac, parse_packet, parse_parameters,
)

class OMCClient:
    def __init__(
        self,
        interface: str = "0.0.0.0",
        broadcast: str = "255.255.255.255",
        timeout: float = 2.0,
        attempts: int = 2,
    ) -> None:
        self.interface = interface
        self.broadcast = broadcast
        self.timeout = timeout
        self.attempts = attempts
        self._ident = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind((interface, PORT))
        self.sock.setblocking(False)

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> "OMCClient":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def next_ident(self) -> int:
        value = self._ident
        self._ident = (self._ident + 1) & 0xFF
        return value

    def _receive_until(self, deadline: float) -> Iterable[Tuple[bytes, str]]:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            ready, _, _ = select.select([self.sock], [], [], remaining)
            if not ready:
                return
            data, address = self.sock.recvfrom(65535)
            yield data, address[0]

    def discover(
        self,
        attempts: Optional[int] = None,
        proxy: Optional[str] = None,
    ) -> Dict[str, Dict[str, object]]:
        found = {}  # type: Dict[str, Dict[str, object]]
        ident = self.next_ident()
        packet = build_packet(ident, BROADCAST_MAC, SCAN)
        if proxy is not None:
            packet = encapsulate_proxy(packet)
        destination = socket.gethostbyname(proxy) if proxy is not None else self.broadcast
        send_attempts = self.attempts if attempts is None else attempts
        if send_attempts < 1:
            raise ValueError("discovery attempts must be at least one")
        for _ in range(send_attempts):
            self.sock.sendto(packet, (destination, PORT))
            for data, address in self._receive_until(time.monotonic() + self.timeout):
                try:
                    reply_ident, mac, action, payload = parse_packet(data)
                except ProtocolError:
                    continue
                if reply_ident == ident and action == (SCAN | 0x10):
                    found[mac] = {
                        "address": None if proxy is not None else address,
                        "proxy": proxy,
                        "scan": parse_parameters(payload),
                    }
        return found

    def discover_subnet(
        self,
        subnet: str,
        attempts: Optional[int] = None,
    ) -> Dict[str, Dict[str, object]]:
        """Discover RFPs by unicasting a scan request to every subnet host."""
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
            raise ValueError("--scan-subnet must be an IPv4 CIDR subnet") from exc
        if network.num_addresses > 65536:
            raise ValueError("L3 scans are limited to 65536 addresses (/16)")

        return self.discover_addresses(
            [str(address) for address in network.hosts()],
            attempts=attempts,
        )

    def discover_address(
        self,
        address: str,
        attempts: Optional[int] = None,
    ) -> Dict[str, Dict[str, object]]:
        """Discover an RFP at exactly one IPv4 address."""
        return self.discover_addresses([address], attempts=attempts)

    def discover_addresses(
        self,
        addresses: Sequence[str],
        attempts: Optional[int] = None,
    ) -> Dict[str, Dict[str, object]]:
        """Discover RFPs by unicasting one scan request to each IPv4 address."""
        destinations = []
        seen_destinations = set()
        for value in addresses:
            try:
                address = str(ipaddress.IPv4Address(value))
            except ipaddress.AddressValueError as exc:
                raise ValueError("discovery target must be an IPv4 address") from exc
            if address not in seen_destinations:
                destinations.append(address)
                seen_destinations.add(address)
        if not destinations:
            raise ValueError("at least one discovery target is required")

        found = {}  # type: Dict[str, Dict[str, object]]
        ident = self.next_ident()
        packet = build_packet(ident, BROADCAST_MAC, SCAN)
        send_attempts = self.attempts if attempts is None else attempts
        if send_attempts < 1:
            raise ValueError("discovery attempts must be at least one")

        for _ in range(send_attempts):
            for address in destinations:
                self.sock.sendto(packet, (address, PORT))
            for data, address in self._receive_until(time.monotonic() + self.timeout):
                try:
                    reply_ident, mac, action, payload = parse_packet(data)
                except ProtocolError:
                    continue
                if reply_ident == ident and action == (SCAN | 0x10):
                    found[mac] = {
                        "address": address,
                        "proxy": None,
                        "scan": parse_parameters(payload),
                    }
        return found

    def exchange(
        self,
        address: str,
        mac: str,
        action: int,
        payload: bytes = b"",
        username: Optional[str] = None,
        password: Optional[str] = None,
        proxy: Optional[str] = None,
    ) -> "OrderedDict[str, str]":
        response, _ = self.exchange_with_status(
            address, mac, action, payload, username, password, proxy
        )
        return response

    def exchange_with_status(
        self,
        address: str,
        mac: str,
        action: int,
        payload: bytes = b"",
        username: Optional[str] = None,
        password: Optional[str] = None,
        proxy: Optional[str] = None,
    ) -> "Tuple[OrderedDict[str, str], bool]":
        """Exchange a packet and report whether V2 authentication completed."""
        target = mac_bytes(mac)
        challenge = None  # type: Optional[bytes]
        for auth_round in range(2):
            ident = self.next_ident()
            packet = build_packet(ident, target, action, payload, username, password, challenge)
            if proxy is not None:
                packet = encapsulate_proxy(packet)
            destination = socket.gethostbyname(proxy if proxy is not None else address)
            expected_action = V2_ACTION[action] if challenge is not None else action
            response = None  # type: Optional[OrderedDict[str, str]]
            for _ in range(self.attempts):
                self.sock.sendto(packet, (destination, PORT))
                deadline = time.monotonic() + self.timeout
                for data, source in self._receive_until(deadline):
                    try:
                        reply_ident, reply_mac, reply_action, reply_payload = parse_packet(data)
                    except ProtocolError:
                        continue
                    if (
                        source == destination
                        and reply_ident == ident
                        and reply_mac == normalize_mac(mac)
                        and reply_action == (expected_action | 0x10)
                    ):
                        response = parse_parameters(reply_payload)
                        break
                if response is not None:
                    break
            if response is None:
                if challenge is not None:
                    raise PermissionError("%s authentication failed or timed out" % mac)
                raise TimeoutError("no response from %s (%s)" % (mac, address))
            challenge_text = response.get("version_mismatch")
            if challenge_text is None:
                return response, challenge is not None
            if auth_round or username is None or password is None:
                raise PermissionError("%s requires valid OMM credentials" % mac)
            try:
                challenge = bytes.fromhex(challenge_text)
            except ValueError as exc:
                raise ProtocolError("RFP returned a malformed authentication challenge") from exc
            if len(challenge) != 16:
                raise ProtocolError("RFP authentication challenge is not 16 bytes")
        raise ProtocolError("authentication retry did not complete")



