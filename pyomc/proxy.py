"""A small OMC proxy relay for forwarding requests onto an RFP broadcast domain."""

from __future__ import annotations

from dataclasses import dataclass
import select
import socket
import time
from typing import List, Optional, Tuple

from .protocol import (
    PORT,
    PROXY,
    SCAN,
    ProtocolError,
    encapsulate_proxy,
    parse_packet,
    parse_proxy_frame,
)


@dataclass
class PendingRequest:
    client: Tuple[str, int]
    ident: int
    target_mac: str
    request_action: int
    expires_at: float

    def matches(self, ident: int, mac: str, response_action: int) -> bool:
        return (
            self.ident == ident
            and response_action == (self.request_action | 0x10)
            and (
                self.target_mac == "FF:FF:FF:FF:FF:FF"
                or self.target_mac == mac
            )
        )


class OMCProxy:
    """Relay OMC proxy frames between clients and a local broadcast domain."""

    def __init__(
        self,
        interface: str = "0.0.0.0",
        broadcast: str = "255.255.255.255",
        request_ttl: float = 5.0,
        sock: Optional[socket.socket] = None,
    ) -> None:
        if request_ttl <= 0:
            raise ValueError("proxy request TTL must be positive")
        self.interface = interface
        self.broadcast = broadcast
        self.request_ttl = request_ttl
        self.pending = []  # type: List[PendingRequest]
        self.sock = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if sock is None:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind((interface, PORT))
            self.sock.setblocking(False)

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> "OMCProxy":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def _expire(self, now: float) -> None:
        self.pending = [request for request in self.pending if request.expires_at > now]

    def relay_datagram(
        self,
        packet: bytes,
        sender: Tuple[str, int],
        now: Optional[float] = None,
    ) -> Optional[str]:
        """Process one datagram, returning a short event description when relayed."""
        current = time.monotonic() if now is None else now
        self._expire(current)

        try:
            _, outer_action, inner = parse_proxy_frame(packet)
        except ProtocolError:
            outer_action = -1
            inner = b""

        if outer_action == PROXY:
            ident, target_mac, request_action, _ = parse_packet(inner, allow_proxy=False)
            if request_action & 0x10:
                return None
            request = PendingRequest(
                sender,
                ident,
                target_mac,
                request_action,
                current + self.request_ttl,
            )
            self.pending = [
                existing
                for existing in self.pending
                if not (
                    existing.client == request.client
                    and existing.ident == request.ident
                    and existing.target_mac == request.target_mac
                    and existing.request_action == request.request_action
                )
            ]
            self.pending.append(request)
            self.sock.sendto(inner, (self.broadcast, PORT))
            return "REQUEST client=%s mac=%s action=%d" % (
                sender[0],
                target_mac,
                request_action,
            )

        try:
            ident, mac, response_action, _ = parse_packet(packet, allow_proxy=False)
        except ProtocolError:
            return None
        if not response_action & 0x10:
            return None

        matched = [
            request
            for request in self.pending
            if request.matches(ident, mac, response_action)
        ]
        if not matched:
            return None
        wrapped = encapsulate_proxy(packet, response=True)
        for request in matched:
            self.sock.sendto(wrapped, request.client)
        # SCAN can legitimately return multiple RFP replies. Other requests
        # have a single response and no longer need a correlation entry.
        completed = {id(request) for request in matched if request.request_action != SCAN}
        self.pending = [request for request in self.pending if id(request) not in completed]
        return "RESPONSE mac=%s action=%d clients=%d" % (mac, response_action, len(matched))

    def run(self, quiet: bool = False) -> None:
        if not quiet:
            print(
                "OMC proxy listening on %s:%d; downstream broadcast=%s"
                % (self.interface, PORT, self.broadcast),
                flush=True,
            )
            print("Press Ctrl+C to stop.", flush=True)
        try:
            while True:
                ready, _, _ = select.select([self.sock], [], [], 1.0)
                if not ready:
                    self._expire(time.monotonic())
                    continue
                packet, sender = self.sock.recvfrom(65535)
                event = self.relay_datagram(packet, sender)
                if event and not quiet:
                    print(event, flush=True)
        except KeyboardInterrupt:
            if not quiet:
                print("\nProxy stopped.")


def command_proxy(args) -> int:
    with OMCProxy(
        interface=args.interface,
        broadcast=args.broadcast,
        request_ttl=args.request_ttl,
    ) as relay:
        relay.run(quiet=args.quiet)
    return 0
