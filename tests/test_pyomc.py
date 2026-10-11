import struct
import tempfile
import unittest
from collections import OrderedDict
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pyomc as omc


class PacketTests(unittest.TestCase):
    def test_scan_vector(self):
        packet = omc.build_packet(0, omc.BROADCAST_MAC, omc.SCAN)
        self.assertEqual(packet.hex(), "0000ffffffffffff051b43edda")

    def test_list_vector(self):
        packet = omc.build_packet(7, bytes.fromhex("00304222898a"), omc.LIST)
        self.assertEqual(packet.hex(), "000700304222898a0291fa7ea1")

    def test_authenticated_set_vector(self):
        payload = b"ip=192.168.1.5\0stream=SIP-DECT\0"
        packet = omc.build_packet(
            9,
            bytes.fromhex("00304222898a"),
            omc.SET,
            payload,
            "omm",
            "omm",
            bytes(range(16)),
        )
        self.assertEqual(
            packet.hex(),
            "000900304222898a0369703d3139322e3136382e312e350073747265616d3d"
            "5349502d44454354006f6d6d0000000000003b7934a3e8bc91a434a9544266"
            "0abd847e496a48",
        )

    def test_md5crypt_known_value(self):
        self.assertEqual(omc.omc_md5crypt("omm"), "$1$$dHMOSgyKKuOkWB6rgPwRv1")

    def test_factory_key_is_raw_md5(self):
        cookie = bytes(range(16))
        secret = bytes(range(256))
        self.assertEqual(omc.derive_factory_key(cookie, secret), __import__("hashlib").md5(cookie + secret).digest())

    def test_factory_key_rejects_wrong_secret_size(self):
        with self.assertRaisesRegex(ValueError, "exactly 256 bytes"):
            omc.derive_factory_key(bytes(16), bytes(255))

    def test_factory_reset_uses_credentials_without_secret(self):
        class FakeClient:
            def __init__(self):
                self.calls = []

            def exchange(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                return OrderedDict()

        client = FakeClient()
        omc.factory_reset_one(client, "10.0.0.2", "00:30:42:22:89:8A", None, "omm", "pw")
        args, kwargs = client.calls[0]
        self.assertEqual(args[:3], ("10.0.0.2", "00:30:42:22:89:8A", omc.RESET))
        self.assertEqual(kwargs["username"], "omm")
        self.assertEqual(kwargs["password"], "pw")

    def test_factory_reset_prefers_secret_when_supplied(self):
        class FakeClient:
            def __init__(self):
                self.calls = []

            def exchange(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                if args[2] == omc.COOKIEREQ:
                    return OrderedDict((("cookie", bytes(range(16)).hex()),))
                return OrderedDict()

        client = FakeClient()
        secret = bytes(range(256))
        omc.factory_reset_one(
            client,
            "10.0.0.2",
            "00:30:42:22:89:8A",
            secret,
            "ignored-user",
            "ignored-password",
        )
        self.assertEqual([call[0][2] for call in client.calls], [omc.COOKIEREQ, omc.BACKDOOR])
        self.assertEqual(client.calls[1][0][3], omc.derive_factory_key(bytes(range(16)), secret))

    def test_cksum_matches_documented_scan(self):
        body = bytes.fromhex("0000ffffffffffff05")
        self.assertEqual(omc.posix_cksum(body), 0x1B43EDDA)

    def test_parse_reply(self):
        body = struct.pack(">H", 4) + bytes.fromhex("00304222898a") + b"\x12ip=1.2.3.4\0foo=bar\0"
        packet = omc.add_crc(body)
        ident, mac, action, payload = omc.parse_packet(packet)
        self.assertEqual((ident, mac, action), (4, "00:30:42:22:89:8A", 0x12))
        self.assertEqual(
            omc.parse_parameters(payload), OrderedDict((("ip", "1.2.3.4"), ("foo", "bar")))
        )

    def test_proxy_encapsulation_and_unwrap(self):
        inner = omc.build_packet(7, bytes.fromhex("00304222898a"), omc.LIST)
        outer = omc.encapsulate_proxy(inner)
        self.assertTrue(omc.check_crc(outer))
        self.assertEqual(outer[:9], bytes.fromhex("0007ffffffffffff08"))
        self.assertEqual(outer[9:-4], inner)
        self.assertEqual(omc.parse_packet(outer), omc.parse_packet(inner))

        reply = omc.encapsulate_proxy(inner, response=True)
        ident, action, unwrapped = omc.parse_proxy_frame(reply)
        self.assertEqual((ident, action, unwrapped), (7, omc.PROXY | 0x10, inner))

    def test_proxy_reply_is_unwrapped(self):
        inner_body = bytes.fromhex("000700304222898a") + b"\x12ip=10.0.0.2\0"
        inner = omc.add_crc(inner_body)
        outer_body = bytes.fromhex("0007ffffffffffff18") + inner
        outer = omc.add_crc(outer_body)
        ident, mac, action, payload = omc.parse_packet(outer)
        self.assertEqual((ident, mac, action), (7, "00:30:42:22:89:8A", 0x12))
        self.assertEqual(omc.parse_parameters(payload)["ip"], "10.0.0.2")

    def test_bad_crc_is_rejected(self):
        packet = bytearray(omc.build_packet(0, omc.BROADCAST_MAC, omc.SCAN))
        packet[-1] ^= 1
        with self.assertRaises(omc.ProtocolError):
            omc.parse_packet(bytes(packet))

    def test_mac_normalization(self):
        self.assertEqual(omc.normalize_mac("00-30-42-22-89-8a"), "00:30:42:22:89:8A")

    def test_parameter_round_trip_keeps_unknown_version_field(self):
        values = OrderedDict((("ip", "10.0.0.2"), ("software_version", "10.0")))
        self.assertEqual(omc.parse_parameters(omc.encode_parameters(values)), values)

    def test_reset_history_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.json"
            history = {"version": 1, "reset": {"00:30:42:22:89:8A": {"address": "10.0.0.2"}}}
            omc.save_history(path, history)
            self.assertEqual(omc.load_history(path), history)

    def test_legacy_reset_history_imports_into_unified_state(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy_path = Path(directory) / "rfp-reset-history.json"
            state_path = Path(directory) / "rfp-provision-state.json"
            mac = "00:30:42:22:89:8A"
            omc.save_history(legacy_path, {"version": 1, "reset": {mac: {"ok": True}}})
            state = omc.load_provision_state(state_path)
            self.assertEqual(omc.import_legacy_reset_history(state, legacy_path), 1)
            omc.save_provision_state(state_path, state)
            self.assertEqual(omc.load_provision_state(state_path)["reset"][mac], {"ok": True})
            self.assertEqual(omc.import_legacy_reset_history(state, legacy_path), 0)

    def test_embedded_reset_record_migrates_into_unified_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "rfp-provision-state.json"
            mac = "00:30:42:22:89:8A"
            omc.save_history(
                state_path,
                {
                    "version": 1,
                    "settings": {},
                    "devices": {mac: {"imported_reset_history": {"reset_at": "now"}}},
                },
            )
            state = omc.load_provision_state(state_path)
            self.assertEqual(state["reset"][mac], {"reset_at": "now"})


class ScanTests(unittest.TestCase):
    def test_omm_password_environment_variable(self):
        args = omc.build_parser().parse_args(["scan", "--username", "omm"])
        with patch.dict(
            omc.commands.os.environ,
            {"OMM_PASSWORD": "secret"},
            clear=True,
        ):
            self.assertEqual(omc.credentials(args), ("omm", "secret"))

    def test_scan_reports_each_mac_only_once_until_interrupted(self):
        record = {"address": "10.0.0.2", "scan": OrderedDict((("name", "rfp"),))}

        class FakeClient:
            calls = 0
            list_calls = 0

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return None

            def discover(self, attempts=None, proxy=None):
                self.assert_attempts = attempts
                self.assert_proxy = proxy
                self.calls += 1
                if self.calls == 3:
                    raise KeyboardInterrupt
                return {"00:30:42:22:89:8A": record}

            def exchange_with_status(self, *unused, **unused_keywords):
                self.list_calls += 1
                return OrderedDict((("ip", "10.0.0.2"),)), True

        fake = FakeClient()
        args = omc.build_parser().parse_args(["scan", "--interval", "0"])
        output = StringIO()
        with patch.object(omc.commands, "client_from_args", return_value=fake), redirect_stdout(output):
            self.assertEqual(omc.command_scan(args), 0)
        self.assertEqual(fake.list_calls, 1)
        self.assertEqual(fake.assert_attempts, 1)
        self.assertIsNone(fake.assert_proxy)
        self.assertEqual(output.getvalue().count("00:30:42:22:89:8A"), 1)
        self.assertIn(
            "00:30:42:22:89:8A  10.0.0.2  login=authenticated  ip=10.0.0.2\n",
            output.getvalue(),
        )
        self.assertNotIn("scan.name", output.getvalue())
        self.assertIn("Stopped after discovering 1 RFP(s).", output.getvalue())

    def test_scan_address_exits_once_target_is_found(self):
        record = {"address": "10.0.0.2", "proxy": None, "scan": OrderedDict()}

        class FakeClient:
            address_calls = 0

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return None

            def discover_address(self, address, attempts=None):
                self.address_calls += 1
                return {"00:30:42:22:89:8A": record}

            def exchange_with_status(self, *unused, **unused_keywords):
                return OrderedDict((("ip", "10.0.0.2"),)), True

        fake = FakeClient()
        args = omc.build_parser().parse_args(["scan", "--address", "10.0.0.2"])
        output = StringIO()
        with patch.object(omc.commands, "client_from_args", return_value=fake), redirect_stdout(output):
            self.assertEqual(omc.command_scan(args), 0)
        # One pass found the target, so the loop exits without a second pass
        # and without needing a KeyboardInterrupt.
        self.assertEqual(fake.address_calls, 1)
        self.assertEqual(output.getvalue().count("00:30:42:22:89:8A"), 1)
        self.assertNotIn("Stopped after discovering", output.getvalue())

    def test_scan_address_keeps_trying_until_target_appears(self):
        record = {"address": "10.0.0.2", "proxy": None, "scan": OrderedDict()}

        class FakeClient:
            address_calls = 0

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return None

            def discover_address(self, address, attempts=None):
                self.address_calls += 1
                return {} if self.address_calls < 3 else {"00:30:42:22:89:8A": record}

            def exchange_with_status(self, *unused, **unused_keywords):
                return OrderedDict((("ip", "10.0.0.2"),)), True

        fake = FakeClient()
        args = omc.build_parser().parse_args(["scan", "--address", "10.0.0.2", "--interval", "0"])
        output = StringIO()
        with patch.object(omc.commands, "client_from_args", return_value=fake), redirect_stdout(output):
            self.assertEqual(omc.command_scan(args), 0)
        self.assertEqual(fake.address_calls, 3)
        self.assertEqual(output.getvalue().count("00:30:42:22:89:8A"), 1)

    def test_scan_defaults_to_ten_second_broadcast_interval(self):
        args = omc.build_parser().parse_args(["scan"])
        self.assertEqual(args.interval, 10.0)

    def test_l3_scan_sends_one_probe_to_each_usable_address(self):
        class FakeSocket:
            def __init__(self):
                self.sent = []

            def sendto(self, packet, destination):
                self.sent.append((packet, destination))

        client = omc.OMCClient.__new__(omc.OMCClient)
        client.timeout = 2.0
        client.attempts = 2
        client._ident = 0
        client.sock = FakeSocket()
        reply = omc.add_crc(
            struct.pack(">H", 0)
            + bytes.fromhex("00304222898a")
            + bytes((omc.SCAN | 0x10,))
            + b"ip=10.0.0.2\0"
        )
        client._receive_until = lambda deadline: iter(((reply, "10.0.0.2"),))

        found = client.discover_subnet("10.0.0.0/30", attempts=1)

        self.assertEqual(
            [destination for _, destination in client.sock.sent],
            [("10.0.0.1", omc.PORT), ("10.0.0.2", omc.PORT)],
        )
        self.assertEqual(found["00:30:42:22:89:8A"]["address"], "10.0.0.2")

    def test_exact_address_scan_sends_one_probe(self):
        class FakeSocket:
            def __init__(self):
                self.sent = []

            def sendto(self, packet, destination):
                self.sent.append((packet, destination))

        client = omc.OMCClient.__new__(omc.OMCClient)
        client.timeout = 2.0
        client.attempts = 2
        client._ident = 0
        client.sock = FakeSocket()
        client._receive_until = lambda deadline: iter(())

        client.discover_address("10.0.0.2", attempts=1)

        self.assertEqual(
            [destination for _, destination in client.sock.sent],
            [("10.0.0.2", omc.PORT)],
        )

    def test_scan_subnet_and_proxy_are_mutually_exclusive(self):
        errors = StringIO()
        with redirect_stderr(errors):
            result = omc.main(
                ["scan", "--scan-subnet", "10.0.0.0/24", "--proxy", "10.0.0.1"]
            )
        self.assertEqual(result, 2)
        self.assertIn("cannot be combined", errors.getvalue())

    def test_scan_rejects_subnet_as_scan_subnet_alias(self):
        parser = omc.build_parser()
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["scan", "--subnet", "10.0.0.0/24"])

    def test_configure_separates_scan_subnet_from_static_netmask(self):
        args = omc.build_parser().parse_args(
            [
                "configure",
                "00:30:42:22:89:8A",
                "--scan-subnet",
                "10.0.0.0/24",
                "--subnet",
                "255.255.255.0",
            ]
        )
        self.assertEqual(args.scan_subnet, "10.0.0.0/24")
        self.assertEqual(args.subnet, "255.255.255.0")

    def test_shared_discovery_uses_l3_subnet(self):
        class FakeClient:
            subnet_call = None

            def discover_subnet(self, subnet, attempts=None):
                self.subnet_call = (subnet, attempts)
                return {"00:30:42:22:89:8A": {"address": "10.0.0.2"}}

            def discover(self, attempts=None, proxy=None):
                raise AssertionError("broadcast discovery should not be used")

        args = omc.build_parser().parse_args(
            ["reset", "--scan-subnet", "10.0.0.0/24"]
        )
        client = FakeClient()
        devices = omc.discover_devices(client, args, attempts=1)
        self.assertIn("00:30:42:22:89:8A", devices)
        self.assertEqual(client.subnet_call, ("10.0.0.0/24", 1))

    def test_shared_discovery_uses_exact_address(self):
        class FakeClient:
            address_call = None

            def discover_address(self, address, attempts=None):
                self.address_call = (address, attempts)
                return {"00:30:42:22:89:8A": {"address": address}}

            def discover(self, attempts=None, proxy=None):
                raise AssertionError("broadcast discovery should not be used")

        args = omc.build_parser().parse_args(
            ["reset", "--address", "10.0.0.2"]
        )
        client = FakeClient()
        devices = omc.discover_devices(client, args, attempts=1)
        self.assertIn("00:30:42:22:89:8A", devices)
        self.assertEqual(client.address_call, ("10.0.0.2", 1))

    def test_configure_location_uses_l3_subnet(self):
        class FakeClient:
            def discover_subnet(self, subnet, attempts=None):
                self.subnet = subnet
                return {
                    "00:30:42:22:89:8A": {
                        "address": "10.0.0.2",
                        "proxy": None,
                        "scan": OrderedDict(),
                    }
                }

            def discover(self, attempts=None, proxy=None):
                raise AssertionError("broadcast discovery should not be used")

        args = omc.build_parser().parse_args(
            ["configure", "00:30:42:22:89:8A", "--scan-subnet", "10.0.0.0/24", "--ip", "10.0.0.2"]
        )
        client = FakeClient()
        address = omc.locate(client, "00:30:42:22:89:8A", args)
        self.assertEqual(address, "10.0.0.2")
        self.assertEqual(client.subnet, "10.0.0.0/24")

    def test_configure_targeted_address_confirms_mac(self):
        class FakeClient:
            def discover_address(self, address, attempts=None):
                self.address = address
                return {
                    "00:30:42:22:89:8A": {
                        "address": address,
                        "proxy": None,
                        "scan": OrderedDict(),
                    }
                }

        args = omc.build_parser().parse_args(
            ["configure", "00:30:42:22:89:8A", "--address", "10.0.0.2", "--ip", "10.0.0.2"]
        )
        client = FakeClient()
        self.assertEqual(omc.locate(client, "00:30:42:22:89:8A", args), "10.0.0.2")
        self.assertEqual(client.address, "10.0.0.2")

    def test_configure_targeted_address_rejects_wrong_mac(self):
        class FakeClient:
            def discover_address(self, address, attempts=None):
                return {
                    "00:30:42:22:89:99": {
                        "address": address,
                        "proxy": None,
                        "scan": OrderedDict(),
                    }
                }

        args = omc.build_parser().parse_args(
            ["configure", "00:30:42:22:89:8A", "--address", "10.0.0.2", "--ip", "10.0.0.2"]
        )
        with self.assertRaises(TimeoutError):
            omc.locate(FakeClient(), "00:30:42:22:89:8A", args)

    def test_no_reboot_subcommand(self):
        # Action 9 is a factory reset, not a reboot; there is deliberately no
        # reboot command, so argparse must reject it as an invalid choice.
        with self.assertRaises(SystemExit):
            omc.build_parser().parse_args(["reboot", "00:30:42:22:89:8A"])
        self.assertFalse(hasattr(omc, "command_reboot"))


class ConfirmWriteTests(unittest.TestCase):
    def test_force_bypasses_prompt(self):
        args = omc.build_parser().parse_args(
            ["configure", "00:30:42:22:89:8A", "--ip", "10.0.0.2", "--force"]
        )
        self.assertTrue(omc.commands.confirm_write(args, "WARNING"))

    def test_non_interactive_without_force_refuses(self):
        args = omc.build_parser().parse_args(
            ["configure", "00:30:42:22:89:8A", "--ip", "10.0.0.2"]
        )
        with patch("sys.stdin.isatty", return_value=False):
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as err:
                self.assertFalse(omc.commands.confirm_write(args, "WARNING"))
        self.assertIn("--force", err.getvalue())

    def test_interactive_yes_proceeds_and_no_aborts(self):
        args = omc.build_parser().parse_args(
            ["configure", "00:30:42:22:89:8A", "--ip", "10.0.0.2"]
        )
        with patch("sys.stdin.isatty", return_value=True):
            with patch("builtins.input", return_value="y"), redirect_stdout(StringIO()):
                self.assertTrue(omc.commands.confirm_write(args, "WARNING"))
            with patch("builtins.input", return_value=""), redirect_stdout(StringIO()):
                self.assertFalse(omc.commands.confirm_write(args, "WARNING"))

    def test_configure_aborts_without_confirmation(self):
        class FakeClient:
            located = False

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return None

            def discover(self, *unused, **unused_keywords):
                FakeClient.located = True
                return {}

        args = omc.build_parser().parse_args(
            ["configure", "00:30:42:22:89:8A", "--ip", "10.0.0.2", "--password", "omm"]
        )
        with patch.object(omc.commands, "client_from_args", return_value=FakeClient()):
            with patch("sys.stdin.isatty", return_value=False):
                with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                    self.assertEqual(omc.command_configure(args), 1)
        # Aborting must happen before any discovery or write is attempted.
        self.assertFalse(FakeClient.located)


class ProxyTests(unittest.TestCase):
    class FakeSocket:
        def __init__(self):
            self.sent = []
            self.closed = False

        def sendto(self, packet, destination):
            self.sent.append((packet, destination))

        def close(self):
            self.closed = True

    def test_proxy_relays_scan_and_wraps_all_responses(self):
        fake = self.FakeSocket()
        relay = omc.OMCProxy(
            broadcast="10.0.0.255",
            request_ttl=5,
            sock=fake,
        )
        request = omc.build_packet(7, omc.BROADCAST_MAC, omc.SCAN)
        event = relay.relay_datagram(
            omc.encapsulate_proxy(request),
            ("192.168.1.20", omc.PORT),
            now=10,
        )
        self.assertIn("REQUEST", event)
        self.assertEqual(fake.sent, [(request, ("10.0.0.255", omc.PORT))])

        reply_body = struct.pack(">H", 7) + bytes.fromhex("00304222898a") + bytes((omc.SCAN | 0x10,))
        reply = omc.add_crc(reply_body)
        event = relay.relay_datagram(reply, ("10.0.0.2", omc.PORT), now=11)
        self.assertIn("RESPONSE", event)
        wrapped, destination = fake.sent[-1]
        self.assertEqual(destination, ("192.168.1.20", omc.PORT))
        self.assertEqual(omc.parse_proxy_frame(wrapped)[1:], (omc.PROXY | 0x10, reply))
        self.assertEqual(len(relay.pending), 1)  # scan accepts more replies until expiry

    def test_proxy_does_not_relay_an_expired_response(self):
        fake = self.FakeSocket()
        relay = omc.OMCProxy(broadcast="10.0.0.255", request_ttl=2, sock=fake)
        request = omc.build_packet(3, omc.BROADCAST_MAC, omc.SCAN)
        relay.relay_datagram(
            omc.encapsulate_proxy(request),
            ("192.168.1.20", omc.PORT),
            now=10,
        )
        reply = omc.add_crc(
            struct.pack(">H", 3)
            + bytes.fromhex("00304222898a")
            + bytes((omc.SCAN | 0x10,))
        )
        self.assertIsNone(relay.relay_datagram(reply, ("10.0.0.2", omc.PORT), now=13))
        self.assertEqual(len(fake.sent), 1)

    def test_proxy_cli_arguments(self):
        args = omc.build_parser().parse_args(
            [
                "proxy",
                "--interface",
                "10.0.0.1",
                "--broadcast",
                "10.0.0.255",
            ]
        )
        self.assertEqual(args.handler, omc.command_proxy)
        self.assertEqual(args.interface, "10.0.0.1")
        self.assertEqual(args.broadcast, "10.0.0.255")

    def test_proxy_rejects_removed_allow_client_option(self):
        errors = StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit):
            omc.build_parser().parse_args(["proxy", "--allow-client", "192.168.1.20"])


class ProvisionTests(unittest.TestCase):
    def test_pool_range_and_cidr(self):
        self.assertEqual(
            omc.parse_address_pool("10.0.0.10-10.0.0.12"),
            ["10.0.0.10", "10.0.0.11", "10.0.0.12"],
        )
        self.assertEqual(
            omc.parse_address_pool("10.0.0.8/30"),
            ["10.0.0.9", "10.0.0.10"],
        )

    def test_netmask_must_be_contiguous(self):
        with self.assertRaisesRegex(ValueError, "contiguous"):
            omc.parse_netmask("255.0.255.0")

    def test_allocation_avoids_reserved_and_previously_assigned_addresses(self):
        settings = {
            "pool": "10.0.0.1-10.0.0.6",
            "router": "10.0.0.1",
            "ommip1": "10.0.0.2",
            "ommip2": None,
            "exclude": ["10.0.0.3"],
        }
        devices = {"AA:AA:AA:AA:AA:AA": {"assigned_ip": "10.0.0.4"}}
        self.assertEqual(omc.allocate_address(settings, devices), "10.0.0.5")

    def test_configuration_drift(self):
        expected = OrderedDict(
            (("use_local_cfg", "1"), ("ip", "10.0.0.10"), ("stream", "SIP-DECT"))
        )
        drift = omc.configuration_drift(expected, {"use_local_cfg": "0", "ip": "10.0.0.10"})
        self.assertEqual(drift, OrderedDict((("use_local_cfg", ("1", "0")),)))

    def test_provision_resets_once_then_configures_without_action_nine(self):
        mac = "00:30:42:22:89:8A"
        live = {"address": "10.0.0.100", "proxy": None, "scan": OrderedDict()}

        class FakeClient:
            discoveries = 0
            exchanges = []
            address_sets = []

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return None

            def discover(self, attempts=None, proxy=None):
                self.discoveries += 1
                if self.discoveries == 4:
                    raise KeyboardInterrupt
                if self.discoveries >= 3:
                    return {
                        mac: {
                            "address": "10.0.0.10",
                            "proxy": None,
                            "scan": OrderedDict(),
                        }
                    }
                return {mac: live}

            def discover_addresses(self, addresses, attempts=None):
                self.address_sets.append(tuple(addresses))
                return self.discover(attempts=attempts)

            def exchange(self, *arguments, **keywords):
                self.exchanges.append((arguments, keywords))
                if arguments[2] == omc.LIST:
                    return OrderedDict(
                        (
                            ("use_local_cfg", "1"),
                            ("ip", "10.0.0.10"),
                            ("subnet", "255.255.255.0"),
                            ("router", "10.0.0.1"),
                            ("ommip1", "10.0.0.2"),
                            ("siaddr", "0.0.0.0"),
                            ("boot_file", "none"),
                        )
                    )
                return OrderedDict()

        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            state_path = directory_path / "state.json"
            reset_history_path = directory_path / "reset-history.json"
            secret_path = directory_path / "secret.bin"
            secret_path.write_bytes(bytes(256))
            args = omc.build_parser().parse_args(
                [
                    "provision",
                    "--address",
                    "10.0.0.100",
                    "--state",
                    str(state_path),
                    "--reset-history",
                    str(reset_history_path),
                    "--secret",
                    str(secret_path),
                    "--pool",
                    "10.0.0.10-10.0.0.12",
                    "--subnet",
                    "255.255.255.0",
                    "--router",
                    "10.0.0.1",
                    "--ommip1",
                    "10.0.0.2",
                    "--password",
                    "omm",
                    "--interval",
                    "0",
                    "--force",
                ]
            )
            fake = FakeClient()
            output = StringIO()
            with patch.object(omc.commands, "client_from_args", return_value=fake):
                with patch.object(
                    omc.commands, "factory_reset_one", return_value=OrderedDict()
                ) as reset:
                    with redirect_stdout(output):
                        self.assertEqual(omc.command_provision(args), 0)
            state = omc.load_provision_state(state_path)
            record = state["devices"][mac]
            self.assertEqual(record["assigned_ip"], "10.0.0.10")
            self.assertEqual(record["phase"], "complete")
            self.assertEqual(reset.call_count, 1)
            self.assertEqual(
                state["reset"][mac]["status"],
                "acknowledged",
            )
            actions = [arguments[2] for arguments, _ in fake.exchanges]
            self.assertEqual(actions, [omc.SET, omc.LIST])
            self.assertEqual(fake.address_sets[0], ("10.0.0.100",))
            self.assertEqual(fake.address_sets[1], ("10.0.0.100", "10.0.0.10"))
            self.assertEqual(record["initial_address"], "10.0.0.100")

    def test_provision_once_returns_failure_exit_code_on_reset_error(self):
        mac = "00:30:42:22:89:8A"

        class FakeClient:
            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return None

            def discover(self, attempts=None, proxy=None):
                return {mac: {"address": "10.0.0.100", "proxy": None, "scan": OrderedDict()}}

        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            args = omc.build_parser().parse_args(
                [
                    "provision",
                    "--state", str(state_path),
                    "--pool", "10.0.0.10-10.0.0.12",
                    "--subnet", "255.255.255.0",
                    "--ommip1", "10.0.0.2",
                    "--password", "omm",
                    "--once",
                    "--force",
                ]
            )
            with patch.object(omc.commands, "client_from_args", return_value=FakeClient()):
                with patch.object(
                    omc.commands, "factory_reset_one", side_effect=TimeoutError("no ack")
                ):
                    with redirect_stdout(StringIO()):
                        self.assertEqual(omc.command_provision(args), 1)

    def test_reset_skips_recorded_mac_even_with_force(self):
        mac = "00:30:42:22:89:8A"

        class FakeClient:
            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return None

            def discover(self, attempts=None, proxy=None):
                return {mac: {"address": "10.0.0.100", "proxy": None, "scan": OrderedDict()}}

        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            omc.save_provision_state(
                state_path,
                {
                    "version": omc.PROVISION_STATE_VERSION,
                    "settings": {},
                    "devices": {},
                    "reset": {mac: {"status": "acknowledged"}},
                },
            )
            args = omc.build_parser().parse_args(
                ["reset", "--state", str(state_path), "--password", "omm", "--force"]
            )
            output = StringIO()
            with patch.object(omc.commands, "client_from_args", return_value=FakeClient()):
                with patch.object(omc.commands, "factory_reset_one") as reset:
                    with redirect_stdout(output):
                        self.assertEqual(omc.command_reset(args), 0)
            # --force only skips the prompt; a recorded MAC is still not reset.
            reset.assert_not_called()
            self.assertIn("already recorded", output.getvalue())

    def test_reconcile_apply_repairs_drift_without_action_nine(self):
        mac = "00:30:42:22:89:8A"

        class FakeClient:
            actions = []

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return None

            def discover(self, attempts=None, proxy=None):
                return {mac: {"address": "10.0.0.100", "proxy": None, "scan": OrderedDict()}}

            def exchange(self, address, target_mac, action, *unused, **unused_keywords):
                self.actions.append(action)
                if action == omc.LIST:
                    return OrderedDict((("use_local_cfg", "0"),))
                return OrderedDict()

        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            state = {
                "version": omc.PROVISION_STATE_VERSION,
                "settings": {
                    "pool": "10.0.0.10-10.0.0.12",
                    "subnet": "255.255.255.0",
                    "router": "10.0.0.1",
                    "ommip1": "10.0.0.2",
                    "ommip2": None,
                    "dns": None,
                    "siaddr": "0.0.0.0",
                    "boot_file": "none",
                    "exclude": [],
                },
                "devices": {mac: {"assigned_ip": "10.0.0.10", "phase": "complete"}},
                "reset": {},
            }
            omc.save_provision_state(state_path, state)
            args = omc.build_parser().parse_args(
                ["reconcile", "--state", str(state_path), "--password", "omm", "--apply", "--force"]
            )
            fake = FakeClient()
            with patch.object(omc.commands, "client_from_args", return_value=fake):
                with redirect_stdout(StringIO()):
                    self.assertEqual(omc.command_reconcile(args), 0)
            self.assertEqual(fake.actions, [omc.LIST, omc.SET])


if __name__ == "__main__":
    unittest.main()
