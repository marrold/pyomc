

# PyOMC

PyOMC is a command-line replacement for the Mitel OM Configurator, written in Python.

It was written with the assistance of AI, and tested by a human.

## Features

- Scans for RFPs, either via broadcast discovery, via a proxy RFP, or by scanning a subnet
- Emulates an RFP proxy for reaching another broadcast domain via L3
- Configures all known OMC parameters
- Factory resets RFPs using OMM credentials or a separately supplied 256-byte secret
- Provisioning RFPs with a static IP and OMM for environments without DHCP options

## Requirements

- Python 3.8 or newer
- IPv4 connectivity to the RFP, or a reachable proxy RFP
- Permission to bind UDP port 64000
- Valid OMM credentials, or the raw 256-byte factory-reset secret

## Install with pipx

From a cloned checkout:

```bash
cd PyOMC
pipx install .
pyomc --help
```

For development, install it in editable mode:

```bash
pipx install --editable .
```

To reinstall after a non-editable local installation:

```bash
pipx install --force .
```

Alternatively, run it directly without installation:

```bash
python3 -m pyomc --help
```

## Common options

These apply to every command that talks to an RFP: `scan`, `configure`,
`reset`, `provision`, and `reconcile`. Command-specific options are described
in each command's own section below.

### Discovery modes

Each command selects exactly one way of finding RFPs:

| Mode | Option | Use when |
| --- | --- | --- |
| Broadcast | `--broadcast IP` (default `255.255.255.255`) | The RFPs share a broadcast domain with this host |
| Proxy | `--proxy HOST` | A reachable RFP or `pyomc proxy` relays into that domain |
| L3 unicast | `--scan-subnet CIDR` | Broadcasts do not pass, so each usable address is probed |
| Targeted | `--address IP` | Exactly one RFP, at a known address |

`--address` cannot be combined with `--scan-subnet` or `--proxy`, and
`--scan-subnet` cannot be combined with `--proxy`.

### Local binding and timing

- `--interface IP` — local IPv4 address to bind (default: all interfaces)
- `--timeout SECONDS` — time to await each response (default: 2)
- `--attempts N` — send attempts per operation (default: 2)
- `--interval SECONDS` — delay between discovery passes on `scan` and
  `provision` (default: 10)

### Credentials

Pass `--username omm` and PyOMC prompts for the password. To avoid the prompt,
set the `OMM_PASSWORD` environment variable, or use `--password` as a last
resort — it is visible in the process list and shell history.

`reset` and `provision` can instead authorize with the raw 256-byte
factory-reset secret; see [Factory reset](#factory-reset).

## Scan

Scan continuously for RFPs on the local broadcast domain. Cancel with Ctrl+C:

```bash
pyomc scan --interface 192.168.1.10 --broadcast 192.168.1.255 --username omm
```

Scan via a reachable proxy RFP:

```bash
pyomc scan --interface 10.222.0.141 --proxy 10.222.0.70 --username omm
```

Scan each usable address in an IPv4 subnet with unicast discovery packets:

```bash
pyomc scan --interface 192.168.1.10 --scan-subnet 10.222.0.0/24 --username omm
```

Use `--json` to emit one JSON object per newly seen RFP instead of the
human-readable report.

## Run a proxy

On a host attached to the RFP broadcast domain, start the relay with that
host's interface address and the downstream broadcast address:

```bash
pyomc proxy \
  --interface 10.222.0.141 \
  --broadcast 10.222.0.255
```

From a client, point any normal operation at the proxy host:

```bash
pyomc scan --interface 192.168.50.20 --proxy 10.222.0.141 --username omm
```

## Configure one RFP

```bash
pyomc configure 00:30:42:29:79:84 \
  --address 10.222.0.70 \
  --interface 10.222.0.141 \
  --username omm \
  --use-local-cfg 1 \
  --ip 10.222.0.70 \
  --subnet 255.255.255.0 \
  --router 10.222.0.1 \
  --ommip1 10.222.0.150
```

Use `--set KEY=VALUE` for a firmware-specific parameter that is not exposed as
a named option. Repeat `--set` as needed. `pyomc configure --help` lists every
named parameter.

`configure` always operates on the one MAC given on the command line and then
exits, in whichever discovery mode locates it.

## Factory reset

Without `--secret`, resets using the OMM credentials:

```bash
pyomc reset \
  --interface 192.168.1.10 \
  --broadcast 192.168.1.255 \
  --username omm
```

Supply `--secret` to authorize with the factory-reset secret instead, which
must be exactly 256 raw bytes. When it is supplied, credentials are not used:

```bash
pyomc reset \
  --interface 192.168.1.10 \
  --broadcast 192.168.1.255 \
  --secret rfp_factory_secret.bin
```

Reset attempts are recorded before transmission, preventing an automatic
second reset if the response is lost. A MAC already recorded in the state file
is skipped; to reset it again, remove its record from the state file.

Reset exactly one RFP by its current address:

```bash
pyomc reset --address 10.222.0.156 --username omm
```

## Provision a fleet

Provision allows you to configure a group of RFPs with a static IP and OMM configuration, for environments where a DHCP server can't send the specific OMM options.

The first run creates the shared state and saves the network settings:

```bash
pyomc provision \
  --interface 10.222.0.141 \
  --broadcast 10.222.0.255 \
  --username omm \
  --pool 10.222.0.70-10.222.0.79 \
  --subnet 255.255.255.0 \
  --router 10.222.0.1 \
  --ommip1 10.222.0.150
```

Subsequent runs can omit the saved pool and network settings:

```bash
pyomc provision \
  --interface 10.222.0.141 \
  --broadcast 10.222.0.255 \
  --username omm
```

Provisioning runs until Ctrl+C, or use `--once` for a single discovery cycle.
It allocates an address once per MAC, records the reset attempt before sending
it, applies local IPv4 and OMM configuration, and waits until the RFP appears
at its assigned address. An acknowledged SET is retried after 60 seconds if the
device remains at its old address; change that with `--config-retry`. Use
`--exclude IP` (repeatable) to keep addresses out of the pool.

Add `--secret ./rfp_factory_secret.bin` to either provisioning
command to select the cookie-derived reset mechanism instead of credential
reset.

To provision one RFP, use a one-address pool and target its current address.
PyOMC follows the discovered MAC from the initial address to its assigned
address:

```bash
pyomc provision \
  --address 10.222.0.156 \
  --state rfp-10.222.0.156.json \
  --username omm \
  --pool 10.222.0.70-10.222.0.70 \
  --subnet 255.255.255.0 \
  --ommip1 10.222.0.241
```

## Reconcile state

Report missing devices and configuration drift:

```bash
pyomc reconcile --interface 10.222.0.141 --broadcast 10.222.0.255 --username omm
```

Apply the saved configuration to devices that have drifted:

```bash
pyomc reconcile --interface 10.222.0.141 --broadcast 10.222.0.255 --username omm --apply
```

## State file

Reset history, pool settings, MAC-to-IP assignments, observed configuration,
and provisioning progress are all stored in one file:

```text
rfp-provision-state.json
```

Use `--state FILE` to select another location. PyOMC can import the former
`rfp-reset-history.json` format once for migration, but all future writes go to
the unified state file. Back up this file: it prevents duplicate allocation and
unintentional repeated factory resets.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests use simulated clients and do not contact or modify an RFP.

## Python API

PyOMC is also an importable package. Common protocol and state APIs are
available from the package root:

```python
from pyomc import LIST, OMCClient

with OMCClient(
    interface="192.168.1.10",
    broadcast="192.168.1.255",
) as client:
    devices = client.discover(attempts=1)
    for mac, device in devices.items():
        config = client.exchange(
            str(device["address"]),
            mac,
            LIST,
            username="omm",
            password="secret",
        )
        print(mac, dict(config))
```

The implementation is divided by responsibility:

- `pyomc.protocol` — packet encoding, CRC, authentication and constants
- `pyomc.client` — UDP discovery and request/reply transport
- `pyomc.state` — persistent state, allocation and drift comparison
- `pyomc.commands` — reusable command implementations
- `pyomc.proxy` — OMC proxy relay and request correlation
- `pyomc.cli` — argument parsing and the console entry point

## License

PyOMC is released under the [MIT License](LICENSE).
