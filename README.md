# rnlog

Telemetry logger for the [Reticulum Network Stack](https://reticulum.network/).

Collects GPS, battery, radio, and traffic data from RNode devices and stores it in a local SQLite database. Works in two modes:

- **`collect`** — polls interface statistics from a local `rnsd` instance
- **`serve`** — runs a Reticulum destination that receives telemetry from remote RNode beacons (encrypted or plaintext)

## Install

```sh
pip install .
# or into the existing RNS venv:
pipx inject rns .
```

Requires `rns >= 0.8.0`.

## Quick start

```sh
# Start the collector (receives beacons from RNode devices)
rnlog serve

# Or poll local rnsd interface stats every 30s
rnlog collect
```

## GPS beacon setup

RNode devices with GPS (e.g. Heltec V4) can transmit GPS beacons over LoRa when no host is connected. The collector receives and stores these automatically.

### 1. Start the collector

```sh
rnlog serve
```

Output shows the destination hashes:

```
============================================================
  rnlog — Telemetry Collector
============================================================
  Destination: 4c32285349d1bbb2a77ded6450c3727c
  Beacon:      18bcd8a3dea16ef6765c6b27d008d220
  Database:    ~/.rnlog/telemetry.db
  Press Ctrl+C to stop.
============================================================
```

Plaintext beacons work immediately with no configuration — the RNode firmware sends to the well-known `rnlog.beacon` PLAIN destination.

### 2. Enable encrypted beacons (recommended)

Encrypted beacons use RNS SINGLE destination encryption (X25519 + AES-256-CBC) so only your collector can read the GPS coordinates.

**a) Get the provisioning key:**

```sh
rnlog provision
```

Output:

```
Beacon Firmware Provisioning
============================================================
  X25519 Public Key (32B): 60d5b1a893fe0ca9b6079372f3db28d2...
  Identity Hash    (16B): ea438487c49b10ecf103f97b005a5606
  Dest Hash        (16B): 4c32285349d1bbb2a77ded6450c3727c

  Combined (64B): 60d5b1a893fe0ca9b6079372f3db28d2...

Send via KISS CMD_BCN_KEY (0x86) to configure beacon firmware.
============================================================
```

**b) Send the key to the RNode:**

```python
import serial, time

FEND, FESC, TFEND, TFESC = 0xC0, 0xDB, 0xDC, 0xDD
CMD_BCN_KEY = 0x86

key_hex = "PASTE_YOUR_64_BYTE_HEX_HERE"
key_bytes = bytes.fromhex(key_hex)

frame = bytearray([FEND, CMD_BCN_KEY])
for b in key_bytes:
    if b == FEND:    frame.extend([FESC, TFEND])
    elif b == FESC:  frame.extend([FESC, TFESC])
    else:            frame.append(b)
frame.append(FEND)

port = serial.Serial('/dev/ttyACM0', 115200, timeout=2)
time.sleep(0.5)
port.write(frame)
port.flush()
time.sleep(1)
resp = port.read(port.in_waiting or 64)
if 0x0F in resp:
    print("Provisioned (CMD_READY received)")
port.close()
```

The key is stored in EEPROM and persists across reboots. Once provisioned, the RNode sends encrypted beacons to your collector's SINGLE destination instead of the plaintext PLAIN destination.

### 3. Optional: forward to Sideband

To relay beacon GPS data as LXMF telemetry messages to a [Sideband](https://github.com/markqvist/Sideband) app:

```sh
rnlog serve --sideband-dest <SIDEBAND_DESTINATION_HASH>
```

The beacon location will appear on Sideband's map.

## Subcommands

| Command     | Description                                          |
|-------------|------------------------------------------------------|
| `serve`     | Run collector destination (receives remote beacons)  |
| `collect`   | Poll local rnsd and store interface telemetry        |
| `provision` | Output collector key for beacon firmware provisioning|
| `query`     | Query stored readings with filters                   |
| `summary`   | Show database summary                                |
| `export`    | Export readings as JSON or CSV                       |
| `ingest`    | Read JSON lines from stdin and store                 |

## Examples

```sh
# Query last 10 beacon readings
rnlog query -I "RNode Beacon" -n 10

# Query readings from the last hour as JSON
rnlog -j query -s 1h

# Database summary
rnlog summary

# Export to CSV
rnlog export -f csv > telemetry.csv

# Export last 24h of a specific interface
rnlog export -I "RNode LoRa" -s 24h

# Forward local telemetry to a remote collector
rnlog collect -D <COLLECTOR_DEST_HASH>
```

## Collected data

For each interface/beacon reporting telemetry:

- **GPS**: fix, satellites, lat/lon, altitude, speed, HDOP
- **Device**: battery level/state, CPU temperature
- **Radio**: noise floor, RSSI, SNR, airtime, channel load
- **Traffic**: bytes rx/tx, bitrate

Data is stored in `~/.rnlog/telemetry.db` (SQLite with WAL mode).

## How it works

```
┌──────────────┐     LoRa      ┌───────────────────────┐
│  RNode       │  ─────────►   │  Router / PC          │
│  (Heltec V4) │   beacon      │  running rnsd         │
│              │   packets     │                       │
│  GPS + LoRa  │               │  rnlog serve          │
│  battery     │               │  ├─ SINGLE dest ◄──── │ encrypted beacons
└──────────────┘               │  ├─ PLAIN dest  ◄──── │ plaintext beacons
                               │  ├─ SQLite DB         │
                               │  └─ LXMF relay ────►  │ Sideband (optional)
                               └───────────────────────┘
```

**Plaintext path**: RNode sends JSON to well-known PLAIN destination `rnlog.beacon`. Anyone in LoRa range can receive it.

**Encrypted path**: RNode encrypts JSON with the collector's X25519 public key and sends to the collector's SINGLE destination. Only the collector (with the matching private key) can decrypt it. Uses ephemeral ECDH per packet — no shared secrets to manage.

## Router setup

The `router/` directory contains an install script for an OpenWrt router running as a Reticulum transport node with LXMF propagation and telemetry collection.

```sh
scp -O -r router/ root@192.168.0.2:/tmp/rns-install
ssh root@192.168.0.2 "sh /tmp/rns-install/install.sh"
```

Services installed:
- `rnsd` — Reticulum transport node (TCP server on :4242, RNode on /dev/ttyACM0)
- `lxmd` — LXMF propagation node with `on_inbound` handler that stores received telemetry to SQLite

## License

MIT
