# rnlog

Telemetry logger for the [Reticulum Network Stack](https://reticulum.network/).

Polls interface statistics from a running `rnsd` instance and stores GPS, battery, radio, and traffic data in a local SQLite database. Follows Reticulum CLI conventions (`--config`, `-v`, `-j`).

## Install

```sh
pip install .
# or into the existing RNS venv:
pipx inject rns .
```

Requires `rns >= 0.8.0` and a running `rnsd` shared instance.

## Usage

```sh
# Collect telemetry every 30s (default)
rnlog collect

# Collect every 5s with verbose output
rnlog -v collect -i 5

# Query last 10 RNode readings
rnlog query -I "RNode LoRa" -n 10

# Query readings from the last hour as JSON
rnlog -j query -s 1h

# Database summary
rnlog summary

# Export to CSV
rnlog export -f csv > telemetry.csv

# Export last 24h of a specific interface
rnlog export -I "RNode LoRa" -s 24h
```

### Subcommands

| Command   | Description                              |
|-----------|------------------------------------------|
| `collect` | Poll rnsd and store interface telemetry  |
| `query`   | Query stored readings with filters       |
| `summary` | Show database summary                    |
| `export`  | Export readings as JSON or CSV           |

### Collected data

For each interface reporting telemetry:

- **GPS**: fix, satellites, lat/lon, altitude, speed, HDOP, NMEA
- **Device**: battery level/state, CPU temperature
- **Radio**: noise floor, RSSI, SNR, airtime, channel load
- **Traffic**: bytes rx/tx, bitrate

Data is stored in `~/.rnlog/telemetry.db` (SQLite with WAL mode).

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
