#!/usr/bin/env python3
"""rnlog — Reticulum interface telemetry logger.

Polls interface statistics from a running rnsd instance and stores
GPS, battery, radio, and traffic data in a local SQLite database.

Usage:
    rnlog collect              Continuously poll and store telemetry
    rnlog query                Query stored readings
    rnlog summary              Show database summary
    rnlog export               Export readings as JSON or CSV
"""

import argparse
import csv
import io
import json
import signal
import sys
import time
from pathlib import Path

import RNS

from . import __version__
from .db import open_db, store_reading, query_readings, get_summary
from .telemetry import extract_telemetry, format_summary


def cmd_serve(args):
    """Run an rnlog collector destination that accepts telemetry over Reticulum."""
    from .relay import CollectorServer

    try:
        reticulum = RNS.Reticulum(
            configdir=args.config,
            loglevel=3 + args.verbose,
            require_shared_instance=True,
        )
    except Exception:
        print("Could not connect to shared RNS instance. Is rnsd running?")
        sys.exit(1)

    db_path = Path(args.db) if args.db else None
    server = CollectorServer(reticulum, db_path=db_path,
                             sideband_dest=args.sideband_dest)

    print()
    print("=" * 60)
    print("  rnlog — Telemetry Collector")
    print("=" * 60)
    print(f"  Destination: {server.dest_hash}")
    print(f"  Beacon:      {server.beacon_hash}")
    if server.lxmf_relay:
        print(f"  LXMF Relay:  {server.lxmf_relay.dest_hash}")
        print(f"  Target:      {args.sideband_dest}")
    print(f"  Database:    {args.db or '~/.rnlog/telemetry.db'}")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)
    print()

    shutdown = False

    def handle_signal(signum, frame):
        nonlocal shutdown
        shutdown = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    while not shutdown:
        if server.lxmf_relay:
            server.lxmf_relay.announce_if_needed()
        time.sleep(1)

    server.close()
    msg = f"\nStopped. {server.received} readings received."
    if server.lxmf_relay:
        msg += f" {server.lxmf_relay.sent} relayed via LXMF."
    print(msg)


def cmd_collect(args):
    """Continuously poll rnsd and store interface telemetry."""
    try:
        reticulum = RNS.Reticulum(
            configdir=args.config,
            loglevel=3 + args.verbose,
            require_shared_instance=True,
        )
    except Exception:
        print("Could not connect to shared RNS instance. Is rnsd running?")
        sys.exit(1)

    db = open_db(Path(args.db) if args.db else None)

    # Verify connectivity
    stats = reticulum.get_interface_stats()
    if not stats:
        print("Could not get interface stats from rnsd")
        sys.exit(2)

    iface_count = len(stats.get("interfaces", []))

    # Set up Reticulum forwarding
    relay_client = None
    if args.dest:
        from .relay import CollectorClient
        relay_client = CollectorClient(reticulum, args.dest)
        print(f"  Connecting to collector {args.dest}...")
        try:
            relay_client.connect()
            print(f"  Connected.")
        except Exception as e:
            print(f"  Could not connect to collector: {e}")
            sys.exit(3)

    print()
    print("=" * 60)
    print("  rnlog — Reticulum Telemetry Logger")
    print("=" * 60)
    print(f"  Database:   {args.db or '~/.rnlog/telemetry.db'}")
    if relay_client:
        print(f"  Collector:  {args.dest}")
    print(f"  Interfaces: {iface_count}")
    print(f"  Interval:   {args.interval}s")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)
    print()

    total = 0
    shutdown = False

    def handle_signal(signum, frame):
        nonlocal shutdown
        shutdown = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    while not shutdown:
        stats = reticulum.get_interface_stats()
        if stats and "interfaces" in stats:
            now = time.time()
            batch = []
            for iface in stats["interfaces"]:
                reading = extract_telemetry(iface)
                if reading is None:
                    continue

                iface_name = iface.get("short_name", iface.get("name", "unknown"))
                raw_hash = iface.get("hash", "unknown")
                if isinstance(raw_hash, bytes):
                    iface_hash = raw_hash.hex()
                else:
                    iface_hash = str(raw_hash)

                store_reading(db, now, iface_name, iface_hash, reading)
                total += 1

                if relay_client:
                    batch.append({
                        "ts": now,
                        "interface": iface_name,
                        "interface_hash": iface_hash,
                        "reading": reading,
                    })

                if not args.quiet:
                    summary = format_summary(reading)
                    ts = time.strftime("%H:%M:%S", time.localtime(now))
                    print(f"  [{ts}] {iface_name}: {summary}")

            db.commit()

            if relay_client and batch:
                if not relay_client.connected:
                    try:
                        relay_client.connect()
                    except Exception:
                        pass
                if relay_client.connected:
                    relay_client.send(batch)

        for _ in range(args.interval):
            if shutdown:
                break
            time.sleep(1)

    if relay_client:
        relay_client.close()

    db.close()
    msg = f"\nStopped. {total} readings stored."
    if relay_client:
        msg += f" {relay_client.sent} forwarded."
    print(msg)


def cmd_query(args):
    """Query stored readings."""
    db = open_db(Path(args.db) if args.db else None)

    since = None
    if args.since:
        since = _parse_duration(args.since)

    readings = query_readings(
        db,
        interface=args.interface,
        since=since,
        limit=args.limit or 20,
    )

    if args.json:
        print(json.dumps(readings, indent=2))
    else:
        for r in reversed(readings):
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
            reading = r["reading"]
            summary = format_summary(reading)
            print(f"  {ts}  {r['interface']:20s}  {summary}")

    db.close()


def cmd_summary(args):
    """Show database summary."""
    db = open_db(Path(args.db) if args.db else None)
    info = get_summary(db)

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print()
        print(f"  Total readings: {info['total_readings']}")
        print()
        if info["interfaces"]:
            print(f"  {'Interface':<25s} {'Readings':>10s}  {'First':>20s}  {'Last':>20s}")
            print(f"  {'-'*25} {'-'*10}  {'-'*20}  {'-'*20}")
            for iface in info["interfaces"]:
                first = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(iface["first"]))
                last = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(iface["last"]))
                print(f"  {iface['name']:<25s} {iface['readings']:>10d}  {first:>20s}  {last:>20s}")
        else:
            print("  No readings stored yet.")
        print()

    db.close()


def cmd_export(args):
    """Export readings as JSON or CSV."""
    db = open_db(Path(args.db) if args.db else None)

    since = None
    if args.since:
        since = _parse_duration(args.since)

    readings = query_readings(
        db,
        interface=args.interface,
        since=since,
        limit=args.limit,
    )

    # Reverse to chronological order for export
    readings.reverse()

    if args.format == "csv":
        _export_csv(readings, sys.stdout)
    else:
        print(json.dumps(readings, indent=2))

    db.close()


def _export_csv(readings, output):
    """Export readings as flattened CSV."""
    if not readings:
        return

    # Collect all possible field paths
    fieldnames = ["id", "ts", "interface", "interface_hash"]
    extra_fields = set()
    for r in readings:
        reading = r["reading"]
        for section in ["gps", "device", "radio", "traffic"]:
            if section in reading:
                for key in reading[section]:
                    extra_fields.add(f"{section}.{key}")

    fieldnames.extend(sorted(extra_fields))

    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    for r in readings:
        row = {
            "id": r["id"],
            "ts": r["ts"],
            "interface": r["interface"],
            "interface_hash": r["interface_hash"],
        }
        reading = r["reading"]
        for section in ["gps", "device", "radio", "traffic"]:
            if section in reading:
                for key, val in reading[section].items():
                    row[f"{section}.{key}"] = val
        writer.writerow(row)


def cmd_ingest(args):
    """Read JSON lines from stdin and store as readings."""
    db = open_db(Path(args.db) if args.db else None)
    count = 0

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            store_reading(
                db,
                rec["ts"],
                rec["interface"],
                rec["interface_hash"],
                rec["reading"],
            )
            count += 1
            if count % 10 == 0:
                db.commit()
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Skipping bad record: {e}", file=sys.stderr)

    db.commit()
    db.close()
    print(f"Ingested {count} readings.", file=sys.stderr)


def cmd_provision(args):
    """Output collector key configuration for beacon firmware provisioning."""
    from .relay import load_or_create_identity, ASPECT, ASPECT_COLLECTOR

    reticulum = RNS.Reticulum(
        configdir=args.config,
        loglevel=3 + args.verbose,
        require_shared_instance=False,
    )

    db_dir = Path(args.db).parent if args.db else Path.home() / ".rnlog"
    db_dir.mkdir(parents=True, exist_ok=True)
    identity = load_or_create_identity(db_dir)

    # X25519 public key (first 32 bytes of get_public_key())
    pub_key = identity.get_public_key()[:32]

    # Identity hash (HKDF salt)
    identity_hash = identity.hash  # 16 bytes

    # Destination hash for rnlog.collector SINGLE
    dest = RNS.Destination(
        identity, RNS.Destination.IN,
        RNS.Destination.SINGLE,
        ASPECT, ASPECT_COLLECTOR,
    )
    dest_hash = dest.hash  # 16 bytes

    combined = pub_key + identity_hash + dest_hash  # 64 bytes

    print()
    print("Beacon Firmware Provisioning")
    print("=" * 60)
    print(f"  X25519 Public Key (32B): {pub_key.hex()}")
    print(f"  Identity Hash    (16B): {identity_hash.hex()}")
    print(f"  Dest Hash        (16B): {dest_hash.hex()}")
    print()
    print(f"  Combined (64B): {combined.hex()}")
    print()
    print("Send via KISS CMD_BCN_KEY (0x86) to configure beacon firmware.")
    print("=" * 60)


def _parse_duration(spec: str) -> float:
    """Parse a duration like '1h', '30m', '7d' into a Unix timestamp (now - duration)."""
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if spec[-1] in multipliers:
        try:
            val = float(spec[:-1])
            return time.time() - (val * multipliers[spec[-1]])
        except ValueError:
            pass
    # Try as raw seconds
    try:
        return time.time() - float(spec)
    except ValueError:
        print(f"Invalid duration: {spec} (use e.g. 1h, 30m, 7d)")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="rnlog",
        description="Reticulum interface telemetry logger",
    )
    parser.add_argument(
        "--config", action="store", default=None,
        help="path to alternative Reticulum config directory", type=str,
    )
    parser.add_argument(
        "--version", action="version",
        version="rnlog {version}".format(version=__version__),
    )
    parser.add_argument(
        "--db", action="store", default=None,
        help="path to SQLite database (default: ~/.rnlog/telemetry.db)", type=str,
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="suppress per-reading output during collect",
    )
    parser.add_argument(
        "-j", "--json", action="store_true",
        help="output in JSON format",
    )

    subparsers = parser.add_subparsers(dest="command")

    # serve
    serve_p = subparsers.add_parser("serve", help="run telemetry collector destination")
    serve_p.add_argument(
        "--sideband-dest", metavar="HASH",
        help="forward beacon telemetry as LXMF to this Sideband destination",
    )

    # collect
    collect_p = subparsers.add_parser("collect", help="poll rnsd and store telemetry")
    collect_p.add_argument(
        "-i", "--interval", type=int, default=30,
        help="seconds between polls (default: 30)",
    )
    collect_p.add_argument(
        "-D", "--dest", type=str, default=None,
        help="forward to rnlog collector destination hash",
    )

    # query
    query_p = subparsers.add_parser("query", help="query stored readings")
    query_p.add_argument(
        "-I", "--interface", type=str, default=None,
        help="filter by interface name",
    )
    query_p.add_argument(
        "-s", "--since", type=str, default=None,
        help="show readings since duration (e.g. 1h, 30m, 7d)",
    )
    query_p.add_argument(
        "-n", "--limit", type=int, default=None,
        help="max number of readings (default: 20)",
    )

    # ingest
    subparsers.add_parser("ingest", help="read JSON lines from stdin and store")

    # summary
    subparsers.add_parser("summary", help="show database summary")

    # provision
    subparsers.add_parser("provision",
        help="output collector key config for beacon firmware")

    # export
    export_p = subparsers.add_parser("export", help="export readings")
    export_p.add_argument(
        "-f", "--format", choices=["json", "csv"], default="json",
        help="output format (default: json)",
    )
    export_p.add_argument(
        "-I", "--interface", type=str, default=None,
        help="filter by interface name",
    )
    export_p.add_argument(
        "-s", "--since", type=str, default=None,
        help="export readings since duration (e.g. 1h, 30m, 7d)",
    )
    export_p.add_argument(
        "-n", "--limit", type=int, default=None,
        help="max number of readings",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "serve":
        cmd_serve(args)
    elif args.command == "collect":
        cmd_collect(args)
    elif args.command == "ingest":
        cmd_ingest(args)
    elif args.command == "query":
        cmd_query(args)
    elif args.command == "summary":
        cmd_summary(args)
    elif args.command == "export":
        cmd_export(args)
    elif args.command == "provision":
        cmd_provision(args)


if __name__ == "__main__":
    main()
