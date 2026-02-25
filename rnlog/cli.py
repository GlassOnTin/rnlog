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

    print()
    print("=" * 60)
    print("  rnlog — Reticulum Telemetry Logger")
    print("=" * 60)
    print(f"  Database:   {args.db or '~/.rnlog/telemetry.db'}")
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

                if not args.quiet:
                    summary = format_summary(reading)
                    ts = time.strftime("%H:%M:%S", time.localtime(now))
                    print(f"  [{ts}] {iface_name}: {summary}")

            db.commit()

        for _ in range(args.interval):
            if shutdown:
                break
            time.sleep(1)

    db.close()
    print(f"\nStopped. {total} readings stored.")


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


def _export_csv(readings: list[dict], output):
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

    # collect
    collect_p = subparsers.add_parser("collect", help="poll rnsd and store telemetry")
    collect_p.add_argument(
        "-i", "--interval", type=int, default=30,
        help="seconds between polls (default: 30)",
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

    # summary
    subparsers.add_parser("summary", help="show database summary")

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

    if args.command == "collect":
        cmd_collect(args)
    elif args.command == "query":
        cmd_query(args)
    elif args.command == "summary":
        cmd_summary(args)
    elif args.command == "export":
        cmd_export(args)


if __name__ == "__main__":
    main()
