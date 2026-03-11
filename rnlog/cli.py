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

    # Optional LXMF relay for GPS telemetry to Sideband
    lxmf_relay = None
    if args.sideband_dest:
        from .relay import LxmfRelay, load_or_create_identity
        db_dir = Path(args.db).parent if args.db else Path.home() / ".rnlog"
        db_dir.mkdir(parents=True, exist_ok=True)
        identity = load_or_create_identity(db_dir)
        lxmf_relay = LxmfRelay(identity=identity, storagepath=str(db_dir))
        lxmf_relay.configure(args.sideband_dest)

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
    if lxmf_relay:
        print(f"  LXMF Relay: {lxmf_relay.dest_hash}")
        print(f"  Target:     {args.sideband_dest}")
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

                if lxmf_relay and "gps" in reading and reading["gps"].get("fix"):
                    beacon = {
                        "lat": reading["gps"].get("lat", 0),
                        "lon": reading["gps"].get("lon", 0),
                        "alt": reading["gps"].get("alt", 0),
                        "spd": reading["gps"].get("speed", 0),
                        "hdop": reading["gps"].get("hdop", 10),
                        "sat": reading["gps"].get("sats", 0),
                        "bat": reading.get("device", {}).get("bat", 0),
                        "fix": True,
                    }
                    try:
                        lxmf_relay.relay_beacon(beacon)
                    except Exception as e:
                        RNS.log(f"rnlog: LXMF relay error: {e}", RNS.LOG_ERROR)

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
            if lxmf_relay:
                lxmf_relay.announce_if_needed()
            time.sleep(1)

    if relay_client:
        relay_client.close()

    db.close()
    msg = f"\nStopped. {total} readings stored."
    if relay_client:
        msg += f" {relay_client.sent} forwarded."
    if lxmf_relay:
        msg += f" {lxmf_relay.sent} relayed via LXMF."
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


def cmd_provision_lxmf(args):
    """Provision RNode with Sideband LXMF destination keys and read back its identity."""
    import struct
    import serial

    dest_hex = args.dest
    port = args.port
    baud = args.baud

    if len(dest_hex) != 32:
        print(f"Error: destination hash must be 32 hex chars, got {len(dest_hex)}")
        sys.exit(1)

    dest_hash = bytes.fromhex(dest_hex)

    # Start Reticulum and resolve the destination
    reticulum = RNS.Reticulum(
        configdir=args.config,
        loglevel=3 + args.verbose,
        require_shared_instance=True,
    )

    print(f"  Resolving destination {dest_hex}...")

    if not RNS.Transport.has_path(dest_hash):
        RNS.Transport.request_path(dest_hash)

    deadline = time.time() + 15
    while not RNS.Transport.has_path(dest_hash):
        if time.time() > deadline:
            print("Error: could not resolve path to destination (timeout 15s)")
            sys.exit(1)
        time.sleep(0.5)

    identity = RNS.Identity.recall(dest_hash)
    if identity is None:
        print("Error: identity not known for destination")
        sys.exit(1)

    # Extract X25519 public key (first 32 bytes) and identity hash
    pub_key = identity.get_public_key()[:32]
    identity_hash = identity.hash  # 16 bytes

    # The dest_hash IS the LXMF delivery destination hash
    combined = pub_key + identity_hash + dest_hash  # 64 bytes

    print()
    print("LXMF Beacon Provisioning")
    print("=" * 60)
    print(f"  Target Dest Hash (16B): {dest_hex}")
    print(f"  X25519 Public Key (32B): {pub_key.hex()}")
    print(f"  Identity Hash    (16B): {identity_hash.hex()}")
    print()
    print(f"  Combined (64B): {combined.hex()}")
    print()

    if not port:
        print("No --port specified; printing key data only.")
        print("Use --port /dev/ttyACMx to send to RNode.")
        return

    # Send via KISS CMD_BCN_KEY (0x86)
    FEND = 0xC0
    FESC = 0xDB
    TFEND = 0xDC
    TFESC = 0xDD
    CMD_BCN_KEY = 0x86
    CMD_LXMF_HASH = 0x87

    def kiss_escape(data):
        out = bytearray()
        for b in data:
            if b == FEND:
                out.extend([FESC, TFEND])
            elif b == FESC:
                out.extend([FESC, TFESC])
            else:
                out.append(b)
        return bytes(out)

    print(f"  Sending keys to {port} at {baud} baud...")

    ser = serial.Serial(port, baud, timeout=2)
    time.sleep(0.5)  # let RNode settle after port open

    # Send CMD_BCN_KEY frame
    frame = bytes([FEND, CMD_BCN_KEY]) + kiss_escape(combined) + bytes([FEND])
    ser.write(frame)
    ser.flush()

    # Wait for KISS_READY response
    time.sleep(1)
    response = ser.read(ser.in_waiting or 64)
    if 0x0F in response:  # CMD_READY
        print("  RNode acknowledged key provisioning.")
    else:
        print(f"  Warning: no READY response (got {response.hex() if response else 'nothing'})")

    # Query LXMF source hash via CMD_LXMF_HASH
    print("  Querying RNode LXMF identity...")
    query_frame = bytes([FEND, CMD_LXMF_HASH, 0x01, FEND])
    ser.write(query_frame)
    ser.flush()
    time.sleep(1)

    raw = ser.read(ser.in_waiting or 128)
    ser.close()

    # Parse KISS response for CMD_LXMF_HASH
    lxmf_hash = _parse_kiss_response(raw, CMD_LXMF_HASH)
    if lxmf_hash and len(lxmf_hash) == 16:
        print(f"  RNode LXMF source hash: {lxmf_hash.hex()}")
    else:
        print("  Could not read RNode LXMF hash (identity may not be initialized yet).")

    print()
    print("Provisioning complete.")
    print("=" * 60)


def cmd_provision_ifac(args):
    """Provision RNode with IFAC key derived from network_name and passphrase."""
    import hashlib
    import serial

    network_name = args.name
    passphrase = args.passphrase
    port = args.port
    baud = args.baud

    IFAC_SALT = bytes.fromhex(
        "adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8"
    )

    # Derive IFAC key using the same algorithm as RNS
    # 1. Hash network_name and passphrase separately
    nn_hash = hashlib.sha256(network_name.encode("utf-8")).digest()
    pp_hash = hashlib.sha256(passphrase.encode("utf-8")).digest()

    # 2. Concatenate and hash again
    ifac_origin = nn_hash + pp_hash
    ifac_origin_hash = hashlib.sha256(ifac_origin).digest()

    # 3. HKDF-SHA256 to derive 64-byte key
    import hmac as hmac_mod

    def hkdf_sha256(ikm, salt, length):
        # Extract
        prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
        # Expand
        blocks = []
        prev = b""
        for i in range((length + 31) // 32):
            prev = hmac_mod.new(
                prk, prev + bytes([(i + 1) % 256]), hashlib.sha256
            ).digest()
            blocks.append(prev)
        return b"".join(blocks)[:length]

    ifac_key = hkdf_sha256(ifac_origin_hash, IFAC_SALT, 64)

    print()
    print("IFAC Provisioning")
    print("=" * 60)
    print(f"  Network name: {network_name}")
    print(f"  Passphrase:   {'*' * len(passphrase)}")
    print(f"  IFAC key:     {ifac_key[:32].hex()}")
    print(f"                {ifac_key[32:].hex()}")
    print()

    if not port:
        print("No --port specified; printing key data only.")
        print("Use --port /dev/ttyACMx to send to RNode.")
        return

    # Send via KISS CMD_IFAC_KEY (0x89)
    FEND = 0xC0
    FESC = 0xDB
    TFEND = 0xDC
    TFESC = 0xDD
    CMD_IFAC_KEY = 0x89

    def kiss_escape(data):
        out = bytearray()
        for b in data:
            if b == FEND:
                out.extend([FESC, TFEND])
            elif b == FESC:
                out.extend([FESC, TFESC])
            else:
                out.append(b)
        return bytes(out)

    print(f"  Sending IFAC key to {port} at {baud} baud...")

    ser = serial.Serial(port, baud, timeout=2)
    time.sleep(0.5)

    frame = bytes([FEND, CMD_IFAC_KEY]) + kiss_escape(ifac_key) + bytes([FEND])
    ser.write(frame)
    ser.flush()

    time.sleep(1)
    response = ser.read(ser.in_waiting or 64)
    ser.close()

    if 0x0F in response:  # CMD_READY
        print("  RNode acknowledged IFAC key provisioning.")
    else:
        print(
            f"  Warning: no READY response "
            f"(got {response.hex() if response else 'nothing'})"
        )

    print()
    print("IFAC provisioning complete.")
    print("=" * 60)


def cmd_test_lxmf(args):
    """Send CMD_LXMF_TEST to trigger a test beacon and decode the CMD_DIAG responses."""
    import struct
    import serial

    port = args.port
    baud = args.baud

    FEND = 0xC0
    FESC = 0xDB
    TFEND = 0xDC
    TFESC = 0xDD
    CMD_LXMF_TEST = 0x88
    CMD_DIAG = 0x2C

    print()
    print("=" * 60)
    print("  LXMF Test Beacon")
    print("=" * 60)
    print(f"  Port: {port} @ {baud} baud")
    print()

    ser = serial.Serial(port, baud, timeout=5)
    import time
    time.sleep(0.5)

    # Flush any pending data
    ser.read(ser.in_waiting or 1)

    # Send CMD_LXMF_TEST
    frame = bytes([FEND, CMD_LXMF_TEST, 0x01, FEND])
    print("  Sending CMD_LXMF_TEST...")
    ser.write(frame)
    ser.flush()

    # Read response frames (announce + beacon as CMD_DIAG)
    time.sleep(3)  # Wait for LoRa transmissions to complete
    raw = ser.read(ser.in_waiting or 2048)
    ser.close()

    if not raw:
        print("  No response received.")
        print("=" * 60)
        return

    print(f"  Received {len(raw)} bytes")
    print()

    # Parse all CMD_DIAG frames
    diag_frames = _parse_all_kiss_frames(raw, CMD_DIAG)
    print(f"  Found {len(diag_frames)} CMD_DIAG frame(s)")
    print()

    for i, frame_data in enumerate(diag_frames):
        print(f"--- Frame {i+1}: {len(frame_data)} bytes ---")
        print(f"  Hex: {frame_data.hex()[:80]}{'...' if len(frame_data.hex()) > 80 else ''}")

        if i == 0 and len(frame_data) > 100:
            # First frame: likely announce packet
            _decode_announce_frame(frame_data)
        elif len(frame_data) >= 84:
            # Subsequent frames: likely LXMF message plaintext
            _decode_lxmf_frame(frame_data)
        else:
            print(f"  (unrecognized frame, {len(frame_data)} bytes)")
        print()

    print("=" * 60)


def _parse_all_kiss_frames(raw, cmd_byte):
    """Extract all KISS frames with the given command byte."""
    FEND = 0xC0
    FESC = 0xDB
    TFEND = 0xDC
    TFESC = 0xDD

    frames = []
    parts = raw.split(bytes([FEND]))
    for part in parts:
        if len(part) < 2:
            continue
        if part[0] != cmd_byte:
            continue
        # Un-escape payload
        payload = bytearray()
        escape = False
        for b in part[1:]:
            if escape:
                if b == TFEND:
                    payload.append(FEND)
                elif b == TFESC:
                    payload.append(FESC)
                escape = False
            elif b == FESC:
                escape = True
            else:
                payload.append(b)
        frames.append(bytes(payload))
    return frames


def _decode_announce_frame(data):
    """Decode an RNS announce packet from CMD_DIAG."""
    import hashlib

    if len(data) < 19 + 64 + 10 + 10 + 64:
        print(f"  Announce too short: {len(data)} bytes")
        return

    flags = data[0]
    hops = data[1]
    dest_hash = data[2:18]
    context = data[18]

    print(f"  Announce packet:")
    print(f"    Flags:     0x{flags:02x}")
    print(f"    Hops:      {hops}")
    print(f"    Dest hash: {dest_hash.hex()}")
    print(f"    Context:   0x{context:02x}")

    pos = 19
    if pos + 64 > len(data):
        print("    (truncated at public_key)")
        return

    x25519_pub = data[pos:pos+32]; pos += 32
    ed25519_pub = data[pos:pos+32]; pos += 32
    print(f"    X25519 PK: {x25519_pub.hex()}")
    print(f"    Ed25519 PK: {ed25519_pub.hex()}")

    # Compute identity hash
    identity_hash = hashlib.sha256(x25519_pub + ed25519_pub).digest()[:16]
    print(f"    Identity hash: {identity_hash.hex()}")

    if pos + 10 > len(data):
        print("    (truncated at name_hash)")
        return
    name_hash = data[pos:pos+10]; pos += 10
    print(f"    Name hash: {name_hash.hex()}")

    # Verify name hash matches "lxmf"+"delivery"
    lxmf_h = hashlib.sha256(b"lxmf").digest()
    delivery_h = hashlib.sha256(b"delivery").digest()
    expected_nh = hashlib.sha256(lxmf_h + delivery_h).digest()[:10]
    if name_hash == expected_nh:
        print(f"    Name hash: VALID (lxmf.delivery)")
    else:
        print(f"    Name hash: MISMATCH (expected {expected_nh.hex()})")

    if pos + 10 > len(data):
        print("    (truncated at random_hash)")
        return
    random_hash = data[pos:pos+10]; pos += 10
    print(f"    Random:    {random_hash.hex()}")

    if pos + 64 > len(data):
        print("    (truncated at signature)")
        return
    signature = data[pos:pos+64]; pos += 64

    # app_data: remaining bytes
    app_data = data[pos:]
    if app_data:
        try:
            import umsgpack
        except ImportError:
            try:
                import RNS.vendor.umsgpack as umsgpack
            except ImportError:
                umsgpack = None

        if umsgpack and len(app_data) > 0:
            try:
                name = umsgpack.unpackb(app_data)
                print(f"    App data:  {repr(name)}")
            except Exception:
                print(f"    App data:  {app_data.hex()} (decode failed)")
        else:
            print(f"    App data:  {app_data.hex()}")

    # Verify signature
    signed_data = dest_hash + x25519_pub + ed25519_pub + name_hash + random_hash + app_data
    try:
        from nacl.signing import VerifyKey
        from nacl.encoding import RawEncoder
        vk = VerifyKey(ed25519_pub, encoder=RawEncoder)
        vk.verify(signed_data, signature)
        print(f"    Signature: VALID")
    except ImportError:
        print(f"    Signature: (pynacl not installed, skipping verification)")
    except Exception as e:
        print(f"    Signature: INVALID ({e})")


def _decode_lxmf_frame(data):
    """Decode an LXMF message plaintext from CMD_DIAG."""
    import struct

    try:
        import umsgpack
    except ImportError:
        try:
            import RNS.vendor.umsgpack as umsgpack
        except ImportError:
            print("  (umsgpack not available)")
            return

    if len(data) < 80:
        print(f"  LXMF message too short: {len(data)} bytes")
        return

    source_hash = data[:16]
    signature = data[16:80]
    payload = data[80:]

    print(f"  LXMF message:")
    print(f"    Source hash: {source_hash.hex()}")
    print(f"    Signature:   {signature.hex()[:32]}...")
    print(f"    Payload len: {len(payload)} bytes")

    try:
        msg = umsgpack.unpackb(payload)
    except Exception as e:
        print(f"    Payload decode failed: {e}")
        return

    if not isinstance(msg, list) or len(msg) != 4:
        print(f"    Unexpected payload structure: {type(msg).__name__}")
        return

    timestamp = msg[0]
    print(f"    Timestamp:   {timestamp}")

    fields = msg[3]
    FIELD_TELEMETRY = 0x02
    SID_TIME = 0x01
    SID_LOCATION = 0x02
    SID_BATTERY = 0x04

    if not isinstance(fields, dict) or FIELD_TELEMETRY not in fields:
        print(f"    Fields: {fields}")
        return

    telem_bytes = fields[FIELD_TELEMETRY]
    telem = umsgpack.unpackb(telem_bytes)

    if SID_TIME in telem:
        print(f"    Telem time:  {telem[SID_TIME]}")

    if SID_LOCATION in telem:
        loc = telem[SID_LOCATION]
        lat = struct.unpack("!i", loc[0])[0] / 1e6
        lon = struct.unpack("!i", loc[1])[0] / 1e6
        alt = struct.unpack("!i", loc[2])[0] / 1e2
        speed = struct.unpack("!I", loc[3])[0] / 1e2
        hdop = struct.unpack("!H", loc[5])[0] / 1e2
        print(f"    Location:    lat={lat:.6f}, lon={lon:.6f}, alt={alt:.1f}m")
        print(f"    Speed:       {speed:.2f} km/h")
        print(f"    HDOP:        {hdop:.2f}")

    if SID_BATTERY in telem:
        bat = telem[SID_BATTERY]
        print(f"    Battery:     {bat[0]:.0f}%")

    # Compare timestamp with host clock
    import time
    host_time = int(time.time())
    delta = abs(host_time - int(timestamp))
    if delta < 10:
        print(f"    Clock delta: {delta}s (OK)")
    else:
        print(f"    Clock delta: {delta}s (WARNING: >10s drift)")


def _parse_kiss_response(raw, expected_cmd):
    """Extract payload from a KISS frame with the given command byte."""
    FEND = 0xC0
    FESC = 0xDB
    TFEND = 0xDC
    TFESC = 0xDD

    # Find frame boundaries
    frames = raw.split(bytes([FEND]))
    for frame in frames:
        if len(frame) < 2:
            continue
        if frame[0] == expected_cmd:
            # Un-escape
            payload = bytearray()
            escape = False
            for b in frame[1:]:
                if escape:
                    if b == TFEND:
                        payload.append(FEND)
                    elif b == TFESC:
                        payload.append(FESC)
                    escape = False
                elif b == FESC:
                    escape = True
                else:
                    payload.append(b)
            return bytes(payload)
    return None


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
    collect_p.add_argument(
        "--sideband-dest", metavar="HASH",
        help="relay GPS telemetry as LXMF to this Sideband destination",
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

    # provision-lxmf
    prov_lxmf_p = subparsers.add_parser("provision-lxmf",
        help="provision RNode with Sideband LXMF destination keys")
    prov_lxmf_p.add_argument(
        "--dest", required=True, metavar="HASH",
        help="Sideband LXMF delivery destination hash (32 hex chars)",
    )
    prov_lxmf_p.add_argument(
        "--port", type=str, default=None,
        help="serial port for RNode (e.g. /dev/ttyACM0)",
    )
    prov_lxmf_p.add_argument(
        "--baud", type=int, default=115200,
        help="serial baud rate (default: 115200)",
    )

    # provision-ifac
    prov_ifac_p = subparsers.add_parser("provision-ifac",
        help="provision RNode with IFAC key for network authentication")
    prov_ifac_p.add_argument(
        "--name", required=True, type=str,
        help="network name (e.g. helv4net)",
    )
    prov_ifac_p.add_argument(
        "--passphrase", required=True, type=str,
        help="network passphrase",
    )
    prov_ifac_p.add_argument(
        "--port", type=str, default=None,
        help="serial port for RNode (e.g. /dev/ttyACM0)",
    )
    prov_ifac_p.add_argument(
        "--baud", type=int, default=115200,
        help="serial baud rate (default: 115200)",
    )

    # test-lxmf
    test_lxmf_p = subparsers.add_parser("test-lxmf",
        help="send CMD_LXMF_TEST and decode response")
    test_lxmf_p.add_argument(
        "--port", required=True, type=str,
        help="serial port for RNode (e.g. /dev/ttyACM0)",
    )
    test_lxmf_p.add_argument(
        "--baud", type=int, default=115200,
        help="serial baud rate (default: 115200)",
    )

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
    elif args.command == "provision-lxmf":
        cmd_provision_lxmf(args)
    elif args.command == "provision-ifac":
        cmd_provision_ifac(args)
    elif args.command == "test-lxmf":
        cmd_test_lxmf(args)


if __name__ == "__main__":
    main()
