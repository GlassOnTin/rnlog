#!/usr/bin/env python3
"""Verification script for RNode LXMF beacon packets.

Decodes LXMF message bytes and verifies:
1. Msgpack structure matches Sideband FIELD_TELEMETRY format
2. Ed25519 signature is valid
3. Telemetry values decode correctly

Usage:
    # Standalone test with synthetic data:
    python test_lxmf_beacon.py

    # With captured packet hex:
    python test_lxmf_beacon.py --hex <hex_bytes> --pubkey <ed25519_pub_hex> --dest <dest_hash_hex>
"""

import argparse
import hashlib
import struct
import sys

try:
    from nacl.signing import VerifyKey
    from nacl.encoding import RawEncoder
except ImportError:
    print("pip install pynacl")
    sys.exit(1)

try:
    import umsgpack
except ImportError:
    try:
        import RNS.vendor.umsgpack as umsgpack
    except ImportError:
        print("pip install u-msgpack-python  (or have RNS installed)")
        sys.exit(1)


SID_TIME = 0x01
SID_LOCATION = 0x02
SID_BATTERY = 0x04
FIELD_TELEMETRY = 0x02


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def decode_lxmf_opportunistic(packet: bytes, dest_hash: bytes):
    """Decode an LXMF OPPORTUNISTIC packet (no dest_hash prefix in wire format).

    Wire format: source_hash(16) + signature(64) + msgpack_payload
    """
    if len(packet) < 80 + 4:
        raise ValueError(f"Packet too short: {len(packet)} bytes")

    source_hash = packet[:16]
    signature = packet[16:80]
    payload = packet[80:]

    print(f"  Source hash: {source_hash.hex()}")
    print(f"  Signature:   {signature.hex()[:32]}...")
    print(f"  Payload len: {len(payload)} bytes")

    # Decode msgpack payload
    msg = umsgpack.unpackb(payload)
    if not isinstance(msg, list) or len(msg) != 4:
        raise ValueError(f"Expected array[4], got {type(msg).__name__} len={len(msg) if isinstance(msg, list) else 'N/A'}")

    timestamp = msg[0]
    title = msg[1]
    content = msg[2]
    fields = msg[3]

    print(f"  Timestamp:   {timestamp}")
    print(f"  Title:       {repr(title)}")
    print(f"  Content:     {repr(content)}")
    print(f"  Fields keys: {list(fields.keys()) if isinstance(fields, dict) else fields}")

    # Decode telemetry
    if FIELD_TELEMETRY in fields:
        telem_bytes = fields[FIELD_TELEMETRY]
        telem = umsgpack.unpackb(telem_bytes)
        print(f"  Telemetry:   {telem}")

        if SID_TIME in telem:
            print(f"    Time:      {telem[SID_TIME]}")

        if SID_LOCATION in telem:
            loc = telem[SID_LOCATION]
            lat = struct.unpack("!i", loc[0])[0] / 1e6
            lon = struct.unpack("!i", loc[1])[0] / 1e6
            alt = struct.unpack("!i", loc[2])[0] / 1e2
            speed = struct.unpack("!I", loc[3])[0] / 1e2
            bearing = struct.unpack("!i", loc[4])[0]
            hdop = struct.unpack("!H", loc[5])[0] / 1e2
            last_update = loc[6]
            print(f"    Location:  lat={lat:.6f}, lon={lon:.6f}, alt={alt:.1f}m")
            print(f"    Speed:     {speed:.2f} km/h")
            print(f"    HDOP:      {hdop:.2f}")
            print(f"    Update:    {last_update}")

        if SID_BATTERY in telem:
            bat = telem[SID_BATTERY]
            print(f"    Battery:   {bat[0]}%")

    return source_hash, signature, payload


def verify_signature(source_hash: bytes, signature: bytes, payload: bytes,
                     dest_hash: bytes, ed25519_pub: bytes):
    """Verify LXMF message signature.

    signed_part = hashed_part + message_hash
    where:
        hashed_part = dest_hash + source_hash + payload
        message_hash = SHA256(hashed_part)  (RNS.Identity.full_hash = single SHA256)
    """
    hashed_part = dest_hash + source_hash + payload
    message_hash = sha256(hashed_part)
    signed_part = hashed_part + message_hash

    vk = VerifyKey(ed25519_pub, encoder=RawEncoder)
    try:
        vk.verify(signed_part, signature)
        print("  Signature:   VALID")
        return True
    except Exception as e:
        print(f"  Signature:   INVALID ({e})")
        return False


def synthetic_test():
    """Build a synthetic LXMF packet matching the firmware's output format and verify it."""
    from nacl.signing import SigningKey

    print("=" * 60)
    print("Synthetic LXMF Beacon Verification")
    print("=" * 60)

    # Generate a test identity (simulating what the firmware does)
    sk = SigningKey.generate()
    ed25519_pub = sk.verify_key.encode()
    ed25519_priv = sk.encode()  # 32-byte seed

    # Derive X25519 from Ed25519 (matching firmware's libsodium calls)
    from nacl.bindings import (
        crypto_sign_ed25519_pk_to_curve25519,
        crypto_sign_ed25519_sk_to_curve25519,
    )
    # libsodium sk is seed(32)+pk(32)
    full_sk = ed25519_priv + ed25519_pub
    x25519_pub = crypto_sign_ed25519_pk_to_curve25519(ed25519_pub)
    x25519_priv = crypto_sign_ed25519_sk_to_curve25519(full_sk)

    # Compute identity hash: SHA256(x25519_pub + ed25519_pub)[:16]
    identity_hash = sha256(x25519_pub + ed25519_pub)[:16]
    print(f"  Identity hash:  {identity_hash.hex()}")

    # Compute source hash (LXMF delivery dest)
    lxmf_hash = sha256(b"lxmf")
    delivery_hash = sha256(b"delivery")
    name_hash = sha256(lxmf_hash + delivery_hash)[:10]
    source_hash = sha256(name_hash + identity_hash)[:16]
    print(f"  Source hash:    {source_hash.hex()}")

    # Simulate a destination (some Sideband app)
    dest_hash = bytes.fromhex("c8d635088f630e582fbefad49044e61b")
    print(f"  Dest hash:      {dest_hash.hex()}")

    # Build telemetry (matching firmware's lxmf_pack_telemetry)
    lat, lon, alt = 51.507351, -0.127758, 11.0
    speed, hdop = 0.5, 1.2
    timestamp = 1700000000
    bat = 85

    # Pack telemetry bytes
    telem = {
        SID_TIME: timestamp,
        SID_LOCATION: [
            struct.pack("!i", int(round(lat * 1e6))),
            struct.pack("!i", int(round(lon * 1e6))),
            struct.pack("!i", int(round(alt * 1e2))),
            struct.pack("!I", int(round(speed * 1e2))),
            struct.pack("!i", 0),
            struct.pack("!H", int(round(hdop * 1e2))),
            timestamp,
        ],
        SID_BATTERY: [float(bat), False, None],
    }
    telem_bytes = umsgpack.packb(telem)

    # Build msgpack payload: [timestamp_f64, "", "", {0x02: telem_bytes}]
    payload = umsgpack.packb([
        float(timestamp),
        b"",
        b"",
        {FIELD_TELEMETRY: telem_bytes},
    ])

    # Sign
    hashed_part = dest_hash + source_hash + payload
    message_hash = sha256(hashed_part)
    signed_part = hashed_part + message_hash
    signature = sk.sign(signed_part).signature

    # Assemble wire format
    packet = source_hash + signature + payload
    print(f"  Packet size:    {len(packet)} bytes")
    print(f"  Packet hex:     {packet.hex()[:64]}...")
    print()

    # Now decode and verify
    print("Decoding:")
    src, sig, pl = decode_lxmf_opportunistic(packet, dest_hash)
    print()

    print("Verifying:")
    ok = verify_signature(src, sig, pl, dest_hash, ed25519_pub)

    # Cross-verify: use RNS.Identity.full_hash to ensure we match the library
    try:
        import RNS
        hashed_part = dest_hash + src + pl
        rns_hash = RNS.Identity.full_hash(hashed_part)
        our_hash = sha256(hashed_part)
        if rns_hash == our_hash:
            print("  RNS cross-check: full_hash matches our SHA256 (single pass)")
        else:
            print(f"  RNS cross-check: MISMATCH!")
            print(f"    RNS full_hash: {rns_hash.hex()}")
            print(f"    Our SHA256:    {our_hash.hex()}")
            ok = False
    except ImportError:
        print("  (RNS not available for cross-check)")

    print()
    print("=" * 60)
    print(f"Result: {'PASS' if ok else 'FAIL'}")
    print("=" * 60)
    return ok


def decode_announce(packet: bytes):
    """Decode and verify an RNS announce packet.

    Returns (identity_hash, ed25519_pub, signature_valid) or raises on error.
    """
    if len(packet) < 19 + 64 + 10 + 10 + 64:
        raise ValueError(f"Announce packet too short: {len(packet)} bytes")

    flags = packet[0]
    hops = packet[1]
    dest_hash = packet[2:18]
    context = packet[18]

    print(f"  Flags:       0x{flags:02x}")
    print(f"  Dest hash:   {dest_hash.hex()}")

    pos = 19
    x25519_pub = packet[pos:pos+32]; pos += 32
    ed25519_pub = packet[pos:pos+32]; pos += 32

    identity_hash = sha256(x25519_pub + ed25519_pub)[:16]
    print(f"  Identity:    {identity_hash.hex()}")
    print(f"  Ed25519 PK:  {ed25519_pub.hex()}")

    name_hash = packet[pos:pos+10]; pos += 10
    random_hash = packet[pos:pos+10]; pos += 10
    signature = packet[pos:pos+64]; pos += 64
    app_data = packet[pos:]

    # Verify name_hash matches lxmf.delivery
    lxmf_h = sha256(b"lxmf")
    delivery_h = sha256(b"delivery")
    expected_nh = sha256(lxmf_h + delivery_h)[:10]
    nh_ok = (name_hash == expected_nh)
    print(f"  Name hash:   {'VALID' if nh_ok else 'MISMATCH'}")

    # Verify signature
    signed_data = dest_hash + x25519_pub + ed25519_pub + name_hash + random_hash + app_data
    vk = VerifyKey(ed25519_pub, encoder=RawEncoder)
    try:
        vk.verify(signed_data, signature)
        print(f"  Signature:   VALID")
        sig_ok = True
    except Exception as e:
        print(f"  Signature:   INVALID ({e})")
        sig_ok = False

    if app_data:
        try:
            name = umsgpack.unpackb(app_data)
            print(f"  App data:    {repr(name)}")
        except Exception:
            print(f"  App data:    {app_data.hex()}")

    return identity_hash, ed25519_pub, sig_ok and nh_ok


def test_timestamp_computation():
    """Verify the firmware's RTC→Unix timestamp computation matches Python's calendar.timegm().

    The firmware computes:
        days = sum(365 or 366 for each year 1970..year-1)
             + mdays[month-1] + (1 if month>2 and leap year) + (day-1)
        timestamp = days * 86400 + hour * 3600 + minute * 60 + second
    """
    import calendar

    print("=" * 60)
    print("Timestamp Cross-Validation")
    print("=" * 60)

    test_cases = [
        # (year, month, day, hour, minute, second)
        (2024, 1, 1, 0, 0, 0),
        (2024, 3, 1, 12, 30, 45),     # Leap year, after Feb
        (2025, 6, 15, 8, 0, 0),
        (2026, 3, 11, 14, 30, 0),     # Today-ish
        (2000, 2, 29, 23, 59, 59),    # Y2K leap day
        (2099, 12, 31, 23, 59, 59),   # End of valid range
    ]

    mdays = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    all_ok = True

    for year, month, day, hour, minute, second in test_cases:
        # Python reference
        expected = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))

        # Firmware algorithm
        days = 0
        for y in range(1970, year):
            days += 366 if (y % 4 == 0) else 365
        days += mdays[month - 1]
        if month > 2 and (year % 4 == 0):
            days += 1
        days += day - 1
        firmware_ts = days * 86400 + hour * 3600 + minute * 60 + second

        ok = (firmware_ts == expected)
        status = "OK" if ok else "FAIL"
        print(f"  {year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}  "
              f"fw={firmware_ts}  py={expected}  {status}")
        if not ok:
            all_ok = False

    print()
    print(f"Result: {'PASS' if all_ok else 'FAIL'}")
    print("=" * 60)
    return all_ok


def hkdf_sha256(ikm, salt, length):
    """HKDF-SHA256 matching RNS Cryptography.hkdf() with context=b""."""
    import hmac as hmac_mod
    prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
    blocks = []
    prev = b""
    for i in range((length + 31) // 32):
        prev = hmac_mod.new(
            prk, prev + bytes([(i + 1) % 256]), hashlib.sha256
        ).digest()
        blocks.append(prev)
    return b"".join(blocks)[:length]


def verify_ifac(masked_packet: bytes, ifac_key: bytes, ifac_size: int = 8):
    """Verify IFAC on a captured over-the-air packet.

    Implements the RX side of RNS Transport.inbound() IFAC verification.

    Args:
        masked_packet: Raw bytes captured over the air (with IFAC flag set)
        ifac_key: 64-byte IFAC key (same as provisioned to device)
        ifac_size: IFAC tag size (default 8)

    Returns:
        (True, original_packet) if IFAC is valid, (False, None) otherwise
    """
    if len(masked_packet) < 2 + ifac_size:
        print(f"  Packet too short for IFAC: {len(masked_packet)} bytes")
        return False, None

    # Check IFAC flag
    if masked_packet[0] & 0x80 != 0x80:
        print("  IFAC flag not set (bit 7 of byte 0)")
        return False, None

    raw = bytearray(masked_packet)

    # Extract IFAC (unmasked bytes 2..2+ifac_size)
    ifac = bytes(raw[2:2 + ifac_size])

    # Generate mask (same as TX)
    mask = hkdf_sha256(ifac, ifac_key, len(raw))

    # Unmask: bytes 0, 1, and ifac_size+2 onwards
    unmasked = bytearray(len(raw))
    for i in range(len(raw)):
        if i <= 1 or i > ifac_size + 1:
            unmasked[i] = raw[i] ^ mask[i]
        else:
            unmasked[i] = raw[i]

    # Clear IFAC flag and reconstruct original packet
    new_header = bytes([unmasked[0] & 0x7F, unmasked[1]])
    original = new_header + bytes(unmasked[2 + ifac_size:])

    # Verify: sign original packet, check last ifac_size bytes match
    from nacl.signing import SigningKey
    from nacl.encoding import RawEncoder

    # Derive Ed25519 signing key from ifac_key[32:64]
    ed25519_seed = ifac_key[32:64]
    sk = SigningKey(ed25519_seed, encoder=RawEncoder)
    signature = sk.sign(original).signature  # 64 bytes
    expected_ifac = signature[-ifac_size:]

    if ifac == expected_ifac:
        print(f"  IFAC: VALID ({ifac.hex()})")
        print(f"  Original packet: {len(original)} bytes")
        print(f"  Header: 0x{original[0]:02x} 0x{original[1]:02x}")
        return True, bytes(original)
    else:
        print(f"  IFAC: INVALID")
        print(f"    Got:      {ifac.hex()}")
        print(f"    Expected: {expected_ifac.hex()}")
        return False, None


def test_ifac_roundtrip():
    """Test IFAC apply/verify roundtrip using the same algorithm as the firmware."""
    from nacl.signing import SigningKey
    from nacl.encoding import RawEncoder
    import hmac as hmac_mod
    import os

    print("=" * 60)
    print("IFAC Round-Trip Verification")
    print("=" * 60)

    # Derive IFAC key from test network_name + passphrase
    network_name = "helv4net"
    passphrase = "R3ticulum-priv8-m3sh"

    IFAC_SALT = bytes.fromhex(
        "adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8"
    )

    nn_hash = hashlib.sha256(network_name.encode("utf-8")).digest()
    pp_hash = hashlib.sha256(passphrase.encode("utf-8")).digest()
    ifac_origin = nn_hash + pp_hash
    ifac_origin_hash = hashlib.sha256(ifac_origin).digest()
    ifac_key = hkdf_sha256(ifac_origin_hash, IFAC_SALT, 64)

    print(f"  Network: {network_name}")
    print(f"  IFAC key: {ifac_key.hex()[:32]}...")
    print()

    # Create a synthetic RNS packet (announce-like)
    original = bytearray(150)
    original[0] = 0x01  # FLAGS: announce
    original[1] = 0x00  # HOPS
    for i in range(2, 150):
        original[i] = i & 0xFF
    original = bytes(original)

    print(f"  Original packet: {len(original)} bytes")
    print(f"  Header: 0x{original[0]:02x} 0x{original[1]:02x}")

    # TX: Apply IFAC (simulate firmware)
    ifac_size = 8

    # Sign
    ed25519_seed = ifac_key[32:64]
    sk = SigningKey(ed25519_seed, encoder=RawEncoder)
    sig = sk.sign(original).signature
    ifac = sig[-ifac_size:]

    # Generate mask
    new_size = len(original) + ifac_size
    mask = hkdf_sha256(ifac, ifac_key, new_size)

    # Assemble: header(2) + ifac(8) + payload
    new_header = bytes([original[0] | 0x80, original[1]])
    assembled = new_header + ifac + original[2:]

    # Apply mask
    masked = bytearray(len(assembled))
    for i in range(len(assembled)):
        if i == 0:
            masked[i] = (assembled[i] ^ mask[i]) | 0x80
        elif i == 1 or i > ifac_size + 1:
            masked[i] = assembled[i] ^ mask[i]
        else:
            masked[i] = assembled[i]

    print(f"  Masked packet: {len(masked)} bytes")

    # RX: Verify IFAC
    print()
    print("Verifying:")
    ok, recovered = verify_ifac(bytes(masked), ifac_key, ifac_size)

    if ok and recovered == original:
        print(f"  Round-trip: PASS (recovered matches original)")
    elif ok:
        print(f"  Round-trip: FAIL (IFAC valid but packet mismatch)")
        ok = False
    else:
        print(f"  Round-trip: FAIL")

    print()
    print(f"Result: {'PASS' if ok else 'FAIL'}")
    print("=" * 60)
    return ok


def main():
    parser = argparse.ArgumentParser(description="Verify RNode LXMF beacon packets")
    parser.add_argument("--hex", help="Packet hex bytes (source_hash + signature + payload)")
    parser.add_argument("--pubkey", help="Ed25519 public key hex (32 bytes)")
    parser.add_argument("--dest", help="Destination hash hex (16 bytes)")
    parser.add_argument("--announce-hex", help="Announce packet hex bytes (full RNS announce)")
    parser.add_argument("--test-timestamp", action="store_true",
                        help="Run timestamp cross-validation test")
    parser.add_argument("--test-ifac", action="store_true",
                        help="Run IFAC round-trip verification test")
    parser.add_argument("--verify-ifac-hex", metavar="HEX",
                        help="Verify IFAC on a captured packet (hex bytes)")
    parser.add_argument("--ifac-name", default="helv4net",
                        help="Network name for IFAC key derivation")
    parser.add_argument("--ifac-pass", default="R3ticulum-priv8-m3sh",
                        help="Passphrase for IFAC key derivation")
    args = parser.parse_args()

    if args.test_ifac:
        ok = test_ifac_roundtrip()
        sys.exit(0 if ok else 1)

    if args.verify_ifac_hex:
        IFAC_SALT = bytes.fromhex(
            "adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8"
        )
        nn_hash = hashlib.sha256(args.ifac_name.encode("utf-8")).digest()
        pp_hash = hashlib.sha256(args.ifac_pass.encode("utf-8")).digest()
        ifac_origin_hash = hashlib.sha256(nn_hash + pp_hash).digest()
        ifac_key = hkdf_sha256(ifac_origin_hash, IFAC_SALT, 64)
        packet = bytes.fromhex(args.verify_ifac_hex)
        ok, original = verify_ifac(packet, ifac_key)
        if ok and original:
            print(f"\n  Recovered packet hex: {original.hex()}")
        sys.exit(0 if ok else 1)

    if args.test_timestamp:
        ok = test_timestamp_computation()
        sys.exit(0 if ok else 1)

    if args.announce_hex:
        packet = bytes.fromhex(args.announce_hex)
        print("Decoding announce packet:")
        identity_hash, ed_pub, ok = decode_announce(packet)
        print()
        sys.exit(0 if ok else 1)

    if args.hex:
        packet = bytes.fromhex(args.hex)
        dest_hash = bytes.fromhex(args.dest) if args.dest else b"\x00" * 16

        print("Decoding LXMF packet:")
        src, sig, pl = decode_lxmf_opportunistic(packet, dest_hash)

        if args.pubkey:
            ed25519_pub = bytes.fromhex(args.pubkey)
            print("\nVerifying signature:")
            verify_signature(src, sig, pl, dest_hash, ed25519_pub)
    else:
        ok1 = synthetic_test()
        print()
        ok2 = test_timestamp_computation()
        print()
        ok3 = test_ifac_roundtrip()
        sys.exit(0 if (ok1 and ok2 and ok3) else 1)


if __name__ == "__main__":
    main()
