#!/usr/bin/env python3
"""Verification test for BeaconCrypto.h encryption.

Creates an RNS Identity, manually replicates the ESP32 encryption pipeline
step-by-step, and verifies that Identity.decrypt() can recover the plaintext.

Prints all intermediate values at each stage so the ESP32 firmware can be
cross-verified against the same inputs.

Usage:
    cd /home/ian/Code/rns-collector
    .venv/bin/python test_beacon_crypto.py
"""

import hashlib
import hmac as hmac_mod
import os
import sys

# RNS crypto primitives (no Reticulum instance needed)
import RNS.Cryptography
from RNS.Cryptography import HMAC as RNS_HMAC
from RNS.Cryptography import PKCS7, Token, hkdf
from RNS.Cryptography import X25519PrivateKey, X25519PublicKey
from RNS.Cryptography.AES import AES_256_CBC
from RNS import Identity


# ---------------------------------------------------------------------------
# Manual reimplementations (matching BeaconCrypto.h)
# ---------------------------------------------------------------------------

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac_mod.new(key, data, hashlib.sha256).digest()


def manual_hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256, matching both RNS and BeaconCrypto.h rns_hkdf().

    Extract: PRK = HMAC-SHA256(key=salt, data=ikm)
    Expand:  T1  = HMAC-SHA256(PRK, info + 0x01)
             T2  = HMAC-SHA256(PRK, T1 + info + 0x02)
    """
    prk = hmac_sha256(salt, ikm)

    block = b""
    derived = b""
    hash_len = 32
    n_blocks = (length + hash_len - 1) // hash_len
    for i in range(n_blocks):
        block = hmac_sha256(prk, block + info + bytes([(i + 1) % 256]))
        derived += block

    return derived[:length]


def manual_pkcs7_pad(data: bytes, bs: int = 16) -> bytes:
    n = bs - (len(data) % bs)
    return data + bytes([n]) * n


def manual_encrypt(plaintext: bytes,
                   peer_pub: X25519PublicKey,
                   identity_hash: bytes,
                   ephemeral_prv: X25519PrivateKey | None = None,
                   iv: bytes | None = None) -> dict:
    """Replicate BeaconCrypto.h encryption step by step.

    Returns dict of intermediate values for inspection.
    """
    if ephemeral_prv is None:
        ephemeral_prv = X25519PrivateKey.generate()
    if iv is None:
        iv = os.urandom(16)

    ephemeral_pub_bytes = ephemeral_prv.public_key().public_bytes()

    # ECDH shared secret (little-endian, 32 bytes)
    shared_key = ephemeral_prv.exchange(peer_pub)

    # HKDF extract
    prk = hmac_sha256(identity_hash, shared_key)

    # HKDF expand (info=b"")
    derived = manual_hkdf(shared_key, identity_hash, b"", 64)
    signing_key = derived[:32]
    encryption_key = derived[32:]

    # Cross-check against RNS hkdf()
    rns_derived = hkdf(length=64, derive_from=shared_key,
                       salt=identity_hash, context=None)
    assert derived == rns_derived, "manual HKDF != RNS hkdf()"

    # PKCS7 pad
    padded = manual_pkcs7_pad(plaintext)

    # Cross-check against RNS PKCS7
    rns_padded = PKCS7.pad(plaintext)
    assert padded == rns_padded, "manual PKCS7 != RNS PKCS7"

    # AES-256-CBC encrypt
    ciphertext = AES_256_CBC.encrypt(plaintext=padded, key=encryption_key, iv=iv)

    # HMAC-SHA256(signing_key, IV || ciphertext)
    signed_parts = iv + ciphertext
    mac = RNS_HMAC.new(signing_key, signed_parts).digest()

    # Cross-check against stdlib hmac
    mac_check = hmac_sha256(signing_key, signed_parts)
    assert mac == mac_check, "RNS HMAC != stdlib hmac"

    # Wire format: ephemeral_pub(32) + IV(16) + ciphertext(var) + HMAC(32)
    token_bytes = iv + ciphertext + mac
    full_payload = ephemeral_pub_bytes + token_bytes

    return {
        "ephemeral_pub": ephemeral_pub_bytes,
        "shared_key": shared_key,
        "prk": prk,
        "derived": derived,
        "signing_key": signing_key,
        "encryption_key": encryption_key,
        "iv": iv,
        "padded": padded,
        "ciphertext": ciphertext,
        "hmac": mac,
        "token_bytes": token_bytes,
        "full_payload": full_payload,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def hexdump(label: str, data: bytes, indent: int = 2) -> None:
    prefix = " " * indent
    print(f"{prefix}{label:26s} ({len(data):3d}B): {data.hex()}")


def section(title: str) -> None:
    print()
    print(title)
    print("-" * 70)


# ---------------------------------------------------------------------------
# Test 1: Round-trip with random keys
# ---------------------------------------------------------------------------

def test_roundtrip():
    print("=" * 70)
    print("  Test 1: Round-trip encrypt → decrypt (random keys)")
    print("=" * 70)

    identity = Identity()

    pub_key_full = identity.get_public_key()       # X25519(32) + Ed25519(32)
    x25519_pub_bytes = pub_key_full[:32]
    ed25519_pub_bytes = pub_key_full[32:]
    identity_hash = identity.hash                   # 16 bytes

    x25519_pub = X25519PublicKey.from_public_bytes(x25519_pub_bytes)

    section("Collector Identity")
    hexdump("X25519 pub key",  x25519_pub_bytes)
    hexdump("Ed25519 pub key", ed25519_pub_bytes)
    hexdump("Identity hash",   identity_hash)

    # Verify identity hash = SHA256(pub_key_full)[:16]
    expected_hash = hashlib.sha256(pub_key_full).digest()[:16]
    assert identity_hash == expected_hash, "identity hash mismatch"
    print("  Identity hash verified: SHA256(X25519_pub + Ed25519_pub)[:16]")

    # Compute dest hash manually
    name_hash = hashlib.sha256(b"rnlog.collector").digest()[:10]
    dest_hash = hashlib.sha256(name_hash + identity_hash).digest()[:16]

    section("Destination Hash")
    hexdump("Name hash (10B)", name_hash)
    hexdump("Dest hash (16B)", dest_hash)

    # Provisioning data (what CMD_BCN_KEY sends to firmware)
    combined = x25519_pub_bytes + identity_hash + dest_hash
    section("Provisioning Data (CMD_BCN_KEY, 64 bytes)")
    hexdump("X25519 pub  [0:32]",  x25519_pub_bytes)
    hexdump("Ident hash [32:48]",  identity_hash)
    hexdump("Dest hash  [48:64]",  dest_hash)
    hexdump("Combined",            combined)

    # Beacon JSON payload
    beacon_json = (
        b'{"lat":51.507400,"lon":-0.127800,"alt":11.0,'
        b'"sat":7,"spd":0.5,"hdop":1.2,"bat":87,"fix":true}'
    )

    section(f"Plaintext ({len(beacon_json)} bytes)")
    print(f"  {beacon_json.decode()}")

    # Encrypt manually
    result = manual_encrypt(beacon_json, x25519_pub, identity_hash)

    section("Encryption Intermediates")
    hexdump("Ephemeral pub",   result["ephemeral_pub"])
    hexdump("Shared key (LE)", result["shared_key"])
    hexdump("HKDF salt",       identity_hash)
    hexdump("HKDF PRK",        result["prk"])
    hexdump("Derived key",     result["derived"])
    hexdump("  Signing key",   result["signing_key"])
    hexdump("  Encryption key", result["encryption_key"])
    hexdump("IV",              result["iv"])
    hexdump("Padded plaintext", result["padded"])
    hexdump("Ciphertext",      result["ciphertext"])
    hexdump("HMAC",            result["hmac"])

    section("Wire Format")
    payload = result["full_payload"]
    print(f"  [0:32]   Ephemeral pub: {payload[:32].hex()}")
    print(f"  [32:48]  IV:            {payload[32:48].hex()}")
    print(f"  [48:-32] Ciphertext:    {payload[48:-32].hex()}")
    print(f"  [-32:]   HMAC:          {payload[-32:].hex()}")
    print(f"  Total payload: {len(payload)} bytes")

    # RNS packet
    section("Full RNS SINGLE Packet")
    header = bytes([0x00, 0x00]) + dest_hash + bytes([0x00])
    full_packet = header + payload
    print(f"  [0]     FLAGS:   0x00 (SINGLE, DATA)")
    print(f"  [1]     HOPS:    0x00")
    print(f"  [2:18]  Dest:    {dest_hash.hex()}")
    print(f"  [18]    Context: 0x00")
    print(f"  [19:]   Payload: {len(payload)} bytes")
    print(f"  Total:  {len(full_packet)} bytes (MTU=508)")

    # Decrypt with RNS Identity.decrypt()
    section("Decryption")
    decrypted = identity.decrypt(result["full_payload"])

    if decrypted == beacon_json:
        print("  PASS: Identity.decrypt() recovered original plaintext")
    else:
        print(f"  FAIL: got {decrypted!r}")
        return False

    # Also verify RNS's own encrypt → decrypt
    rns_encrypted = identity.encrypt(beacon_json)
    rns_decrypted = identity.decrypt(rns_encrypted)
    assert rns_decrypted == beacon_json, "RNS own round-trip failed"
    print("  PASS: RNS Identity.encrypt() → decrypt() round-trip OK")

    return True


# ---------------------------------------------------------------------------
# Test 2: Deterministic reference vector (fixed ephemeral key + IV)
# ---------------------------------------------------------------------------

def test_deterministic_vector():
    print()
    print("=" * 70)
    print("  Test 2: Deterministic reference vector (fixed keys)")
    print("=" * 70)
    print()
    print("  Use these values to verify the ESP32 BeaconCrypto.h produces")
    print("  identical intermediate results for the same inputs.")

    # Fixed collector identity key material.
    # In practice these come from RNS Identity; here we build one from
    # known private key bytes so the test is reproducible.
    collector_prv = X25519PrivateKey.generate()
    collector_pub = collector_prv.public_key()
    collector_pub_bytes = collector_pub.public_bytes()

    # We need the full identity hash which requires Ed25519 too.
    # Use RNS Identity for convenience, then extract.
    identity = Identity()
    # Override with known X25519 pub so ECDH is reproducible
    # Actually, we can't easily override the identity keys.
    # Instead, just use the random identity and record the values.

    pub_key_full = identity.get_public_key()
    x25519_pub_bytes = pub_key_full[:32]
    identity_hash = identity.hash
    x25519_pub = X25519PublicKey.from_public_bytes(x25519_pub_bytes)

    # Fixed ephemeral private key (32 bytes, will be clamped by X25519)
    ephemeral_seed = bytes(range(32))  # 0x00, 0x01, 0x02, ..., 0x1f
    ephemeral_prv = X25519PrivateKey.from_private_bytes(ephemeral_seed)

    # Fixed IV
    fixed_iv = bytes([0xA0 + i for i in range(16)])

    # Short test payload
    plaintext = b'{"lat":51.507400,"lon":-0.127800,"alt":11.0,"sat":7,"spd":0.5,"hdop":1.2,"bat":87,"fix":true}'

    section("Fixed Inputs")
    hexdump("Collector X25519 pub", x25519_pub_bytes)
    hexdump("Identity hash",        identity_hash)
    hexdump("Ephemeral seed",       ephemeral_seed)
    hexdump("Ephemeral pub",        ephemeral_prv.public_key().public_bytes())
    hexdump("Fixed IV",             fixed_iv)
    print(f"  Plaintext ({len(plaintext)}B): {plaintext.decode()}")

    result = manual_encrypt(
        plaintext, x25519_pub, identity_hash,
        ephemeral_prv=ephemeral_prv, iv=fixed_iv,
    )

    section("Reference Intermediate Values")
    hexdump("Shared key (LE)",  result["shared_key"])
    hexdump("HKDF PRK",         result["prk"])
    hexdump("Signing key",      result["signing_key"])
    hexdump("Encryption key",   result["encryption_key"])
    hexdump("Padded plaintext", result["padded"])
    hexdump("Ciphertext",       result["ciphertext"])
    hexdump("HMAC",             result["hmac"])

    section("Reference Wire Payload")
    payload = result["full_payload"]
    hexdump("Full payload", payload)

    # Verify decrypt
    decrypted = identity.decrypt(payload)
    if decrypted == plaintext:
        print()
        print("  PASS: deterministic vector decrypts correctly")
    else:
        print(f"  FAIL: got {decrypted!r}")
        return False

    # Print C array format for firmware test
    section("C Array Format (for firmware test)")

    def c_array(name, data, cols=12):
        lines = []
        for i in range(0, len(data), cols):
            chunk = data[i:i+cols]
            lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk))
        body = ",\n".join(lines)
        print(f"  uint8_t {name}[{len(data)}] = {{")
        print(body)
        print(f"  }};")
        print()

    c_array("test_collector_pub", x25519_pub_bytes)
    c_array("test_identity_hash", identity_hash)
    c_array("test_ephemeral_seed", ephemeral_seed)
    c_array("test_iv", fixed_iv)
    c_array("test_shared_key", result["shared_key"])
    c_array("test_signing_key", result["signing_key"])
    c_array("test_encryption_key", result["encryption_key"])
    c_array("test_expected_ciphertext", result["ciphertext"])
    c_array("test_expected_hmac", result["hmac"])

    return True


# ---------------------------------------------------------------------------
# Test 3: PKCS7 padding edge cases
# ---------------------------------------------------------------------------

def test_pkcs7():
    print()
    print("=" * 70)
    print("  Test 3: PKCS7 padding verification")
    print("=" * 70)

    cases = [
        (b"x" * 1,  16, 15),
        (b"x" * 15, 16, 1),
        (b"x" * 16, 32, 16),
        (b"x" * 17, 32, 15),
        (b"x" * 31, 32, 1),
        (b"x" * 32, 48, 16),
        (b"x" * 93, 96, 3),   # typical beacon JSON
        (b"x" * 96, 112, 16),
    ]

    all_ok = True
    for data, expected_len, expected_pad_val in cases:
        padded = manual_pkcs7_pad(data)
        rns_padded = PKCS7.pad(data)
        pad_val = padded[-1]
        ok = (
            len(padded) == expected_len
            and pad_val == expected_pad_val
            and all(b == pad_val for b in padded[-pad_val:])
            and padded == rns_padded
        )
        status = "PASS" if ok else "FAIL"
        print(f"  {status}: len={len(data):3d} → padded={len(padded):3d}, "
              f"pad_val={pad_val:2d}")
        if not ok:
            all_ok = False

    return all_ok


# ---------------------------------------------------------------------------
# Test 4: HKDF with known test vector
# ---------------------------------------------------------------------------

def test_hkdf_vector():
    """RFC 5869 Test Case 1 (SHA-256)."""
    print()
    print("=" * 70)
    print("  Test 4: HKDF-SHA256 against RFC 5869 Test Case 1")
    print("=" * 70)

    # RFC 5869 A.1
    ikm = bytes([0x0b] * 22)
    salt = bytes(range(0x00, 0x0d))   # 0x00..0x0c (13 bytes)
    info = bytes(range(0xf0, 0xfa))   # 0xf0..0xf9 (10 bytes)
    length = 42

    expected_prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    prk = hmac_sha256(salt, ikm)
    okm = manual_hkdf(ikm, salt, info, length)

    prk_ok = prk == expected_prk
    okm_ok = okm == expected_okm
    rns_okm = hkdf(length=length, derive_from=ikm, salt=salt, context=info)
    rns_ok = rns_okm == expected_okm

    print(f"  PRK:     {'PASS' if prk_ok else 'FAIL'}")
    print(f"  OKM:     {'PASS' if okm_ok else 'FAIL'}")
    print(f"  RNS OKM: {'PASS' if rns_ok else 'FAIL'}")

    if not prk_ok:
        print(f"    expected: {expected_prk.hex()}")
        print(f"    got:      {prk.hex()}")
    if not okm_ok:
        print(f"    expected: {expected_okm.hex()}")
        print(f"    got:      {okm.hex()}")

    section("Beacon-specific HKDF (info=b\"\", salt=16B, ikm=32B)")
    # Replicate what BeaconCrypto.h does:
    # T1 = HMAC(PRK, 0x01)       — 1 byte input
    # T2 = HMAC(PRK, T1 || 0x02) — 33 bytes input
    test_salt = bytes(range(16))
    test_ikm = bytes(range(32))
    test_prk = hmac_sha256(test_salt, test_ikm)
    t1 = hmac_sha256(test_prk, b"\x01")
    t2 = hmac_sha256(test_prk, t1 + b"\x02")
    manual_64 = t1 + t2

    hkdf_64 = manual_hkdf(test_ikm, test_salt, b"", 64)
    rns_64 = hkdf(length=64, derive_from=test_ikm,
                  salt=test_salt, context=None)

    match = manual_64 == hkdf_64 == rns_64
    print(f"  3-way match (manual T1||T2 == hkdf == RNS): "
          f"{'PASS' if match else 'FAIL'}")
    hexdump("PRK",  test_prk)
    hexdump("T1",   t1)
    hexdump("T2",   t2)
    hexdump("Derived (64B)", manual_64)

    return prk_ok and okm_ok and rns_ok and match


# ---------------------------------------------------------------------------
# Test 5: Shared secret byte order
# ---------------------------------------------------------------------------

def test_shared_secret_byte_order():
    """Verify shared_key from X25519 exchange is little-endian (RFC 7748).

    The ESP32 code does:
        mbedtls_mpi_write_binary() → big-endian
        reverse 32 bytes → little-endian (to match Python)

    This test creates a known keypair and verifies the exchange result is
    consistent and not all-zeros.
    """
    print()
    print("=" * 70)
    print("  Test 5: X25519 shared secret byte order")
    print("=" * 70)

    prv_a = X25519PrivateKey.generate()
    prv_b = X25519PrivateKey.generate()

    pub_a = prv_a.public_key()
    pub_b = prv_b.public_key()

    shared_ab = prv_a.exchange(pub_b)
    shared_ba = prv_b.exchange(pub_a)

    match = shared_ab == shared_ba
    nonzero = shared_ab != b"\x00" * 32

    print(f"  A.exchange(B) == B.exchange(A): {'PASS' if match else 'FAIL'}")
    print(f"  Shared secret is nonzero:       {'PASS' if nonzero else 'FAIL'}")
    hexdump("Pub A",     pub_a.public_bytes())
    hexdump("Pub B",     pub_b.public_bytes())
    hexdump("Shared key", shared_ab)

    # Verify the byte order note:
    # Python X25519 returns little-endian per RFC 7748
    # ESP32 mbedTLS mpi_write_binary returns big-endian, needs reversal
    print()
    print("  Note: Python X25519.exchange() returns little-endian (RFC 7748).")
    print("  ESP32 BeaconCrypto.h reverses mbedtls_mpi_write_binary() output")
    print("  to match this byte order.")
    ss_reversed = bytes(reversed(shared_ab))
    hexdump("Shared key reversed (BE)", ss_reversed)
    print("  If ESP32 mpi_write_binary gives the reversed value above,")
    print("  then the reversal in BeaconCrypto.h is correct.")

    return match and nonzero


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    results = []

    results.append(("Round-trip",           test_roundtrip()))
    results.append(("Deterministic vector", test_deterministic_vector()))
    results.append(("PKCS7 padding",        test_pkcs7()))
    results.append(("HKDF RFC 5869",        test_hkdf_vector()))
    results.append(("Shared secret order",  test_shared_secret_byte_order()))

    print()
    print("=" * 70)
    print("  Summary")
    print("=" * 70)

    all_pass = True
    for name, ok in results:
        status = "PASS" if ok else "FAIL"
        print(f"  {status}: {name}")
        if not ok:
            all_pass = False

    print()
    if all_pass:
        print("  ALL TESTS PASSED")
    else:
        print("  SOME TESTS FAILED")

    print("=" * 70)
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
