"""Reticulum relay for forwarding telemetry between rnlog instances."""
from __future__ import annotations

import json
import struct
import threading
import time
from pathlib import Path

import RNS
import RNS.vendor.umsgpack as umsgpack

from .db import open_db, store_reading

ASPECT = "rnlog"
ASPECT_COLLECTOR = "collector"
ASPECT_BEACON = "beacon"
IDENTITY_FILE = "collector_identity"


SID_TIME = 0x01
SID_LOCATION = 0x02
SID_BATTERY = 0x04


def pack_sideband_telemetry(beacon):
    """Pack beacon dict into Sideband-compatible telemetry bytes.

    Matches the format expected by Sideband's Telemeter.from_packed():
    msgpack dict with SID_TIME, SID_LOCATION, and optionally SID_BATTERY.
    """
    now = int(time.time())
    lat = beacon.get("lat", 0.0)
    lon = beacon.get("lon", 0.0)
    alt = beacon.get("alt", 0.0)
    speed = beacon.get("spd", 0.0)

    packed = {
        SID_TIME: now,
        SID_LOCATION: [
            struct.pack("!i", int(round(lat, 6) * 1e6)),
            struct.pack("!i", int(round(lon, 6) * 1e6)),
            struct.pack("!i", int(round(alt, 2) * 1e2)),
            struct.pack("!I", int(round(speed, 2) * 1e2)),
            struct.pack("!i", 0),           # bearing (unknown)
            struct.pack("!H", int(round(beacon.get("hdop", 10.0), 2) * 1e2)),
            now,                             # last_update
        ],
    }

    bat = beacon.get("bat", 0)
    if bat > 0:
        packed[SID_BATTERY] = [float(bat), False, None]

    return umsgpack.packb(packed)


def load_or_create_identity(db_dir: Path) -> RNS.Identity:
    """Load collector identity from db_dir, or create a new one."""
    id_path = db_dir / IDENTITY_FILE
    if id_path.exists():
        return RNS.Identity.from_file(str(id_path))
    identity = RNS.Identity()
    identity.to_file(str(id_path))
    return identity


class LxmfRelay:
    """Relays beacon GPS data as LXMF telemetry messages to Sideband."""

    ANNOUNCE_INTERVAL = 600  # Re-announce every 10 minutes

    def __init__(self, identity, storagepath, display_name="Heltec GPS Tracker"):
        import LXMF

        self.identity = identity
        self.router = LXMF.LXMRouter(
            identity=identity,
            storagepath=storagepath,
        )
        self.delivery_dest = self.router.register_delivery_identity(
            identity, display_name=display_name,
        )
        self.dest_hash = self.delivery_dest.hash.hex()
        self.target_dest_hash = None
        self.last_announce = 0
        self.sent = 0

    def configure(self, target_dest_hex):
        """Set the Sideband destination to send telemetry to."""
        self.target_dest_hash = bytes.fromhex(target_dest_hex)
        # Request path so we can resolve the identity
        if not RNS.Transport.has_path(self.target_dest_hash):
            RNS.Transport.request_path(self.target_dest_hash)

    def announce_if_needed(self):
        if time.time() - self.last_announce > self.ANNOUNCE_INTERVAL:
            self.router.announce(self.delivery_dest.hash)
            self.last_announce = time.time()

    def relay_beacon(self, beacon):
        """Pack beacon GPS data and send as LXMF telemetry."""
        import LXMF

        if not self.target_dest_hash:
            return

        self.announce_if_needed()

        packed_telemetry = pack_sideband_telemetry(beacon)

        dest_identity = RNS.Identity.recall(self.target_dest_hash)
        if dest_identity is None:
            RNS.Transport.request_path(self.target_dest_hash)
            RNS.log("rnlog: relay target identity not known yet, path requested", RNS.LOG_WARNING)
            return

        dest = RNS.Destination(
            dest_identity, RNS.Destination.OUT,
            RNS.Destination.SINGLE, "lxmf", "delivery",
        )

        lxm = LXMF.LXMessage(
            dest, self.delivery_dest, "",
            fields={LXMF.FIELD_TELEMETRY: packed_telemetry},
            desired_method=LXMF.LXMessage.OPPORTUNISTIC,
        )

        self.router.handle_outbound(lxm)
        self.sent += 1
        RNS.log(f"rnlog: LXMF telemetry sent ({self.sent} total)", RNS.LOG_NOTICE)


class CollectorServer:
    """Reticulum destination that accepts telemetry from remote rnlog collectors."""

    def __init__(self, reticulum, db_path=None, announce=True, sideband_dest=None):
        self.reticulum = reticulum
        self.db = open_db(db_path)

        db_dir = (db_path or Path.home() / ".rnlog" / "telemetry.db").parent
        db_dir.mkdir(parents=True, exist_ok=True)
        self.identity = load_or_create_identity(db_dir)

        self.dest = RNS.Destination(
            self.identity, RNS.Destination.IN,
            RNS.Destination.SINGLE,
            ASPECT, ASPECT_COLLECTOR,
        )
        self.dest.set_link_established_callback(self._link_established)
        self.dest.set_packet_callback(self._encrypted_beacon_received)

        self.dest_hash = self.dest.hash.hex()
        self.links = []
        self.received = 0

        # PLAIN destination for standalone GPS beacons (no identity/crypto)
        self.beacon_dest = RNS.Destination(
            None,
            RNS.Destination.IN,
            RNS.Destination.PLAIN,
            ASPECT, ASPECT_BEACON,
        )
        self.beacon_dest.set_packet_callback(self._beacon_received)
        self.beacon_hash = self.beacon_dest.hash.hex()

        # Optional LXMF relay for forwarding beacons to Sideband
        self.lxmf_relay = None
        if sideband_dest:
            self.lxmf_relay = LxmfRelay(
                identity=self.identity,
                storagepath=str(db_dir),
                display_name="Heltec GPS Tracker",
            )
            self.lxmf_relay.configure(sideband_dest)

        if announce:
            self.dest.announce()

    def _link_established(self, link):
        RNS.log(f"rnlog: incoming link from {link}", RNS.LOG_NOTICE)
        link.set_packet_callback(self._packet_received)
        link.set_link_closed_callback(self._link_closed)
        self.links.append(link)

    def _packet_received(self, message, packet):
        try:
            data = json.loads(message)
            if isinstance(data, list):
                readings = data
            else:
                readings = [data]

            for rec in readings:
                store_reading(
                    self.db,
                    rec["ts"],
                    rec["interface"],
                    rec["interface_hash"],
                    rec["reading"],
                )
                self.received += 1

            self.db.commit()
        except Exception as e:
            RNS.log(f"rnlog: error processing packet: {e}", RNS.LOG_ERROR)

    def _encrypted_beacon_received(self, data, packet):
        """Handle encrypted beacon on SINGLE destination.

        RNS decrypts SINGLE packets before calling this callback.
        The data parameter is already plaintext.
        """
        try:
            beacon = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        reading = {
            "gps": {
                "fix": beacon.get("fix", False),
                "sats": beacon.get("sat", 0),
                "lat": beacon.get("lat"),
                "lon": beacon.get("lon"),
                "alt": beacon.get("alt"),
                "speed": beacon.get("spd"),
                "hdop": beacon.get("hdop"),
            },
        }
        if "bat" in beacon and beacon["bat"] > 0:
            reading["device"] = {"bat": beacon["bat"]}

        now = time.time()
        store_reading(self.db, now, "RNode Beacon",
                      self.dest_hash, reading)
        self.db.commit()
        self.received += 1
        RNS.log(f"rnlog: encrypted beacon received "
                 f"lat={beacon.get('lat')} lon={beacon.get('lon')} "
                 f"sats={beacon.get('sat')}", RNS.LOG_NOTICE)

        if self.lxmf_relay:
            try:
                self.lxmf_relay.relay_beacon(beacon)
            except Exception as e:
                RNS.log(f"rnlog: LXMF relay error: {e}", RNS.LOG_ERROR)

    def _beacon_received(self, data, packet):
        try:
            beacon = json.loads(data)
            reading = {
                "gps": {
                    "fix": beacon.get("fix", False),
                    "sats": beacon.get("sat", 0),
                    "lat": beacon.get("lat"),
                    "lon": beacon.get("lon"),
                    "alt": beacon.get("alt"),
                    "speed": beacon.get("spd"),
                    "hdop": beacon.get("hdop"),
                },
            }
            if "bat" in beacon and beacon["bat"] > 0:
                reading["device"] = {"bat": beacon["bat"]}

            now = time.time()
            store_reading(self.db, now, "RNode Beacon",
                          self.beacon_hash, reading)
            self.db.commit()
            self.received += 1
            RNS.log(f"rnlog: beacon received "
                     f"lat={beacon.get('lat')} lon={beacon.get('lon')} "
                     f"sats={beacon.get('sat')}", RNS.LOG_NOTICE)

            # Relay to Sideband via LXMF
            if self.lxmf_relay:
                try:
                    self.lxmf_relay.relay_beacon(beacon)
                except Exception as e:
                    RNS.log(f"rnlog: LXMF relay error: {e}", RNS.LOG_ERROR)
        except Exception as e:
            RNS.log(f"rnlog: beacon parse error: {e}", RNS.LOG_ERROR)

    def _link_closed(self, link):
        RNS.log(f"rnlog: link closed", RNS.LOG_NOTICE)
        if link in self.links:
            self.links.remove(link)

    def close(self):
        self.db.close()


class CollectorClient:
    """Sends telemetry readings to a remote CollectorServer over Reticulum."""

    PATH_TIMEOUT = 15
    LINK_TIMEOUT = 15

    def __init__(self, reticulum, dest_hash_hex):
        self.reticulum = reticulum
        self.dest_hash = bytes.fromhex(dest_hash_hex)
        self.link = None
        self.connected = False
        self.sent = 0

    def connect(self):
        """Resolve path and establish link to collector."""
        if not RNS.Transport.has_path(self.dest_hash):
            RNS.Transport.request_path(self.dest_hash)
            deadline = time.time() + self.PATH_TIMEOUT
            while not RNS.Transport.has_path(self.dest_hash):
                if time.time() > deadline:
                    raise TimeoutError("Could not resolve path to collector")
                time.sleep(0.5)

        identity = RNS.Identity.recall(self.dest_hash)
        if identity is None:
            raise ValueError("No identity known for collector destination")

        dest = RNS.Destination(
            identity, RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            ASPECT, ASPECT_COLLECTOR,
        )

        self.link = RNS.Link(dest)
        deadline = time.time() + self.LINK_TIMEOUT
        while self.link.status != RNS.Link.ACTIVE:
            if self.link.status == RNS.Link.CLOSED:
                raise ConnectionError("Link closed during establishment")
            if time.time() > deadline:
                raise TimeoutError("Link establishment timed out")
            time.sleep(0.2)

        self.connected = True
        self.link.set_link_closed_callback(self._link_closed)

    def _link_closed(self, link):
        self.connected = False
        self.link = None

    def send(self, readings):
        """Send a batch of readings over the link. Returns True on success."""
        if not self.connected or not self.link:
            return False
        try:
            data = json.dumps(readings, separators=(",", ":")).encode()
            packet = RNS.Packet(self.link, data)
            receipt = packet.send()
            if receipt:
                self.sent += len(readings) if isinstance(readings, list) else 1
                return True
        except Exception as e:
            RNS.log(f"rnlog: send error: {e}", RNS.LOG_ERROR)
        return False

    def close(self):
        if self.link:
            self.link.teardown()
