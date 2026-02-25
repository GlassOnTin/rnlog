"""Reticulum relay for forwarding telemetry between rnlog instances."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import RNS

from .db import open_db, store_reading

ASPECT = "rnlog"
ASPECT_COLLECTOR = "collector"
IDENTITY_FILE = "collector_identity"


def load_or_create_identity(db_dir: Path) -> RNS.Identity:
    """Load collector identity from db_dir, or create a new one."""
    id_path = db_dir / IDENTITY_FILE
    if id_path.exists():
        return RNS.Identity.from_file(str(id_path))
    identity = RNS.Identity()
    identity.to_file(str(id_path))
    return identity


class CollectorServer:
    """Reticulum destination that accepts telemetry from remote rnlog collectors."""

    def __init__(self, reticulum, db_path=None, announce=True):
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

        self.dest_hash = self.dest.hash.hex()
        self.links = []
        self.received = 0

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
