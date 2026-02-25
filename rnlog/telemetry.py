"""Extract telemetry from Reticulum interface stats."""


def extract_telemetry(iface: dict) -> dict | None:
    """Extract telemetry fields from an interface stats dict.

    Returns None if the interface has no telemetry data worth storing.
    """
    reading = {}

    # GPS
    if iface.get("gps_chars") is not None and iface.get("gps_chars", 0) > 0:
        gps = {
            "fix": iface.get("gps_has_fix", False),
            "sats": iface.get("gps_sats", 0),
            "lat": iface.get("gps_latitude"),
            "lon": iface.get("gps_longitude"),
            "alt": iface.get("gps_altitude"),
            "speed": iface.get("gps_speed"),
            "hdop": iface.get("gps_hdop"),
            "chars": iface.get("gps_chars"),
            "passed": iface.get("gps_passed"),
            "failed": iface.get("gps_failed"),
            "with_fix": iface.get("gps_with_fix"),
        }
        if iface.get("gps_nmea"):
            gps["nmea"] = iface["gps_nmea"]
        reading["gps"] = gps

    # Device
    device = {}
    if iface.get("battery_percent") is not None and iface["battery_percent"] > 0:
        device["bat"] = iface["battery_percent"]
    if iface.get("battery_state") is not None:
        device["bat_state"] = iface["battery_state"]
    if iface.get("cpu_temp") is not None:
        device["temp"] = iface["cpu_temp"]
    if iface.get("cpu_load") is not None:
        device["cpu_load"] = iface["cpu_load"]
    if iface.get("mem_load") is not None:
        device["mem_load"] = iface["mem_load"]
    if device:
        reading["device"] = device

    # Radio
    radio = {}
    if iface.get("noise_floor") is not None:
        radio["noise"] = iface["noise_floor"]
    if iface.get("interference") is not None:
        radio["interference"] = iface["interference"]
    if iface.get("rssi") is not None:
        radio["rssi"] = iface["rssi"]
    if iface.get("snr") is not None:
        radio["snr"] = iface["snr"]
    if iface.get("airtime_short") is not None:
        radio["at_15s"] = iface["airtime_short"]
    if iface.get("airtime_long") is not None:
        radio["at_1h"] = iface["airtime_long"]
    if iface.get("channel_load_short") is not None:
        radio["cl_15s"] = iface["channel_load_short"]
    if iface.get("channel_load_long") is not None:
        radio["cl_1h"] = iface["channel_load_long"]
    if radio:
        reading["radio"] = radio

    # Network traffic
    if iface.get("rxb", 0) > 0 or iface.get("txb", 0) > 0:
        reading["traffic"] = {
            "rxb": iface.get("rxb", 0),
            "txb": iface.get("txb", 0),
            "bitrate": iface.get("bitrate"),
        }

    if not reading:
        return None

    reading["interface"] = iface.get("short_name", iface.get("name", "unknown"))
    reading["type"] = iface.get("type", "unknown")
    reading["status"] = iface.get("status", False)
    return reading


def format_summary(reading: dict) -> str:
    """One-line summary for console output."""
    parts = []
    if "gps" in reading:
        g = reading["gps"]
        if g.get("fix") and g.get("lat") is not None:
            parts.append(
                f"GPS {g['lat']:.5f},{g['lon']:.5f} "
                f"sats={g.get('sats', 0)}"
            )
        else:
            parts.append(f"GPS searching sats={g.get('sats', 0)}")
    if "device" in reading:
        d = reading["device"]
        if "bat" in d:
            parts.append(f"bat={d['bat']}%")
        if "temp" in d:
            parts.append(f"temp={d['temp']}C")
    if "radio" in reading:
        r = reading["radio"]
        if "rssi" in r:
            parts.append(f"rssi={r['rssi']}")
        if "snr" in r:
            parts.append(f"snr={r['snr']}")
        if "at_15s" in r:
            parts.append(f"air={r['at_15s']}%")
    if "traffic" in reading:
        t = reading["traffic"]
        parts.append(f"rx={t['rxb']}B tx={t['txb']}B")
    return " | ".join(parts) if parts else "no telemetry"
