#!/usr/bin/env python3
"""Offline cloud/LAN comparison; no network calls or credential printing."""
import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import statistics

from local_server import Frames
from midealocal.security import LocalSecurity
from capture_lan_status import decode_inner
from obtain_lan_key import save_private


def inspect(lan_directory):
    raw = Path("proxy-logs/events.jsonl").read_bytes()
    events = []
    partial = 0
    for line in raw.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            partial += 1
    save_private(Path("proxy-logs/inspection-events-snapshot.json"), events)
    frames = [e for e in events if e["event"] == "frame"]
    lan = json.loads((lan_directory / "capture.json").read_text())
    key = bytes.fromhex(json.loads((lan_directory / "session-secret.json").read_text())["session_key_hex"])
    security = LocalSecurity()
    security._tcp_key = key
    lan_checks = []
    for event in lan["events"]:
        if event["direction"] != "rx" or "outer_sha256_valid" not in event:
            continue
        messages, tail = security.decode_8370(bytes.fromhex(event["wire_hex"]))
        decoded = decode_inner(messages[0], security)
        assert not tail and decoded.get("appliance_hex") == event.get("appliance_hex")
        assert decoded["inner_md5_valid"] and decoded["appliance_checksum_valid"]
        lan_checks.append({"utc": event["utc"], "message_type": decoded["message_type"],
                           "appliance_hex": decoded["appliance_hex"], "body_hex": decoded["body_hex"],
                           "status": decoded.get("status")})
    result = {"snapshot_last_event": events[-1]["time"], "event_count": len(events),
              "cloud_frame_count": len(frames), "partial_json_lines": partial,
              "lan_revalidated_responses": lan_checks, "sessions": [],
              "cloud_frames_verified_with_lan_session_key": 0, "cloud_key_trials": 0}
    for event in frames:
        if event["type"] != 3:
            continue
        result["cloud_key_trials"] += 1
        try:
            security.decode_8370(bytes.fromhex(event["hex"]))
        except Exception:
            continue
        result["cloud_frames_verified_with_lan_session_key"] += 1
    stable_hashes = []
    for session in dict.fromkeys(e["session"] for e in frames):
        subset = [e for e in frames if e["session"] == session]
        summary = {"session": session, "first_frame": subset[0]["time"], "last_frame": subset[-1]["time"],
                   "frames": len(subset), "frame_counts": [], "streams": [], "handshake": []}
        for (direction, kind, length), count in Counter((e["direction"],e["type"],e["length"]) for e in subset).items():
            summary["frame_counts"].append({"direction":direction,"type":kind,"length":length,"count":count})
        for direction in ("device-to-cloud", "cloud-to-device"):
            path = Path("proxy-logs") / f"{session}-{direction}.bin"
            data = path.read_bytes()
            parser = Frames()
            parsed = parser.feed(data)
            logged = b"".join(bytes.fromhex(e["hex"]) for e in subset if e["direction"] == direction)
            summary["streams"].append({"direction":direction,"bytes":len(data),"parsed_frames":len(parsed),
                                       "snapshot_frames_match_stream_prefix":data.startswith(logged),
                                       "unlogged_or_partial_bytes":len(data)-len(logged),
                                       "incomplete_bytes":len(parser.buffer)})
        for event in subset:
            if event["type"] in (8,1,2):
                packet = bytes.fromhex(event["hex"])
                summary["handshake"].append({"type":event["type"],"length":len(packet),
                    "wire_sha256_trailer_matches":hashlib.sha256(packet[:-32]).digest()==packet[-32:]})
                if event["type"]==8:
                    stable_hashes.append(hashlib.sha256(packet[264:392]).hexdigest())
        periodic=[datetime.fromisoformat(e["time"]) for e in subset
                  if e["direction"]=="device-to-cloud" and e["type"]==3 and e["length"]==166]
        if len(periodic)>1:
            gaps=[(b-a).total_seconds() for a,b in zip(periodic,periodic[1:])]
            summary["device_166_byte_interval_median_seconds"]=statistics.median(gaps)
        result["sessions"].append(summary)
    result["type8_stable_field_sha256_values"]=sorted(set(stable_hashes))
    result["cloud_frames_during_lan_capture"]=[{k:e[k] for k in ("time","session","direction","type","length")}
        for e in frames if lan["started_utc"]<=e["time"]<=lan["finished_utc"]]
    save_private(Path("proxy-logs/cloud-inspection.json"), result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lan_directory",type=Path)
    inspect(parser.parse_args().lan_directory)
