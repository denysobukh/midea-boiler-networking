#!/usr/bin/env python3
"""Capture one authenticated LAN session with appliance/status queries only."""
import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import importlib.metadata
import json
import os
from pathlib import Path
import socket
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from midealocal.const import DeviceType
from midealocal.devices.e6.message import MessageQuery, MessageE6Response
from midealocal.message import MessageQueryAppliance, MessageType, MessageApplianceResponse
from midealocal.packet_builder import PacketBuilder
from midealocal.security import LocalSecurity, MSGTYPE_HANDSHAKE_REQUEST, MSGTYPE_ENCRYPTED_REQUEST
from obtain_lan_key import DEVICE_ID, HOST, ROOT, save_private


class FrameReader:
    def __init__(self, connection):
        self.connection = connection
        self.buffer = bytearray()

    def read(self, deadline):
        while True:
            if len(self.buffer) >= 6:
                if self.buffer[:2] != b"\x83\x70":
                    raise ValueError("Unexpected TCP framing; buffered bytes retained in failure record")
                size = int.from_bytes(self.buffer[2:4], "big") + 8
                if size > 8192:
                    raise ValueError("Oversized LAN frame")
                if len(self.buffer) >= size:
                    result = bytes(self.buffer[:size])
                    del self.buffer[:size]
                    return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Response deadline expired")
            self.connection.settimeout(remaining)
            chunk = self.connection.recv(8192)
            if not chunk:
                raise ConnectionError("Boiler closed connection")
            self.buffer.extend(chunk)


def decode_inner(inner, security):
    result = {"inner_hex": inner.hex()}
    if len(inner) < 56 or inner[:2] != b"\x5a\x5a":
        result["decode_error"] = "Not a complete 5a5a packet"
        return result
    length = int.from_bytes(inner[4:6], "little")
    result["inner_length_valid"] = length == len(inner)
    result["inner_md5_valid"] = hmac.compare_digest(security.encode32_data(inner[:-16]), inner[-16:])
    if not result["inner_length_valid"] or not result["inner_md5_valid"]:
        result["decode_error"] = "Inner length or signature mismatch"
        return result
    if not inner[40:-16]:
        result["decode_error"] = "No encrypted appliance payload"
        return result
    try:
        plain = unpad(AES.new(security.aes_key, AES.MODE_ECB).decrypt(inner[40:-16]), 16)
        result["appliance_hex"] = plain.hex()
        if len(plain) < 11 or plain[0] != 0xAA:
            raise ValueError("Not an AA appliance message")
        result["appliance_checksum_valid"] = sum(plain[1:]) % 256 == 0
        result["appliance_length_valid"] = plain[1] == len(plain) - 1
        result["device_type"] = plain[2]
        result["message_type"] = plain[9]
        result["protocol_version"] = plain[8]
        result["body_hex"] = plain[10:-1].hex()
        if not result["appliance_checksum_valid"] or not result["appliance_length_valid"] or plain[2] != 0xE6:
            raise ValueError("Appliance checksum, length or type mismatch")
        if plain[9] == MessageType.query_appliance:
            parsed = MessageApplianceResponse(bytearray(plain))
            result["appliance_protocol_version"] = parsed.protocol_version
        elif plain[9] == MessageType.set:
            body = plain[10:-1]
            result["set_message"] = decode_set_body(body)
            result["interpretation"] = "midea-local E6 set layout; direction determines command versus response"
        elif plain[9] in (MessageType.query, MessageType.notify1, MessageType.notify2):
            parsed = MessageE6Response(plain)
            # Only fields decoded from the actual response, never device defaults.
            result["status"] = {k: v for k, v in vars(parsed).items()
                                if not k.startswith("_") and k not in ("body_type", "parser_list")}
            result["interpretation"] = "midea-local E6 mapping; validate against appliance display"
    except Exception as error:
        result["decode_error"] = type(error).__name__ + ": " + str(error)
    return result


def decode_set_body(body):
    """Interpret the library's E6 set layout; preserve unknown bodies verbatim."""
    result = {"body_hex": body.hex(), "recognized": False}
    if len(body) != 30:
        result["reason"] = "Expected 30-byte E6 set body"
        return result
    prefix = tuple(body[:2])
    if prefix in ((4, 0x12), (4, 0x13)):
        result.update(recognized=True,
                      attribute="bathing_temperature" if prefix[1] == 0x12 else "heating_temperature",
                      value=body[2], unit="C", trailing_bytes_zero=not any(body[3:]))
    else:
        result["reason"] = "Set selector is not mapped by this decoder"
    return result


def run(samples, interval=2):
    os.umask(0o077)
    credentials = json.loads((ROOT / "lan-secrets/credentials.json").read_text())
    if credentials["device_id"] != str(DEVICE_ID):
        raise ValueError("Credentials belong to another device")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = ROOT / "lan-captures" / stamp
    directory.mkdir(parents=True, mode=0o700)
    security = LocalSecurity()
    report = {"device_id": str(DEVICE_ID), "host": HOST, "port": 6444,
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "midea_local_version": importlib.metadata.version("midea-local"),
              "status_responses": 0, "samples": samples, "interval_seconds": interval,
              "target_changes": [], "events": []}
    reader = None
    previous_targets = None

    def record(direction, frame, **extra):
        number = len(report["events"]) + 1
        (directory / f"{number:03d}-{direction}.bin").write_bytes(frame)
        event = {"utc": datetime.now(timezone.utc).isoformat(), "direction": direction,
                 "wire_hex": frame.hex(), **extra}
        report["events"].append(event)
        save_private(directory / "capture.json", report)
        return event

    try:
        with socket.create_connection((HOST, 6444), timeout=10) as connection:
            reader = FrameReader(connection)
            request = security.encode_8370(bytes.fromhex(credentials["token"]), MSGTYPE_HANDSHAKE_REQUEST)
            connection.sendall(request)
            record("tx", request, purpose="LAN authentication")
            response = reader.read(time.monotonic() + 10)
            record("rx", response, purpose="LAN authentication")
            if len(response) != 72 or response[:6] != bytes.fromhex("837000402001"):
                raise ValueError("Unexpected authentication response")
            session_key = security.tcp_key(response[8:], bytes.fromhex(credentials["key"]))
            report["handshake_sha256_valid"] = True
            save_private(directory / "session-secret.json", {"session_key_hex": session_key.hex()})
            print("Fresh LAN handshake verified.", flush=True)
            version = 0
            for index in range(samples + 1):
                command = MessageQueryAppliance(DeviceType.E6) if index == 0 else MessageQuery(version)
                plain = bytes(command.serialize())
                # Fail closed: these two query classes and types are the only allowed commands.
                if type(command) not in (MessageQueryAppliance, MessageQuery) or plain[9] not in (0xA0, 0x03):
                    raise ValueError("Command is outside read-only query allowlist")
                purpose = "appliance protocol query" if index == 0 else f"E6 status query {index}"
                inner = PacketBuilder(DEVICE_ID, plain).finalize()
                frame = security.encode_8370(inner, MSGTYPE_ENCRYPTED_REQUEST)
                connection.sendall(frame)
                record("tx", frame, purpose=purpose, appliance_hex=plain.hex(), inner_hex=inner.hex())
                deadline = time.monotonic() + 8
                matched = False
                while time.monotonic() < deadline:
                    try:
                        response = reader.read(deadline)
                    except TimeoutError:
                        print(purpose + ": response timeout", flush=True)
                        break
                    event = record("rx", response, after_query=purpose)
                    try:
                        if response[5] & 15 != 3:
                            event["decode_error"] = "Not an encrypted LAN response (type 3)"
                            continue
                        messages, leftover = security.decode_8370(response)
                        if leftover or len(messages) != 1:
                            raise ValueError("Unexpected decoded frame count")
                        event["outer_sha256_valid"] = True
                        event.update(decode_inner(messages[0], security))
                        if "appliance_protocol_version" in event:
                            version = event["appliance_protocol_version"]
                        if "status" in event:
                            report["status_responses"] += 1
                            targets = {k: event["status"][k] for k in
                                       ("bathing_temperature", "heating_temperature")}
                            if previous_targets is not None and targets != previous_targets:
                                change = {"utc": event["utc"], "before": previous_targets,
                                          "after": targets, "appliance_hex": event["appliance_hex"]}
                                report["target_changes"].append(change)
                                print(event["utc"], "TARGET CHANGE:", json.dumps(change), flush=True)
                            previous_targets = targets
                            print(event["utc"], "Decoded E6 status:",
                                  json.dumps(event["status"], sort_keys=True), flush=True)
                        if event.get("message_type") == plain[9] and "decode_error" not in event:
                            matched = True
                            break
                    except Exception as error:
                        event["decode_error"] = type(error).__name__ + ": " + str(error)
                    finally:
                        save_private(directory / "capture.json", report)
                report.setdefault("queries", []).append({"purpose": purpose, "matching_response": matched})
                if index < samples:
                    time.sleep(interval)
    except KeyboardInterrupt:
        report["interrupted"] = True
        print("Capture interrupted; saving collected responses.", flush=True)
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        print("Capture stopped:", report["error"], flush=True)
    finally:
        if reader and reader.buffer:
            report["unassembled_rx_hex"] = bytes(reader.buffer).hex()
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save_private(directory / "capture.json", report)
        print("Capture saved:", directory, flush=True)
        print("Decoded status responses:", report["status_responses"], flush=True)
    return 0 if report["status_responses"] and "error" not in report else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=3, help="Number of status queries (1–300)")
    parser.add_argument("--interval", type=float, default=2, help="Pause between queries in seconds (1–60)")
    parser.add_argument("--decode-inner-file", type=Path,
                        help="Offline: decode a decrypted V3 payload containing one 5a5a packet")
    args = parser.parse_args()
    if args.decode_inner_file:
        print(json.dumps(decode_inner(args.decode_inner_file.read_bytes(), LocalSecurity()), indent=2))
    else:
        if not 1 <= args.samples <= 300 or not 1 <= args.interval <= 60:
            parser.error("samples must be 1–300 and interval must be 1–60 seconds")
        raise SystemExit(run(args.samples, args.interval))
