#!/usr/bin/env python3
"""Retrieve candidate LAN credentials and verify only the V3 handshake."""
import argparse
import asyncio
from datetime import datetime, timezone
import getpass
import hashlib
import hmac
import importlib.metadata
import json
import os
from pathlib import Path
import socket
import sys
import tempfile

HOST = "192.168.200.133"
DEVICE_ID = 151732607790550
ROOT = Path(__file__).resolve().parent


def save_private(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def receive_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise ConnectionError("Device closed the handshake connection")
        result.extend(chunk)
    return bytes(result)


def verify(candidate):
    from Crypto.Cipher import AES
    token, key = bytes.fromhex(candidate["token"]), bytes.fromhex(candidate["key"])
    if len(key) != 32 or not token or len(token) > 1024:
        raise ValueError("Unexpected LAN token/key lengths")
    # Fresh connection: request counter is zero. LAN handshake type is 0.
    request = b"\x83\x70" + len(token).to_bytes(2, "big") + b"\x20\x00\x00\x00" + token
    with socket.create_connection((HOST, 6444), timeout=10) as connection:
        connection.sendall(request)
        header = receive_exact(connection, 6)
        if header[:2] != b"\x83\x70" or header[4:] != b"\x20\x01":
            raise ValueError("Not a LAN V3 handshake response")
        length = int.from_bytes(header[2:4], "big")
        if length != 64:
            raise ValueError("Unexpected LAN handshake response length")
        response = header + receive_exact(connection, length + 2)
    challenge = AES.new(key, AES.MODE_CBC, iv=bytes(16)).decrypt(response[8:40])
    if not hmac.compare_digest(hashlib.sha256(challenge).digest(), response[40:72]):
        raise ValueError("LAN handshake SHA-256 verification failed")
    session_key = bytes(a ^ b for a, b in zip(challenge, key))
    return {
        "verified_utc": datetime.now(timezone.utc).isoformat(),
        "device_id": str(DEVICE_ID), "host": HOST, "port": 6444,
        "midea_local_version": importlib.metadata.version("midea-local"),
        "handshake_sha256_valid": True,
        "request_hex": request.hex(), "response_hex": response.hex(),
        "challenge_hex": challenge.hex(), "session_key_hex": session_key.hex(),
        "note": "Session ended after handshake; session key is specific to this connection.",
    }


async def retrieve(cloud_name):
    import aiohttp
    from midealocal.cloud import get_default_cloud, get_midea_cloud, get_preset_account_cloud
    if cloud_name:
        account = input("Midea account email/phone: ").strip()
        password = getpass.getpass("Midea password (hidden): ")
    else:
        preset = get_preset_account_cloud()
        account, password = preset["username"], preset["password"]
        cloud_name = get_default_cloud()
        print("Trying library preset account on", cloud_name, flush=True)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=40)) as session:
        cloud = get_midea_cloud(cloud_name=cloud_name, session=session,
                                account=account, password=password)
        defaults = await cloud.get_default_keys()
        try:
            if await cloud.login():
                fetched = await cloud.get_cloud_keys(DEVICE_ID)
                print(f"Cloud returned {len(fetched)} matching credential candidate(s).", flush=True)
                return list(fetched.values()) + list(defaults.values())
            print("Cloud login was unsuccessful; checking published default candidates.")
        except Exception as error:
            # Exception strings from cloud libraries may include sensitive responses.
            print("Cloud lookup failed:", type(error).__name__, flush=True)
        return list(defaults.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cloud", help="Use your paired account, e.g. SmartHome or 'NetHome Plus'")
    args = parser.parse_args()
    os.umask(0o077)
    secrets = ROOT / "lan-secrets"
    cache = secrets / "credentials.json"
    # Check reachability before making any cloud request.
    try:
        with socket.create_connection((HOST, 6444), timeout=5):
            pass
    except OSError as error:
        print(f"Cannot connect to {HOST}:6444: {type(error).__name__}, "
              f"errno={error.errno}, {error.strerror or str(error)}", file=sys.stderr)
        if error.errno in (1, 13):
            print("Network access was denied by the execution environment. "
                  "Run this command in the macOS Terminal application outside Codex.",
                  file=sys.stderr)
        return 2
    candidates = []
    if cache.exists():
        saved = json.loads(cache.read_text())
        if saved.get("device_id") != str(DEVICE_ID):
            raise ValueError("Credential cache belongs to another device")
        candidates.append(saved)
    # First reuse existing credentials; contact cloud only if needed.
    for source in ("cache", "cloud"):
        if source == "cloud":
            candidates = asyncio.run(retrieve(args.cloud))
        seen = set()
        for number, candidate in enumerate(candidates, 1):
            pair = (candidate["token"], candidate["key"])
            if pair in seen:
                continue
            seen.add(pair)
            print(f"Checking {source} candidate {number} against {HOST}:6444", flush=True)
            try:
                evidence = verify(candidate)
            except (OSError, ValueError, ConnectionError) as error:
                detail = (str(error) if isinstance(error, ValueError)
                          else f"errno={getattr(error, 'errno', None)}")
                print("Candidate unsuccessful:", type(error).__name__, detail, flush=True)
                continue
            save_private(cache, {"device_id": str(DEVICE_ID), "host": HOST,
                                "token": pair[0], "key": pair[1]})
            save_private(secrets / "handshake.json", evidence)
            print("VERIFIED: decrypted handshake challenge matches its SHA-256 digest.")
            print("Credentials: lan-secrets/credentials.json (mode 600)")
            print("Exact handshake and derived session key: lan-secrets/handshake.json (mode 600)")
            return 0
    print("No verified pair. Retry with --cloud and the account paired to this boiler.")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        sys.exit(130)
    except Exception as error:
        print("Stopped:", type(error).__name__, file=sys.stderr)
        sys.exit(2)
