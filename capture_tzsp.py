#!/usr/bin/env python3
"""Receive MikroTik TZSP over UDP and save Ethernet frames for tcpdump."""
import argparse
import collections
import socket
import struct
import time


def ethernet_frame(data):
    if len(data) < 4:
        raise ValueError("short TZSP header")
    version, packet_type, encapsulation = struct.unpack("!BBH", data[:4])
    if (version, packet_type, encapsulation) != (1, 0, 1):
        raise ValueError(f"unsupported TZSP header {(version, packet_type, encapsulation)}")
    offset = 4
    while offset < len(data):
        tag = data[offset]
        offset += 1
        if tag == 0:  # Padding.
            continue
        if tag == 1:  # End of tags.
            frame = data[offset:]
            if len(frame) < 14:
                raise ValueError("short Ethernet frame")
            return frame
        if offset >= len(data):
            raise ValueError("missing tag length")
        length = data[offset]
        offset += 1 + length
        if offset > len(data):
            raise ValueError("truncated tag")
    raise ValueError("missing end tag")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="192.168.200.164")
    parser.add_argument("--port", type=int, default=37008)
    parser.add_argument("--seconds", type=float, default=180)
    parser.add_argument("--output", default="midea-inner.pcap")
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    counts = collections.Counter()
    errors = collections.Counter()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind((args.bind, args.port))
        receiver.settimeout(1)
        with open(args.output, "wb") as output:
            # PCAP, microsecond timestamps, Ethernet link type.
            output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            print(f"Listening on {args.bind}:{args.port} for {args.seconds:g}s; saving {args.output}", flush=True)
            deadline = time.monotonic() + args.seconds
            try:
                while time.monotonic() < deadline:
                    try:
                        data, peer = receiver.recvfrom(65535)
                    except socket.timeout:
                        continue
                    timestamp = time.time_ns()
                    try:
                        frame = ethernet_frame(data)
                    except ValueError as error:
                        errors[str(error)] += 1
                        continue
                    seconds, nanoseconds = divmod(timestamp, 1_000_000_000)
                    output.write(struct.pack("<IIII", seconds, nanoseconds // 1000, len(frame), len(frame)))
                    output.write(frame)
                    output.flush()
                    counts[peer[0]] += 1
                    if sum(counts.values()) == 1:
                        print(f"First Ethernet packet received from {peer[0]}", flush=True)
            except KeyboardInterrupt:
                pass
    print(f"Saved {sum(counts.values())} packets; senders: {dict(counts)}; rejected: {dict(errors)}")
    if not counts:
        print("No Ethernet packets received. Check /tool/sniffer/start, destination address, and the Mac firewall.")


if __name__ == "__main__":
    main()
