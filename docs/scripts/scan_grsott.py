#!/usr/bin/env python3
"""Summarize grsott PCAPNG frames and identify unknown packet keys."""

import argparse
import hashlib
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


KNOWN_KEYS = {
    "065129",
    "060118",
    "060116",
    "060119",
    "065119",
    "065104",
    "065120",
}
XOR_KEY = b"Growatt"


def capture_reads(path):
    data = path.read_bytes()
    offset = 0
    endian = None
    capture_number = 0

    while offset < len(data):
        # A section header's byte-order magic determines the byte order for
        # that section. Block type 0x0a0d0d0a has the same bytes either way.
        if data[offset : offset + 4] == bytes.fromhex("0a0d0d0a"):
            magic = data[offset + 8 : offset + 12]
            if magic == bytes.fromhex("4d3c2b1a"):
                endian = "<"
            elif magic == bytes.fromhex("1a2b3c4d"):
                endian = ">"
            else:
                raise ValueError(f"bad byte-order magic at {offset}")

        if endian is None:
            raise ValueError("PCAPNG section header missing")

        block_type, block_len = struct.unpack_from(endian + "II", data, offset)
        if block_len < 12 or offset + block_len > len(data):
            raise ValueError(f"bad block length {block_len} at {offset}")
        trailer = struct.unpack_from(endian + "I", data, offset + block_len - 4)[0]
        if trailer != block_len:
            raise ValueError(f"block trailer mismatch at {offset}")

        if block_type == 6:  # Enhanced Packet Block
            capture_number += 1
            interface, ts_hi, ts_lo, captured_len, _original_len = (
                struct.unpack_from(endian + "IIIII", data, offset + 8)
            )
            packet_data = data[offset + 28 : offset + 28 + captured_len]
            ticks = (ts_hi << 32) | ts_lo
            yield capture_number, interface, ticks / 1_000_000, packet_data

        offset += block_len


def frames(path):
    for capture_number, interface, timestamp, data in capture_reads(path):
        offset = 0
        subframe = 0
        while offset < len(data):
            if len(data) - offset < 8:
                raise ValueError(f"short header in capture packet {capture_number}")
            header = data[offset : offset + 8]
            payload_len = (header[4] << 8) | header[5]
            frame_len = 8 + payload_len
            if offset + frame_len > len(data):
                raise ValueError(f"frame overruns capture packet {capture_number}")

            encrypted = data[offset + 8 : offset + frame_len]
            decrypted = bytes(
                value ^ XOR_KEY[i % len(XOR_KEY)]
                for i, value in enumerate(encrypted)
            )
            body = decrypted[:-2]  # discard trailing CRC bytes, as Rust does
            key = bytes((header[3], header[6], header[7])).hex()
            yield capture_number, subframe, interface, timestamp, key, body

            offset += frame_len
            subframe += 1


def packet_key(value):
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("key must be six hexadecimal digits") from error
    if len(decoded) != 3:
        raise argparse.ArgumentTypeError("key must be six hexadecimal digits")
    return decoded.hex()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="grsott .pcapng file")
    parser.add_argument(
        "--key",
        type=packet_key,
        help="show this key instead of keys unknown to the web UI",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    rows = list(frames(args.capture))
    counts = Counter((interface, key) for _, _, interface, _, key, _ in rows)

    print(f"protocol frames: {len(rows)}")
    for (interface, key), count in sorted(counts.items()):
        direction = "from_inverter" if interface == 0 else "to_inverter"
        print(f"{direction:13} {key} {count:5}")

    heading = f"frames with key {args.key}:" if args.key else "unknown frames:"
    print(heading)
    for capture_number, subframe, interface, timestamp, key, body in rows:
        selected = key == args.key if args.key else key not in KNOWN_KEYS
        if not selected:
            continue
        direction = "from_inverter" if interface == 0 else "to_inverter"
        when = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
        digest = hashlib.sha256(body).hexdigest()[:16]
        print(
            f"capture={capture_number} subframe={subframe} {direction} "
            f"time={when} key={key} body_len={len(body)} "
            f"sha256={digest}"
        )


if __name__ == "__main__":
    main()
