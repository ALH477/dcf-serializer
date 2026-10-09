#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
#
# Independent check of dcf_ser_write_varsint against the STANDARD ZigZag vectors.
#
#   varsint_interop.py < <(./varsint_emit)        (make interop does exactly that)
#
# Each input line is "<value> <hex frame>" from scripts/varsint_emit.c. This script knows
# nothing of the library: it parses the frame by the wire-format description (17-byte header,
# payload, big-endian CRC-32 from zlib), reads the payload as one VARINT value (tag 0x10, LEB128,
# canonical), decodes the ZigZag by the textbook formula (n >> 1) ^ -(n & 1), and compares both
# the unsigned value and the signed result with a hard-coded table of the standard vectors.
# A round trip alone cannot catch an encoder and decoder that are wrong in opposite directions;
# this can.
import struct
import sys
import zlib

# value -> zigzag (the protobuf spec's table, extended with the 32- and 64-bit extremes)
VECTORS = {
    0: 0, -1: 1, 1: 2, -2: 3, 2: 4, 63: 126, -64: 127, 64: 128, -65: 129,
    2147483647: 4294967294, -2147483648: 4294967295,
    9223372036854775807: 18446744073709551614, -9223372036854775808: 18446744073709551615,
}


def zigzag_encode(n):            # the spec's formula, on an unbounded Python int
    return ((n << 1) ^ (n >> 63)) & 0xFFFFFFFFFFFFFFFF


def zigzag_decode(u):
    return (u >> 1) ^ -(u & 1)


def leb128(payload):
    value, shift = 0, 0
    for i, b in enumerate(payload):
        if i >= 10:
            raise ValueError("varint longer than 10 bytes")
        value |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            if i + 1 != len(payload):
                raise ValueError("bytes after the varint")
            if i >= 1 and b == 0:
                raise ValueError("non-canonical varint")
            return value
    raise ValueError("unterminated varint")


def main():
    bad = checked = 0
    for line in sys.stdin:
        line = line.split()
        if not line:
            continue
        val, frame = int(line[0]), bytes.fromhex(line[1])
        magic, version, msg_type, flags, plen, seq = struct.unpack_from(">IHHBII", frame, 0)
        assert magic == 0x44434653 and flags == 0 and len(frame) == 17 + plen + 4, "frame layout"
        body = frame[:17 + plen]
        assert struct.unpack(">I", frame[17 + plen:])[0] == zlib.crc32(body), "CRC-32"
        payload = frame[17:17 + plen]
        assert payload[0] == 0x10, "VARINT tag"
        u = leb128(payload[1:])
        want = zigzag_encode(val)
        if val in VECTORS:
            assert VECTORS[val] == want, "table and formula disagree for %d" % val
            want = VECTORS[val]
        got = zigzag_decode(u)
        checked += 1
        if u != want or got != val:
            bad += 1
            print("FAIL: write_varsint(%d): wire value %d, standard ZigZag %d; decodes to %d" % (val, u, want, got))
    if checked == 0:
        print("FAIL: no input")
        return 2
    if bad:
        print("FAIL: %d of %d values wrong on the wire" % (bad, checked))
        return 1
    print("varsint interop: %d values, wire bytes equal the standard ZigZag, decoded by an independent decoder" % checked)
    return 0


sys.exit(main())
