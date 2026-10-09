# DCF Serialize

**Universal Serialization/Deserialization Shim for the DeMoD Communications Framework**

[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-5.2.0-green.svg)]()
[![NixOS](https://img.shields.io/badge/NixOS-flake-5277C3.svg?logo=nixos)](flake.nix)

## Overview

DCF Serialize provides a system-agnostic binary serialization layer for the DeMoD Communications Framework transport protocol. Designed for high-performance distributed systems, real-time gaming, and IoT applications.

### Features

- **Platform Independent**: Works on Linux, macOS, Windows, and BSD systems
- **Network Byte Order**: Big-endian wire format with automatic conversion
- **Zero-Copy Reads**: Direct buffer access where possible
- **Type-Safe**: Self-describing format with type tags
- **CRC32 Integrity**: Built-in checksum validation (error detection, **not** authentication -- see [Security](#security))
- **Strict by Default**: the reader refuses what it cannot vouch for; trusted channels opt back in per reader
- **Two-implementation check**: an Exsecutor-generated admission gate agrees with the C validator on every accepted frame
- **Schema Support**: Reflection-based struct serialization
- **Variable-Length Encoding**: LEB128 for efficient integer encoding
- **No Dependencies**: Pure C11, no external libraries required

## Wire Format

```
┌──────────┬─────────┬──────────┬───────┬────────────┬──────────┬──────────┬──────────┐
│  Magic   │ Version │ MsgType  │ Flags │ PayloadLen │ Sequence │ Payload  │  CRC32   │
│  4 bytes │ 2 bytes │ 2 bytes  │ 1 byte│  4 bytes   │  4 bytes │ N bytes  │  4 bytes │
└──────────┴─────────┴──────────┴───────┴────────────┴──────────┴──────────┴──────────┘
```

## Security

DCF frames are parsed from bytes a remote peer chose, so the reader is built to
refuse, not to guess.

**The reader is strict by default.** A frame is accepted only if its magic and
major version are right, no unsupported flag bit is set, a CRC-32 is present and
correct, `payload_len` is at most `DCF_SER_MAX_MESSAGE` (16 MiB), the buffer is
exactly one frame (no bytes after it), and the payload is a well-formed sequence of
tagged values: nesting at most `DCF_SER_MAX_DEPTH` (32), array and map counts at
most `DCF_SER_MAX_ARRAY` (1 Mi) and never more than the bytes that are there,
strings at most `DCF_SER_MAX_STRING` (64 KiB) and valid UTF-8, varints in canonical
form. The grammar is written down in [`gate/README.md`](gate/README.md).

**A trusted channel opts back in, explicitly, per reader:**

```c
DCFSerReader r;
dcf_ser_reader_init(&r, buf, len);
dcf_ser_reader_set_policy(&r, DCF_SER_POLICY_ALLOW_NO_CRC);   /* between init and validate */
if (dcf_ser_reader_validate(&r) != DCF_SER_OK) { /* ... */ }
```

| flag | relaxes |
|---|---|
| `DCF_SER_POLICY_ALLOW_NO_CRC` | accept `DCF_SER_FLAG_NO_CRC` frames (no integrity check at all) |
| `DCF_SER_POLICY_ALLOW_TRAILING` | accept bytes after the end of the frame (e.g. padded datagrams) |
| `DCF_SER_POLICY_ALLOW_NONCANONICAL_VARINT` | accept overlong varints (bits are still never dropped) |
| `DCF_SER_POLICY_ALLOW_INVALID_UTF8` | accept `STRING` values that are not UTF-8 |
| `DCF_SER_POLICY_ALLOW_UNSTRUCTURED` | the payload is not a sequence of tagged values (you used `dcf_ser_write_raw` / `write_reserve`) |
| `DCF_SER_POLICY_ALLOW_APP_FLAGS` | accept `COMPRESSED` / `ENCRYPTED` frames (the library does neither; your application does) |
| `DCF_SER_POLICY_LAX_SCHEMA` | schema reads tolerate a missing `REQUIRED` field, repeated ids, header/schema type disagreement |
| `DCF_SER_POLICY_ALLOW_LEGACY_CRC` | migration only: also accept the CRC of releases with the mistyped table (see below) |
| `DCF_SER_POLICY_NO_GATE` | do not consult the Exsecutor admission gate |

`EXTENDED` and the reserved flag bit are never accepted: they change the framing and
this reader cannot honour them. An unknown policy bit is refused and leaves the policy
unchanged; the policy is frozen once `dcf_ser_reader_validate()` has succeeded.
`dcf_ser_validate_message()` always uses the strict policy.

**CRC32 is an error-detection code, not authentication.** It catches bit rot. It does
not stop anyone who can alter a frame from recomputing the CRC. Where the sender must
be proven, use a MAC or an authenticated transport; the strict reader makes a hostile
frame *safe to parse*, not *trustworthy*.

**Memory safety does not depend on the gate.** Every length, count and depth is
checked in C with arithmetic that cannot wrap (`n > end - pos`, never `pos + n`).
The [Exsecutor](https://github.com/ALH477/exsecutor) gate in [`gate/`](gate/) is an
additional, independent statement of the same policy; a frame is admitted only if the
C validator and the gate agree (disagreement refuses the frame and is counted by
`dcf_ser_gate_disagreements()`). Build with `-DDCF_SER_NO_GATE` to drop it. **The
gate's `.exsc` source is GPL-3.0-or-later; whether its emitted C may ship in this
BSD-3-Clause repository is pending an owner decision** ([`gate/PROVENANCE.md`](gate/PROVENANCE.md)).

## Security changes

This release hardens the reader and writer. `DCF_SER_VERSION` is **not** bumped and the
wire layout and type tags are unchanged, but several things that used to be accepted are
refused, and two things the library *computed* were wrong (the CRC-32 table and the ZigZag encoding of
negative `varsint` values; both are wire-visible and described below). Exactly what changed:

**Reader (strict by default)**

| before | now | opt back in |
|---|---|---|
| a `NO_CRC` frame was accepted; nothing checked its bytes | refused, `DCF_SER_ERR_POLICY` | `ALLOW_NO_CRC` |
| `COMPRESSED` / `ENCRYPTED` bits accepted and ignored | refused, `DCF_SER_ERR_POLICY` | `ALLOW_APP_FLAGS` |
| `EXTENDED` and bit `0x40` accepted and ignored (`EXTENDED` desynchronised the parse) | refused, `DCF_SER_ERR_POLICY` | never |
| `payload_len` above 16 MiB accepted | `DCF_SER_ERR_TOO_LARGE` | never |
| bytes after the CRC silently accepted | refused, `DCF_SER_ERR_POLICY` | `ALLOW_TRAILING` |
| `validate()` checked header and CRC only | also walks the payload: it must be well-formed tagged values (depth <= 32, counts, UTF-8, canonical varints) | `ALLOW_UNSTRUCTURED` (skip the walk); `ALLOW_NONCANONICAL_VARINT`; `ALLOW_INVALID_UTF8` |
| `dcf_ser_reader_skip` advanced without bounds checks (`remaining()` could underflow to ~2^64), recursed without limit (stack overflow on nested headers), and its MAP count overflowed `uint32_t` | bounds-checked, iterative, depth-limited, all-or-nothing (position unchanged on error); `DCF_SER_ERR_TRUNCATED` / `DCF_SER_ERR_DEPTH_EXCEEDED` | never |
| `read_raw` / `read_raw_ptr` could wrap on a huge length and copy out of bounds | `DCF_SER_ERR_TRUNCATED` | never |
| `read_raw(r, out, 0)` / `read_raw_ptr(r, &p, 0)` on a reader that was never validated (a failed `reader_init` leaves it zeroed) returned OK and did `memcpy(out, NULL, 0)` (undefined behaviour) | `DCF_SER_ERR_TRUNCATED` for any length on an unvalidated reader | never |
| a typed read that failed (type mismatch, truncated body, invalid string, too-small copy buffer, refused container header) had already consumed the tag byte, so the next read started in the middle of the value | **every typed read is all-or-nothing**: on any error the reader is exactly where it was (`dcf_ser_read_field` is the one exception: the struct end marker, reported as `DCF_SER_ERR_NOT_FOUND`, is consumed on purpose). A too-small `read_string_copy` / `read_bytes_copy` buffer reports `OVERFLOW` with the needed length in `*out_len` and consumes nothing, so the call can be repeated with a bigger one | never |
| `dcf_ser_reader_validate` did not reset `reader->depth`, and a failed `dcf_ser_read_struct_schema` returned with `depth` still incremented: a reader pointed at a new frame, or a "read schema, on error skip, continue" loop, accumulated depth until every container read and skip was `DEPTH_EXCEEDED` | `validate` starts at depth 0; a failed schema read restores **both** position (the struct is still there to skip) and depth | never |
| `dcf_ser_read_struct_schema` scanned the whole schema for every wire field: a 16 MiB frame of 4,194,302 unknown 4-byte fields against a 256-field schema cost 423-524 ms of CPU (about 3.2-3.9x its receive time at 1 Gbit/s) | the schema's ids are indexed once per call (sorted, binary search): same frame 86-109 ms (table below). Which entry wins for a repeated id in the *schema* (the first) is unchanged | never |
| `read_array_begin` / `read_map_begin` returned any `uint32_t` count | refused above `DCF_SER_MAX_ARRAY` or more than the bytes left | never |
| `read_string` ignored `DCF_SER_MAX_STRING` and UTF-8 | refused above 64 KiB (`TOO_LARGE`) or invalid UTF-8 (`MALFORMED`) | `ALLOW_INVALID_UTF8` for UTF-8 only |
| `read_string_copy` accepted an embedded NUL (the C string was silently truncated) | `DCF_SER_ERR_MALFORMED` | never |
| `read_varint` accepted overlong encodings and silently dropped bits of a 10th byte above 1 | overlong: `MALFORMED`; 10th byte above 1: `OVERFLOW` | `ALLOW_NONCANONICAL_VARINT` for overlong only |
| schema reads: `DCF_FIELD_REQUIRED` never enforced, a repeated field id silently last-wins | missing required field / repeated id: `MALFORMED`; field header type differing from the schema: `TYPE_MISMATCH` | `LAX_SCHEMA` |
| schema reads silently **dropped** `DCF_TYPE_STRING` fields that `dcf_ser_write_struct_schema` can write | the schema is refused up front, `DCF_SER_ERR_INVALID_TYPE` (a string cannot be read into a struct; use the typed API) | never |
| a schema field whose type, size or offset did not fit the type / `struct_size` became a wire-driven overflow; fields were loaded and stored through misaligned casts | `DCF_SER_ERR_INVALID_ARG` / `INVALID_TYPE` before any access; at most `DCF_SER_MAX_SCHEMA_FIELDS` (256) fields; `memcpy` loads and stores. **On a wire-driven error the struct is zeroed and the reader is left where it was; when the schema itself is refused (a `STRING` field, a field that does not fit) nothing is touched: the struct keeps whatever it held and the reader does not move** | never |
| `dcf_ser_reader_init` left the reader untouched on error | leaves a zeroed (empty, strict) reader | n/a |

**Writer**

| before | now |
|---|---|
| a failed write was forgotten: `last_error` was not always set and `finish()` produced a CRC-valid, truncated frame | errors are sticky; every later call and `finish()` return the first error |
| `finish()` twice appended a second CRC; writes after `finish()` corrupted the buffer | the second `finish()` and any write after it return `DCF_SER_ERR_INVALID_ARG` |
| `write_string_n` / `write_bytes` with `(NULL, len > 0)` wrote a length prefix and no bytes | `DCF_SER_ERR_NULL_PTR` |
| `write_string*` accepted any bytes although strings are UTF-8 | invalid UTF-8 is `DCF_SER_ERR_MALFORMED` (use `write_bytes` for binary) |
| `write_raw` / `write_reserve` and buffer growth did arithmetic that could wrap (out-of-bounds `memcpy`; an infinite loop in `writer_grow`) | overflow-safe; a length above `DCF_SER_MAX_MESSAGE` is `DCF_SER_ERR_TOO_LARGE` |
| the payload was uncapped for external buffers | capped at `DCF_SER_MAX_MESSAGE`; `finish()` refuses more |
| `dcf_ser_write_array_end` documented "validates count" but did not | the documentation is corrected: it only closes the nesting level |
| `dcf_ser_writer_init` / `_init_buffer` accepted flag bits `0x40` and `0x80` that no reader of this library accepts | `DCF_SER_ERR_INVALID_ARG` (the writer is left zeroed). `dcf_ser_writer_reset` has no result to return, so bad flags there make the writer fail closed: the next write and `finish()` return `INVALID_ARG` until a good reset |
| **`dcf_ser_write_varsint` wrote every negative value wrong** (see "ZigZag" below) | fixed; a **wire change** for negative values |

**CRC-32 (a wire-visible fix, found by the gate's differential test).** `crc32_table[245]`
was `0xCDD706B3`; the IEEE 802.3 value is `0xCDD70693`. `dcf_ser_crc32()` therefore was
not CRC-32 for any input that looks up entry 245 (about one table lookup in 256). Measured on
100,000 random buffers per size: the two CRCs differ for 7.7% of 20-byte buffers, 32.5% of
100-byte, 54% of 200-byte, 98% of 1 KiB buffers (real frames are not random bytes, so treat
these as an estimate). The documented test vector (`"123456789"`) never touches the entry. The table is corrected. **A corrected node and an
uncorrected node reject each other's frames whenever entry 245 is hit.** Upgrade
readers first with `DCF_SER_POLICY_ALLOW_LEGACY_CRC` (accepts the standard CRC *or* the old
one, nothing else relaxed; the gate is not consulted under it), then writers, then drop the flag.
**Turn the flag off as soon as every peer is upgraded**: it is not "either CRC and nothing else". Because
`0xCDD706B3 ^ 0xCDD70693 == 0x20` and CRC-32 is linear, a standard-CRC frame whose byte after a
table-entry-245 lookup has exactly bit 5 flipped (and which has no other entry-245 lookup after it) is
accepted as a "legacy" frame: under the flag a single-bit error in that one position is not detected
(`t_i1_legacy_crc_one_bit_blind_spot` pins this down). Without the flag the CRC catches it.

**ZigZag (a wire-visible fix, found by an independent review; pre-existing).** `dcf_ser_write_varsint`
computed `((uint64_t)val << 1) ^ ((uint64_t)val >> 63)`: the cast to unsigned came *before* the shift, so
the "sign fill" was a logical shift (0 or 1) instead of all-zeros / all-ones, and **every negative value was
encoded wrong** (`-1` was written as 2^64-1 and read back as `INT64_MIN`; `INT64_MIN` was written as `1` and read
back as `-1`). The reader's decoder was always the standard one. Non-negative values are unchanged. The
sign fill is now `0 - (sign bit)`, which does not rely on the implementation-defined right shift of a
negative signed value. The wire bytes now equal the standard ZigZag (protobuf's), checked against
hard-coded vectors and by an independent Python decoder (`make interop`), not by a round trip, which is how
this was missed:

| value | ZigZag | LEB128 bytes after the `0x10` tag |
|---|---|---|
| `0` | 0 | `00` |
| `-1` | 1 | `01` |
| `1` | 2 | `02` |
| `-2` | 3 | `03` |
| `2` | 4 | `04` |
| `2147483647` | 4294967294 | `fe ff ff ff 0f` |
| `-2147483648` | 4294967295 | `ff ff ff ff 0f` |
| `INT64_MAX` | 2^64-2 | `fe ff ff ff ff ff ff ff ff 01` |
| `INT64_MIN` | 2^64-1 | `ff ff ff ff ff ff ff ff ff 01` |

There is deliberately **no compatibility flag**: the old writer and the (correct) reader were already
inconsistent for negatives, so a negative `varsint` from an old sender was corrupt on arrival, and there is no
value to "accept as legacy". Values written by an old sender that were negative must be treated as lost;
those written as `>= 0` are fine. Because a corrected writer's negative values differ from an old
writer's, **this changes the wire for negative `varsint` values**, like the CRC-32 fix above; both are
listed for the owner's version / soname decision.

**Writer / reader asymmetries.** The writer is not a grammar enforcer: it does not stop you from writing a
frame the strict reader refuses. Everything that can happen with the typed writer functions, and what the
reader does with it (each row is a test, `t_n7_documented_asymmetries`):

| the writer lets you | the strict reader |
|---|---|
| `dcf_ser_write_array_begin(count)` / `map_begin(count)` followed by **fewer** elements than `count` | refuses (`TRUNCATED`: the count is checked against the bytes present, and the elements are walked) |
| the same followed by **more** elements than `count` | **accepts**: the extras are read as top-level values after the container, so a typed consumer sees a different shape than the sender meant (the library does not count the elements the writer was given) |
| `dcf_ser_write_struct_begin` without `dcf_ser_write_struct_end` | refuses (`TRUNCATED`: no end marker) |
| `dcf_ser_write_field(w, 0, DCF_TYPE_NULL)` (id 0, type NULL) | that pair *is* the struct end marker: the struct ends there and what follows is read as top-level values |
| `dcf_ser_write_field` with a type that differs from the value then written | accepts it in the structure walk; **schema** reads refuse it (`TYPE_MISMATCH`) unless `LAX_SCHEMA` |
| `dcf_ser_write_field` outside a struct, `*_end` without `*_begin` | the field header is read as values (usually refused); `*_end` without `*_begin` is `MALFORMED` at the writer (sticky) |
| `dcf_ser_write_raw` / `dcf_ser_write_reserve` | refuses unless `ALLOW_UNSTRUCTURED` |
| flags `NO_CRC`, `COMPRESSED`, `ENCRYPTED` | refuses unless `ALLOW_NO_CRC` / `ALLOW_APP_FLAGS` |
| flags `0x40`, `0x80` | the writer now refuses to start (see above); a hand-built frame with them is refused by the reader under every policy |
| invalid UTF-8 in `write_string*`, a payload over 16 MiB, nesting over 32 | the writer refuses, like the reader (no asymmetry) |

**Framing.** `dcf_ser_message_length()` reads 17 bytes blind and returned unvalidated sizes
up to 4 GiB + 21. It is **deprecated** (a compiler warning; silence with
`-DDCF_SER_NO_DEPRECATION_WARNINGS`) and now returns 0 for what the new
`dcf_ser_message_length_checked(data, avail, &total)` refuses (too short, wrong magic or major
version, `payload_len` above 16 MiB).

**API / ABI.** `DCFSerReader` has a new trailing member `uint32_t policy`: **recompile
consumers** (the shared object keeps its name `libdcf_serialize.so.5.2.0`; whether to bump the
soname is the owner's decision). New: `dcf_ser_reader_set_policy`, `dcf_ser_validate_payload`,
`dcf_ser_message_length_checked`, `dcf_ser_gate_disagreements`, `DCF_SER_ERR_POLICY` (`0x208`),
`DCF_SER_FLAG_RESERVED`, `DCF_SER_MAX_SCHEMA_FIELDS`, the `DCF_SER_POLICY_*` flags and the
feature macro `DCF_SER_HARDENED_API`.

**Not changed:** `DCF_SER_VERSION` (5.2.0), the header layout, the type tags, the encoding of every type
except negative `varsint` and the CRC value, and the round trip of a
frame built with the typed writer functions (with a CRC, honest array counts, UTF-8 strings): the
hostile suite and the fuzzer both check that what the writer finishes the strict reader accepts.
Payloads built with `dcf_ser_write_raw` / `dcf_ser_write_reserve` need `ALLOW_UNSTRUCTURED` to be read back.

**Measured, schema reads** (the independent reviewer's `g6_dos.c`, unmodified: a 16 MiB frame of 4,194,302
unknown 4-byte fields against a 256-field schema; gcc -O2; six runs each, three before the change and three
interleaved with the "after" runs, on a shared 4-core sandbox whose load average was 1.3-4.7, so read the
ranges, not the single numbers):

| `dcf_ser_read_struct_schema` | before | after |
|---|---|---|
| CPU per frame | 423 - 524 ms (475, 493, 459, 494, 423, 524) | 86 - 109 ms (89, 92, 95, 109, 87, 86) |
| per wire field | 101 - 125 ns | 21 - 26 ns |
| compared with `dcf_ser_reader_validate` of the same frame (about 52 ms) | about 8 - 10x | about 1.7 - 2.1x |
| against a 1 Gbit/s receive time (about 134 ms) | about 3.2 - 3.9x | about 0.65 - 0.8x |

The regression test (`t_n2_schema_lookup_not_linear`) is relative, not absolute: a 256-field schema must
cost no more than 2.5x a 1-field schema on the same 1,000,000-field frame. Before: 11.5x (-O2), 10.9x
(ASan, -O0); after: 1.5x (-O2), 1.3x (ASan, -O0).

## Quick Start

### Using Nix (Recommended)

```bash
# Enter development shell
nix develop

# Build the library
nix build

# Run tests
nix flake check

# Build Docker image
nix build .#docker
docker load < ./result
```

### Using Make

```bash
# Build library and tests
make

# Run tests: unit, hostile-input regression suite, C-vs-Exsecutor-gate differential, trap guard
make test

# Install system-wide
sudo make install PREFIX=/usr/local

# Build with debug symbols and sanitizers (a sanitizer report fails the run)
make DEBUG=1 test

# Fuzz the reader, the writer and the C/gate agreement (FUZZ_SECONDS=120 by default)
make fuzz

# Valgrind over the test programs
make memcheck

# Without the Exsecutor gate / without the hardening flags
make GATE=0 test
make HARDEN=0 test
```

`make clean` between switching `DEBUG`, `GATE` or `HARDEN`: object files do not track flags.
`make fuzz` builds a deterministic mutation fuzzer under ASan+UBSan that needs only a C compiler and
runs it for `FUZZ_SECONDS` (default 120). With a clang that has the libFuzzer runtime,
`make fuzz CC=clang FUZZ_ENGINE=libfuzzer` builds a coverage-guided target instead (the distro clang in
the development sandbox had no runtime; `nix shell nixpkgs#clang -c make fuzz CC=clang FUZZ_ENGINE=libfuzzer`
did). Both drive the same entry point (`dcf_serialize_fuzz.c`): the reader on raw frames and on payloads
wrapped in a valid header, the writer round trip, and the C-versus-gate agreement. The `Dockerfile` runtime
image runs as an unprivileged user.

### Using Docker

```bash
# Build via Nix (preferred)
nix build .#docker
docker load < ./result

# Or build directly
docker build -t dcf-serialize:5.2.0 .

# Run tests in container
docker run --rm dcf-serialize:5.2.0-test
```

---

## Network Transport Examples

These examples demonstrate capturing data on one port, serializing it with DCF, and forwarding to another port—plus how to receive and deserialize on the other end.

### Example 1: Capture and Serialize Network Data (Sender/Relay)

This program listens on a **capture port**, wraps incoming raw data in DCF serialization, and forwards it to a **destination port**.

```c
/**
 * dcf_capture_relay.c - Capture raw data, serialize, and forward
 * 
 * Usage: ./dcf_capture_relay <capture_port> <dest_host> <dest_port>
 * Example: ./dcf_capture_relay 8080 127.0.0.1 9090
 */

#include "dcf_serialize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#define BUFFER_SIZE 65536

/* Message types for our protocol */
enum {
    MSG_RAW_CAPTURE = 0x0100,
    MSG_HEARTBEAT   = 0x0101,
};

/* Get current timestamp in microseconds */
static uint64_t get_timestamp_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

/* Serialize captured data into DCF format.
 *
 * Every dcf_ser_write_* result is checked. Writer errors are sticky -- a failed
 * write makes dcf_ser_writer_finish() fail too -- but checking each call says
 * where it went wrong, and a frame that did not fit is dropped, not sent short. */
static int serialize_capture(const void* raw_data, size_t raw_len,
                             uint16_t src_port, uint32_t sequence,
                             uint8_t* out_buf, size_t out_cap, size_t* out_len) {
    DCFSerWriter writer;
    
    /* Use external buffer to avoid allocation */
    if (dcf_ser_writer_init_buffer(&writer, out_buf, out_cap, 
                                    MSG_RAW_CAPTURE, DCF_SER_FLAG_NONE) != DCF_SER_OK) {
        return -1;
    }
    
    dcf_ser_writer_set_sequence(&writer, sequence);
    
    DCFSerError err;
    
    /* Write metadata */
    if ((err = dcf_ser_write_timestamp(&writer, get_timestamp_us())) != DCF_SER_OK ||  /* Capture time */
        (err = dcf_ser_write_u16(&writer, src_port)) != DCF_SER_OK ||                  /* Source port */
        (err = dcf_ser_write_u32(&writer, (uint32_t)raw_len)) != DCF_SER_OK ||         /* Original length */
        /* Write the captured payload */
        (err = dcf_ser_write_bytes(&writer, raw_data, raw_len)) != DCF_SER_OK) {
        fprintf(stderr, "[DCF Relay] write failed: %s\n", dcf_ser_error_str(err));
        return -1;
    }
    
    /* Finalize - adds header and CRC */
    const uint8_t* data;
    if ((err = dcf_ser_writer_finish(&writer, &data, out_len)) != DCF_SER_OK) {
        fprintf(stderr, "[DCF Relay] finish failed: %s\n", dcf_ser_error_str(err));
        return -1;
    }
    
    return 0;
}

/* Connect to destination */
static int connect_to_dest(const char* host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    inet_pton(AF_INET, host, &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
    return sock;
}

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <capture_port> <dest_host> <dest_port>\n", argv[0]);
        return 1;
    }
    
    int capture_port = atoi(argv[1]);
    const char* dest_host = argv[2];
    int dest_port = atoi(argv[3]);
    
    /* Create capture socket */
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in listen_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(capture_port),
    };
    
    bind(listen_sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr));
    listen(listen_sock, 5);
    
    printf("[DCF Relay] Listening on port %d, forwarding to %s:%d\n",
           capture_port, dest_host, dest_port);
    
    uint8_t raw_buf[BUFFER_SIZE];
    uint8_t ser_buf[BUFFER_SIZE + 256];  /* Extra space for DCF overhead */
    uint32_t sequence = 0;
    
    while (1) {
        /* Accept incoming connection */
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_sock < 0) continue;
        
        uint16_t src_port = ntohs(client_addr.sin_port);
        printf("[DCF Relay] Client connected from port %d\n", src_port);
        
        /* Connect to destination */
        int dest_sock = connect_to_dest(dest_host, dest_port);
        if (dest_sock < 0) {
            fprintf(stderr, "[DCF Relay] Failed to connect to destination\n");
            close(client_sock);
            continue;
        }
        
        /* Relay loop: capture -> serialize -> forward */
        ssize_t n;
        while ((n = recv(client_sock, raw_buf, sizeof(raw_buf), 0)) > 0) {
            size_t ser_len;
            
            /* Serialize the captured data */
            if (serialize_capture(raw_buf, n, src_port, sequence++,
                                  ser_buf, sizeof(ser_buf), &ser_len) == 0) {
                /* Send serialized DCF message */
                send(dest_sock, ser_buf, ser_len, 0);
                
                printf("[DCF Relay] Captured %zd bytes -> Serialized %zu bytes (seq=%u)\n",
                       n, ser_len, sequence - 1);
            }
        }
        
        close(dest_sock);
        close(client_sock);
        printf("[DCF Relay] Client disconnected\n");
    }
    
    close(listen_sock);
    return 0;
}
```

### Example 2: Receive and Deserialize DCF Messages (Receiver)

This program listens for incoming DCF-serialized messages, validates them, and extracts the original payload.

```c
/**
 * dcf_receiver.c - Receive and deserialize DCF messages
 * 
 * Usage: ./dcf_receiver <listen_port>
 * Example: ./dcf_receiver 9090
 */

#include "dcf_serialize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#define BUFFER_SIZE 65536

enum {
    MSG_RAW_CAPTURE = 0x0100,
};

/* Format timestamp for display */
static void format_timestamp(uint64_t ts_us, char* buf, size_t len) {
    time_t secs = ts_us / 1000000;
    uint32_t usecs = ts_us % 1000000;
    struct tm* tm = localtime(&secs);
    snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%06u",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec, usecs);
}

/* Process a complete DCF message */
static int process_dcf_message(const uint8_t* data, size_t len) {
    DCFSerReader reader;
    
    /* Initialize reader */
    if (dcf_ser_reader_init(&reader, data, len) != DCF_SER_OK) {
        fprintf(stderr, "[Receiver] Failed to init reader\n");
        return -1;
    }
    
    /* Validate message (magic, version, CRC) */
    DCFSerError err = dcf_ser_reader_validate(&reader);
    if (err != DCF_SER_OK) {
        fprintf(stderr, "[Receiver] Validation failed: %s\n", dcf_ser_error_str(err));
        return -1;
    }
    
    /* Get header info */
    const DCFSerHeader* hdr = dcf_ser_reader_header(&reader);
    printf("\n[Receiver] === DCF Message Received ===\n");
    printf("  Message Type: 0x%04X\n", hdr->msg_type);
    printf("  Sequence:     %u\n", hdr->sequence);
    printf("  Payload Size: %u bytes\n", hdr->payload_len);
    printf("  Flags:        0x%02X\n", hdr->flags);
    
    /* Process based on message type */
    if (hdr->msg_type == MSG_RAW_CAPTURE) {
        /* Read capture metadata */
        uint64_t timestamp;
        uint16_t src_port;
        uint32_t original_len;
        
        if (dcf_ser_read_timestamp(&reader, &timestamp) != DCF_SER_OK ||
            dcf_ser_read_u16(&reader, &src_port) != DCF_SER_OK ||
            dcf_ser_read_u32(&reader, &original_len) != DCF_SER_OK) {
            fprintf(stderr, "[Receiver] Malformed capture header\n");
            return -1;
        }
        
        char ts_str[64];
        format_timestamp(timestamp, ts_str, sizeof(ts_str));
        
        printf("  --- Capture Info ---\n");
        printf("  Capture Time: %s\n", ts_str);
        printf("  Source Port:  %u\n", src_port);
        printf("  Original Len: %u bytes\n", original_len);
        
        /* Read the captured payload (zero-copy) */
        const void* payload;
        size_t payload_len;
        if (dcf_ser_read_bytes(&reader, &payload, &payload_len) != DCF_SER_OK) {
            fprintf(stderr, "[Receiver] Malformed capture payload\n");
            return -1;
        }
        
        printf("  --- Payload (%zu bytes) ---\n", payload_len);
        
        /* Print as hex dump (first 64 bytes) */
        const uint8_t* p = (const uint8_t*)payload;
        printf("  Hex:  ");
        for (size_t i = 0; i < payload_len && i < 64; i++) {
            printf("%02x ", p[i]);
            if ((i + 1) % 16 == 0) printf("\n        ");
        }
        if (payload_len > 64) printf("...");
        printf("\n");
        
        /* Try to print as ASCII if printable */
        int printable = 1;
        for (size_t i = 0; i < payload_len && i < 256; i++) {
            if (p[i] < 32 && p[i] != '\n' && p[i] != '\r' && p[i] != '\t') {
                printable = 0;
                break;
            }
        }
        if (printable && payload_len > 0) {
            printf("  ASCII: %.*s\n", (int)(payload_len > 256 ? 256 : payload_len), 
                   (const char*)payload);
        }
    } else {
        printf("  Unknown message type, skipping payload\n");
    }
    
    return 0;
}

/* Read exactly n bytes from socket */
static ssize_t recv_exact(int sock, void* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = recv(sock, (char*)buf + total, n - total, 0);
        if (r <= 0) return r;
        total += r;
    }
    return total;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <listen_port>\n", argv[0]);
        return 1;
    }
    
    int port = atoi(argv[1]);
    
    /* Create listening socket */
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port),
    };
    
    bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(listen_sock, 5);
    
    printf("[Receiver] Listening for DCF messages on port %d\n", port);
    
    uint8_t header_buf[sizeof(DCFSerHeader)];
    uint8_t* msg_buf = malloc(BUFFER_SIZE);
    
    while (1) {
        int client = accept(listen_sock, NULL, NULL);
        if (client < 0) continue;
        
        printf("[Receiver] Client connected\n");
        
        /* Message receive loop */
        while (1) {
            /* Read DCF header first (17 bytes) */
            if (recv_exact(client, header_buf, sizeof(DCFSerHeader)) <= 0) {
                break;
            }
            
            /* Get the total message length from the header -- checked: it validates
             * the magic, the major version and the length cap before returning one */
            size_t msg_len;
            DCFSerError lerr = dcf_ser_message_length_checked(header_buf, sizeof(header_buf), &msg_len);
            if (lerr != DCF_SER_OK || msg_len > BUFFER_SIZE) {
                fprintf(stderr, "[Receiver] Invalid message length: %s\n", dcf_ser_error_str(lerr));
                break;
            }
            
            /* Copy header to message buffer */
            memcpy(msg_buf, header_buf, sizeof(DCFSerHeader));
            
            /* Read rest of message (payload + CRC) */
            size_t remaining = msg_len - sizeof(DCFSerHeader);
            if (remaining > 0) {
                if (recv_exact(client, msg_buf + sizeof(DCFSerHeader), remaining) <= 0) {
                    break;
                }
            }
            
            /* Process the complete DCF message (strict reader: CRC required, nothing after the frame) */
            (void)process_dcf_message(msg_buf, msg_len);
        }
        
        close(client);
        printf("[Receiver] Client disconnected\n");
    }
    
    free(msg_buf);
    close(listen_sock);
    return 0;
}
```

### Example 3: Simple UDP Sender and Receiver

For low-latency applications (gaming, real-time telemetry), here's a UDP variant:

**UDP Sender:**
```c
/**
 * dcf_udp_sender.c - Send serialized DCF messages over UDP
 * 
 * Usage: ./dcf_udp_sender <dest_host> <dest_port>
 */

#include "dcf_serialize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

enum { MSG_TELEMETRY = 0x2000 };

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <dest_host> <dest_port>\n", argv[0]);
        return 1;
    }
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(atoi(argv[2])),
    };
    inet_pton(AF_INET, argv[1], &dest.sin_addr);
    
    uint8_t buf[1024];
    uint32_t seq = 0;
    
    /* Send telemetry every 100ms */
    while (1) {
        DCFSerWriter w;
        /* Keep the CRC. DCF_SER_FLAG_NO_CRC is possible, but a strict reader refuses
         * such frames unless it opts in with DCF_SER_POLICY_ALLOW_NO_CRC, and then
         * nothing checks the bytes at all. */
        if (dcf_ser_writer_init_buffer(&w, buf, sizeof(buf), MSG_TELEMETRY,
                                       DCF_SER_FLAG_NONE) != DCF_SER_OK) return 1;
        dcf_ser_writer_set_sequence(&w, seq++);
        
        /* Simulated sensor data */
        if (dcf_ser_write_f32(&w, 23.5f + (seq % 10) * 0.1f) != DCF_SER_OK ||  /* Temperature */
            dcf_ser_write_f32(&w, 45.2f) != DCF_SER_OK ||                       /* Humidity */
            dcf_ser_write_u32(&w, seq * 100) != DCF_SER_OK) {                   /* Counter */
            fprintf(stderr, "[UDP TX] write failed\n");
            usleep(100000);
            continue;
        }
        
        const uint8_t* data;
        size_t len;
        if (dcf_ser_writer_finish(&w, &data, &len) != DCF_SER_OK) {
            fprintf(stderr, "[UDP TX] finish failed\n");
            usleep(100000);
            continue;
        }
        
        sendto(sock, data, len, 0, (struct sockaddr*)&dest, sizeof(dest));
        printf("[UDP TX] Sent %zu bytes, seq=%u\n", len, seq - 1);
        
        usleep(100000);  /* 100ms */
    }
    
    return 0;
}
```

**UDP Receiver:**
```c
/**
 * dcf_udp_receiver.c - Receive DCF messages over UDP
 * 
 * Usage: ./dcf_udp_receiver <port>
 */

#include "dcf_serialize.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

enum { MSG_TELEMETRY = 0x2000 };

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(atoi(argv[1])),
    };
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    printf("[UDP RX] Listening on port %s\n", argv[1]);
    
    uint8_t buf[1024];
    
    while (1) {
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
        if (n <= 0) continue;
        
        DCFSerReader r;
        if (dcf_ser_reader_init(&r, buf, (size_t)n) != DCF_SER_OK) continue;
        
        /* Strict by default. To accept NO_CRC datagrams from a sender you control:
         *     dcf_ser_reader_set_policy(&r, DCF_SER_POLICY_ALLOW_NO_CRC);
         * (between init and validate). */
        DCFSerError verr = dcf_ser_reader_validate(&r);
        if (verr != DCF_SER_OK) {
            printf("[UDP RX] Invalid message: %s\n", dcf_ser_error_str(verr));
            continue;
        }
        
        const DCFSerHeader* h = dcf_ser_reader_header(&r);
        
        if (h->msg_type == MSG_TELEMETRY) {
            float temp, humidity;
            uint32_t counter;
            
            if (dcf_ser_read_f32(&r, &temp) != DCF_SER_OK ||
                dcf_ser_read_f32(&r, &humidity) != DCF_SER_OK ||
                dcf_ser_read_u32(&r, &counter) != DCF_SER_OK) {
                printf("[UDP RX] Malformed telemetry\n");
                continue;
            }
            
            printf("[UDP RX] seq=%u temp=%.1f°C humidity=%.1f%% counter=%u\n",
                   h->sequence, temp, humidity, counter);
        }
    }
    
    return 0;
}
```

### Example 4: Port Mirroring / Traffic Capture Tool

A complete tool that mirrors traffic from one port to another with DCF serialization:

```c
/**
 * dcf_mirror.c - Traffic mirroring with DCF serialization
 * 
 * Captures all traffic on a port and mirrors it in DCF format.
 * Useful for debugging, logging, or protocol analysis.
 * 
 * Usage: ./dcf_mirror <listen_port> <mirror_host> <mirror_port> [--passthrough <upstream_host> <upstream_port>]
 * 
 * Example (capture and mirror only):
 *   ./dcf_mirror 8080 127.0.0.1 9090
 * 
 * Example (transparent proxy with mirroring):
 *   ./dcf_mirror 8080 127.0.0.1 9090 --passthrough api.example.com 443
 */

#include "dcf_serialize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUF_SIZE 65536

enum {
    MSG_TRAFFIC_INBOUND  = 0x3000,
    MSG_TRAFFIC_OUTBOUND = 0x3001,
    MSG_CONNECTION_OPEN  = 0x3002,
    MSG_CONNECTION_CLOSE = 0x3003,
};

typedef struct {
    int client_sock;
    int upstream_sock;
    int mirror_sock;
    uint32_t conn_id;
    struct sockaddr_in client_addr;
} Connection;

static uint32_t g_sequence = 0;
static pthread_mutex_t g_seq_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint32_t next_seq(void) {
    pthread_mutex_lock(&g_seq_mutex);
    uint32_t s = g_sequence++;
    pthread_mutex_unlock(&g_seq_mutex);
    return s;
}

/* Send DCF-wrapped traffic to mirror port */
static void mirror_traffic(int mirror_sock, uint16_t msg_type, uint32_t conn_id,
                           const void* data, size_t len) {
    uint8_t buf[BUF_SIZE + 256];
    DCFSerWriter w;
    
    if (dcf_ser_writer_init_buffer(&w, buf, sizeof(buf), msg_type, DCF_SER_FLAG_NONE) != DCF_SER_OK) return;
    dcf_ser_writer_set_sequence(&w, next_seq());
    
    if (dcf_ser_write_u32(&w, conn_id) != DCF_SER_OK ||
        dcf_ser_write_timestamp(&w, /* timestamp */
            (uint64_t)time(NULL) * 1000000ULL) != DCF_SER_OK ||
        dcf_ser_write_bytes(&w, data, len) != DCF_SER_OK) {
        return;                                  /* does not fit: drop the mirror copy, never send it short */
    }
    
    const uint8_t* out;
    size_t out_len;
    if (dcf_ser_writer_finish(&w, &out, &out_len) != DCF_SER_OK) return;
    
    send(mirror_sock, out, out_len, MSG_NOSIGNAL);
}

/* Bidirectional relay thread */
static void* relay_thread(void* arg) {
    Connection* conn = (Connection*)arg;
    uint8_t buf[BUF_SIZE];
    fd_set fds;
    int maxfd = (conn->client_sock > conn->upstream_sock) ? 
                 conn->client_sock : conn->upstream_sock;
    
    while (1) {
        FD_ZERO(&fds);
        FD_SET(conn->client_sock, &fds);
        if (conn->upstream_sock >= 0) {
            FD_SET(conn->upstream_sock, &fds);
        }
        
        struct timeval tv = {.tv_sec = 30, .tv_usec = 0};
        if (select(maxfd + 1, &fds, NULL, NULL, &tv) <= 0) break;
        
        /* Client -> Upstream (inbound from client's perspective) */
        if (FD_ISSET(conn->client_sock, &fds)) {
            ssize_t n = recv(conn->client_sock, buf, sizeof(buf), 0);
            if (n <= 0) break;
            
            mirror_traffic(conn->mirror_sock, MSG_TRAFFIC_INBOUND, 
                          conn->conn_id, buf, n);
            
            if (conn->upstream_sock >= 0) {
                send(conn->upstream_sock, buf, n, 0);
            }
        }
        
        /* Upstream -> Client (outbound to client) */
        if (conn->upstream_sock >= 0 && FD_ISSET(conn->upstream_sock, &fds)) {
            ssize_t n = recv(conn->upstream_sock, buf, sizeof(buf), 0);
            if (n <= 0) break;
            
            mirror_traffic(conn->mirror_sock, MSG_TRAFFIC_OUTBOUND,
                          conn->conn_id, buf, n);
            
            send(conn->client_sock, buf, n, 0);
        }
    }
    
    /* Send connection close notification */
    mirror_traffic(conn->mirror_sock, MSG_CONNECTION_CLOSE, conn->conn_id, "", 0);
    
    close(conn->client_sock);
    if (conn->upstream_sock >= 0) close(conn->upstream_sock);
    free(conn);
    return NULL;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <listen_port> <mirror_host> <mirror_port> "
                        "[--passthrough <upstream_host> <upstream_port>]\n", argv[0]);
        return 1;
    }
    /* ... socket setup ... */
    printf("[DCF Mirror] Traffic mirroring active\n");
    /* ... main accept loop: for each client, fill in a Connection and start
     *     pthread_create(&tid, NULL, relay_thread, conn) ... */
    void* (*start)(void*) = relay_thread;     /* what the accept loop passes to pthread_create */
    (void)start;
    return 0;
}
```

### Building the Examples

Add to your Makefile or compile directly:

```bash
# Compile with the DCF library
gcc -Wall -Wextra -Werror -o dcf_capture_relay dcf_capture_relay.c -L. -ldcf_serialize -lpthread
gcc -Wall -Wextra -Werror -o dcf_receiver dcf_receiver.c -L. -ldcf_serialize
gcc -Wall -Wextra -Werror -o dcf_udp_sender dcf_udp_sender.c -L. -ldcf_serialize
gcc -Wall -Wextra -Werror -o dcf_udp_receiver dcf_udp_receiver.c -L. -ldcf_serialize
gcc -Wall -Wextra -Werror -o dcf_mirror dcf_mirror.c -L. -ldcf_serialize -lpthread

# Or link statically
gcc -o dcf_receiver dcf_receiver.c dcf_serialize.c -O2
```

The five programs are written for the compiler's default (GNU) mode. They use POSIX/GNU functions
(`clock_gettime`, `usleep`, `fd_set`, `accept`, ...), so under a strict `-std=c11` add
`-D_GNU_SOURCE`. All five were extracted from this file and built with `-Wall -Wextra -Werror`,
both in the default mode and with `-std=c11 -D_GNU_SOURCE`, against this tree's `dcf_serialize.h`
and linked against `libdcf_serialize.a` (`make check-readme` repeats it). A `-Werror` build of your
own code also needs the deprecation warning kept out of it: use `dcf_ser_message_length_checked`,
as Example 2 does.

### Testing the Examples

```bash
# Terminal 1: Start receiver
./dcf_receiver 9090

# Terminal 2: Start capture relay (listens on 8080, forwards to 9090)
./dcf_capture_relay 8080 127.0.0.1 9090

# Terminal 3: Send test data to the capture port
echo "Hello, DCF!" | nc localhost 8080
curl -X POST -d '{"test": "data"}' http://localhost:8080/api

# Watch serialized messages appear in Terminal 1
```

### Docker Compose for Testing

```yaml
# docker-compose.yml
version: '3.8'
services:
  receiver:
    build: .
    command: ["/usr/bin/dcf_receiver", "9090"]
    ports:
      - "9090:9090"
  
  relay:
    build: .
    command: ["/usr/bin/dcf_capture_relay", "8080", "receiver", "9090"]
    ports:
      - "8080:8080"
    depends_on:
      - receiver
```

---

## API Usage

### Serializing Data

```c
#include <dcf/dcf_serialize.h>

// Create writer
DCFSerWriter writer;
dcf_ser_writer_init(&writer, MSG_PLAYER_STATE, DCF_SER_FLAG_NONE);
dcf_ser_writer_set_sequence(&writer, 42);

// Write primitives
dcf_ser_write_string(&writer, "Alice");
dcf_ser_write_u32(&writer, 100);
dcf_ser_write_f32(&writer, 3.14159f);

// Write array
dcf_ser_write_array_begin(&writer, DCF_TYPE_U32, 3);
dcf_ser_write_u32(&writer, 1);
dcf_ser_write_u32(&writer, 2);
dcf_ser_write_u32(&writer, 3);
dcf_ser_write_array_end(&writer);

// Finalize and get wire data
const uint8_t* data;
size_t len;
dcf_ser_writer_finish(&writer, &data, &len);

// Send data over network...
send(socket, data, len, 0);

dcf_ser_writer_destroy(&writer);
```

### Deserializing Data

```c
// Initialize reader with received data
DCFSerReader reader;
dcf_ser_reader_init(&reader, buffer, buffer_len);

// Strict by default. On a trusted channel, opt in to what you need, e.g.:
//   dcf_ser_reader_set_policy(&reader, DCF_SER_POLICY_ALLOW_NO_CRC);

// Validate message (magic, version, flags, length, CRC, and the payload's structure)
DCFSerError err = dcf_ser_reader_validate(&reader);
if (err != DCF_SER_OK) {
    fprintf(stderr, "Invalid message: %s\n", dcf_ser_error_str(err));
    return;
}

// Check message type
uint16_t msg_type = dcf_ser_reader_msg_type(&reader);

// Read data (zero-copy for strings/bytes). Every read can fail on hostile input: check it.
const char* name;
size_t name_len;
uint32_t score;
float position;
if (dcf_ser_read_string(&reader, &name, &name_len) != DCF_SER_OK ||
    dcf_ser_read_u32(&reader, &score) != DCF_SER_OK ||
    dcf_ser_read_f32(&reader, &position) != DCF_SER_OK) {
    return;
}
```

### Schema-Based Serialization

```c
typedef struct {
    uint32_t id;
    bool     active;
    float    score;
} Player;

static const DCFSerField player_fields[] = {
    DCF_SER_FIELD_DEF(Player, id, DCF_TYPE_U32, 1),
    DCF_SER_FIELD_DEF(Player, active, DCF_TYPE_BOOL, 2),
    DCF_SER_FIELD_DEF(Player, score, DCF_TYPE_F32, 3),
};

static const DCFSerSchema player_schema = {
    .name = "Player",
    .type_id = 0x0100,
    .fields = player_fields,
    .field_count = 3,
    .struct_size = sizeof(Player),
};

// Serialize
Player p = {.id = 123, .active = true, .score = 98.5f};
dcf_ser_write_struct_schema(&writer, &p, &player_schema);

// Deserialize: strict -- a DCF_FIELD_REQUIRED field that is missing, or an id sent
// twice, is an error (DCF_SER_POLICY_LAX_SCHEMA relaxes it); unknown ids are skipped.
// Every field must be the size its type implies and lie inside struct_size.
// DCF_TYPE_STRING cannot be read into a struct: read such fields with the typed API.
Player decoded;
dcf_ser_read_struct_schema(&reader, &decoded, &player_schema);
```

## Integration with DCF

```c
#include <dcf/dcf_serialize.h>
#include <dcf/dcf_ringbuf.h>
#include <dcf/dcf_connpool.h>

// Serialize message
DCFSerWriter writer;
dcf_ser_writer_init(&writer, MSG_TYPE, DCF_SER_FLAG_PRIORITY);
// ... write data ...
dcf_ser_writer_finish(&writer, &data, &len);

// Write to ring buffer for transport
dcf_ringbuf_write_bytes(ringbuf, data, len);

// Later, on receive side:
size_t msg_len = DCF_SER_MAX_MESSAGE;
dcf_ringbuf_read_bytes(ringbuf, recv_buf, &msg_len);

// Deserialize
DCFSerReader reader;
dcf_ser_reader_init(&reader, recv_buf, msg_len);
dcf_ser_reader_validate(&reader);
// ... read data ...
```

---

## NixOS Module

```nix
{
  inputs.dcf-serialize.url = "github:demod-llc/dcf-serialize";

  outputs = { self, nixpkgs, dcf-serialize }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        dcf-serialize.nixosModules.default
        {
          services.dcf-serialize.enable = true;
        }
      ];
    };
  };
}
```

## Supported Types

| Type | Tag | Size | Description |
|------|-----|------|-------------|
| `null` | 0x00 | 0 | Null value |
| `bool` | 0x01 | 1 | Boolean |
| `u8`/`i8` | 0x02/0x03 | 1 | 8-bit integers |
| `u16`/`i16` | 0x04/0x05 | 2 | 16-bit integers |
| `u32`/`i32` | 0x06/0x07 | 4 | 32-bit integers |
| `u64`/`i64` | 0x08/0x09 | 8 | 64-bit integers |
| `f32`/`f64` | 0x0A/0x0B | 4/8 | IEEE 754 floats |
| `varint` | 0x10 | 1-10 | LEB128 variable int |
| `string` | 0x11 | 4+N | Length-prefixed UTF-8 |
| `bytes` | 0x12 | 4+N | Length-prefixed bytes |
| `uuid` | 0x13 | 16 | 128-bit UUID |
| `array` | 0x20 | 5+N | Homogeneous array |
| `map` | 0x21 | 6+N | Key-value map |
| `struct` | 0x22 | 2+N | Named fields |
| `timestamp` | 0x30 | 8 | Microseconds since epoch |

## License

BSD 3-Clause License

Copyright (c) 2024-2025, DeMoD LLC. All rights reserved.

See [LICENSE](LICENSE) for the full license text.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure tests pass: `make test` or `nix flake check`
4. Submit a pull request

## Contact

- **Organization**: DeMoD LLC
- **Website**: https://demod.ltd
- **Issues**: https://github.com/demod-llc/dcf-serialize/issues
