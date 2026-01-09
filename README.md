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
- **CRC32 Integrity**: Built-in checksum validation
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

# Run tests
make test

# Install system-wide
sudo make install PREFIX=/usr/local

# Build with debug symbols and sanitizers
make DEBUG=1 test
```

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

// Validate message (checks magic, version, CRC)
DCFSerError err = dcf_ser_reader_validate(&reader);
if (err != DCF_SER_OK) {
    fprintf(stderr, "Invalid message: %s\n", dcf_ser_error_str(err));
    return;
}

// Check message type
uint16_t msg_type = dcf_ser_reader_msg_type(&reader);

// Read data (zero-copy for strings/bytes)
const char* name;
size_t name_len;
dcf_ser_read_string(&reader, &name, &name_len);

uint32_t score;
dcf_ser_read_u32(&reader, &score);

float position;
dcf_ser_read_f32(&reader, &position);
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

// Deserialize
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
- **Issues**: https://github.com/ALH477/dcf-serialize/issues
