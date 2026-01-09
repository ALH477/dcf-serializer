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

/* Serialize captured data into DCF format */
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
    
    /* Write metadata */
    dcf_ser_write_timestamp(&writer, get_timestamp_us());  /* Capture time */
    dcf_ser_write_u16(&writer, src_port);                  /* Source port */
    dcf_ser_write_u32(&writer, (uint32_t)raw_len);         /* Original length */
    
    /* Write the captured payload */
    dcf_ser_write_bytes(&writer, raw_data, raw_len);
    
    /* Finalize - adds header and CRC */
    const uint8_t* data;
    if (dcf_ser_writer_finish(&writer, &data, out_len) != DCF_SER_OK) {
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
        
        dcf_ser_read_timestamp(&reader, &timestamp);
        dcf_ser_read_u16(&reader, &src_port);
        dcf_ser_read_u32(&reader, &original_len);
        
        char ts_str[64];
        format_timestamp(timestamp, ts_str, sizeof(ts_str));
        
        printf("  --- Capture Info ---\n");
        printf("  Capture Time: %s\n", ts_str);
        printf("  Source Port:  %u\n", src_port);
        printf("  Original Len: %u bytes\n", original_len);
        
        /* Read the captured payload (zero-copy) */
        const void* payload;
        size_t payload_len;
        dcf_ser_read_bytes(&reader, &payload, &payload_len);
        
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
            
            /* Get total message length from header */
            size_t msg_len = dcf_ser_message_length(header_buf);
            if (msg_len == 0 || msg_len > BUFFER_SIZE) {
                fprintf(stderr, "[Receiver] Invalid message length: %zu\n", msg_len);
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
            
            /* Process the complete DCF message */
            process_dcf_message(msg_buf, msg_len);
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
        dcf_ser_writer_init_buffer(&w, buf, sizeof(buf), MSG_TELEMETRY, 
                                    DCF_SER_FLAG_NO_CRC);  /* Skip CRC for speed */
        dcf_ser_writer_set_sequence(&w, seq++);
        
        /* Simulated sensor data */
        dcf_ser_write_f32(&w, 23.5f + (seq % 10) * 0.1f);  /* Temperature */
        dcf_ser_write_f32(&w, 45.2f);                       /* Humidity */
        dcf_ser_write_u32(&w, seq * 100);                   /* Counter */
        
        const uint8_t* data;
        size_t len;
        dcf_ser_writer_finish(&w, &data, &len);
        
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
        dcf_ser_reader_init(&r, buf, n);
        
        if (dcf_ser_reader_validate(&r) != DCF_SER_OK) {
            printf("[UDP RX] Invalid message\n");
            continue;
        }
        
        const DCFSerHeader* h = dcf_ser_reader_header(&r);
        
        if (h->msg_type == MSG_TELEMETRY) {
            float temp, humidity;
            uint32_t counter;
            
            dcf_ser_read_f32(&r, &temp);
            dcf_ser_read_f32(&r, &humidity);
            dcf_ser_read_u32(&r, &counter);
            
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
#include <unistd.h>
#include <pthread.h>
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
    
    dcf_ser_writer_init_buffer(&w, buf, sizeof(buf), msg_type, DCF_SER_FLAG_NONE);
    dcf_ser_writer_set_sequence(&w, next_seq());
    
    dcf_ser_write_u32(&w, conn_id);
    dcf_ser_write_timestamp(&w, /* timestamp */
        (uint64_t)time(NULL) * 1000000ULL);
    dcf_ser_write_bytes(&w, data, len);
    
    const uint8_t* out;
    size_t out_len;
    dcf_ser_writer_finish(&w, &out, &out_len);
    
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
    /* ... argument parsing and socket setup ... */
    printf("[DCF Mirror] Traffic mirroring active\n");
    /* ... main accept loop creating relay threads ... */
    return 0;
}
```

### Building the Examples

Add to your Makefile or compile directly:

```bash
# Compile with the DCF library
gcc -o dcf_capture_relay dcf_capture_relay.c -L. -ldcf_serialize -lpthread
gcc -o dcf_receiver dcf_receiver.c -L. -ldcf_serialize
gcc -o dcf_udp_sender dcf_udp_sender.c -L. -ldcf_serialize
gcc -o dcf_udp_receiver dcf_udp_receiver.c -L. -ldcf_serialize

# Or link statically
gcc -o dcf_receiver dcf_receiver.c dcf_serialize.c -O2
```

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
