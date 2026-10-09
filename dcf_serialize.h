/**
 * @file dcf_serialize.h
 * @brief Universal Serialization/Deserialization Shim for DCF Transport
 * @version 5.2.0
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
 * 
 * See LICENSE file for full license text.
 * 
 * System-agnostic binary serialization with:
 * - Network byte order (big-endian) wire format
 * - Zero-copy reads where possible
 * - Schema-based type-safe serialization
 * - CRC32 integrity validation
 * - Nested structure support
 * - Variable-length encoding for efficiency
 * 
 * Security model:
 * - The reader is STRICT BY DEFAULT: every frame it accepts has a valid CRC32,
 *   no unsupported flag bits, exactly the advertised length, and a payload that
 *   is a well-formed sequence of tagged values (bounded depth, counts and string
 *   lengths checked against the bytes actually present, canonical varints,
 *   UTF-8 strings). A caller on a trusted channel opts out of individual checks
 *   with dcf_ser_reader_set_policy().
 * - CRC32 is an error-detection code, NOT authentication. Anyone who can alter
 *   a frame can recompute its CRC. Use a MAC or an authenticated transport
 *   where the sender must be proven.
 * 
 * Wire Format:
 * ┌──────────┬─────────┬──────────┬───────┬────────┬──────────┬──────────┐
 * │  Magic   │ Version │ MsgType  │ Flags │ Length │ Payload  │  CRC32   │
 * │  4 bytes │ 2 bytes │ 2 bytes  │ 1 byte│ 4 bytes│ N bytes  │  4 bytes │
 * └──────────┴─────────┴──────────┴───────┴────────┴──────────┴──────────┘
 */

#ifndef DCF_SERIALIZE_H
#define DCF_SERIALIZE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Platform Detection
 * ============================================================================ */

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    #define DCF_SER_PLATFORM_WINDOWS 1
#elif defined(__linux__)
    #define DCF_SER_PLATFORM_LINUX 1
    #define DCF_SER_PLATFORM_POSIX 1
#elif defined(__APPLE__) && defined(__MACH__)
    #define DCF_SER_PLATFORM_MACOS 1
    #define DCF_SER_PLATFORM_POSIX 1
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    #define DCF_SER_PLATFORM_BSD 1
    #define DCF_SER_PLATFORM_POSIX 1
#else
    #define DCF_SER_PLATFORM_GENERIC 1
#endif

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

#define DCF_SER_MAGIC           0x44434653  /* "DCFS" in big-endian */
#define DCF_SER_VERSION         0x0520      /* Version 5.2.0 */
#define DCF_SER_HEADER_SIZE     17          /* Fixed header size */
#define DCF_SER_MAX_MESSAGE     (16 * 1024 * 1024)  /* 16MB max message */
#define DCF_SER_MAX_STRING      (64 * 1024)         /* 64KB max string */
#define DCF_SER_MAX_ARRAY       (1024 * 1024)       /* 1M max array elements */
#define DCF_SER_MAX_DEPTH       32          /* Max nesting depth */
#define DCF_SER_INITIAL_CAP     256         /* Initial buffer capacity */
#define DCF_SER_MAX_SCHEMA_FIELDS 256       /* Max fields in one DCFSerSchema */

/* Defined when this header provides the reader-policy API, dcf_ser_validate_payload()
 * and dcf_ser_message_length_checked(). Lets a caller compile against both. */
#define DCF_SER_HARDENED_API    1

/* Mark an API as deprecated; define DCF_SER_NO_DEPRECATION_WARNINGS to silence. */
#if defined(DCF_SER_NO_DEPRECATION_WARNINGS)
    #define DCF_SER_DEPRECATED(msg)
#elif defined(__GNUC__) || defined(__clang__)
    #define DCF_SER_DEPRECATED(msg) __attribute__((deprecated(msg)))
#elif defined(_MSC_VER)
    #define DCF_SER_DEPRECATED(msg) __declspec(deprecated(msg))
#else
    #define DCF_SER_DEPRECATED(msg)
#endif

/* ============================================================================
 * Error Codes
 * ============================================================================ */

typedef enum DCFSerError {
    DCF_SER_OK = 0,
    
    /* Encoding errors (0x1XX) */
    DCF_SER_ERR_BUFFER_FULL     = 0x101,
    DCF_SER_ERR_ALLOC_FAIL      = 0x102,
    DCF_SER_ERR_TOO_LARGE       = 0x103,
    DCF_SER_ERR_DEPTH_EXCEEDED  = 0x104,
    
    /* Decoding errors (0x2XX) */
    DCF_SER_ERR_INVALID_MAGIC   = 0x201,
    DCF_SER_ERR_VERSION_MISMATCH= 0x202,
    DCF_SER_ERR_TRUNCATED       = 0x203,
    DCF_SER_ERR_CRC_MISMATCH    = 0x204,
    DCF_SER_ERR_INVALID_TYPE    = 0x205,
    DCF_SER_ERR_OVERFLOW        = 0x206,
    DCF_SER_ERR_MALFORMED       = 0x207,
    DCF_SER_ERR_POLICY          = 0x208,  /* Frame uses something the reader policy does not allow */
    
    /* General errors (0x3XX) */
    DCF_SER_ERR_NULL_PTR        = 0x301,
    DCF_SER_ERR_INVALID_ARG     = 0x302,
    DCF_SER_ERR_INTERNAL        = 0x303,
    DCF_SER_ERR_NOT_FOUND       = 0x304,
    DCF_SER_ERR_TYPE_MISMATCH   = 0x305,
} DCFSerError;

/* ============================================================================
 * Message Flags
 * ============================================================================ */

typedef enum DCFSerFlags {
    DCF_SER_FLAG_NONE       = 0x00,
    /* COMPRESSED / ENCRYPTED: this library does not compress or encrypt. The
     * reader refuses them unless DCF_SER_POLICY_ALLOW_APP_FLAGS says the
     * application handles the payload itself. */
    DCF_SER_FLAG_COMPRESSED = 0x01,  /* Payload is compressed */
    DCF_SER_FLAG_ENCRYPTED  = 0x02,  /* Payload is encrypted */
    DCF_SER_FLAG_STREAMING  = 0x04,  /* Part of a streaming message */
    DCF_SER_FLAG_FINAL      = 0x08,  /* Final chunk of streaming message */
    DCF_SER_FLAG_PRIORITY   = 0x10,  /* High-priority message */
    /* NO_CRC: the frame carries no checksum. The reader refuses it unless
     * DCF_SER_POLICY_ALLOW_NO_CRC is set (trusted channels only). */
    DCF_SER_FLAG_NO_CRC     = 0x20,  /* No CRC32 follows the payload */
    DCF_SER_FLAG_RESERVED   = 0x40,  /* Reserved: always refused by the reader */
    DCF_SER_FLAG_EXTENDED   = 0x80,  /* Extended header follows: always refused (not implemented) */
} DCFSerFlags;

/* ============================================================================
 * Data Type Tags (for self-describing format)
 * ============================================================================ */

typedef enum DCFSerType {
    /* Primitives */
    DCF_TYPE_NULL       = 0x00,
    DCF_TYPE_BOOL       = 0x01,
    DCF_TYPE_U8         = 0x02,
    DCF_TYPE_I8         = 0x03,
    DCF_TYPE_U16        = 0x04,
    DCF_TYPE_I16        = 0x05,
    DCF_TYPE_U32        = 0x06,
    DCF_TYPE_I32        = 0x07,
    DCF_TYPE_U64        = 0x08,
    DCF_TYPE_I64        = 0x09,
    DCF_TYPE_F32        = 0x0A,
    DCF_TYPE_F64        = 0x0B,
    
    /* Variable-length */
    DCF_TYPE_VARINT     = 0x10,  /* LEB128 variable-length integer */
    DCF_TYPE_STRING     = 0x11,  /* Length-prefixed UTF-8 string */
    DCF_TYPE_BYTES      = 0x12,  /* Length-prefixed byte array */
    DCF_TYPE_UUID       = 0x13,  /* 16-byte UUID */
    
    /* Containers */
    DCF_TYPE_ARRAY      = 0x20,  /* Homogeneous array */
    DCF_TYPE_MAP        = 0x21,  /* Key-value map */
    DCF_TYPE_STRUCT     = 0x22,  /* Named fields */
    DCF_TYPE_TUPLE      = 0x23,  /* Fixed-size heterogeneous sequence */
    
    /* Special */
    DCF_TYPE_TIMESTAMP  = 0x30,  /* 64-bit microseconds since epoch */
    DCF_TYPE_DURATION   = 0x31,  /* 64-bit nanoseconds */
    DCF_TYPE_OPTIONAL   = 0x32,  /* Optional/nullable wrapper */
    DCF_TYPE_ENUM       = 0x33,  /* Enumeration value */
    
    /* Reserved */
    DCF_TYPE_EXTENSION  = 0xFE,  /* User-defined type */
    DCF_TYPE_INVALID    = 0xFF,
} DCFSerType;

/* ============================================================================
 * Wire Header Structure
 * ============================================================================ */

#pragma pack(push, 1)
typedef struct DCFSerHeader {
    uint32_t magic;         /* DCF_SER_MAGIC */
    uint16_t version;       /* Protocol version */
    uint16_t msg_type;      /* Application message type */
    uint8_t  flags;         /* DCFSerFlags */
    uint32_t payload_len;   /* Payload length (excluding header/CRC) */
    uint32_t sequence;      /* Message sequence number */
} DCFSerHeader;
#pragma pack(pop)

/* ============================================================================
 * Writer Context (Encoder)
 * ============================================================================ */

typedef struct DCFSerWriter {
    uint8_t* buffer;        /* Output buffer */
    size_t   capacity;      /* Buffer capacity */
    size_t   position;      /* Current write position */
    size_t   depth;         /* Current nesting depth */
    uint16_t msg_type;      /* Message type for header */
    uint8_t  flags;         /* Message flags */
    uint32_t sequence;      /* Sequence number */
    bool     owns_buffer;   /* True if we allocated the buffer */
    bool     header_written;/* True if header is committed */
    DCFSerError last_error; /* Last error code */
} DCFSerWriter;

/* ============================================================================
 * Reader Context (Decoder)
 * ============================================================================ */

typedef struct DCFSerReader {
    const uint8_t* buffer;  /* Input buffer */
    size_t   length;        /* Total buffer length */
    size_t   position;      /* Current read position */
    size_t   payload_start; /* Start of payload (after header) */
    size_t   payload_end;   /* End of payload (before CRC) */
    size_t   depth;         /* Current nesting depth */
    DCFSerHeader header;    /* Parsed header */
    bool     header_valid;  /* True if header parsed successfully */
    bool     crc_verified;  /* True if CRC was verified */
    DCFSerError last_error; /* Last error code */
    uint32_t policy;        /* DCF_SER_POLICY_* (0 = strict); appended last */
} DCFSerReader;

/* ============================================================================
 * Schema Definition (for structured serialization)
 * ============================================================================ */

typedef struct DCFSerField {
    const char* name;       /* Field name (for debugging/schemas) */
    uint16_t    field_id;   /* Numeric field ID for wire format */
    DCFSerType  type;       /* Field type */
    uint16_t    flags;      /* Field flags (optional, repeated, etc.) */
    size_t      offset;     /* Offset within struct (for reflection) */
    size_t      size;       /* Size of field data */
} DCFSerField;

typedef struct DCFSerSchema {
    const char*         name;           /* Type name */
    uint16_t            type_id;        /* Numeric type ID */
    const DCFSerField*  fields;         /* Field definitions */
    size_t              field_count;    /* Number of fields */
    size_t              struct_size;    /* sizeof(struct) */
} DCFSerSchema;

/* Field flags */
#define DCF_FIELD_REQUIRED  0x0001
#define DCF_FIELD_OPTIONAL  0x0002
#define DCF_FIELD_REPEATED  0x0004
#define DCF_FIELD_PACKED    0x0008

/* ============================================================================
 * Byte Order Utilities (Always convert to/from network order)
 * ============================================================================ */

/**
 * Check if the current platform is little-endian
 */
bool dcf_ser_is_little_endian(void);

/**
 * Swap bytes for 16-bit value
 */
uint16_t dcf_ser_bswap16(uint16_t val);

/**
 * Swap bytes for 32-bit value
 */
uint32_t dcf_ser_bswap32(uint32_t val);

/**
 * Swap bytes for 64-bit value
 */
uint64_t dcf_ser_bswap64(uint64_t val);

/**
 * Convert host to network byte order
 */
uint16_t dcf_ser_hton16(uint16_t val);
uint32_t dcf_ser_hton32(uint32_t val);
uint64_t dcf_ser_hton64(uint64_t val);

/**
 * Convert network to host byte order
 */
uint16_t dcf_ser_ntoh16(uint16_t val);
uint32_t dcf_ser_ntoh32(uint32_t val);
uint64_t dcf_ser_ntoh64(uint64_t val);

/* ============================================================================
 * CRC32 Checksum
 * ============================================================================ */

/**
 * Calculate CRC32 checksum: the standard CRC-32 (IEEE 802.3, reflected, polynomial
 * 0xEDB88320, init and final xor 0xFFFFFFFF; crc32("123456789") = 0xCBF43926).
 * Releases before the hardening change had a mistyped table entry and computed a
 * different value for many inputs; see DCF_SER_POLICY_ALLOW_LEGACY_CRC.
 */
uint32_t dcf_ser_crc32(const void* data, size_t len);

/**
 * Update running CRC32 with more data
 */
uint32_t dcf_ser_crc32_update(uint32_t crc, const void* data, size_t len);

/* ============================================================================
 * Writer API
 * ============================================================================ */

/**
 * Initialize a writer with internal buffer allocation
 * 
 * @param writer    Writer context to initialize
 * @param msg_type  Application message type
 * @param flags     Message flags
 * @return          DCF_SER_OK on success
 */
DCFSerError dcf_ser_writer_init(DCFSerWriter* writer, uint16_t msg_type, uint8_t flags);

/**
 * Initialize a writer with external buffer
 * 
 * @param writer    Writer context to initialize
 * @param buffer    External buffer to use
 * @param capacity  Buffer capacity
 * @param msg_type  Application message type
 * @param flags     Message flags
 * @return          DCF_SER_OK on success
 */
DCFSerError dcf_ser_writer_init_buffer(DCFSerWriter* writer, uint8_t* buffer,
                                        size_t capacity, uint16_t msg_type, uint8_t flags);

/**
 * Clean up writer resources
 */
void dcf_ser_writer_destroy(DCFSerWriter* writer);

/**
 * Reset writer for reuse (keeps buffer)
 */
void dcf_ser_writer_reset(DCFSerWriter* writer, uint16_t msg_type, uint8_t flags);

/**
 * Finalize the message (write header and CRC)
 * 
 * Writer errors are sticky: once any write has failed (buffer full, too large,
 * bad argument, ...) every later call returns that first error and finish()
 * refuses to produce a frame, so a message that lost a write is never sent.
 * dcf_ser_writer_reset() clears the error. A writer can be finished once;
 * writing to it afterwards, or finishing it again, returns
 * DCF_SER_ERR_INVALID_ARG. The payload is capped at DCF_SER_MAX_MESSAGE.
 * 
 * @param writer    Writer context
 * @param out_data  Output pointer to serialized data
 * @param out_len   Output length of serialized data
 * @return          DCF_SER_OK on success
 */
DCFSerError dcf_ser_writer_finish(DCFSerWriter* writer, const uint8_t** out_data, size_t* out_len);

/**
 * Get current buffer position (payload size so far)
 */
size_t dcf_ser_writer_payload_size(const DCFSerWriter* writer);

/**
 * Set sequence number for message
 */
void dcf_ser_writer_set_sequence(DCFSerWriter* writer, uint32_t seq);

/* ----------------------------------------------------------------------------
 * Primitive Writers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_write_null(DCFSerWriter* w);
DCFSerError dcf_ser_write_bool(DCFSerWriter* w, bool val);
DCFSerError dcf_ser_write_u8(DCFSerWriter* w, uint8_t val);
DCFSerError dcf_ser_write_i8(DCFSerWriter* w, int8_t val);
DCFSerError dcf_ser_write_u16(DCFSerWriter* w, uint16_t val);
DCFSerError dcf_ser_write_i16(DCFSerWriter* w, int16_t val);
DCFSerError dcf_ser_write_u32(DCFSerWriter* w, uint32_t val);
DCFSerError dcf_ser_write_i32(DCFSerWriter* w, int32_t val);
DCFSerError dcf_ser_write_u64(DCFSerWriter* w, uint64_t val);
DCFSerError dcf_ser_write_i64(DCFSerWriter* w, int64_t val);
DCFSerError dcf_ser_write_f32(DCFSerWriter* w, float val);
DCFSerError dcf_ser_write_f64(DCFSerWriter* w, double val);

/* ----------------------------------------------------------------------------
 * Variable-Length Writers
 * ---------------------------------------------------------------------------- */

/**
 * Write variable-length integer (LEB128). varsint is ZigZag first: (n << 1) ^ (n >> 63) with an
 * arithmetic shift, so 0, -1, 1, -2, 2 become 0, 1, 2, 3, 4 and INT64_MIN becomes 2^64-1.
 */
DCFSerError dcf_ser_write_varint(DCFSerWriter* w, uint64_t val);
DCFSerError dcf_ser_write_varsint(DCFSerWriter* w, int64_t val);

/**
 * Write length-prefixed string. The bytes must be valid UTF-8 and at most
 * DCF_SER_MAX_STRING long; use dcf_ser_write_bytes() for anything else.
 * (str == NULL with len > 0 is an error; NULL with len 0 is the empty string.)
 */
DCFSerError dcf_ser_write_string(DCFSerWriter* w, const char* str);
DCFSerError dcf_ser_write_string_n(DCFSerWriter* w, const char* str, size_t len);

/**
 * Write length-prefixed byte array
 */
DCFSerError dcf_ser_write_bytes(DCFSerWriter* w, const void* data, size_t len);

/**
 * Write 16-byte UUID
 */
DCFSerError dcf_ser_write_uuid(DCFSerWriter* w, const uint8_t uuid[16]);

/**
 * Write timestamp (microseconds since epoch)
 */
DCFSerError dcf_ser_write_timestamp(DCFSerWriter* w, uint64_t timestamp_us);

/* ----------------------------------------------------------------------------
 * Container Writers
 * ---------------------------------------------------------------------------- */

/**
 * Begin writing an array
 * 
 * @param w         Writer context
 * @param elem_type Type of array elements
 * @param count     Number of elements
 */
DCFSerError dcf_ser_write_array_begin(DCFSerWriter* w, DCFSerType elem_type, size_t count);

/**
 * End array writing. Only closes the nesting level (the writer does NOT count
 * the elements written against the count given to dcf_ser_write_array_begin;
 * writing a different number of elements yields a frame strict readers refuse).
 */
DCFSerError dcf_ser_write_array_end(DCFSerWriter* w);

/**
 * Begin writing a map
 * 
 * @param w         Writer context
 * @param key_type  Type of map keys
 * @param val_type  Type of map values
 * @param count     Number of entries
 */
DCFSerError dcf_ser_write_map_begin(DCFSerWriter* w, DCFSerType key_type, 
                                     DCFSerType val_type, size_t count);

/**
 * End map writing
 */
DCFSerError dcf_ser_write_map_end(DCFSerWriter* w);

/**
 * Begin writing a struct
 * 
 * @param w         Writer context
 * @param type_id   Struct type identifier
 */
DCFSerError dcf_ser_write_struct_begin(DCFSerWriter* w, uint16_t type_id);

/**
 * Write a struct field header
 */
DCFSerError dcf_ser_write_field(DCFSerWriter* w, uint16_t field_id, DCFSerType type);

/**
 * End struct writing
 */
DCFSerError dcf_ser_write_struct_end(DCFSerWriter* w);

/* ----------------------------------------------------------------------------
 * Raw/Direct Writers
 * ---------------------------------------------------------------------------- */

/**
 * Write raw bytes directly (no length prefix). The bytes are not tagged
 * values: a reader must use DCF_SER_POLICY_ALLOW_UNSTRUCTURED to accept such
 * a payload. len is capped (DCF_SER_ERR_TOO_LARGE) so the payload stays
 * within DCF_SER_MAX_MESSAGE.
 */
DCFSerError dcf_ser_write_raw(DCFSerWriter* w, const void* data, size_t len);

/**
 * Reserve space and get pointer for direct writes. The pointer is valid only
 * until the next write (the buffer may move); the same cap as write_raw applies.
 */
DCFSerError dcf_ser_write_reserve(DCFSerWriter* w, size_t len, uint8_t** out_ptr);

/* ============================================================================
 * Reader API
 * ============================================================================ */

/**
 * Initialize a reader with input buffer
 * 
 * @param reader    Reader context to initialize
 * @param data      Input buffer
 * @param len       Buffer length
 * @return          DCF_SER_OK on success
 */
DCFSerError dcf_ser_reader_init(DCFSerReader* reader, const void* data, size_t len);

/**
 * Reader policy flags. The default is 0: STRICT. Each flag relaxes exactly one
 * check, for callers that really do own both ends of the channel. Set them
 * with dcf_ser_reader_set_policy() between dcf_ser_reader_init() and
 * dcf_ser_reader_validate().
 */
#define DCF_SER_POLICY_STRICT                   0x00u
#define DCF_SER_POLICY_ALLOW_NO_CRC             0x01u  /* accept DCF_SER_FLAG_NO_CRC frames (no integrity check at all) */
#define DCF_SER_POLICY_ALLOW_TRAILING           0x02u  /* accept bytes after the end of the frame */
#define DCF_SER_POLICY_ALLOW_NONCANONICAL_VARINT 0x04u /* accept overlong varints (value bits are never dropped) */
#define DCF_SER_POLICY_ALLOW_INVALID_UTF8       0x08u  /* accept STRING values that are not UTF-8 */
#define DCF_SER_POLICY_NO_GATE                  0x10u  /* do not consult the Exsecutor admission gate */
#define DCF_SER_POLICY_ALLOW_UNSTRUCTURED       0x20u  /* payload need not be a sequence of tagged values (write_raw / write_reserve users) */
#define DCF_SER_POLICY_LAX_SCHEMA               0x40u  /* schema reads: tolerate missing REQUIRED fields, duplicate ids, header/type disagreement */
#define DCF_SER_POLICY_ALLOW_APP_FLAGS          0x80u  /* accept DCF_SER_FLAG_COMPRESSED / DCF_SER_FLAG_ENCRYPTED (application handles them) */
#define DCF_SER_POLICY_ALLOW_LEGACY_CRC         0x100u /* migration only: also accept the CRC computed by releases whose table entry 245 was mistyped */
#define DCF_SER_POLICY_ALL                      0x1FFu

/**
 * Set the reader policy. Must be called after dcf_ser_reader_init() and before
 * dcf_ser_reader_validate(); once validate has succeeded the policy is frozen.
 * An unknown bit is refused (DCF_SER_ERR_INVALID_ARG) and leaves the policy as it was.
 */
DCFSerError dcf_ser_reader_set_policy(DCFSerReader* reader, uint32_t policy);

/**
 * Validate and parse the message header.
 * 
 * Under the default (strict) policy this checks: magic; major version; no
 * EXTENDED/reserved/COMPRESSED/ENCRYPTED flag; a CRC32 is present and correct;
 * payload_len <= DCF_SER_MAX_MESSAGE; the buffer is exactly one frame (no bytes
 * after it); the payload is a well-formed sequence of tagged values
 * (see dcf_ser_validate_payload); and, unless DCF_SER_NO_GATE or a policy that
 * the gate does not model is in force, that the Exsecutor admission gate agrees.
 * Returns DCF_SER_ERR_POLICY for a feature the policy forbids.
 */
DCFSerError dcf_ser_reader_validate(DCFSerReader* reader);

/**
 * Get parsed header
 */
const DCFSerHeader* dcf_ser_reader_header(const DCFSerReader* reader);

/**
 * Get message type from header
 */
uint16_t dcf_ser_reader_msg_type(const DCFSerReader* reader);

/**
 * Get remaining payload bytes
 */
size_t dcf_ser_reader_remaining(const DCFSerReader* reader);

/**
 * Check if at end of payload
 */
bool dcf_ser_reader_at_end(const DCFSerReader* reader);

/**
 * Peek at next type tag without consuming
 */
DCFSerType dcf_ser_reader_peek_type(const DCFSerReader* reader);

/**
 * Skip one value (useful for unknown fields). Bounds-checked and depth-limited
 * (DCF_SER_MAX_DEPTH, counting the reader's current typed-read depth). On
 * failure the position is unchanged.
 */
DCFSerError dcf_ser_reader_skip(DCFSerReader* reader);

/* ----------------------------------------------------------------------------
 * Primitive Readers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_read_null(DCFSerReader* r);
DCFSerError dcf_ser_read_bool(DCFSerReader* r, bool* out);
DCFSerError dcf_ser_read_u8(DCFSerReader* r, uint8_t* out);
DCFSerError dcf_ser_read_i8(DCFSerReader* r, int8_t* out);
DCFSerError dcf_ser_read_u16(DCFSerReader* r, uint16_t* out);
DCFSerError dcf_ser_read_i16(DCFSerReader* r, int16_t* out);
DCFSerError dcf_ser_read_u32(DCFSerReader* r, uint32_t* out);
DCFSerError dcf_ser_read_i32(DCFSerReader* r, int32_t* out);
DCFSerError dcf_ser_read_u64(DCFSerReader* r, uint64_t* out);
DCFSerError dcf_ser_read_i64(DCFSerReader* r, int64_t* out);
DCFSerError dcf_ser_read_f32(DCFSerReader* r, float* out);
DCFSerError dcf_ser_read_f64(DCFSerReader* r, double* out);

/* ----------------------------------------------------------------------------
 * Variable-Length Readers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_read_varint(DCFSerReader* r, uint64_t* out);
DCFSerError dcf_ser_read_varsint(DCFSerReader* r, int64_t* out);

/**
 * Read string (returns pointer into buffer - zero-copy). Length-delimited, not
 * NUL-terminated, may contain NUL. Refused if longer than DCF_SER_MAX_STRING or
 * (unless DCF_SER_POLICY_ALLOW_INVALID_UTF8) not valid UTF-8.
 */
DCFSerError dcf_ser_read_string(DCFSerReader* r, const char** out_str, size_t* out_len);

/**
 * Read string into caller-provided buffer as a C string. A string containing a
 * NUL byte is refused (DCF_SER_ERR_MALFORMED): the C string would be truncated.
 */
DCFSerError dcf_ser_read_string_copy(DCFSerReader* r, char* buf, size_t buf_size, size_t* out_len);

/**
 * Read bytes (returns pointer into buffer - zero-copy)
 */
DCFSerError dcf_ser_read_bytes(DCFSerReader* r, const void** out_data, size_t* out_len);

/**
 * Read bytes into caller-provided buffer
 */
DCFSerError dcf_ser_read_bytes_copy(DCFSerReader* r, void* buf, size_t buf_size, size_t* out_len);

DCFSerError dcf_ser_read_uuid(DCFSerReader* r, uint8_t out_uuid[16]);
DCFSerError dcf_ser_read_timestamp(DCFSerReader* r, uint64_t* out_us);

/* ----------------------------------------------------------------------------
 * Container Readers
 * ---------------------------------------------------------------------------- */

/**
 * Read array header. The count is refused if it exceeds DCF_SER_MAX_ARRAY or
 * the number of payload bytes left (each element is at least one byte), so it
 * is safe to size an allocation from it.
 */
DCFSerError dcf_ser_read_array_begin(DCFSerReader* r, DCFSerType* out_elem_type, size_t* out_count);

/**
 * Finish reading array (optional validation)
 */
DCFSerError dcf_ser_read_array_end(DCFSerReader* r);

/**
 * Read map header
 */
DCFSerError dcf_ser_read_map_begin(DCFSerReader* r, DCFSerType* out_key_type,
                                    DCFSerType* out_val_type, size_t* out_count);

DCFSerError dcf_ser_read_map_end(DCFSerReader* r);

/**
 * Read struct header
 */
DCFSerError dcf_ser_read_struct_begin(DCFSerReader* r, uint16_t* out_type_id);

/**
 * Read next field header (returns DCF_SER_ERR_NOT_FOUND at end of struct)
 */
DCFSerError dcf_ser_read_field(DCFSerReader* r, uint16_t* out_field_id, DCFSerType* out_type);

DCFSerError dcf_ser_read_struct_end(DCFSerReader* r);

/* ----------------------------------------------------------------------------
 * Raw/Direct Readers
 * ---------------------------------------------------------------------------- */

/**
 * Read raw bytes directly (no length prefix)
 */
DCFSerError dcf_ser_read_raw(DCFSerReader* r, void* out, size_t len);

/**
 * Get pointer to raw bytes (zero-copy)
 */
DCFSerError dcf_ser_read_raw_ptr(DCFSerReader* r, const void** out_ptr, size_t len);

/* ============================================================================
 * Schema-Based Serialization
 * ============================================================================ */

/**
 * Serialize a struct using schema. Every field must be the size its type
 * implies (dcf_ser_type_size(); STRING is a const char*) and lie inside
 * struct_size, else DCF_SER_ERR_INVALID_ARG; at most DCF_SER_MAX_SCHEMA_FIELDS.
 */
DCFSerError dcf_ser_write_struct_schema(DCFSerWriter* w, const void* data,
                                         const DCFSerSchema* schema);

/**
 * Deserialize a struct using schema. Fields not in the schema are skipped.
 * Strict: a DCF_FIELD_REQUIRED field that is absent, a field id sent twice, or
 * a field header whose type differs from the schema, is refused (relax with
 * DCF_SER_POLICY_LAX_SCHEMA). A STRING field cannot be read this way and the
 * schema is refused with DCF_SER_ERR_INVALID_TYPE (it used to be dropped
 * silently); read such fields with the typed API. On any error the struct is
 * left zeroed.
 */
DCFSerError dcf_ser_read_struct_schema(DCFSerReader* r, void* data,
                                        const DCFSerSchema* schema);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Get error string
 */
const char* dcf_ser_error_str(DCFSerError err);

/**
 * Get type name string
 */
const char* dcf_ser_type_str(DCFSerType type);

/**
 * Calculate serialized size of a type (fixed-size types only)
 * Returns 0 for variable-length types
 */
size_t dcf_ser_type_size(DCFSerType type);

/**
 * Validate a complete message buffer under the STRICT policy.
 */
DCFSerError dcf_ser_validate_message(const void* data, size_t len);

/**
 * Check that payload[0, len) is a well-formed sequence of tagged values and
 * consumes exactly len bytes. Iterative and depth-limited; time is O(len) and
 * memory is constant. `policy` is a DCF_SER_POLICY_* set (only the varint and
 * UTF-8 relaxations apply). The grammar is documented in dcf_serialize.c and
 * gate/README.md. An empty payload is valid.
 */
DCFSerError dcf_ser_validate_payload(const void* payload, size_t len, uint32_t policy);

/**
 * Get message length from header (for framing), checked.
 * 
 * Validates avail >= DCF_SER_HEADER_SIZE, the magic, the major version and
 * payload_len <= DCF_SER_MAX_MESSAGE, then stores the total frame length
 * (header + payload + CRC unless NO_CRC) in *out_total. *out_total is only
 * written on DCF_SER_OK. Use this to size a receive buffer; never trust a
 * length that did not come through here.
 */
DCFSerError dcf_ser_message_length_checked(const void* data, size_t avail, size_t* out_total);

/**
 * @deprecated Takes no length (reads DCF_SER_HEADER_SIZE bytes blind) and does
 * no validation of the caller's buffer. Use dcf_ser_message_length_checked().
 * It now returns 0 when the checked variant would fail (bad magic, wrong major
 * version, payload_len above DCF_SER_MAX_MESSAGE).
 */
DCF_SER_DEPRECATED("use dcf_ser_message_length_checked()")
size_t dcf_ser_message_length(const void* header_data);

/**
 * Number of frames the C validator accepted and the Exsecutor gate refused (or
 * that made the gate trap) since the process started. Each one is a bug in one
 * of the two implementations; the frame is rejected. Always 0 with DCF_SER_NO_GATE.
 */
uint64_t dcf_ser_gate_disagreements(void);

/* ============================================================================
 * Helper Macros
 * ============================================================================ */

#define DCF_SER_CHECK(expr) do { \
    DCFSerError _err = (expr); \
    if (_err != DCF_SER_OK) return _err; \
} while(0)

#define DCF_SER_FIELD_DEF(struct_type, field, type_tag, fid) \
    { #field, (fid), (type_tag), DCF_FIELD_REQUIRED, \
      offsetof(struct_type, field), sizeof(((struct_type*)0)->field) }

#define DCF_SER_FIELD_OPT(struct_type, field, type_tag, fid) \
    { #field, (fid), (type_tag), DCF_FIELD_OPTIONAL, \
      offsetof(struct_type, field), sizeof(((struct_type*)0)->field) }

#ifdef __cplusplus
}
#endif

#endif /* DCF_SERIALIZE_H */
