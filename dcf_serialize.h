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
    DCF_SER_FLAG_COMPRESSED = 0x01,  /* Payload is compressed */
    DCF_SER_FLAG_ENCRYPTED  = 0x02,  /* Payload is encrypted */
    DCF_SER_FLAG_STREAMING  = 0x04,  /* Part of a streaming message */
    DCF_SER_FLAG_FINAL      = 0x08,  /* Final chunk of streaming message */
    DCF_SER_FLAG_PRIORITY   = 0x10,  /* High-priority message */
    DCF_SER_FLAG_NO_CRC     = 0x20,  /* Skip CRC validation (trusted channel) */
    DCF_SER_FLAG_EXTENDED   = 0x80,  /* Extended header follows */
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
 * Calculate CRC32 checksum
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
 * Write variable-length integer (LEB128)
 */
DCFSerError dcf_ser_write_varint(DCFSerWriter* w, uint64_t val);
DCFSerError dcf_ser_write_varsint(DCFSerWriter* w, int64_t val);

/**
 * Write length-prefixed string (UTF-8)
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
 * End array writing (validates count)
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
 * Write raw bytes directly (no length prefix)
 */
DCFSerError dcf_ser_write_raw(DCFSerWriter* w, const void* data, size_t len);

/**
 * Reserve space and get pointer for direct writes
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
 * Validate and parse the message header
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
 * Skip a value (useful for unknown fields)
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
 * Read string (returns pointer into buffer - zero-copy)
 */
DCFSerError dcf_ser_read_string(DCFSerReader* r, const char** out_str, size_t* out_len);

/**
 * Read string into caller-provided buffer
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
 * Read array header
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
 * Serialize a struct using schema
 */
DCFSerError dcf_ser_write_struct_schema(DCFSerWriter* w, const void* data,
                                         const DCFSerSchema* schema);

/**
 * Deserialize a struct using schema
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
 * Validate a complete message buffer
 */
DCFSerError dcf_ser_validate_message(const void* data, size_t len);

/**
 * Get message length from header (for framing)
 * Returns total message length including header and CRC
 */
size_t dcf_ser_message_length(const void* header_data);

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
