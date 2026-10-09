/**
 * @file dcf_serialize.c
 * @brief Universal Serialization/Deserialization Implementation
 * @version 5.2.0
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
 * 
 * See LICENSE file for full license text.
 */

#include "dcf_serialize.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* The Exsecutor-generated admission gate is built for hosted POSIX targets
 * (setjmp/_Thread_local). Elsewhere it is compiled out. */
#if defined(DCF_SER_PLATFORM_WINDOWS) && !defined(DCF_SER_NO_GATE)
    #define DCF_SER_NO_GATE 1
#endif
#ifndef DCF_SER_NO_GATE
    #include "gate/dcfs_gate_host.h"
#endif

/* ============================================================================
 * Platform-Specific Includes
 * ============================================================================ */

#ifdef DCF_SER_PLATFORM_WINDOWS
    #include <winsock2.h>
    #include <intrin.h>
#else
    #include <arpa/inet.h>
#endif

/* ============================================================================
 * Internal Macros
 * ============================================================================ */

/* Writer: reserve n payload bytes. Overflow-safe (no `position + n`), capped at
 * DCF_SER_MAX_MESSAGE of payload, and sticky on failure. */
#define WRITER_ENSURE_SPACE(w, n) do { \
    DCFSerError _e = writer_ensure((w), (n), true); \
    if (_e != DCF_SER_OK) return _e; \
} while(0)

/* Reader: n bytes must remain before payload_end. Written as `n > end - pos`
 * so a hostile n cannot wrap `pos + n`; the guard on pos keeps the subtraction
 * itself from wrapping if the invariant pos <= end were ever broken. */
#define READER_ENSURE_BYTES(r, n) do { \
    if ((r)->position > (r)->payload_end || \
        (size_t)(n) > (r)->payload_end - (r)->position) { \
        return DCF_SER_ERR_TRUNCATED; \
    } \
} while(0)

/* Writer: refuse any call on a NULL, finished, destroyed or already-failed writer. */
#define WRITER_ENTER(w) do { \
    if (!(w)) return DCF_SER_ERR_NULL_PTR; \
    DCFSerError _st = writer_state(w); \
    if (_st != DCF_SER_OK) return _st; \
} while(0)

/* ============================================================================
 * CRC32 Table (IEEE 802.3 polynomial)
 * ============================================================================ */

static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
    0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
    0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
    0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
    0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
    0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
    0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
    0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
    0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
    0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
    0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
    0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
    0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
    0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
    0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
    0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
    0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
    0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
    0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
    0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD706B3,
    0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

/* ============================================================================
 * Byte Order Utilities
 * ============================================================================ */

bool dcf_ser_is_little_endian(void) {
    static const uint16_t test = 0x0001;
    return *((const uint8_t*)&test) == 0x01;
}

uint16_t dcf_ser_bswap16(uint16_t val) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap16(val);
#elif defined(_MSC_VER)
    return _byteswap_ushort(val);
#else
    return (val >> 8) | (val << 8);
#endif
}

uint32_t dcf_ser_bswap32(uint32_t val) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(val);
#elif defined(_MSC_VER)
    return _byteswap_ulong(val);
#else
    return ((val >> 24) & 0x000000FF) |
           ((val >>  8) & 0x0000FF00) |
           ((val <<  8) & 0x00FF0000) |
           ((val << 24) & 0xFF000000);
#endif
}

uint64_t dcf_ser_bswap64(uint64_t val) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap64(val);
#elif defined(_MSC_VER)
    return _byteswap_uint64(val);
#else
    return ((val >> 56) & 0x00000000000000FFULL) |
           ((val >> 40) & 0x000000000000FF00ULL) |
           ((val >> 24) & 0x0000000000FF0000ULL) |
           ((val >>  8) & 0x00000000FF000000ULL) |
           ((val <<  8) & 0x000000FF00000000ULL) |
           ((val << 24) & 0x0000FF0000000000ULL) |
           ((val << 40) & 0x00FF000000000000ULL) |
           ((val << 56) & 0xFF00000000000000ULL);
#endif
}

uint16_t dcf_ser_hton16(uint16_t val) {
    return dcf_ser_is_little_endian() ? dcf_ser_bswap16(val) : val;
}

uint32_t dcf_ser_hton32(uint32_t val) {
    return dcf_ser_is_little_endian() ? dcf_ser_bswap32(val) : val;
}

uint64_t dcf_ser_hton64(uint64_t val) {
    return dcf_ser_is_little_endian() ? dcf_ser_bswap64(val) : val;
}

uint16_t dcf_ser_ntoh16(uint16_t val) {
    return dcf_ser_is_little_endian() ? dcf_ser_bswap16(val) : val;
}

uint32_t dcf_ser_ntoh32(uint32_t val) {
    return dcf_ser_is_little_endian() ? dcf_ser_bswap32(val) : val;
}

uint64_t dcf_ser_ntoh64(uint64_t val) {
    return dcf_ser_is_little_endian() ? dcf_ser_bswap64(val) : val;
}

/* ============================================================================
 * CRC32 Implementation
 * ============================================================================ */

uint32_t dcf_ser_crc32(const void* data, size_t len) {
    return dcf_ser_crc32_update(0xFFFFFFFF, data, len) ^ 0xFFFFFFFF;
}

uint32_t dcf_ser_crc32_update(uint32_t crc, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    while (len--) {
        crc = crc32_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    }
    return crc;
}

/* ============================================================================
 * Small helpers
 * ============================================================================ */

static uint16_t rd_be16(const uint8_t* p) {
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

static uint32_t rd_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Strict UTF-8 (RFC 3629): no overlongs, no surrogates, nothing above U+10FFFF,
 * no sequence cut short by the end of the string. NUL is a valid scalar value. */
static bool utf8_valid(const uint8_t* s, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        if (c < 0x80) { i++; continue; }
        size_t need;
        uint8_t lo = 0x80, hi = 0xBF;
        if (c >= 0xC2 && c <= 0xDF)      need = 1;
        else if (c == 0xE0)            { need = 2; lo = 0xA0; }
        else if (c == 0xED)            { need = 2; hi = 0x9F; }
        else if (c >= 0xE1 && c <= 0xEF) need = 2;
        else if (c == 0xF0)            { need = 3; lo = 0x90; }
        else if (c == 0xF4)            { need = 3; hi = 0x8F; }
        else if (c >= 0xF1 && c <= 0xF3) need = 3;
        else return false;
        if (need > n - 1 - i) return false;
        if (s[i + 1] < lo || s[i + 1] > hi) return false;
        for (size_t k = 2; k <= need; k++) {
            if ((s[i + k] & 0xC0) != 0x80) return false;
        }
        i += need + 1;
    }
    return true;
}

/* ============================================================================
 * Writer Internal Functions
 * ============================================================================ */

/* Errors are sticky: the first failure is recorded and every later call, and
 * finish(), returns it. A message that lost a write is never finished. */
static DCFSerError writer_fail(DCFSerWriter* w, DCFSerError e) {
    if (w->last_error == DCF_SER_OK) w->last_error = e;
    return e;
}

static DCFSerError writer_state(const DCFSerWriter* w) {
    if (w->last_error != DCF_SER_OK) return w->last_error;
    if (w->header_written || !w->buffer) return DCF_SER_ERR_INVALID_ARG;
    return DCF_SER_OK;
}

static DCFSerError writer_grow(DCFSerWriter* w, size_t needed) {
    if (!w->owns_buffer) return writer_fail(w, DCF_SER_ERR_BUFFER_FULL);

    /* Header + payload + CRC of a maximum-size message. */
    const size_t max_total = (size_t)DCF_SER_MAX_MESSAGE + DCF_SER_HEADER_SIZE + 4;

    /* Callers guarantee needed <= DCF_SER_MAX_MESSAGE and position <= capacity
     * <= max_total, so neither the subtraction nor the addition can wrap. */
    if (needed > max_total - w->position) return writer_fail(w, DCF_SER_ERR_TOO_LARGE);
    size_t required = w->position + needed;

    size_t new_cap = w->capacity ? w->capacity : DCF_SER_INITIAL_CAP;
    while (new_cap < required) {
        if (new_cap > max_total / 2) { new_cap = max_total; break; }
        new_cap *= 2;
    }

    uint8_t* new_buf = (uint8_t*)realloc(w->buffer, new_cap);
    if (!new_buf) return writer_fail(w, DCF_SER_ERR_ALLOC_FAIL);

    w->buffer = new_buf;
    w->capacity = new_cap;
    return DCF_SER_OK;
}

/* Make room for n more bytes. `payload` is false only for the trailing CRC,
 * which is not counted against DCF_SER_MAX_MESSAGE. */
static DCFSerError writer_ensure(DCFSerWriter* w, size_t n, bool payload) {
    if (n > DCF_SER_MAX_MESSAGE) return writer_fail(w, DCF_SER_ERR_TOO_LARGE);
    if (w->position > w->capacity || w->position < DCF_SER_HEADER_SIZE) {
        return writer_fail(w, DCF_SER_ERR_INTERNAL);
    }
    if (payload) {
        size_t used = w->position - DCF_SER_HEADER_SIZE;
        if (used > DCF_SER_MAX_MESSAGE || n > DCF_SER_MAX_MESSAGE - used) {
            return writer_fail(w, DCF_SER_ERR_TOO_LARGE);
        }
    }
    if (n > w->capacity - w->position) return writer_grow(w, n);
    return DCF_SER_OK;
}

static DCFSerError writer_put_u8(DCFSerWriter* w, uint8_t val) {
    WRITER_ENSURE_SPACE(w, 1);
    w->buffer[w->position++] = val;
    return DCF_SER_OK;
}

static DCFSerError writer_put_u16(DCFSerWriter* w, uint16_t val) {
    WRITER_ENSURE_SPACE(w, 2);
    uint16_t net = dcf_ser_hton16(val);
    memcpy(w->buffer + w->position, &net, 2);
    w->position += 2;
    return DCF_SER_OK;
}

static DCFSerError writer_put_u32(DCFSerWriter* w, uint32_t val) {
    WRITER_ENSURE_SPACE(w, 4);
    uint32_t net = dcf_ser_hton32(val);
    memcpy(w->buffer + w->position, &net, 4);
    w->position += 4;
    return DCF_SER_OK;
}

static DCFSerError writer_put_u64(DCFSerWriter* w, uint64_t val) {
    WRITER_ENSURE_SPACE(w, 8);
    uint64_t net = dcf_ser_hton64(val);
    memcpy(w->buffer + w->position, &net, 8);
    w->position += 8;
    return DCF_SER_OK;
}

/* ============================================================================
 * Writer API Implementation
 * ============================================================================ */

DCFSerError dcf_ser_writer_init(DCFSerWriter* writer, uint16_t msg_type, uint8_t flags) {
    if (!writer) return DCF_SER_ERR_NULL_PTR;
    
    memset(writer, 0, sizeof(DCFSerWriter));
    
    writer->buffer = (uint8_t*)malloc(DCF_SER_INITIAL_CAP);
    if (!writer->buffer) return DCF_SER_ERR_ALLOC_FAIL;
    
    writer->capacity = DCF_SER_INITIAL_CAP;
    writer->owns_buffer = true;
    writer->msg_type = msg_type;
    writer->flags = flags;
    
    /* Reserve space for header */
    writer->position = sizeof(DCFSerHeader);
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_writer_init_buffer(DCFSerWriter* writer, uint8_t* buffer,
                                        size_t capacity, uint16_t msg_type, uint8_t flags) {
    if (!writer || !buffer) return DCF_SER_ERR_NULL_PTR;
    if (capacity < sizeof(DCFSerHeader) + 4) return DCF_SER_ERR_BUFFER_FULL;
    
    memset(writer, 0, sizeof(DCFSerWriter));
    
    writer->buffer = buffer;
    writer->capacity = capacity;
    writer->owns_buffer = false;
    writer->msg_type = msg_type;
    writer->flags = flags;
    writer->position = sizeof(DCFSerHeader);
    
    return DCF_SER_OK;
}

void dcf_ser_writer_destroy(DCFSerWriter* writer) {
    if (writer && writer->owns_buffer && writer->buffer) {
        free(writer->buffer);
        writer->buffer = NULL;
        writer->capacity = 0;
        writer->position = 0;
    }
}

void dcf_ser_writer_reset(DCFSerWriter* writer, uint16_t msg_type, uint8_t flags) {
    if (!writer) return;
    
    writer->position = sizeof(DCFSerHeader);
    writer->depth = 0;
    writer->msg_type = msg_type;
    writer->flags = flags;
    writer->sequence = 0;
    writer->header_written = false;
    writer->last_error = DCF_SER_OK;
}

DCFSerError dcf_ser_writer_finish(DCFSerWriter* writer, const uint8_t** out_data, size_t* out_len) {
    if (!writer || !out_data || !out_len) return DCF_SER_ERR_NULL_PTR;
    
    /* A failed write, a second finish, or a destroyed writer: no frame. */
    DCFSerError st = writer_state(writer);
    if (st != DCF_SER_OK) return st;
    if (writer->position < sizeof(DCFSerHeader) || writer->position > writer->capacity) {
        return writer_fail(writer, DCF_SER_ERR_INTERNAL);
    }
    
    size_t payload_len = writer->position - sizeof(DCFSerHeader);
    if (payload_len > DCF_SER_MAX_MESSAGE) return writer_fail(writer, DCF_SER_ERR_TOO_LARGE);
    
    /* Write header at beginning */
    DCFSerHeader header;
    header.magic = dcf_ser_hton32(DCF_SER_MAGIC);
    header.version = dcf_ser_hton16(DCF_SER_VERSION);
    header.msg_type = dcf_ser_hton16(writer->msg_type);
    header.flags = writer->flags;
    header.payload_len = dcf_ser_hton32((uint32_t)payload_len);
    header.sequence = dcf_ser_hton32(writer->sequence);
    
    memcpy(writer->buffer, &header, sizeof(DCFSerHeader));
    
    /* Calculate and write CRC (unless disabled) */
    if (!(writer->flags & DCF_SER_FLAG_NO_CRC)) {
        DCFSerError e = writer_ensure(writer, 4, false);
        if (e != DCF_SER_OK) return e;
        uint32_t crc = dcf_ser_crc32(writer->buffer, writer->position);
        uint32_t crc_net = dcf_ser_hton32(crc);
        memcpy(writer->buffer + writer->position, &crc_net, 4);
        writer->position += 4;
    }
    
    writer->header_written = true;
    *out_data = writer->buffer;
    *out_len = writer->position;
    
    return DCF_SER_OK;
}

size_t dcf_ser_writer_payload_size(const DCFSerWriter* writer) {
    if (!writer || writer->position < sizeof(DCFSerHeader)) return 0;
    return writer->position - sizeof(DCFSerHeader);
}

void dcf_ser_writer_set_sequence(DCFSerWriter* writer, uint32_t seq) {
    if (writer) writer->sequence = seq;
}

/* ----------------------------------------------------------------------------
 * Primitive Writers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_write_null(DCFSerWriter* w) {
    WRITER_ENTER(w);
    return writer_put_u8(w, DCF_TYPE_NULL);
}

DCFSerError dcf_ser_write_bool(DCFSerWriter* w, bool val) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_BOOL));
    return writer_put_u8(w, val ? 1 : 0);
}

DCFSerError dcf_ser_write_u8(DCFSerWriter* w, uint8_t val) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_U8));
    return writer_put_u8(w, val);
}

DCFSerError dcf_ser_write_i8(DCFSerWriter* w, int8_t val) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_I8));
    return writer_put_u8(w, (uint8_t)val);
}

DCFSerError dcf_ser_write_u16(DCFSerWriter* w, uint16_t val) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_U16));
    return writer_put_u16(w, val);
}

DCFSerError dcf_ser_write_i16(DCFSerWriter* w, int16_t val) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_I16));
    return writer_put_u16(w, (uint16_t)val);
}

DCFSerError dcf_ser_write_u32(DCFSerWriter* w, uint32_t val) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_U32));
    return writer_put_u32(w, val);
}

DCFSerError dcf_ser_write_i32(DCFSerWriter* w, int32_t val) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_I32));
    return writer_put_u32(w, (uint32_t)val);
}

DCFSerError dcf_ser_write_u64(DCFSerWriter* w, uint64_t val) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_U64));
    return writer_put_u64(w, val);
}

DCFSerError dcf_ser_write_i64(DCFSerWriter* w, int64_t val) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_I64));
    return writer_put_u64(w, (uint64_t)val);
}

DCFSerError dcf_ser_write_f32(DCFSerWriter* w, float val) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_F32));
    uint32_t bits;
    memcpy(&bits, &val, sizeof(bits));
    return writer_put_u32(w, bits);
}

DCFSerError dcf_ser_write_f64(DCFSerWriter* w, double val) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_F64));
    uint64_t bits;
    memcpy(&bits, &val, sizeof(bits));
    return writer_put_u64(w, bits);
}

/* ----------------------------------------------------------------------------
 * Variable-Length Writers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_write_varint(DCFSerWriter* w, uint64_t val) {
    WRITER_ENTER(w);
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_VARINT));
    
    /* LEB128 encoding */
    do {
        uint8_t byte = (uint8_t)(val & 0x7F);
        val >>= 7;
        if (val != 0) byte |= 0x80;
        DCF_SER_CHECK(writer_put_u8(w, byte));
    } while (val != 0);
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_varsint(DCFSerWriter* w, int64_t val) {
    /* ZigZag encoding: (n << 1) ^ (n >> 63) */
    uint64_t zigzag = ((uint64_t)val << 1) ^ ((uint64_t)val >> 63);
    return dcf_ser_write_varint(w, zigzag);
}

DCFSerError dcf_ser_write_string(DCFSerWriter* w, const char* str) {
    WRITER_ENTER(w);
    size_t len = str ? strlen(str) : 0;
    return dcf_ser_write_string_n(w, str, len);
}

DCFSerError dcf_ser_write_string_n(DCFSerWriter* w, const char* str, size_t len) {
    WRITER_ENTER(w);
    if (len > DCF_SER_MAX_STRING) return writer_fail(w, DCF_SER_ERR_TOO_LARGE);
    if (len > 0 && !str) return writer_fail(w, DCF_SER_ERR_NULL_PTR);
    /* Strings are UTF-8 on the wire (use write_bytes for anything else). */
    if (len > 0 && !utf8_valid((const uint8_t*)str, len)) {
        return writer_fail(w, DCF_SER_ERR_MALFORMED);
    }
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_STRING));
    DCF_SER_CHECK(writer_put_u32(w, (uint32_t)len));
    
    if (len > 0) {
        WRITER_ENSURE_SPACE(w, len);
        memcpy(w->buffer + w->position, str, len);
        w->position += len;
    }
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_bytes(DCFSerWriter* w, const void* data, size_t len) {
    WRITER_ENTER(w);
    if (len > DCF_SER_MAX_MESSAGE) return writer_fail(w, DCF_SER_ERR_TOO_LARGE);
    if (len > 0 && !data) return writer_fail(w, DCF_SER_ERR_NULL_PTR);
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_BYTES));
    DCF_SER_CHECK(writer_put_u32(w, (uint32_t)len));
    
    if (len > 0) {
        WRITER_ENSURE_SPACE(w, len);
        memcpy(w->buffer + w->position, data, len);
        w->position += len;
    }
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_uuid(DCFSerWriter* w, const uint8_t uuid[16]) {
    WRITER_ENTER(w);
    if (!uuid) return writer_fail(w, DCF_SER_ERR_NULL_PTR);
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_UUID));
    WRITER_ENSURE_SPACE(w, 16);
    memcpy(w->buffer + w->position, uuid, 16);
    w->position += 16;
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_timestamp(DCFSerWriter* w, uint64_t timestamp_us) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_TIMESTAMP));
    return writer_put_u64(w, timestamp_us);
}

/* ----------------------------------------------------------------------------
 * Container Writers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_write_array_begin(DCFSerWriter* w, DCFSerType elem_type, size_t count) {
    WRITER_ENTER(w);
    if (count > DCF_SER_MAX_ARRAY) return writer_fail(w, DCF_SER_ERR_TOO_LARGE);
    if (w->depth >= DCF_SER_MAX_DEPTH) return writer_fail(w, DCF_SER_ERR_DEPTH_EXCEEDED);
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_ARRAY));
    DCF_SER_CHECK(writer_put_u8(w, (uint8_t)elem_type));
    DCF_SER_CHECK(writer_put_u32(w, (uint32_t)count));
    
    w->depth++;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_array_end(DCFSerWriter* w) {
    WRITER_ENTER(w);
    if (w->depth == 0) return writer_fail(w, DCF_SER_ERR_MALFORMED);
    w->depth--;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_map_begin(DCFSerWriter* w, DCFSerType key_type,
                                     DCFSerType val_type, size_t count) {
    WRITER_ENTER(w);
    if (count > DCF_SER_MAX_ARRAY) return writer_fail(w, DCF_SER_ERR_TOO_LARGE);
    if (w->depth >= DCF_SER_MAX_DEPTH) return writer_fail(w, DCF_SER_ERR_DEPTH_EXCEEDED);
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_MAP));
    DCF_SER_CHECK(writer_put_u8(w, (uint8_t)key_type));
    DCF_SER_CHECK(writer_put_u8(w, (uint8_t)val_type));
    DCF_SER_CHECK(writer_put_u32(w, (uint32_t)count));
    
    w->depth++;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_map_end(DCFSerWriter* w) {
    WRITER_ENTER(w);
    if (w->depth == 0) return writer_fail(w, DCF_SER_ERR_MALFORMED);
    w->depth--;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_struct_begin(DCFSerWriter* w, uint16_t type_id) {
    WRITER_ENTER(w);
    if (w->depth >= DCF_SER_MAX_DEPTH) return writer_fail(w, DCF_SER_ERR_DEPTH_EXCEEDED);
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_STRUCT));
    DCF_SER_CHECK(writer_put_u16(w, type_id));
    
    w->depth++;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_field(DCFSerWriter* w, uint16_t field_id, DCFSerType type) {
    WRITER_ENTER(w);
    DCF_SER_CHECK(writer_put_u16(w, field_id));
    DCF_SER_CHECK(writer_put_u8(w, (uint8_t)type));
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_struct_end(DCFSerWriter* w) {
    WRITER_ENTER(w);
    if (w->depth == 0) return writer_fail(w, DCF_SER_ERR_MALFORMED);
    
    /* Write end marker: field_id=0, type=NULL */
    DCF_SER_CHECK(writer_put_u16(w, 0));
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_NULL));
    
    w->depth--;
    return DCF_SER_OK;
}

/* ----------------------------------------------------------------------------
 * Raw/Direct Writers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_write_raw(DCFSerWriter* w, const void* data, size_t len) {
    WRITER_ENTER(w);
    if (len == 0) return DCF_SER_OK;
    if (!data) return writer_fail(w, DCF_SER_ERR_NULL_PTR);
    
    WRITER_ENSURE_SPACE(w, len);
    memcpy(w->buffer + w->position, data, len);
    w->position += len;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_reserve(DCFSerWriter* w, size_t len, uint8_t** out_ptr) {
    WRITER_ENTER(w);
    if (!out_ptr) return writer_fail(w, DCF_SER_ERR_NULL_PTR);
    
    WRITER_ENSURE_SPACE(w, len);
    *out_ptr = w->buffer + w->position;
    w->position += len;
    return DCF_SER_OK;
}

/* ============================================================================
 * Reader Internal Functions
 * ============================================================================ */

static DCFSerError reader_get_u8(DCFSerReader* r, uint8_t* out) {
    READER_ENSURE_BYTES(r, 1);
    *out = r->buffer[r->position++];
    return DCF_SER_OK;
}

static DCFSerError reader_get_u16(DCFSerReader* r, uint16_t* out) {
    READER_ENSURE_BYTES(r, 2);
    uint16_t net;
    memcpy(&net, r->buffer + r->position, 2);
    *out = dcf_ser_ntoh16(net);
    r->position += 2;
    return DCF_SER_OK;
}

static DCFSerError reader_get_u32(DCFSerReader* r, uint32_t* out) {
    READER_ENSURE_BYTES(r, 4);
    uint32_t net;
    memcpy(&net, r->buffer + r->position, 4);
    *out = dcf_ser_ntoh32(net);
    r->position += 4;
    return DCF_SER_OK;
}

static DCFSerError reader_get_u64(DCFSerReader* r, uint64_t* out) {
    READER_ENSURE_BYTES(r, 8);
    uint64_t net;
    memcpy(&net, r->buffer + r->position, 8);
    *out = dcf_ser_ntoh64(net);
    r->position += 8;
    return DCF_SER_OK;
}

static DCFSerError reader_expect_type(DCFSerReader* r, DCFSerType expected) {
    uint8_t type_byte;
    DCF_SER_CHECK(reader_get_u8(r, &type_byte));
    if ((DCFSerType)type_byte != expected) {
        r->last_error = DCF_SER_ERR_TYPE_MISMATCH;
        return DCF_SER_ERR_TYPE_MISMATCH;
    }
    return DCF_SER_OK;
}

/* ============================================================================
 * Structural walker (shared by dcf_ser_validate_payload and dcf_ser_reader_skip)
 *
 * This is the C reference for the payload grammar. The grammar is written down
 * in gate/README.md and in examples/dcfs_gate/README.md of the Exsecutor tree;
 * the Exsecutor gate (gate/dcfs_gate.gen.c) is an independent implementation of
 * the same grammar and the two are compared frame by frame.
 *
 *   payload := value*                                  (exactly payload_len bytes)
 *   value   := tag body
 *   NULL                                  no body
 *   BOOL U8 I8                            1 byte
 *   U16 I16                               2 bytes
 *   U32 I32 F32                           4 bytes
 *   U64 I64 F64 TIMESTAMP DURATION        8 bytes
 *   UUID                                  16 bytes
 *   VARINT    LEB128, 1..10 bytes; the 10th byte is <= 1; a multi-byte varint
 *             does not end in a 0x00 byte (canonical) unless the policy allows
 *   STRING    u32 len (<= DCF_SER_MAX_STRING), len bytes of UTF-8 (unless the
 *             policy allows anything)
 *   BYTES     u32 len, len bytes
 *   ARRAY     elem_type u8, u32 count (<= DCF_SER_MAX_ARRAY, <= bytes left),
 *             then count values
 *   MAP       key_type u8, val_type u8, u32 count (<= DCF_SER_MAX_ARRAY,
 *             2*count <= bytes left), then 2*count values
 *   STRUCT    u16 type_id, then fields until the end marker; a field is
 *             u16 id, u8 type, value; the end marker is id 0 with type NULL
 *   any other tag (TUPLE, OPTIONAL, ENUM, EXTENSION, unassigned): refused
 *   Containers nest to at most DCF_SER_MAX_DEPTH (including the reader's
 *   current typed-read depth when used by dcf_ser_reader_skip).
 *
 * Iterative with an explicit stack: no recursion, O(bytes) time, bounded stack.
 * Every step consumes at least one byte or pops a frame that a byte pushed.
 * ============================================================================ */

enum { WALK_SEQ = 1, WALK_STRUCT = 2 };

typedef struct {
    uint64_t remaining;     /* WALK_SEQ: values still to read */
    uint8_t  kind;
} WalkFrame;

/* Parses `payload := value*` (single=false) or exactly one value (single=true)
 * from buf[*pos_io, end). On success *pos_io is the first byte not consumed. */
static DCFSerError walk_values(const uint8_t* buf, size_t* pos_io, size_t end,
                               size_t base_depth, uint32_t policy, bool single) {
    WalkFrame stack[DCF_SER_MAX_DEPTH];
    size_t depth = 0;
    size_t pos = *pos_io;
    bool started = false;

    if (pos > end) return DCF_SER_ERR_TRUNCATED;
    if (base_depth > DCF_SER_MAX_DEPTH) return DCF_SER_ERR_DEPTH_EXCEEDED;
    const size_t room = DCF_SER_MAX_DEPTH - base_depth;     /* containers we may still open */

    for (;;) {
        /* What comes next? */
        if (depth == 0) {
            if (single ? started : (pos == end)) break;
            started = true;
        } else {
            WalkFrame* f = &stack[depth - 1];
            if (f->kind == WALK_STRUCT) {
                if (end - pos < 3) return DCF_SER_ERR_TRUNCATED;
                uint16_t id = rd_be16(buf + pos);
                uint8_t  ft = buf[pos + 2];
                pos += 3;
                if (id == 0 && ft == DCF_TYPE_NULL) { depth--; continue; }
            } else {
                if (f->remaining == 0) { depth--; continue; }
                f->remaining--;
            }
        }

        /* One value. */
        if (pos >= end) return DCF_SER_ERR_TRUNCATED;
        const uint8_t tag = buf[pos++];
        size_t fixed = 0;

        switch (tag) {
            case DCF_TYPE_NULL:
                break;
            case DCF_TYPE_BOOL:
            case DCF_TYPE_U8:
            case DCF_TYPE_I8:
                fixed = 1;
                break;
            case DCF_TYPE_U16:
            case DCF_TYPE_I16:
                fixed = 2;
                break;
            case DCF_TYPE_U32:
            case DCF_TYPE_I32:
            case DCF_TYPE_F32:
                fixed = 4;
                break;
            case DCF_TYPE_U64:
            case DCF_TYPE_I64:
            case DCF_TYPE_F64:
            case DCF_TYPE_TIMESTAMP:
            case DCF_TYPE_DURATION:
                fixed = 8;
                break;
            case DCF_TYPE_UUID:
                fixed = 16;
                break;

            case DCF_TYPE_VARINT: {
                unsigned count = 0;
                uint8_t b;
                for (;;) {
                    if (pos >= end) return DCF_SER_ERR_TRUNCATED;
                    b = buf[pos++];
                    count++;
                    /* A 10th byte above 1 would carry bits past bit 63. */
                    if (count == 10 && b > 1) return DCF_SER_ERR_OVERFLOW;
                    if (!(b & 0x80)) break;
                }
                if (count >= 2 && b == 0 && !(policy & DCF_SER_POLICY_ALLOW_NONCANONICAL_VARINT)) {
                    return DCF_SER_ERR_MALFORMED;
                }
                break;
            }

            case DCF_TYPE_STRING:
            case DCF_TYPE_BYTES: {
                if (end - pos < 4) return DCF_SER_ERR_TRUNCATED;
                uint32_t len = rd_be32(buf + pos);
                pos += 4;
                if (tag == DCF_TYPE_STRING && len > DCF_SER_MAX_STRING) return DCF_SER_ERR_TOO_LARGE;
                if (len > end - pos) return DCF_SER_ERR_TRUNCATED;
                if (tag == DCF_TYPE_STRING && !(policy & DCF_SER_POLICY_ALLOW_INVALID_UTF8) &&
                    !utf8_valid(buf + pos, len)) {
                    return DCF_SER_ERR_MALFORMED;
                }
                pos += len;
                break;
            }

            case DCF_TYPE_ARRAY: {
                if (end - pos < 5) return DCF_SER_ERR_TRUNCATED;
                uint32_t count = rd_be32(buf + pos + 1);       /* buf[pos] is elem_type */
                pos += 5;
                if (count > DCF_SER_MAX_ARRAY) return DCF_SER_ERR_TOO_LARGE;
                if (count > end - pos) return DCF_SER_ERR_TRUNCATED;   /* each element is >= 1 byte */
                if (depth >= room) return DCF_SER_ERR_DEPTH_EXCEEDED;
                stack[depth].kind = WALK_SEQ;
                stack[depth].remaining = count;
                depth++;
                break;
            }

            case DCF_TYPE_MAP: {
                if (end - pos < 6) return DCF_SER_ERR_TRUNCATED;
                uint32_t count = rd_be32(buf + pos + 2);       /* key_type, val_type, then count */
                pos += 6;
                if (count > DCF_SER_MAX_ARRAY) return DCF_SER_ERR_TOO_LARGE;
                if ((uint64_t)count * 2 > end - pos) return DCF_SER_ERR_TRUNCATED;
                if (depth >= room) return DCF_SER_ERR_DEPTH_EXCEEDED;
                stack[depth].kind = WALK_SEQ;
                stack[depth].remaining = (uint64_t)count * 2;
                depth++;
                break;
            }

            case DCF_TYPE_STRUCT: {
                if (end - pos < 2) return DCF_SER_ERR_TRUNCATED;
                pos += 2;                                      /* type_id */
                if (depth >= room) return DCF_SER_ERR_DEPTH_EXCEEDED;
                stack[depth].kind = WALK_STRUCT;
                stack[depth].remaining = 0;
                depth++;
                break;
            }

            default:
                return DCF_SER_ERR_INVALID_TYPE;
        }

        if (fixed) {
            if (end - pos < fixed) return DCF_SER_ERR_TRUNCATED;
            pos += fixed;
        }
    }

    *pos_io = pos;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_validate_payload(const void* payload, size_t len, uint32_t policy) {
    if (!payload && len > 0) return DCF_SER_ERR_NULL_PTR;
    if (policy & ~DCF_SER_POLICY_ALL) return DCF_SER_ERR_INVALID_ARG;
    if (len > DCF_SER_MAX_MESSAGE) return DCF_SER_ERR_TOO_LARGE;
    size_t pos = 0;
    return walk_values((const uint8_t*)payload, &pos, len, 0, policy, false);
}

/* ============================================================================
 * Gate (Exsecutor-generated admission check, run in addition to the C checks)
 * ============================================================================ */

static uint64_t g_gate_disagreements = 0;

#ifndef DCF_SER_NO_GATE
static void gate_count_disagreement(void) {
#if defined(__GNUC__) || defined(__clang__)
    __atomic_fetch_add(&g_gate_disagreements, 1, __ATOMIC_RELAXED);
#else
    g_gate_disagreements++;
#endif
}
#endif

uint64_t dcf_ser_gate_disagreements(void) {
#if defined(__GNUC__) || defined(__clang__)
    return __atomic_load_n(&g_gate_disagreements, __ATOMIC_RELAXED);
#else
    return g_gate_disagreements;
#endif
}

#ifndef DCF_SER_NO_GATE
/* Called only after every C check has accepted `frame` (exactly one frame, CRC
 * included). The gate must agree. A gate that rejects what C accepted, or that
 * traps, is a bug in one of the two: the frame is refused and the event counted. */
static DCFSerError gate_confirm(const uint8_t* frame, size_t frame_len) {
    DcfsGateResult res = dcfs_gate_judge(frame, frame_len, NULL);
    if (res == DCFS_GATE_ADMIT) return DCF_SER_OK;
    gate_count_disagreement();
    return DCF_SER_ERR_INTERNAL;
}
#endif

/* ============================================================================
 * Reader API Implementation
 * ============================================================================ */

DCFSerError dcf_ser_reader_init(DCFSerReader* reader, const void* data, size_t len) {
    if (!reader) return DCF_SER_ERR_NULL_PTR;
    
    /* Always leave a fully zeroed (strict, empty, unvalidated) reader behind,
     * even when we refuse, so a caller that ignores the result cannot walk
     * garbage. */
    memset(reader, 0, sizeof(DCFSerReader));
    if (!data) return DCF_SER_ERR_NULL_PTR;
    if (len < sizeof(DCFSerHeader)) return DCF_SER_ERR_TRUNCATED;
    
    reader->buffer = (const uint8_t*)data;
    reader->length = len;
    reader->position = 0;
    reader->policy = DCF_SER_POLICY_STRICT;
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_reader_set_policy(DCFSerReader* reader, uint32_t policy) {
    if (!reader) return DCF_SER_ERR_NULL_PTR;
    if (policy & ~DCF_SER_POLICY_ALL) return DCF_SER_ERR_INVALID_ARG;      /* unknown bit: fail closed */
    if (reader->header_valid) return DCF_SER_ERR_INVALID_ARG;              /* frozen once validated */
    reader->policy = policy;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_reader_validate(DCFSerReader* reader) {
    if (!reader) return DCF_SER_ERR_NULL_PTR;
    reader->header_valid = false;
    reader->crc_verified = false;
    reader->payload_start = 0;
    reader->payload_end = 0;
    reader->position = 0;
    if (!reader->buffer || reader->length < sizeof(DCFSerHeader)) {
        reader->last_error = DCF_SER_ERR_TRUNCATED;
        return DCF_SER_ERR_TRUNCATED;
    }
    
    const uint32_t policy = reader->policy;
    const uint8_t* h = reader->buffer;
    
    /* Parse header (byte-wise: no unaligned or aliasing struct cast) */
    reader->header.magic = rd_be32(h);
    reader->header.version = rd_be16(h + 4);
    reader->header.msg_type = rd_be16(h + 6);
    reader->header.flags = h[8];
    reader->header.payload_len = rd_be32(h + 9);
    reader->header.sequence = rd_be32(h + 13);
    
    /* Validate magic */
    if (reader->header.magic != DCF_SER_MAGIC) {
        reader->last_error = DCF_SER_ERR_INVALID_MAGIC;
        return DCF_SER_ERR_INVALID_MAGIC;
    }
    
    /* Check version compatibility (major version must match) */
    uint16_t major = (uint16_t)(reader->header.version >> 8);
    uint16_t our_major = (uint16_t)(DCF_SER_VERSION >> 8);
    if (major != our_major) {
        reader->last_error = DCF_SER_ERR_VERSION_MISMATCH;
        return DCF_SER_ERR_VERSION_MISMATCH;
    }
    
    /* Flags. EXTENDED and the reserved bit change the framing and this reader
     * cannot honour them: never accepted. COMPRESSED / ENCRYPTED are not
     * interpreted here; they are accepted only when the application says it
     * handles them. NO_CRC removes the only integrity check: opt-in. */
    const uint8_t flags = reader->header.flags;
    if (flags & (DCF_SER_FLAG_EXTENDED | DCF_SER_FLAG_RESERVED)) {
        reader->last_error = DCF_SER_ERR_POLICY;
        return DCF_SER_ERR_POLICY;
    }
    if ((flags & (DCF_SER_FLAG_COMPRESSED | DCF_SER_FLAG_ENCRYPTED)) &&
        !(policy & DCF_SER_POLICY_ALLOW_APP_FLAGS)) {
        reader->last_error = DCF_SER_ERR_POLICY;
        return DCF_SER_ERR_POLICY;
    }
    const bool no_crc = (flags & DCF_SER_FLAG_NO_CRC) != 0;
    if (no_crc && !(policy & DCF_SER_POLICY_ALLOW_NO_CRC)) {
        reader->last_error = DCF_SER_ERR_POLICY;
        return DCF_SER_ERR_POLICY;
    }
    
    /* Length. Capped before any arithmetic on it. */
    if (reader->header.payload_len > DCF_SER_MAX_MESSAGE) {
        reader->last_error = DCF_SER_ERR_TOO_LARGE;
        return DCF_SER_ERR_TOO_LARGE;
    }
    const size_t payload_len = reader->header.payload_len;
    const size_t crc_offset = sizeof(DCFSerHeader) + payload_len;
    const size_t expected_size = crc_offset + (no_crc ? 0 : 4);
    
    if (reader->length < expected_size) {
        reader->last_error = DCF_SER_ERR_TRUNCATED;
        return DCF_SER_ERR_TRUNCATED;
    }
    if (reader->length > expected_size && !(policy & DCF_SER_POLICY_ALLOW_TRAILING)) {
        /* Bytes after the frame: two readers could disagree on where it ends. */
        reader->last_error = DCF_SER_ERR_POLICY;
        return DCF_SER_ERR_POLICY;
    }
    
    /* Verify CRC if present */
    if (!no_crc) {
        uint32_t stored_crc = rd_be32(reader->buffer + crc_offset);
        uint32_t computed_crc = dcf_ser_crc32(reader->buffer, crc_offset);
        
        if (stored_crc != computed_crc) {
            reader->last_error = DCF_SER_ERR_CRC_MISMATCH;
            return DCF_SER_ERR_CRC_MISMATCH;
        }
    }
    
    /* The payload must be a clean sequence of tagged values. */
    if (!(policy & DCF_SER_POLICY_ALLOW_UNSTRUCTURED)) {
        size_t pos = 0;
        DCFSerError e = walk_values(reader->buffer + sizeof(DCFSerHeader), &pos, payload_len,
                                    0, policy, false);
        if (e != DCF_SER_OK) {
            reader->last_error = e;
            return e;
        }
    }
    
#ifndef DCF_SER_NO_GATE
    /* Second, independent opinion on the whole frame. It encodes the fully
     * strict policy, so it is consulted only when the policy asks for nothing
     * beyond that; trailing bytes are cut off before it sees the frame. */
    if (!(policy & (DCF_SER_POLICY_NO_GATE | DCF_SER_POLICY_ALLOW_NO_CRC |
                    DCF_SER_POLICY_ALLOW_NONCANONICAL_VARINT | DCF_SER_POLICY_ALLOW_INVALID_UTF8 |
                    DCF_SER_POLICY_ALLOW_UNSTRUCTURED | DCF_SER_POLICY_ALLOW_APP_FLAGS))) {
        DCFSerError e = gate_confirm(reader->buffer, expected_size);
        if (e != DCF_SER_OK) {
            reader->last_error = e;
            return e;
        }
    }
#endif
    
    /* Set up payload bounds */
    reader->crc_verified = !no_crc;
    reader->payload_start = sizeof(DCFSerHeader);
    reader->payload_end = crc_offset;
    reader->position = reader->payload_start;
    reader->header_valid = true;
    
    return DCF_SER_OK;
}

const DCFSerHeader* dcf_ser_reader_header(const DCFSerReader* reader) {
    return (reader && reader->header_valid) ? &reader->header : NULL;
}

uint16_t dcf_ser_reader_msg_type(const DCFSerReader* reader) {
    return (reader && reader->header_valid) ? reader->header.msg_type : 0;
}

size_t dcf_ser_reader_remaining(const DCFSerReader* reader) {
    if (!reader || !reader->header_valid) return 0;
    if (reader->position > reader->payload_end) return 0;
    return reader->payload_end - reader->position;
}

bool dcf_ser_reader_at_end(const DCFSerReader* reader) {
    return !reader || !reader->header_valid || reader->position >= reader->payload_end;
}

DCFSerType dcf_ser_reader_peek_type(const DCFSerReader* reader) {
    if (!reader || !reader->header_valid || reader->position >= reader->payload_end) {
        return DCF_TYPE_INVALID;
    }
    return (DCFSerType)reader->buffer[reader->position];
}

DCFSerError dcf_ser_reader_skip(DCFSerReader* reader) {
    if (!reader) return DCF_SER_ERR_NULL_PTR;
    if (!reader->header_valid) return DCF_SER_ERR_INVALID_ARG;
    
    /* All-or-nothing: position moves only if one whole value was skipped, and
     * never past payload_end. */
    size_t pos = reader->position;
    DCFSerError e = walk_values(reader->buffer, &pos, reader->payload_end,
                                reader->depth, reader->policy, true);
    if (e != DCF_SER_OK) {
        reader->last_error = e;
        return e;
    }
    reader->position = pos;
    return DCF_SER_OK;
}

/* ----------------------------------------------------------------------------
 * Primitive Readers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_read_null(DCFSerReader* r) {
    return reader_expect_type(r, DCF_TYPE_NULL);
}

DCFSerError dcf_ser_read_bool(DCFSerReader* r, bool* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_BOOL));
    uint8_t val;
    DCF_SER_CHECK(reader_get_u8(r, &val));
    *out = (val != 0);
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_u8(DCFSerReader* r, uint8_t* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_U8));
    return reader_get_u8(r, out);
}

DCFSerError dcf_ser_read_i8(DCFSerReader* r, int8_t* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_I8));
    return reader_get_u8(r, (uint8_t*)out);
}

DCFSerError dcf_ser_read_u16(DCFSerReader* r, uint16_t* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_U16));
    return reader_get_u16(r, out);
}

DCFSerError dcf_ser_read_i16(DCFSerReader* r, int16_t* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_I16));
    return reader_get_u16(r, (uint16_t*)out);
}

DCFSerError dcf_ser_read_u32(DCFSerReader* r, uint32_t* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_U32));
    return reader_get_u32(r, out);
}

DCFSerError dcf_ser_read_i32(DCFSerReader* r, int32_t* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_I32));
    return reader_get_u32(r, (uint32_t*)out);
}

DCFSerError dcf_ser_read_u64(DCFSerReader* r, uint64_t* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_U64));
    return reader_get_u64(r, out);
}

DCFSerError dcf_ser_read_i64(DCFSerReader* r, int64_t* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_I64));
    return reader_get_u64(r, (uint64_t*)out);
}

DCFSerError dcf_ser_read_f32(DCFSerReader* r, float* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_F32));
    uint32_t bits;
    DCF_SER_CHECK(reader_get_u32(r, &bits));
    memcpy(out, &bits, sizeof(*out));
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_f64(DCFSerReader* r, double* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_F64));
    uint64_t bits;
    DCF_SER_CHECK(reader_get_u64(r, &bits));
    memcpy(out, &bits, sizeof(*out));
    return DCF_SER_OK;
}

/* ----------------------------------------------------------------------------
 * Variable-Length Readers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_read_varint(DCFSerReader* r, uint64_t* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_VARINT));
    
    uint64_t result = 0;
    unsigned count = 0;
    uint8_t b;
    
    do {
        DCF_SER_CHECK(reader_get_u8(r, &b));
        count++;
        /* The 10th byte carries bit 63 only: anything above 1 would be shifted
         * out and the caller would silently get a different number. Never
         * allowed, whatever the policy. */
        if (count == 10 && b > 1) {
            r->last_error = DCF_SER_ERR_OVERFLOW;
            return DCF_SER_ERR_OVERFLOW;
        }
        result |= (uint64_t)(b & 0x7F) << (7 * (count - 1));
    } while (b & 0x80);
    
    /* Canonical form: the same number has exactly one encoding. */
    if (count >= 2 && b == 0 && !(r->policy & DCF_SER_POLICY_ALLOW_NONCANONICAL_VARINT)) {
        r->last_error = DCF_SER_ERR_MALFORMED;
        return DCF_SER_ERR_MALFORMED;
    }
    
    *out = result;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_varsint(DCFSerReader* r, int64_t* out) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    
    uint64_t zigzag;
    DCF_SER_CHECK(dcf_ser_read_varint(r, &zigzag));
    
    /* ZigZag decoding */
    *out = (int64_t)((zigzag >> 1) ^ -(int64_t)(zigzag & 1));
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_string(DCFSerReader* r, const char** out_str, size_t* out_len) {
    if (!r || !out_str || !out_len) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_STRING));
    
    uint32_t len;
    DCF_SER_CHECK(reader_get_u32(r, &len));
    
    if (len > DCF_SER_MAX_STRING) {
        r->last_error = DCF_SER_ERR_TOO_LARGE;
        return DCF_SER_ERR_TOO_LARGE;
    }
    READER_ENSURE_BYTES(r, len);
    
    if (!(r->policy & DCF_SER_POLICY_ALLOW_INVALID_UTF8) &&
        !utf8_valid(r->buffer + r->position, len)) {
        r->last_error = DCF_SER_ERR_MALFORMED;
        return DCF_SER_ERR_MALFORMED;
    }
    
    *out_str = (const char*)(r->buffer + r->position);
    *out_len = len;
    r->position += len;
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_string_copy(DCFSerReader* r, char* buf, size_t buf_size, size_t* out_len) {
    if (!r || !buf || !out_len) return DCF_SER_ERR_NULL_PTR;
    
    const char* str;
    size_t len;
    DCF_SER_CHECK(dcf_ser_read_string(r, &str, &len));
    
    if (len >= buf_size) {
        *out_len = len;
        return DCF_SER_ERR_OVERFLOW;
    }
    
    /* The result is a C string: an embedded NUL would silently truncate it. */
    if (len > 0 && memchr(str, '\0', len) != NULL) {
        r->last_error = DCF_SER_ERR_MALFORMED;
        return DCF_SER_ERR_MALFORMED;
    }
    
    if (len > 0) memcpy(buf, str, len);
    buf[len] = '\0';
    *out_len = len;
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_bytes(DCFSerReader* r, const void** out_data, size_t* out_len) {
    if (!r || !out_data || !out_len) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_BYTES));
    
    uint32_t len;
    DCF_SER_CHECK(reader_get_u32(r, &len));
    
    READER_ENSURE_BYTES(r, len);
    
    *out_data = r->buffer + r->position;
    *out_len = len;
    r->position += len;
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_bytes_copy(DCFSerReader* r, void* buf, size_t buf_size, size_t* out_len) {
    if (!r || !buf || !out_len) return DCF_SER_ERR_NULL_PTR;
    
    const void* data;
    size_t len;
    DCF_SER_CHECK(dcf_ser_read_bytes(r, &data, &len));
    
    if (len > buf_size) {
        *out_len = len;
        return DCF_SER_ERR_OVERFLOW;
    }
    
    memcpy(buf, data, len);
    *out_len = len;
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_uuid(DCFSerReader* r, uint8_t out_uuid[16]) {
    if (!r || !out_uuid) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_UUID));
    
    READER_ENSURE_BYTES(r, 16);
    memcpy(out_uuid, r->buffer + r->position, 16);
    r->position += 16;
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_timestamp(DCFSerReader* r, uint64_t* out_us) {
    if (!r || !out_us) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_TIMESTAMP));
    return reader_get_u64(r, out_us);
}

/* ----------------------------------------------------------------------------
 * Container Readers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_read_array_begin(DCFSerReader* r, DCFSerType* out_elem_type, size_t* out_count) {
    if (!r || !out_elem_type || !out_count) return DCF_SER_ERR_NULL_PTR;
    if (r->depth >= DCF_SER_MAX_DEPTH) return DCF_SER_ERR_DEPTH_EXCEEDED;
    
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_ARRAY));
    
    uint8_t elem_type;
    uint32_t count;
    DCF_SER_CHECK(reader_get_u8(r, &elem_type));
    DCF_SER_CHECK(reader_get_u32(r, &count));
    
    /* A count the payload cannot hold (each element is at least one byte) or
     * above the documented cap is a lie, whatever the caller does with it next
     * (typically malloc(count * size)). */
    if (count > DCF_SER_MAX_ARRAY) {
        r->last_error = DCF_SER_ERR_TOO_LARGE;
        return DCF_SER_ERR_TOO_LARGE;
    }
    if (count > dcf_ser_reader_remaining(r)) {
        r->last_error = DCF_SER_ERR_TRUNCATED;
        return DCF_SER_ERR_TRUNCATED;
    }
    
    *out_elem_type = (DCFSerType)elem_type;
    *out_count = count;
    r->depth++;
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_array_end(DCFSerReader* r) {
    if (!r) return DCF_SER_ERR_NULL_PTR;
    if (r->depth == 0) return DCF_SER_ERR_MALFORMED;
    r->depth--;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_map_begin(DCFSerReader* r, DCFSerType* out_key_type,
                                    DCFSerType* out_val_type, size_t* out_count) {
    if (!r || !out_key_type || !out_val_type || !out_count) return DCF_SER_ERR_NULL_PTR;
    if (r->depth >= DCF_SER_MAX_DEPTH) return DCF_SER_ERR_DEPTH_EXCEEDED;
    
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_MAP));
    
    uint8_t key_type, val_type;
    uint32_t count;
    DCF_SER_CHECK(reader_get_u8(r, &key_type));
    DCF_SER_CHECK(reader_get_u8(r, &val_type));
    DCF_SER_CHECK(reader_get_u32(r, &count));
    
    if (count > DCF_SER_MAX_ARRAY) {
        r->last_error = DCF_SER_ERR_TOO_LARGE;
        return DCF_SER_ERR_TOO_LARGE;
    }
    if ((uint64_t)count * 2 > dcf_ser_reader_remaining(r)) {    /* key and value: >= 1 byte each */
        r->last_error = DCF_SER_ERR_TRUNCATED;
        return DCF_SER_ERR_TRUNCATED;
    }
    
    *out_key_type = (DCFSerType)key_type;
    *out_val_type = (DCFSerType)val_type;
    *out_count = count;
    r->depth++;
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_map_end(DCFSerReader* r) {
    if (!r) return DCF_SER_ERR_NULL_PTR;
    if (r->depth == 0) return DCF_SER_ERR_MALFORMED;
    r->depth--;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_struct_begin(DCFSerReader* r, uint16_t* out_type_id) {
    if (!r || !out_type_id) return DCF_SER_ERR_NULL_PTR;
    if (r->depth >= DCF_SER_MAX_DEPTH) return DCF_SER_ERR_DEPTH_EXCEEDED;
    
    DCF_SER_CHECK(reader_expect_type(r, DCF_TYPE_STRUCT));
    DCF_SER_CHECK(reader_get_u16(r, out_type_id));
    
    r->depth++;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_field(DCFSerReader* r, uint16_t* out_field_id, DCFSerType* out_type) {
    if (!r || !out_field_id || !out_type) return DCF_SER_ERR_NULL_PTR;
    
    DCF_SER_CHECK(reader_get_u16(r, out_field_id));
    
    uint8_t type_byte;
    DCF_SER_CHECK(reader_get_u8(r, &type_byte));
    *out_type = (DCFSerType)type_byte;
    
    /* Check for end marker */
    if (*out_field_id == 0 && *out_type == DCF_TYPE_NULL) {
        return DCF_SER_ERR_NOT_FOUND;
    }
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_struct_end(DCFSerReader* r) {
    if (!r) return DCF_SER_ERR_NULL_PTR;
    if (r->depth == 0) return DCF_SER_ERR_MALFORMED;
    r->depth--;
    return DCF_SER_OK;
}

/* ----------------------------------------------------------------------------
 * Raw/Direct Readers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_read_raw(DCFSerReader* r, void* out, size_t len) {
    if (!r || !out) return DCF_SER_ERR_NULL_PTR;
    READER_ENSURE_BYTES(r, len);
    memcpy(out, r->buffer + r->position, len);
    r->position += len;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_raw_ptr(DCFSerReader* r, const void** out_ptr, size_t len) {
    if (!r || !out_ptr) return DCF_SER_ERR_NULL_PTR;
    READER_ENSURE_BYTES(r, len);
    *out_ptr = r->buffer + r->position;
    r->position += len;
    return DCF_SER_OK;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

const char* dcf_ser_error_str(DCFSerError err) {
    switch (err) {
        case DCF_SER_OK:                  return "Success";
        case DCF_SER_ERR_BUFFER_FULL:     return "Buffer full";
        case DCF_SER_ERR_ALLOC_FAIL:      return "Allocation failed";
        case DCF_SER_ERR_TOO_LARGE:       return "Data too large";
        case DCF_SER_ERR_DEPTH_EXCEEDED:  return "Max nesting depth exceeded";
        case DCF_SER_ERR_INVALID_MAGIC:   return "Invalid magic number";
        case DCF_SER_ERR_VERSION_MISMATCH:return "Protocol version mismatch";
        case DCF_SER_ERR_TRUNCATED:       return "Truncated message";
        case DCF_SER_ERR_CRC_MISMATCH:    return "CRC checksum mismatch";
        case DCF_SER_ERR_INVALID_TYPE:    return "Invalid type tag";
        case DCF_SER_ERR_OVERFLOW:        return "Value overflow";
        case DCF_SER_ERR_MALFORMED:       return "Malformed data";
        case DCF_SER_ERR_POLICY:          return "Rejected by reader policy";
        case DCF_SER_ERR_NULL_PTR:        return "Null pointer";
        case DCF_SER_ERR_INVALID_ARG:     return "Invalid argument";
        case DCF_SER_ERR_INTERNAL:        return "Internal error";
        case DCF_SER_ERR_NOT_FOUND:       return "Not found";
        case DCF_SER_ERR_TYPE_MISMATCH:   return "Type mismatch";
        default:                          return "Unknown error";
    }
}

const char* dcf_ser_type_str(DCFSerType type) {
    switch (type) {
        case DCF_TYPE_NULL:       return "null";
        case DCF_TYPE_BOOL:       return "bool";
        case DCF_TYPE_U8:         return "u8";
        case DCF_TYPE_I8:         return "i8";
        case DCF_TYPE_U16:        return "u16";
        case DCF_TYPE_I16:        return "i16";
        case DCF_TYPE_U32:        return "u32";
        case DCF_TYPE_I32:        return "i32";
        case DCF_TYPE_U64:        return "u64";
        case DCF_TYPE_I64:        return "i64";
        case DCF_TYPE_F32:        return "f32";
        case DCF_TYPE_F64:        return "f64";
        case DCF_TYPE_VARINT:     return "varint";
        case DCF_TYPE_STRING:     return "string";
        case DCF_TYPE_BYTES:      return "bytes";
        case DCF_TYPE_UUID:       return "uuid";
        case DCF_TYPE_ARRAY:      return "array";
        case DCF_TYPE_MAP:        return "map";
        case DCF_TYPE_STRUCT:     return "struct";
        case DCF_TYPE_TUPLE:      return "tuple";
        case DCF_TYPE_TIMESTAMP:  return "timestamp";
        case DCF_TYPE_DURATION:   return "duration";
        case DCF_TYPE_OPTIONAL:   return "optional";
        case DCF_TYPE_ENUM:       return "enum";
        case DCF_TYPE_EXTENSION:  return "extension";
        case DCF_TYPE_INVALID:    return "invalid";
        default:                  return "unknown";
    }
}

size_t dcf_ser_type_size(DCFSerType type) {
    switch (type) {
        case DCF_TYPE_NULL:       return 0;
        case DCF_TYPE_BOOL:
        case DCF_TYPE_U8:
        case DCF_TYPE_I8:         return 1;
        case DCF_TYPE_U16:
        case DCF_TYPE_I16:        return 2;
        case DCF_TYPE_U32:
        case DCF_TYPE_I32:
        case DCF_TYPE_F32:        return 4;
        case DCF_TYPE_U64:
        case DCF_TYPE_I64:
        case DCF_TYPE_F64:
        case DCF_TYPE_TIMESTAMP:
        case DCF_TYPE_DURATION:   return 8;
        case DCF_TYPE_UUID:       return 16;
        default:                  return 0;  /* Variable-length */
    }
}

DCFSerError dcf_ser_validate_message(const void* data, size_t len) {
    /* Always the strict (default) policy. A caller that needs to relax it
     * uses a reader and dcf_ser_reader_set_policy(). */
    DCFSerReader reader;
    DCFSerError err = dcf_ser_reader_init(&reader, data, len);
    if (err != DCF_SER_OK) return err;
    return dcf_ser_reader_validate(&reader);
}

DCFSerError dcf_ser_message_length_checked(const void* data, size_t avail, size_t* out_total) {
    if (!data || !out_total) return DCF_SER_ERR_NULL_PTR;
    if (avail < DCF_SER_HEADER_SIZE) return DCF_SER_ERR_TRUNCATED;
    
    const uint8_t* h = (const uint8_t*)data;
    if (rd_be32(h) != DCF_SER_MAGIC) return DCF_SER_ERR_INVALID_MAGIC;
    if ((rd_be16(h + 4) >> 8) != (DCF_SER_VERSION >> 8)) return DCF_SER_ERR_VERSION_MISMATCH;
    
    uint32_t payload_len = rd_be32(h + 9);
    if (payload_len > DCF_SER_MAX_MESSAGE) return DCF_SER_ERR_TOO_LARGE;
    
    size_t total = (size_t)DCF_SER_HEADER_SIZE + payload_len;
    if (!(h[8] & DCF_SER_FLAG_NO_CRC)) total += 4;      /* CRC32 */
    
    *out_total = total;
    return DCF_SER_OK;
}

size_t dcf_ser_message_length(const void* header_data) {
    /* Deprecated: no length argument, so it reads DCF_SER_HEADER_SIZE bytes on
     * the caller's word. It now at least refuses what the checked variant
     * refuses (returning 0) instead of handing a 4 GiB size to a malloc(). */
    size_t total = 0;
    if (!header_data) return 0;
    if (dcf_ser_message_length_checked(header_data, DCF_SER_HEADER_SIZE, &total) != DCF_SER_OK) return 0;
    return total;
}

/* ============================================================================
 * Schema-Based Serialization
 * ============================================================================ */

/* Size of the C object a schema field of this type points at, or 0 if the type
 * cannot be carried by a schema. STRING is a `const char*`. */
static size_t schema_field_size(DCFSerType type) {
    switch (type) {
        case DCF_TYPE_BOOL: case DCF_TYPE_U8: case DCF_TYPE_I8:
        case DCF_TYPE_U16: case DCF_TYPE_I16:
        case DCF_TYPE_U32: case DCF_TYPE_I32: case DCF_TYPE_F32:
        case DCF_TYPE_U64: case DCF_TYPE_I64: case DCF_TYPE_F64:
        case DCF_TYPE_TIMESTAMP:
            return dcf_ser_type_size(type);
        case DCF_TYPE_STRING:
            return sizeof(const char*);
        default:
            return 0;
    }
}

/* A schema is trusted code, but a wrong one must not become a wire-driven
 * overflow: every field has to be the size its type implies and lie wholly
 * inside the struct. `for_read` refuses STRING (see read_struct_schema). */
static DCFSerError schema_check(const DCFSerSchema* schema, bool for_read) {
    if (schema->field_count > DCF_SER_MAX_SCHEMA_FIELDS) return DCF_SER_ERR_INVALID_ARG;
    if (schema->field_count > 0 && !schema->fields) return DCF_SER_ERR_NULL_PTR;
    for (size_t i = 0; i < schema->field_count; i++) {
        const DCFSerField* f = &schema->fields[i];
        size_t want = schema_field_size(f->type);
        if (want == 0) return DCF_SER_ERR_INVALID_TYPE;
        if (for_read && f->type == DCF_TYPE_STRING) return DCF_SER_ERR_INVALID_TYPE;
        if (f->size != want) return DCF_SER_ERR_INVALID_ARG;
        if (f->offset > schema->struct_size || f->size > schema->struct_size - f->offset) {
            return DCF_SER_ERR_INVALID_ARG;
        }
    }
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_struct_schema(DCFSerWriter* w, const void* data,
                                         const DCFSerSchema* schema) {
    if (!w || !data || !schema) return DCF_SER_ERR_NULL_PTR;
    WRITER_ENTER(w);
    {
        DCFSerError e = schema_check(schema, false);
        if (e != DCF_SER_OK) return writer_fail(w, e);
    }
    
    DCF_SER_CHECK(dcf_ser_write_struct_begin(w, schema->type_id));
    
    for (size_t i = 0; i < schema->field_count; i++) {
        const DCFSerField* field = &schema->fields[i];
        const uint8_t* field_data = (const uint8_t*)data + field->offset;
        
        /* Write field header */
        DCF_SER_CHECK(dcf_ser_write_field(w, field->field_id, field->type));
        
        /* Write field value based on type. Loads go through memcpy: the
         * offset need not be aligned for the type (packed structs). */
        switch (field->type) {
            case DCF_TYPE_BOOL: {
                uint8_t val = *field_data;
                DCF_SER_CHECK(dcf_ser_write_bool(w, val != 0));
                break;
            }
            case DCF_TYPE_U8:
                DCF_SER_CHECK(dcf_ser_write_u8(w, *field_data));
                break;
            case DCF_TYPE_I8: {
                int8_t val;
                memcpy(&val, field_data, sizeof val);
                DCF_SER_CHECK(dcf_ser_write_i8(w, val));
                break;
            }
            case DCF_TYPE_U16: {
                uint16_t val;
                memcpy(&val, field_data, sizeof val);
                DCF_SER_CHECK(dcf_ser_write_u16(w, val));
                break;
            }
            case DCF_TYPE_I16: {
                int16_t val;
                memcpy(&val, field_data, sizeof val);
                DCF_SER_CHECK(dcf_ser_write_i16(w, val));
                break;
            }
            case DCF_TYPE_U32: {
                uint32_t val;
                memcpy(&val, field_data, sizeof val);
                DCF_SER_CHECK(dcf_ser_write_u32(w, val));
                break;
            }
            case DCF_TYPE_I32: {
                int32_t val;
                memcpy(&val, field_data, sizeof val);
                DCF_SER_CHECK(dcf_ser_write_i32(w, val));
                break;
            }
            case DCF_TYPE_U64: {
                uint64_t val;
                memcpy(&val, field_data, sizeof val);
                DCF_SER_CHECK(dcf_ser_write_u64(w, val));
                break;
            }
            case DCF_TYPE_I64: {
                int64_t val;
                memcpy(&val, field_data, sizeof val);
                DCF_SER_CHECK(dcf_ser_write_i64(w, val));
                break;
            }
            case DCF_TYPE_F32: {
                float val;
                memcpy(&val, field_data, sizeof val);
                DCF_SER_CHECK(dcf_ser_write_f32(w, val));
                break;
            }
            case DCF_TYPE_F64: {
                double val;
                memcpy(&val, field_data, sizeof val);
                DCF_SER_CHECK(dcf_ser_write_f64(w, val));
                break;
            }
            case DCF_TYPE_STRING: {
                const char* val;
                memcpy(&val, field_data, sizeof val);
                DCF_SER_CHECK(dcf_ser_write_string(w, val));
                break;
            }
            case DCF_TYPE_TIMESTAMP: {
                uint64_t val;
                memcpy(&val, field_data, sizeof val);
                DCF_SER_CHECK(dcf_ser_write_timestamp(w, val));
                break;
            }
            default:
                return writer_fail(w, DCF_SER_ERR_INVALID_TYPE);
        }
    }
    
    DCF_SER_CHECK(dcf_ser_write_struct_end(w));
    return DCF_SER_OK;
}

static DCFSerError read_struct_schema_fields(DCFSerReader* r, void* data,
                                             const DCFSerSchema* schema) {
    const bool lax = (r->policy & DCF_SER_POLICY_LAX_SCHEMA) != 0;
    uint64_t seen[(DCF_SER_MAX_SCHEMA_FIELDS + 63) / 64];
    memset(seen, 0, sizeof seen);
    
    uint16_t type_id;
    DCF_SER_CHECK(dcf_ser_read_struct_begin(r, &type_id));
    
    if (type_id != schema->type_id) {
        return DCF_SER_ERR_TYPE_MISMATCH;
    }
    
    /* Clear the struct first */
    memset(data, 0, schema->struct_size);
    
    /* Read fields until end marker */
    while (true) {
        uint16_t field_id;
        DCFSerType field_type;
        DCFSerError err = dcf_ser_read_field(r, &field_id, &field_type);
        
        if (err == DCF_SER_ERR_NOT_FOUND) break;  /* End of struct */
        if (err != DCF_SER_OK) return err;
        
        /* Find field in schema */
        size_t index = 0;
        const DCFSerField* field = NULL;
        for (size_t i = 0; i < schema->field_count; i++) {
            if (schema->fields[i].field_id == field_id) {
                field = &schema->fields[i];
                index = i;
                break;
            }
        }
        
        if (!field) {
            /* Unknown field, skip it */
            DCF_SER_CHECK(dcf_ser_reader_skip(r));
            continue;
        }
        
        /* The same id twice is ambiguous (which one is meant?); a header that
         * names a different type than the schema is not what we agreed on. */
        if (!lax) {
            if (seen[index / 64] & ((uint64_t)1 << (index % 64))) return DCF_SER_ERR_MALFORMED;
            if (field_type != field->type) return DCF_SER_ERR_TYPE_MISMATCH;
        }
        seen[index / 64] |= (uint64_t)1 << (index % 64);
        
        uint8_t* field_data = (uint8_t*)data + field->offset;
        
        /* Read field value based on type. Stores go through memcpy: the
         * offset need not be aligned for the type (packed structs). */
        switch (field->type) {
            case DCF_TYPE_BOOL: {
                bool v;
                DCF_SER_CHECK(dcf_ser_read_bool(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            case DCF_TYPE_U8: {
                uint8_t v;
                DCF_SER_CHECK(dcf_ser_read_u8(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            case DCF_TYPE_I8: {
                int8_t v;
                DCF_SER_CHECK(dcf_ser_read_i8(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            case DCF_TYPE_U16: {
                uint16_t v;
                DCF_SER_CHECK(dcf_ser_read_u16(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            case DCF_TYPE_I16: {
                int16_t v;
                DCF_SER_CHECK(dcf_ser_read_i16(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            case DCF_TYPE_U32: {
                uint32_t v;
                DCF_SER_CHECK(dcf_ser_read_u32(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            case DCF_TYPE_I32: {
                int32_t v;
                DCF_SER_CHECK(dcf_ser_read_i32(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            case DCF_TYPE_U64: {
                uint64_t v;
                DCF_SER_CHECK(dcf_ser_read_u64(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            case DCF_TYPE_I64: {
                int64_t v;
                DCF_SER_CHECK(dcf_ser_read_i64(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            case DCF_TYPE_F32: {
                float v;
                DCF_SER_CHECK(dcf_ser_read_f32(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            case DCF_TYPE_F64: {
                double v;
                DCF_SER_CHECK(dcf_ser_read_f64(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            case DCF_TYPE_TIMESTAMP: {
                uint64_t v;
                DCF_SER_CHECK(dcf_ser_read_timestamp(r, &v));
                memcpy(field_data, &v, sizeof v);
                break;
            }
            default:
                /* schema_check() refused every other type before we got here. */
                return DCF_SER_ERR_INTERNAL;
        }
    }
    
    DCF_SER_CHECK(dcf_ser_read_struct_end(r));
    
    if (!lax) {
        for (size_t i = 0; i < schema->field_count; i++) {
            if ((schema->fields[i].flags & DCF_FIELD_REQUIRED) &&
                !(seen[i / 64] & ((uint64_t)1 << (i % 64)))) {
                return DCF_SER_ERR_MALFORMED;
            }
        }
    }
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_struct_schema(DCFSerReader* r, void* data,
                                        const DCFSerSchema* schema) {
    if (!r || !data || !schema) return DCF_SER_ERR_NULL_PTR;
    
    /* A STRING field cannot be read into a struct (it would be a pointer into
     * the receive buffer with no terminator); it used to be dropped silently.
     * Refuse the schema up front, independent of what the wire holds. */
    DCF_SER_CHECK(schema_check(schema, true));
    
    DCFSerError err = read_struct_schema_fields(r, data, schema);
    if (err != DCF_SER_OK) {
        /* Never leave a half-filled struct for a caller that ignores the result. */
        memset(data, 0, schema->struct_size);
    }
    return err;
}
