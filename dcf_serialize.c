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

#define WRITER_ENSURE_SPACE(w, n) do { \
    if ((w)->position + (n) > (w)->capacity) { \
        DCFSerError _e = writer_grow(w, (n)); \
        if (_e != DCF_SER_OK) return _e; \
    } \
} while(0)

#define READER_ENSURE_BYTES(r, n) do { \
    if ((r)->position + (n) > (r)->payload_end) { \
        return DCF_SER_ERR_TRUNCATED; \
    } \
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
 * Writer Internal Functions
 * ============================================================================ */

static DCFSerError writer_grow(DCFSerWriter* w, size_t needed) {
    if (!w->owns_buffer) {
        w->last_error = DCF_SER_ERR_BUFFER_FULL;
        return DCF_SER_ERR_BUFFER_FULL;
    }
    
    size_t new_cap = w->capacity * 2;
    while (new_cap < w->position + needed) {
        new_cap *= 2;
    }
    
    if (new_cap > DCF_SER_MAX_MESSAGE) {
        w->last_error = DCF_SER_ERR_TOO_LARGE;
        return DCF_SER_ERR_TOO_LARGE;
    }
    
    uint8_t* new_buf = (uint8_t*)realloc(w->buffer, new_cap);
    if (!new_buf) {
        w->last_error = DCF_SER_ERR_ALLOC_FAIL;
        return DCF_SER_ERR_ALLOC_FAIL;
    }
    
    w->buffer = new_buf;
    w->capacity = new_cap;
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
    
    size_t payload_len = writer->position - sizeof(DCFSerHeader);
    
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
        WRITER_ENSURE_SPACE(writer, 4);
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
    return writer ? (writer->position - sizeof(DCFSerHeader)) : 0;
}

void dcf_ser_writer_set_sequence(DCFSerWriter* writer, uint32_t seq) {
    if (writer) writer->sequence = seq;
}

/* ----------------------------------------------------------------------------
 * Primitive Writers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_write_null(DCFSerWriter* w) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    return writer_put_u8(w, DCF_TYPE_NULL);
}

DCFSerError dcf_ser_write_bool(DCFSerWriter* w, bool val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_BOOL));
    return writer_put_u8(w, val ? 1 : 0);
}

DCFSerError dcf_ser_write_u8(DCFSerWriter* w, uint8_t val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_U8));
    return writer_put_u8(w, val);
}

DCFSerError dcf_ser_write_i8(DCFSerWriter* w, int8_t val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_I8));
    return writer_put_u8(w, (uint8_t)val);
}

DCFSerError dcf_ser_write_u16(DCFSerWriter* w, uint16_t val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_U16));
    return writer_put_u16(w, val);
}

DCFSerError dcf_ser_write_i16(DCFSerWriter* w, int16_t val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_I16));
    return writer_put_u16(w, (uint16_t)val);
}

DCFSerError dcf_ser_write_u32(DCFSerWriter* w, uint32_t val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_U32));
    return writer_put_u32(w, val);
}

DCFSerError dcf_ser_write_i32(DCFSerWriter* w, int32_t val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_I32));
    return writer_put_u32(w, (uint32_t)val);
}

DCFSerError dcf_ser_write_u64(DCFSerWriter* w, uint64_t val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_U64));
    return writer_put_u64(w, val);
}

DCFSerError dcf_ser_write_i64(DCFSerWriter* w, int64_t val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_I64));
    return writer_put_u64(w, (uint64_t)val);
}

DCFSerError dcf_ser_write_f32(DCFSerWriter* w, float val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_F32));
    uint32_t bits;
    memcpy(&bits, &val, sizeof(bits));
    return writer_put_u32(w, bits);
}

DCFSerError dcf_ser_write_f64(DCFSerWriter* w, double val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_F64));
    uint64_t bits;
    memcpy(&bits, &val, sizeof(bits));
    return writer_put_u64(w, bits);
}

/* ----------------------------------------------------------------------------
 * Variable-Length Writers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_write_varint(DCFSerWriter* w, uint64_t val) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_VARINT));
    
    /* LEB128 encoding */
    do {
        uint8_t byte = val & 0x7F;
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
    if (!w) return DCF_SER_ERR_NULL_PTR;
    size_t len = str ? strlen(str) : 0;
    return dcf_ser_write_string_n(w, str, len);
}

DCFSerError dcf_ser_write_string_n(DCFSerWriter* w, const char* str, size_t len) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    if (len > DCF_SER_MAX_STRING) return DCF_SER_ERR_TOO_LARGE;
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_STRING));
    DCF_SER_CHECK(writer_put_u32(w, (uint32_t)len));
    
    if (len > 0 && str) {
        WRITER_ENSURE_SPACE(w, len);
        memcpy(w->buffer + w->position, str, len);
        w->position += len;
    }
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_bytes(DCFSerWriter* w, const void* data, size_t len) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    if (len > DCF_SER_MAX_MESSAGE) return DCF_SER_ERR_TOO_LARGE;
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_BYTES));
    DCF_SER_CHECK(writer_put_u32(w, (uint32_t)len));
    
    if (len > 0 && data) {
        WRITER_ENSURE_SPACE(w, len);
        memcpy(w->buffer + w->position, data, len);
        w->position += len;
    }
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_uuid(DCFSerWriter* w, const uint8_t uuid[16]) {
    if (!w || !uuid) return DCF_SER_ERR_NULL_PTR;
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_UUID));
    WRITER_ENSURE_SPACE(w, 16);
    memcpy(w->buffer + w->position, uuid, 16);
    w->position += 16;
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_timestamp(DCFSerWriter* w, uint64_t timestamp_us) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_TIMESTAMP));
    return writer_put_u64(w, timestamp_us);
}

/* ----------------------------------------------------------------------------
 * Container Writers
 * ---------------------------------------------------------------------------- */

DCFSerError dcf_ser_write_array_begin(DCFSerWriter* w, DCFSerType elem_type, size_t count) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    if (count > DCF_SER_MAX_ARRAY) return DCF_SER_ERR_TOO_LARGE;
    if (w->depth >= DCF_SER_MAX_DEPTH) return DCF_SER_ERR_DEPTH_EXCEEDED;
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_ARRAY));
    DCF_SER_CHECK(writer_put_u8(w, (uint8_t)elem_type));
    DCF_SER_CHECK(writer_put_u32(w, (uint32_t)count));
    
    w->depth++;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_array_end(DCFSerWriter* w) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    if (w->depth == 0) return DCF_SER_ERR_MALFORMED;
    w->depth--;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_map_begin(DCFSerWriter* w, DCFSerType key_type,
                                     DCFSerType val_type, size_t count) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    if (count > DCF_SER_MAX_ARRAY) return DCF_SER_ERR_TOO_LARGE;
    if (w->depth >= DCF_SER_MAX_DEPTH) return DCF_SER_ERR_DEPTH_EXCEEDED;
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_MAP));
    DCF_SER_CHECK(writer_put_u8(w, (uint8_t)key_type));
    DCF_SER_CHECK(writer_put_u8(w, (uint8_t)val_type));
    DCF_SER_CHECK(writer_put_u32(w, (uint32_t)count));
    
    w->depth++;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_map_end(DCFSerWriter* w) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    if (w->depth == 0) return DCF_SER_ERR_MALFORMED;
    w->depth--;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_struct_begin(DCFSerWriter* w, uint16_t type_id) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    if (w->depth >= DCF_SER_MAX_DEPTH) return DCF_SER_ERR_DEPTH_EXCEEDED;
    
    DCF_SER_CHECK(writer_put_u8(w, DCF_TYPE_STRUCT));
    DCF_SER_CHECK(writer_put_u16(w, type_id));
    
    w->depth++;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_field(DCFSerWriter* w, uint16_t field_id, DCFSerType type) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    DCF_SER_CHECK(writer_put_u16(w, field_id));
    DCF_SER_CHECK(writer_put_u8(w, (uint8_t)type));
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_struct_end(DCFSerWriter* w) {
    if (!w) return DCF_SER_ERR_NULL_PTR;
    if (w->depth == 0) return DCF_SER_ERR_MALFORMED;
    
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
    if (!w) return DCF_SER_ERR_NULL_PTR;
    if (len == 0) return DCF_SER_OK;
    if (!data) return DCF_SER_ERR_NULL_PTR;
    
    WRITER_ENSURE_SPACE(w, len);
    memcpy(w->buffer + w->position, data, len);
    w->position += len;
    return DCF_SER_OK;
}

DCFSerError dcf_ser_write_reserve(DCFSerWriter* w, size_t len, uint8_t** out_ptr) {
    if (!w || !out_ptr) return DCF_SER_ERR_NULL_PTR;
    
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
 * Reader API Implementation
 * ============================================================================ */

DCFSerError dcf_ser_reader_init(DCFSerReader* reader, const void* data, size_t len) {
    if (!reader || !data) return DCF_SER_ERR_NULL_PTR;
    if (len < sizeof(DCFSerHeader)) return DCF_SER_ERR_TRUNCATED;
    
    memset(reader, 0, sizeof(DCFSerReader));
    reader->buffer = (const uint8_t*)data;
    reader->length = len;
    reader->position = 0;
    
    return DCF_SER_OK;
}

DCFSerError dcf_ser_reader_validate(DCFSerReader* reader) {
    if (!reader) return DCF_SER_ERR_NULL_PTR;
    if (reader->length < sizeof(DCFSerHeader)) return DCF_SER_ERR_TRUNCATED;
    
    /* Parse header */
    const DCFSerHeader* wire_hdr = (const DCFSerHeader*)reader->buffer;
    
    reader->header.magic = dcf_ser_ntoh32(wire_hdr->magic);
    reader->header.version = dcf_ser_ntoh16(wire_hdr->version);
    reader->header.msg_type = dcf_ser_ntoh16(wire_hdr->msg_type);
    reader->header.flags = wire_hdr->flags;
    reader->header.payload_len = dcf_ser_ntoh32(wire_hdr->payload_len);
    reader->header.sequence = dcf_ser_ntoh32(wire_hdr->sequence);
    
    /* Validate magic */
    if (reader->header.magic != DCF_SER_MAGIC) {
        reader->last_error = DCF_SER_ERR_INVALID_MAGIC;
        return DCF_SER_ERR_INVALID_MAGIC;
    }
    
    /* Check version compatibility (major version must match) */
    uint16_t major = reader->header.version >> 8;
    uint16_t our_major = DCF_SER_VERSION >> 8;
    if (major != our_major) {
        reader->last_error = DCF_SER_ERR_VERSION_MISMATCH;
        return DCF_SER_ERR_VERSION_MISMATCH;
    }
    
    /* Calculate expected message size */
    size_t expected_size = sizeof(DCFSerHeader) + reader->header.payload_len;
    if (!(reader->header.flags & DCF_SER_FLAG_NO_CRC)) {
        expected_size += 4;  /* CRC32 */
    }
    
    if (reader->length < expected_size) {
        reader->last_error = DCF_SER_ERR_TRUNCATED;
        return DCF_SER_ERR_TRUNCATED;
    }
    
    /* Verify CRC if present */
    if (!(reader->header.flags & DCF_SER_FLAG_NO_CRC)) {
        size_t crc_offset = sizeof(DCFSerHeader) + reader->header.payload_len;
        uint32_t stored_crc;
        memcpy(&stored_crc, reader->buffer + crc_offset, 4);
        stored_crc = dcf_ser_ntoh32(stored_crc);
        
        uint32_t computed_crc = dcf_ser_crc32(reader->buffer, crc_offset);
        
        if (stored_crc != computed_crc) {
            reader->last_error = DCF_SER_ERR_CRC_MISMATCH;
            return DCF_SER_ERR_CRC_MISMATCH;
        }
        reader->crc_verified = true;
    }
    
    /* Set up payload bounds */
    reader->payload_start = sizeof(DCFSerHeader);
    reader->payload_end = sizeof(DCFSerHeader) + reader->header.payload_len;
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
    return reader->payload_end - reader->position;
}

bool dcf_ser_reader_at_end(const DCFSerReader* reader) {
    return !reader || !reader->header_valid || reader->position >= reader->payload_end;
}

DCFSerType dcf_ser_reader_peek_type(const DCFSerReader* reader) {
    if (!reader || reader->position >= reader->payload_end) {
        return DCF_TYPE_INVALID;
    }
    return (DCFSerType)reader->buffer[reader->position];
}

DCFSerError dcf_ser_reader_skip(DCFSerReader* reader) {
    if (!reader) return DCF_SER_ERR_NULL_PTR;
    
    uint8_t type_byte;
    DCF_SER_CHECK(reader_get_u8(reader, &type_byte));
    DCFSerType type = (DCFSerType)type_byte;
    
    switch (type) {
        case DCF_TYPE_NULL:
            break;
        case DCF_TYPE_BOOL:
        case DCF_TYPE_U8:
        case DCF_TYPE_I8:
            reader->position += 1;
            break;
        case DCF_TYPE_U16:
        case DCF_TYPE_I16:
            reader->position += 2;
            break;
        case DCF_TYPE_U32:
        case DCF_TYPE_I32:
        case DCF_TYPE_F32:
            reader->position += 4;
            break;
        case DCF_TYPE_U64:
        case DCF_TYPE_I64:
        case DCF_TYPE_F64:
        case DCF_TYPE_TIMESTAMP:
        case DCF_TYPE_DURATION:
            reader->position += 8;
            break;
        case DCF_TYPE_UUID:
            reader->position += 16;
            break;
        case DCF_TYPE_VARINT: {
            /* Skip LEB128 bytes until high bit is clear */
            uint8_t b;
            do {
                DCF_SER_CHECK(reader_get_u8(reader, &b));
            } while (b & 0x80);
            break;
        }
        case DCF_TYPE_STRING:
        case DCF_TYPE_BYTES: {
            uint32_t len;
            DCF_SER_CHECK(reader_get_u32(reader, &len));
            reader->position += len;
            break;
        }
        case DCF_TYPE_ARRAY: {
            uint8_t elem_type;
            uint32_t count;
            DCF_SER_CHECK(reader_get_u8(reader, &elem_type));
            DCF_SER_CHECK(reader_get_u32(reader, &count));
            (void)elem_type;  /* Type info available but not used in skip */
            for (uint32_t i = 0; i < count; i++) {
                DCF_SER_CHECK(dcf_ser_reader_skip(reader));
            }
            break;
        }
        case DCF_TYPE_MAP: {
            reader->position += 2; /* key_type, val_type */
            uint32_t count;
            DCF_SER_CHECK(reader_get_u32(reader, &count));
            for (uint32_t i = 0; i < count * 2; i++) {
                DCF_SER_CHECK(dcf_ser_reader_skip(reader));
            }
            break;
        }
        case DCF_TYPE_STRUCT: {
            reader->position += 2; /* type_id */
            while (true) {
                uint16_t field_id;
                uint8_t field_type;
                DCF_SER_CHECK(reader_get_u16(reader, &field_id));
                DCF_SER_CHECK(reader_get_u8(reader, &field_type));
                if (field_id == 0 && field_type == DCF_TYPE_NULL) break;
                DCF_SER_CHECK(dcf_ser_reader_skip(reader));
            }
            break;
        }
        default:
            return DCF_SER_ERR_INVALID_TYPE;
    }
    
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
    uint8_t shift = 0;
    uint8_t b;
    
    do {
        if (shift >= 64) return DCF_SER_ERR_OVERFLOW;
        DCF_SER_CHECK(reader_get_u8(r, &b));
        result |= (uint64_t)(b & 0x7F) << shift;
        shift += 7;
    } while (b & 0x80);
    
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
    
    READER_ENSURE_BYTES(r, len);
    
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
    
    memcpy(buf, str, len);
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
    DCFSerReader reader;
    DCFSerError err = dcf_ser_reader_init(&reader, data, len);
    if (err != DCF_SER_OK) return err;
    return dcf_ser_reader_validate(&reader);
}

size_t dcf_ser_message_length(const void* header_data) {
    if (!header_data) return 0;
    
    const DCFSerHeader* wire_hdr = (const DCFSerHeader*)header_data;
    uint32_t payload_len = dcf_ser_ntoh32(wire_hdr->payload_len);
    uint8_t flags = wire_hdr->flags;
    
    size_t total = sizeof(DCFSerHeader) + payload_len;
    if (!(flags & DCF_SER_FLAG_NO_CRC)) {
        total += 4;  /* CRC32 */
    }
    
    return total;
}

/* ============================================================================
 * Schema-Based Serialization
 * ============================================================================ */

DCFSerError dcf_ser_write_struct_schema(DCFSerWriter* w, const void* data,
                                         const DCFSerSchema* schema) {
    if (!w || !data || !schema) return DCF_SER_ERR_NULL_PTR;
    
    DCF_SER_CHECK(dcf_ser_write_struct_begin(w, schema->type_id));
    
    for (size_t i = 0; i < schema->field_count; i++) {
        const DCFSerField* field = &schema->fields[i];
        const uint8_t* field_data = (const uint8_t*)data + field->offset;
        
        /* Write field header */
        DCF_SER_CHECK(dcf_ser_write_field(w, field->field_id, field->type));
        
        /* Write field value based on type */
        switch (field->type) {
            case DCF_TYPE_BOOL: {
                bool val = *(const bool*)field_data;
                DCF_SER_CHECK(dcf_ser_write_bool(w, val));
                break;
            }
            case DCF_TYPE_U8:
                DCF_SER_CHECK(dcf_ser_write_u8(w, *(const uint8_t*)field_data));
                break;
            case DCF_TYPE_I8:
                DCF_SER_CHECK(dcf_ser_write_i8(w, *(const int8_t*)field_data));
                break;
            case DCF_TYPE_U16:
                DCF_SER_CHECK(dcf_ser_write_u16(w, *(const uint16_t*)field_data));
                break;
            case DCF_TYPE_I16:
                DCF_SER_CHECK(dcf_ser_write_i16(w, *(const int16_t*)field_data));
                break;
            case DCF_TYPE_U32:
                DCF_SER_CHECK(dcf_ser_write_u32(w, *(const uint32_t*)field_data));
                break;
            case DCF_TYPE_I32:
                DCF_SER_CHECK(dcf_ser_write_i32(w, *(const int32_t*)field_data));
                break;
            case DCF_TYPE_U64:
                DCF_SER_CHECK(dcf_ser_write_u64(w, *(const uint64_t*)field_data));
                break;
            case DCF_TYPE_I64:
                DCF_SER_CHECK(dcf_ser_write_i64(w, *(const int64_t*)field_data));
                break;
            case DCF_TYPE_F32:
                DCF_SER_CHECK(dcf_ser_write_f32(w, *(const float*)field_data));
                break;
            case DCF_TYPE_F64:
                DCF_SER_CHECK(dcf_ser_write_f64(w, *(const double*)field_data));
                break;
            case DCF_TYPE_STRING:
                DCF_SER_CHECK(dcf_ser_write_string(w, *(const char**)field_data));
                break;
            case DCF_TYPE_TIMESTAMP:
                DCF_SER_CHECK(dcf_ser_write_timestamp(w, *(const uint64_t*)field_data));
                break;
            default:
                return DCF_SER_ERR_INVALID_TYPE;
        }
    }
    
    DCF_SER_CHECK(dcf_ser_write_struct_end(w));
    return DCF_SER_OK;
}

DCFSerError dcf_ser_read_struct_schema(DCFSerReader* r, void* data,
                                        const DCFSerSchema* schema) {
    if (!r || !data || !schema) return DCF_SER_ERR_NULL_PTR;
    
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
        const DCFSerField* field = NULL;
        for (size_t i = 0; i < schema->field_count; i++) {
            if (schema->fields[i].field_id == field_id) {
                field = &schema->fields[i];
                break;
            }
        }
        
        if (!field) {
            /* Unknown field, skip it */
            DCF_SER_CHECK(dcf_ser_reader_skip(r));
            continue;
        }
        
        uint8_t* field_data = (uint8_t*)data + field->offset;
        
        /* Read field value based on type */
        switch (field->type) {
            case DCF_TYPE_BOOL:
                DCF_SER_CHECK(dcf_ser_read_bool(r, (bool*)field_data));
                break;
            case DCF_TYPE_U8:
                DCF_SER_CHECK(dcf_ser_read_u8(r, (uint8_t*)field_data));
                break;
            case DCF_TYPE_I8:
                DCF_SER_CHECK(dcf_ser_read_i8(r, (int8_t*)field_data));
                break;
            case DCF_TYPE_U16:
                DCF_SER_CHECK(dcf_ser_read_u16(r, (uint16_t*)field_data));
                break;
            case DCF_TYPE_I16:
                DCF_SER_CHECK(dcf_ser_read_i16(r, (int16_t*)field_data));
                break;
            case DCF_TYPE_U32:
                DCF_SER_CHECK(dcf_ser_read_u32(r, (uint32_t*)field_data));
                break;
            case DCF_TYPE_I32:
                DCF_SER_CHECK(dcf_ser_read_i32(r, (int32_t*)field_data));
                break;
            case DCF_TYPE_U64:
                DCF_SER_CHECK(dcf_ser_read_u64(r, (uint64_t*)field_data));
                break;
            case DCF_TYPE_I64:
                DCF_SER_CHECK(dcf_ser_read_i64(r, (int64_t*)field_data));
                break;
            case DCF_TYPE_F32:
                DCF_SER_CHECK(dcf_ser_read_f32(r, (float*)field_data));
                break;
            case DCF_TYPE_F64:
                DCF_SER_CHECK(dcf_ser_read_f64(r, (double*)field_data));
                break;
            case DCF_TYPE_TIMESTAMP:
                DCF_SER_CHECK(dcf_ser_read_timestamp(r, (uint64_t*)field_data));
                break;
            default:
                DCF_SER_CHECK(dcf_ser_reader_skip(r));
                break;
        }
    }
    
    DCF_SER_CHECK(dcf_ser_read_struct_end(r));
    return DCF_SER_OK;
}
