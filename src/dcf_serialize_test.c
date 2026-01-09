/**
 * @file dcf_serialize_test.c
 * @brief Test and Examples for DCF Serialization Shim
 * @version 5.2.0
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
 * 
 * See LICENSE file for full license text.
 * 
 * Build: gcc -o dcf_serialize_test dcf_serialize_test.c dcf_serialize.c -Wall -Wextra
 */

#include "dcf_serialize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ============================================================================
 * Test Helpers
 * ============================================================================ */

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s at %s:%d\n", msg, __FILE__, __LINE__); \
        return 1; \
    } \
} while(0)

#define TEST_CHECK(err) do { \
    DCFSerError _e = (err); \
    if (_e != DCF_SER_OK) { \
        fprintf(stderr, "FAIL: %s at %s:%d\n", dcf_ser_error_str(_e), __FILE__, __LINE__); \
        return 1; \
    } \
} while(0)

static void print_hex(const uint8_t* data, size_t len, const char* label) {
    printf("%s [%zu bytes]: ", label, len);
    for (size_t i = 0; i < len && i < 64; i++) {
        printf("%02x ", data[i]);
    }
    if (len > 64) printf("...");
    printf("\n");
}

/* ============================================================================
 * Test: Byte Order
 * ============================================================================ */

static int test_byte_order(void) {
    printf("Testing byte order utilities...\n");
    
    /* Test endianness detection */
    bool is_le = dcf_ser_is_little_endian();
    printf("  Platform is %s-endian\n", is_le ? "little" : "big");
    
    /* Test byte swaps */
    TEST_ASSERT(dcf_ser_bswap16(0x1234) == 0x3412, "bswap16 failed");
    TEST_ASSERT(dcf_ser_bswap32(0x12345678) == 0x78563412, "bswap32 failed");
    TEST_ASSERT(dcf_ser_bswap64(0x123456789ABCDEF0ULL) == 0xF0DEBC9A78563412ULL, "bswap64 failed");
    
    /* Test round-trip */
    uint32_t val = 0xDEADBEEF;
    uint32_t net = dcf_ser_hton32(val);
    uint32_t back = dcf_ser_ntoh32(net);
    TEST_ASSERT(val == back, "hton32/ntoh32 round-trip failed");
    
    printf("  Byte order tests PASSED\n");
    return 0;
}

/* ============================================================================
 * Test: CRC32
 * ============================================================================ */

static int test_crc32(void) {
    printf("Testing CRC32...\n");
    
    /* Test known value: "123456789" should be 0xCBF43926 */
    const char* test_str = "123456789";
    uint32_t crc = dcf_ser_crc32(test_str, 9);
    TEST_ASSERT(crc == 0xCBF43926, "CRC32 mismatch for '123456789'");
    
    /* Test incremental */
    uint32_t running = dcf_ser_crc32_update(0xFFFFFFFF, "1234", 4);
    running = dcf_ser_crc32_update(running, "56789", 5);
    running ^= 0xFFFFFFFF;
    TEST_ASSERT(running == 0xCBF43926, "Incremental CRC32 failed");
    
    printf("  CRC32 tests PASSED\n");
    return 0;
}

/* ============================================================================
 * Test: Primitive Serialization
 * ============================================================================ */

static int test_primitives(void) {
    printf("Testing primitive serialization...\n");
    
    DCFSerWriter writer;
    TEST_CHECK(dcf_ser_writer_init(&writer, 0x0001, DCF_SER_FLAG_NONE));
    
    /* Write primitives */
    TEST_CHECK(dcf_ser_write_bool(&writer, true));
    TEST_CHECK(dcf_ser_write_u8(&writer, 0x42));
    TEST_CHECK(dcf_ser_write_i8(&writer, -42));
    TEST_CHECK(dcf_ser_write_u16(&writer, 0x1234));
    TEST_CHECK(dcf_ser_write_i16(&writer, -1234));
    TEST_CHECK(dcf_ser_write_u32(&writer, 0xDEADBEEF));
    TEST_CHECK(dcf_ser_write_i32(&writer, -123456789));
    TEST_CHECK(dcf_ser_write_u64(&writer, 0x123456789ABCDEF0ULL));
    TEST_CHECK(dcf_ser_write_i64(&writer, -9223372036854775807LL));
    TEST_CHECK(dcf_ser_write_f32(&writer, 3.14159f));
    TEST_CHECK(dcf_ser_write_f64(&writer, 2.718281828459045));
    
    /* Finalize */
    const uint8_t* data;
    size_t len;
    TEST_CHECK(dcf_ser_writer_finish(&writer, &data, &len));
    
    print_hex(data, len, "Primitives");
    
    /* Read back */
    DCFSerReader reader;
    TEST_CHECK(dcf_ser_reader_init(&reader, data, len));
    TEST_CHECK(dcf_ser_reader_validate(&reader));
    
    TEST_ASSERT(dcf_ser_reader_msg_type(&reader) == 0x0001, "Wrong message type");
    
    bool b;
    uint8_t u8;
    int8_t i8;
    uint16_t u16;
    int16_t i16;
    uint32_t u32;
    int32_t i32;
    uint64_t u64;
    int64_t i64;
    float f32;
    double f64;
    
    TEST_CHECK(dcf_ser_read_bool(&reader, &b));
    TEST_ASSERT(b == true, "bool mismatch");
    
    TEST_CHECK(dcf_ser_read_u8(&reader, &u8));
    TEST_ASSERT(u8 == 0x42, "u8 mismatch");
    
    TEST_CHECK(dcf_ser_read_i8(&reader, &i8));
    TEST_ASSERT(i8 == -42, "i8 mismatch");
    
    TEST_CHECK(dcf_ser_read_u16(&reader, &u16));
    TEST_ASSERT(u16 == 0x1234, "u16 mismatch");
    
    TEST_CHECK(dcf_ser_read_i16(&reader, &i16));
    TEST_ASSERT(i16 == -1234, "i16 mismatch");
    
    TEST_CHECK(dcf_ser_read_u32(&reader, &u32));
    TEST_ASSERT(u32 == 0xDEADBEEF, "u32 mismatch");
    
    TEST_CHECK(dcf_ser_read_i32(&reader, &i32));
    TEST_ASSERT(i32 == -123456789, "i32 mismatch");
    
    TEST_CHECK(dcf_ser_read_u64(&reader, &u64));
    TEST_ASSERT(u64 == 0x123456789ABCDEF0ULL, "u64 mismatch");
    
    TEST_CHECK(dcf_ser_read_i64(&reader, &i64));
    TEST_ASSERT(i64 == -9223372036854775807LL, "i64 mismatch");
    
    TEST_CHECK(dcf_ser_read_f32(&reader, &f32));
    TEST_ASSERT(f32 > 3.14f && f32 < 3.15f, "f32 mismatch");
    
    TEST_CHECK(dcf_ser_read_f64(&reader, &f64));
    TEST_ASSERT(f64 > 2.71 && f64 < 2.72, "f64 mismatch");
    
    TEST_ASSERT(dcf_ser_reader_at_end(&reader), "Reader not at end");
    
    dcf_ser_writer_destroy(&writer);
    
    printf("  Primitive tests PASSED\n");
    return 0;
}

/* ============================================================================
 * Test: Variable-Length Data
 * ============================================================================ */

static int test_variable_length(void) {
    printf("Testing variable-length serialization...\n");
    
    DCFSerWriter writer;
    TEST_CHECK(dcf_ser_writer_init(&writer, 0x0002, DCF_SER_FLAG_NONE));
    
    /* Write variable-length data */
    TEST_CHECK(dcf_ser_write_string(&writer, "Hello, DCF!"));
    TEST_CHECK(dcf_ser_write_string(&writer, ""));  /* Empty string */
    
    uint8_t blob[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    TEST_CHECK(dcf_ser_write_bytes(&writer, blob, sizeof(blob)));
    
    uint8_t uuid[16] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    TEST_CHECK(dcf_ser_write_uuid(&writer, uuid));
    
    TEST_CHECK(dcf_ser_write_varint(&writer, 127));           /* 1 byte */
    TEST_CHECK(dcf_ser_write_varint(&writer, 300));           /* 2 bytes */
    TEST_CHECK(dcf_ser_write_varint(&writer, 0xFFFFFFFFULL)); /* 5 bytes */
    
    TEST_CHECK(dcf_ser_write_timestamp(&writer, 1704067200000000ULL)); /* Jan 1, 2024 */
    
    /* Finalize */
    const uint8_t* data;
    size_t len;
    TEST_CHECK(dcf_ser_writer_finish(&writer, &data, &len));
    
    print_hex(data, len, "Variable-length");
    
    /* Read back */
    DCFSerReader reader;
    TEST_CHECK(dcf_ser_reader_init(&reader, data, len));
    TEST_CHECK(dcf_ser_reader_validate(&reader));
    
    const char* str;
    size_t str_len;
    TEST_CHECK(dcf_ser_read_string(&reader, &str, &str_len));
    TEST_ASSERT(str_len == 11 && memcmp(str, "Hello, DCF!", 11) == 0, "string mismatch");
    
    TEST_CHECK(dcf_ser_read_string(&reader, &str, &str_len));
    TEST_ASSERT(str_len == 0, "empty string mismatch");
    
    const void* blob_out;
    size_t blob_len;
    TEST_CHECK(dcf_ser_read_bytes(&reader, &blob_out, &blob_len));
    TEST_ASSERT(blob_len == 8 && memcmp(blob_out, blob, 8) == 0, "bytes mismatch");
    
    uint8_t uuid_out[16];
    TEST_CHECK(dcf_ser_read_uuid(&reader, uuid_out));
    TEST_ASSERT(memcmp(uuid_out, uuid, 16) == 0, "uuid mismatch");
    
    uint64_t varint;
    TEST_CHECK(dcf_ser_read_varint(&reader, &varint));
    TEST_ASSERT(varint == 127, "varint 127 mismatch");
    
    TEST_CHECK(dcf_ser_read_varint(&reader, &varint));
    TEST_ASSERT(varint == 300, "varint 300 mismatch");
    
    TEST_CHECK(dcf_ser_read_varint(&reader, &varint));
    TEST_ASSERT(varint == 0xFFFFFFFFULL, "varint max32 mismatch");
    
    uint64_t ts;
    TEST_CHECK(dcf_ser_read_timestamp(&reader, &ts));
    TEST_ASSERT(ts == 1704067200000000ULL, "timestamp mismatch");
    
    dcf_ser_writer_destroy(&writer);
    
    printf("  Variable-length tests PASSED\n");
    return 0;
}

/* ============================================================================
 * Test: Containers (Array, Map, Struct)
 * ============================================================================ */

static int test_containers(void) {
    printf("Testing container serialization...\n");
    
    DCFSerWriter writer;
    TEST_CHECK(dcf_ser_writer_init(&writer, 0x0003, DCF_SER_FLAG_NONE));
    
    /* Write an array of u32 */
    TEST_CHECK(dcf_ser_write_array_begin(&writer, DCF_TYPE_U32, 3));
    TEST_CHECK(dcf_ser_write_u32(&writer, 100));
    TEST_CHECK(dcf_ser_write_u32(&writer, 200));
    TEST_CHECK(dcf_ser_write_u32(&writer, 300));
    TEST_CHECK(dcf_ser_write_array_end(&writer));
    
    /* Write a map of string -> i32 */
    TEST_CHECK(dcf_ser_write_map_begin(&writer, DCF_TYPE_STRING, DCF_TYPE_I32, 2));
    TEST_CHECK(dcf_ser_write_string(&writer, "one"));
    TEST_CHECK(dcf_ser_write_i32(&writer, 1));
    TEST_CHECK(dcf_ser_write_string(&writer, "two"));
    TEST_CHECK(dcf_ser_write_i32(&writer, 2));
    TEST_CHECK(dcf_ser_write_map_end(&writer));
    
    /* Write a struct */
    TEST_CHECK(dcf_ser_write_struct_begin(&writer, 0x0100));  /* type_id = 0x0100 */
    
    TEST_CHECK(dcf_ser_write_field(&writer, 1, DCF_TYPE_STRING));
    TEST_CHECK(dcf_ser_write_string(&writer, "Alice"));
    
    TEST_CHECK(dcf_ser_write_field(&writer, 2, DCF_TYPE_U32));
    TEST_CHECK(dcf_ser_write_u32(&writer, 30));
    
    TEST_CHECK(dcf_ser_write_field(&writer, 3, DCF_TYPE_BOOL));
    TEST_CHECK(dcf_ser_write_bool(&writer, true));
    
    TEST_CHECK(dcf_ser_write_struct_end(&writer));
    
    /* Finalize */
    const uint8_t* data;
    size_t len;
    TEST_CHECK(dcf_ser_writer_finish(&writer, &data, &len));
    
    print_hex(data, len, "Containers");
    
    /* Read back */
    DCFSerReader reader;
    TEST_CHECK(dcf_ser_reader_init(&reader, data, len));
    TEST_CHECK(dcf_ser_reader_validate(&reader));
    
    /* Read array */
    DCFSerType elem_type;
    size_t count;
    TEST_CHECK(dcf_ser_read_array_begin(&reader, &elem_type, &count));
    TEST_ASSERT(elem_type == DCF_TYPE_U32 && count == 3, "array header mismatch");
    
    uint32_t arr_vals[3];
    TEST_CHECK(dcf_ser_read_u32(&reader, &arr_vals[0]));
    TEST_CHECK(dcf_ser_read_u32(&reader, &arr_vals[1]));
    TEST_CHECK(dcf_ser_read_u32(&reader, &arr_vals[2]));
    TEST_ASSERT(arr_vals[0] == 100 && arr_vals[1] == 200 && arr_vals[2] == 300, "array values mismatch");
    TEST_CHECK(dcf_ser_read_array_end(&reader));
    
    /* Read map */
    DCFSerType key_type, val_type;
    TEST_CHECK(dcf_ser_read_map_begin(&reader, &key_type, &val_type, &count));
    TEST_ASSERT(key_type == DCF_TYPE_STRING && val_type == DCF_TYPE_I32 && count == 2, "map header mismatch");
    
    const char* key;
    size_t key_len;
    int32_t val;
    
    TEST_CHECK(dcf_ser_read_string(&reader, &key, &key_len));
    TEST_CHECK(dcf_ser_read_i32(&reader, &val));
    TEST_ASSERT(key_len == 3 && memcmp(key, "one", 3) == 0 && val == 1, "map entry 1 mismatch");
    
    TEST_CHECK(dcf_ser_read_string(&reader, &key, &key_len));
    TEST_CHECK(dcf_ser_read_i32(&reader, &val));
    TEST_ASSERT(key_len == 3 && memcmp(key, "two", 3) == 0 && val == 2, "map entry 2 mismatch");
    TEST_CHECK(dcf_ser_read_map_end(&reader));
    
    /* Read struct */
    uint16_t struct_type_id;
    TEST_CHECK(dcf_ser_read_struct_begin(&reader, &struct_type_id));
    TEST_ASSERT(struct_type_id == 0x0100, "struct type_id mismatch");
    
    uint16_t field_id;
    DCFSerType field_type;
    
    /* Field 1: name (string) */
    TEST_CHECK(dcf_ser_read_field(&reader, &field_id, &field_type));
    TEST_ASSERT(field_id == 1 && field_type == DCF_TYPE_STRING, "field 1 header mismatch");
    TEST_CHECK(dcf_ser_read_string(&reader, &key, &key_len));
    TEST_ASSERT(key_len == 5 && memcmp(key, "Alice", 5) == 0, "name field mismatch");
    
    /* Field 2: age (u32) */
    TEST_CHECK(dcf_ser_read_field(&reader, &field_id, &field_type));
    TEST_ASSERT(field_id == 2 && field_type == DCF_TYPE_U32, "field 2 header mismatch");
    uint32_t age;
    TEST_CHECK(dcf_ser_read_u32(&reader, &age));
    TEST_ASSERT(age == 30, "age field mismatch");
    
    /* Field 3: active (bool) */
    TEST_CHECK(dcf_ser_read_field(&reader, &field_id, &field_type));
    TEST_ASSERT(field_id == 3 && field_type == DCF_TYPE_BOOL, "field 3 header mismatch");
    bool active;
    TEST_CHECK(dcf_ser_read_bool(&reader, &active));
    TEST_ASSERT(active == true, "active field mismatch");
    
    /* End marker */
    DCFSerError err = dcf_ser_read_field(&reader, &field_id, &field_type);
    TEST_ASSERT(err == DCF_SER_ERR_NOT_FOUND, "struct end marker expected");
    
    TEST_CHECK(dcf_ser_read_struct_end(&reader));
    
    dcf_ser_writer_destroy(&writer);
    
    printf("  Container tests PASSED\n");
    return 0;
}

/* ============================================================================
 * Test: Schema-Based Serialization
 * ============================================================================ */

typedef struct {
    uint32_t id;
    bool     active;
    float    score;
    uint64_t timestamp;
} TestRecord;

static const DCFSerField test_record_fields[] = {
    DCF_SER_FIELD_DEF(TestRecord, id, DCF_TYPE_U32, 1),
    DCF_SER_FIELD_DEF(TestRecord, active, DCF_TYPE_BOOL, 2),
    DCF_SER_FIELD_DEF(TestRecord, score, DCF_TYPE_F32, 3),
    DCF_SER_FIELD_DEF(TestRecord, timestamp, DCF_TYPE_TIMESTAMP, 4),
};

static const DCFSerSchema test_record_schema = {
    .name = "TestRecord",
    .type_id = 0x0200,
    .fields = test_record_fields,
    .field_count = sizeof(test_record_fields) / sizeof(test_record_fields[0]),
    .struct_size = sizeof(TestRecord),
};

static int test_schema(void) {
    printf("Testing schema-based serialization...\n");
    
    TestRecord original = {
        .id = 12345,
        .active = true,
        .score = 98.5f,
        .timestamp = 1704153600000000ULL,
    };
    
    DCFSerWriter writer;
    TEST_CHECK(dcf_ser_writer_init(&writer, 0x0004, DCF_SER_FLAG_NONE));
    TEST_CHECK(dcf_ser_write_struct_schema(&writer, &original, &test_record_schema));
    
    const uint8_t* data;
    size_t len;
    TEST_CHECK(dcf_ser_writer_finish(&writer, &data, &len));
    
    print_hex(data, len, "Schema-based");
    
    /* Read back */
    DCFSerReader reader;
    TEST_CHECK(dcf_ser_reader_init(&reader, data, len));
    TEST_CHECK(dcf_ser_reader_validate(&reader));
    
    TestRecord decoded = {0};
    TEST_CHECK(dcf_ser_read_struct_schema(&reader, &decoded, &test_record_schema));
    
    TEST_ASSERT(decoded.id == original.id, "id mismatch");
    TEST_ASSERT(decoded.active == original.active, "active mismatch");
    TEST_ASSERT(decoded.score > 98.0f && decoded.score < 99.0f, "score mismatch");
    TEST_ASSERT(decoded.timestamp == original.timestamp, "timestamp mismatch");
    
    dcf_ser_writer_destroy(&writer);
    
    printf("  Schema tests PASSED\n");
    return 0;
}

/* ============================================================================
 * Test: Error Conditions
 * ============================================================================ */

static int test_errors(void) {
    printf("Testing error conditions...\n");
    
    /* Test CRC mismatch */
    DCFSerWriter writer;
    TEST_CHECK(dcf_ser_writer_init(&writer, 0x0005, DCF_SER_FLAG_NONE));
    TEST_CHECK(dcf_ser_write_u32(&writer, 42));
    
    const uint8_t* data;
    size_t len;
    TEST_CHECK(dcf_ser_writer_finish(&writer, &data, &len));
    
    /* Corrupt a byte in the payload */
    uint8_t* corrupt = malloc(len);
    memcpy(corrupt, data, len);
    corrupt[sizeof(DCFSerHeader) + 2] ^= 0xFF;  /* Flip bits in payload */
    
    DCFSerReader reader;
    TEST_CHECK(dcf_ser_reader_init(&reader, corrupt, len));
    DCFSerError err = dcf_ser_reader_validate(&reader);
    TEST_ASSERT(err == DCF_SER_ERR_CRC_MISMATCH, "CRC corruption not detected");
    
    free(corrupt);
    
    /* Test truncated message */
    TEST_CHECK(dcf_ser_reader_init(&reader, data, len - 5));
    err = dcf_ser_reader_validate(&reader);
    TEST_ASSERT(err == DCF_SER_ERR_TRUNCATED, "Truncation not detected");
    
    /* Test invalid magic */
    uint8_t bad_magic[32] = {0x00, 0x00, 0x00, 0x00};  /* Not DCFS */
    err = dcf_ser_reader_init(&reader, bad_magic, sizeof(bad_magic));
    TEST_CHECK(err);  /* Init should work */
    err = dcf_ser_reader_validate(&reader);
    TEST_ASSERT(err == DCF_SER_ERR_INVALID_MAGIC, "Invalid magic not detected");
    
    dcf_ser_writer_destroy(&writer);
    
    printf("  Error tests PASSED\n");
    return 0;
}

/* ============================================================================
 * Test: External Buffer
 * ============================================================================ */

static int test_external_buffer(void) {
    printf("Testing external buffer mode...\n");
    
    uint8_t buffer[1024];
    DCFSerWriter writer;
    TEST_CHECK(dcf_ser_writer_init_buffer(&writer, buffer, sizeof(buffer), 0x0006, DCF_SER_FLAG_NONE));
    
    TEST_CHECK(dcf_ser_write_string(&writer, "Using external buffer!"));
    TEST_CHECK(dcf_ser_write_u64(&writer, 0xCAFEBABEDEADBEEFULL));
    
    const uint8_t* data;
    size_t len;
    TEST_CHECK(dcf_ser_writer_finish(&writer, &data, &len));
    
    TEST_ASSERT(data == buffer, "Data should point to external buffer");
    
    print_hex(data, len, "External buffer");
    
    /* Verify */
    DCFSerReader reader;
    TEST_CHECK(dcf_ser_reader_init(&reader, data, len));
    TEST_CHECK(dcf_ser_reader_validate(&reader));
    
    const char* str;
    size_t str_len;
    TEST_CHECK(dcf_ser_read_string(&reader, &str, &str_len));
    TEST_ASSERT(str_len == 22, "string length mismatch");
    
    uint64_t val;
    TEST_CHECK(dcf_ser_read_u64(&reader, &val));
    TEST_ASSERT(val == 0xCAFEBABEDEADBEEFULL, "u64 mismatch");
    
    /* Note: No destroy needed for external buffer mode */
    
    printf("  External buffer tests PASSED\n");
    return 0;
}

/* ============================================================================
 * Test: No-CRC Mode
 * ============================================================================ */

static int test_no_crc(void) {
    printf("Testing no-CRC mode...\n");
    
    DCFSerWriter writer;
    TEST_CHECK(dcf_ser_writer_init(&writer, 0x0007, DCF_SER_FLAG_NO_CRC));
    
    TEST_CHECK(dcf_ser_write_string(&writer, "Fast path - no CRC"));
    
    const uint8_t* data;
    size_t len;
    TEST_CHECK(dcf_ser_writer_finish(&writer, &data, &len));
    
    print_hex(data, len, "No-CRC");
    
    /* Message should be 4 bytes shorter (no CRC) */
    DCFSerReader reader;
    TEST_CHECK(dcf_ser_reader_init(&reader, data, len));
    TEST_CHECK(dcf_ser_reader_validate(&reader));
    
    TEST_ASSERT(!reader.crc_verified, "CRC should not be verified in NO_CRC mode");
    
    const char* str;
    size_t str_len;
    TEST_CHECK(dcf_ser_read_string(&reader, &str, &str_len));
    TEST_ASSERT(str_len == 18, "string length mismatch");
    
    dcf_ser_writer_destroy(&writer);
    
    printf("  No-CRC tests PASSED\n");
    return 0;
}

/* ============================================================================
 * Example: Game State Message
 * ============================================================================ */

/* Message types for a game protocol */
enum {
    MSG_PLAYER_STATE = 0x1000,
    MSG_GAME_EVENT   = 0x1001,
    MSG_CHAT         = 0x1002,
};

static int example_game_protocol(void) {
    printf("\n=== Example: Game Protocol ===\n");
    
    /* Serialize a player state update */
    DCFSerWriter writer;
    dcf_ser_writer_init(&writer, MSG_PLAYER_STATE, DCF_SER_FLAG_PRIORITY);
    dcf_ser_writer_set_sequence(&writer, 42);
    
    /* Player ID */
    uint8_t player_uuid[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    dcf_ser_write_uuid(&writer, player_uuid);
    
    /* Position (x, y, z) */
    dcf_ser_write_f32(&writer, 123.456f);
    dcf_ser_write_f32(&writer, 78.9f);
    dcf_ser_write_f32(&writer, 42.0f);
    
    /* Health */
    dcf_ser_write_u16(&writer, 85);  /* Out of 100 */
    
    /* Inventory items (array of item IDs) */
    dcf_ser_write_array_begin(&writer, DCF_TYPE_U32, 3);
    dcf_ser_write_u32(&writer, 1001);  /* Sword */
    dcf_ser_write_u32(&writer, 2005);  /* Shield */
    dcf_ser_write_u32(&writer, 3042);  /* Potion */
    dcf_ser_write_array_end(&writer);
    
    /* Server timestamp */
    dcf_ser_write_timestamp(&writer, 1704153600000000ULL);
    
    const uint8_t* data;
    size_t len;
    dcf_ser_writer_finish(&writer, &data, &len);
    
    printf("Player state message: %zu bytes\n", len);
    print_hex(data, len, "Wire format");
    
    /* Parse it back */
    DCFSerReader reader;
    dcf_ser_reader_init(&reader, data, len);
    dcf_ser_reader_validate(&reader);
    
    const DCFSerHeader* hdr = dcf_ser_reader_header(&reader);
    printf("  Message type: 0x%04X\n", hdr->msg_type);
    printf("  Sequence: %u\n", hdr->sequence);
    printf("  Flags: 0x%02X (priority=%d)\n", hdr->flags, 
           (hdr->flags & DCF_SER_FLAG_PRIORITY) ? 1 : 0);
    
    dcf_ser_writer_destroy(&writer);
    
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("=== DCF Serialization Shim Tests ===\n\n");
    
    int failures = 0;
    
    failures += test_byte_order();
    failures += test_crc32();
    failures += test_primitives();
    failures += test_variable_length();
    failures += test_containers();
    failures += test_schema();
    failures += test_errors();
    failures += test_external_buffer();
    failures += test_no_crc();
    
    example_game_protocol();
    
    printf("\n=== Results ===\n");
    if (failures == 0) {
        printf("All tests PASSED!\n");
        return 0;
    } else {
        printf("%d test(s) FAILED\n", failures);
        return 1;
    }
}
