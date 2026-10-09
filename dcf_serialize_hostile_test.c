/**
 * @file dcf_serialize_hostile_test.c
 * @brief Hostile-input regression suite for the DCF serialization shim
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
 *
 * Every test here feeds the library bytes (or API arguments) that a hostile
 * peer, or a careless caller reading a hostile length, can produce, and states
 * what a safe library does with them. Findings are tagged S1..S8; S0 are
 * positive controls (valid input must keep working).
 *
 * Each test runs in its own forked child with an 8 MiB stack limit and a 30 s
 * alarm, so a crash, a sanitizer abort, a stack overflow or a hang is reported
 * as a failure of that one test instead of ending the suite. Build with
 * -fsanitize=address,undefined to get the memory-safety findings as aborts.
 *
 * Tests that need an API added by the hardening change are compiled only when
 * the header defines DCF_SER_HARDENED_API; against an older library they
 * report "API absent" and FAIL, so a build of the old library is red.
 *
 * Usage: dcf_serialize_hostile_test [-v] [substring-of-test-name]
 */

#define _POSIX_C_SOURCE 200809L

/* the suite exercises the deprecated dcf_ser_message_length() on purpose */
#define DCF_SER_NO_DEPRECATION_WARNINGS 1
#include "dcf_serialize.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ============================================================================
 * Harness
 * ============================================================================ */

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

#define CHECK_EQ(got, want) do { \
    long long _g = (long long)(got), _w = (long long)(want); \
    if (_g != _w) { \
        fprintf(stderr, "FAIL: %s == 0x%llx, want 0x%llx (%s:%d)\n", #got, \
                (unsigned long long)_g, (unsigned long long)_w, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

#define CHECK_OK(call) CHECK_EQ((call), DCF_SER_OK)
#define CHECK_ERR(call) do { \
    DCFSerError _e = (call); \
    if (_e == DCF_SER_OK) { \
        fprintf(stderr, "FAIL: %s returned OK, want an error (%s:%d)\n", #call, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

#ifdef DCF_SER_HARDENED_API
#define API_ABSENT_PROLOGUE
#else
#define API_ABSENT_PROLOGUE do { \
    fprintf(stderr, "FAIL: API absent (this library lacks the hardening API)\n"); \
    return 1; \
} while (0)
#endif

#ifdef DCF_SER_ERR_POLICY
#define ERR_POLICY DCF_SER_ERR_POLICY
#else
#define ERR_POLICY 0x208
#endif

/* ============================================================================
 * Builders
 * ============================================================================ */

typedef struct { uint8_t* p; size_t n, cap; } Buf;

static void bput(Buf* b, const void* d, size_t n) {
    if (b->n + n > b->cap) {
        size_t nc = b->cap ? b->cap : 64;
        while (nc < b->n + n) nc *= 2;
        b->p = (uint8_t*)realloc(b->p, nc);
        if (!b->p) { fprintf(stderr, "FAIL: test out of memory\n"); exit(2); }
        b->cap = nc;
    }
    if (n) memcpy(b->p + b->n, d, n);
    b->n += n;
}
static void b8(Buf* b, unsigned v)  { uint8_t x = (uint8_t)v; bput(b, &x, 1); }
static void b16(Buf* b, unsigned v) { b8(b, v >> 8); b8(b, v & 0xFF); }
static void b32(Buf* b, uint32_t v) { b16(b, v >> 16); b16(b, v & 0xFFFF); }
static void bzero(Buf* b, size_t n) { while (n--) b8(b, 0); }

/* A frame in a malloc block of EXACTLY its length (so ASan sees any overread).
 * plen_field is the payload_len written in the header (may lie); crc selects
 * whether a CRC over header+payload is appended; trailing bytes follow. */
static uint8_t* mkframe(uint8_t flags, uint16_t version, const uint8_t* pl, size_t plen,
                        uint32_t plen_field, int crc, size_t trailing, size_t* out_len) {
    size_t total = 17 + plen + (crc ? 4 : 0) + trailing;
    uint8_t* f = (uint8_t*)malloc(total);
    if (!f) { fprintf(stderr, "FAIL: test out of memory\n"); exit(2); }
    f[0] = 0x44; f[1] = 0x43; f[2] = 0x46; f[3] = 0x53;
    f[4] = (uint8_t)(version >> 8); f[5] = (uint8_t)version;
    f[6] = 0x00; f[7] = 0x01;
    f[8] = flags;
    f[9] = (uint8_t)(plen_field >> 24); f[10] = (uint8_t)(plen_field >> 16);
    f[11] = (uint8_t)(plen_field >> 8); f[12] = (uint8_t)plen_field;
    f[13] = 0; f[14] = 0; f[15] = 0; f[16] = 7;
    if (plen) memcpy(f + 17, pl, plen);
    size_t off = 17 + plen;
    if (crc) {
        uint32_t c = dcf_ser_crc32(f, off);
        f[off] = (uint8_t)(c >> 24); f[off + 1] = (uint8_t)(c >> 16);
        f[off + 2] = (uint8_t)(c >> 8); f[off + 3] = (uint8_t)c;
        off += 4;
    }
    for (size_t i = 0; i < trailing; i++) f[off + i] = 0xAA;
    *out_len = total;
    return f;
}

static uint8_t* okframe(const uint8_t* pl, size_t plen, size_t* out_len) {
    return mkframe(0, 0x0520, pl, plen, (uint32_t)plen, 1, 0, out_len);
}

/* Policy used by tests that must reach a reader whose payload the strict
 * validator would refuse up front: skip the structural walk, keep the rest. */
#ifdef DCF_SER_HARDENED_API
#define POL_RAW DCF_SER_POLICY_ALLOW_UNSTRUCTURED
#else
#define POL_RAW 0u
#endif

static DCFSerError open_reader(DCFSerReader* r, const uint8_t* f, size_t n, uint32_t pol) {
    DCFSerError e = dcf_ser_reader_init(r, f, n);
    if (e != DCF_SER_OK) return e;
#ifdef DCF_SER_HARDENED_API
    e = dcf_ser_reader_set_policy(r, pol);
    if (e != DCF_SER_OK) return e;
#else
    (void)pol;
#endif
    return dcf_ser_reader_validate(r);
}

/* The reader invariant every API call must preserve. */
static int reader_sane(const DCFSerReader* r, size_t plen) {
    return r->position <= r->payload_end && dcf_ser_reader_remaining(r) <= plen;
}

/* Skip one value out of payload `pl` (frame accepted under POL_RAW). */
static int skip_case(const uint8_t* pl, size_t plen, int want_err_code, const char* what) {
    size_t flen;
    uint8_t* f = okframe(pl, plen, &flen);
    DCFSerReader r;
    DCFSerError e = open_reader(&r, f, flen, POL_RAW);
    if (e != DCF_SER_OK) {
        fprintf(stderr, "FAIL: %s: frame did not open: 0x%x\n", what, e);
        return 1;
    }
    e = dcf_ser_reader_skip(&r);
    if (e == DCF_SER_OK) {
        fprintf(stderr, "FAIL: %s: skip returned OK (position=%zu payload_end=%zu remaining=%zu)\n",
                what, r.position, r.payload_end, dcf_ser_reader_remaining(&r));
        return 1;
    }
    if (want_err_code && (int)e != want_err_code) {
        fprintf(stderr, "FAIL: %s: skip returned 0x%x, want 0x%x\n", what, e, want_err_code);
        return 1;
    }
    if (!reader_sane(&r, plen)) {
        fprintf(stderr, "FAIL: %s: reader invariant broken after failed skip: position=%zu "
                "payload_end=%zu remaining=%zu\n", what, r.position, r.payload_end,
                dcf_ser_reader_remaining(&r));
        return 1;
    }
    free(f);
    return 0;
}

/* ============================================================================
 * S0 - positive controls: valid input keeps working
 * ============================================================================ */

static int t_s0_roundtrip_all_types(void) {
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 0x42, DCF_SER_FLAG_PRIORITY));
    CHECK_OK(dcf_ser_write_null(&w));
    CHECK_OK(dcf_ser_write_bool(&w, true));
    CHECK_OK(dcf_ser_write_u8(&w, 1));
    CHECK_OK(dcf_ser_write_i16(&w, -2));
    CHECK_OK(dcf_ser_write_u32(&w, 3));
    CHECK_OK(dcf_ser_write_i64(&w, -4));
    CHECK_OK(dcf_ser_write_f32(&w, 1.5f));
    CHECK_OK(dcf_ser_write_f64(&w, 2.5));
    CHECK_OK(dcf_ser_write_varint(&w, 0));
    CHECK_OK(dcf_ser_write_varint(&w, 127));
    CHECK_OK(dcf_ser_write_varint(&w, 128));
    CHECK_OK(dcf_ser_write_varint(&w, UINT64_MAX));
    CHECK_OK(dcf_ser_write_varsint(&w, INT64_MIN));
    CHECK_OK(dcf_ser_write_string(&w, "h\xC3\xA9llo \xE2\x82\xAC \xF0\x9F\x98\x80"));
    CHECK_OK(dcf_ser_write_bytes(&w, "\x00\xFF\xFE", 3));
    uint8_t uu[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    CHECK_OK(dcf_ser_write_uuid(&w, uu));
    CHECK_OK(dcf_ser_write_timestamp(&w, 1704067200000000ULL));
    CHECK_OK(dcf_ser_write_array_begin(&w, DCF_TYPE_U32, 2));
    CHECK_OK(dcf_ser_write_u32(&w, 1));
    CHECK_OK(dcf_ser_write_u32(&w, 2));
    CHECK_OK(dcf_ser_write_array_end(&w));
    CHECK_OK(dcf_ser_write_map_begin(&w, DCF_TYPE_U8, DCF_TYPE_U8, 1));
    CHECK_OK(dcf_ser_write_u8(&w, 1));
    CHECK_OK(dcf_ser_write_u8(&w, 2));
    CHECK_OK(dcf_ser_write_map_end(&w));
    CHECK_OK(dcf_ser_write_struct_begin(&w, 9));
    CHECK_OK(dcf_ser_write_field(&w, 1, DCF_TYPE_U8));
    CHECK_OK(dcf_ser_write_u8(&w, 7));
    CHECK_OK(dcf_ser_write_struct_end(&w));
    const uint8_t* d; size_t n;
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));

    DCFSerReader r;
    CHECK_OK(dcf_ser_reader_init(&r, d, n));
    CHECK_OK(dcf_ser_reader_validate(&r));
    /* skip every top-level value and land exactly on the end */
    int count = 0;
    while (!dcf_ser_reader_at_end(&r)) {
        CHECK_OK(dcf_ser_reader_skip(&r));
        count++;
        CHECK(count < 100);
    }
    CHECK_EQ(count, 20);
    CHECK_EQ(dcf_ser_reader_remaining(&r), 0);
    CHECK_OK(dcf_ser_validate_message(d, n));

    /* and read the scalars back as VALUES, not just over them (a skip-only round trip is how
     * the sign-fill bug in write_varsint went unnoticed) */
    DCFSerReader t;
    CHECK_OK(dcf_ser_reader_init(&t, d, n));
    CHECK_OK(dcf_ser_reader_validate(&t));
    bool bv; uint8_t u8v; int16_t i16v; uint32_t u32v; int64_t i64v; float fv; double dv; uint64_t uv; int64_t sv;
    CHECK_OK(dcf_ser_read_null(&t));
    CHECK_OK(dcf_ser_read_bool(&t, &bv));      CHECK(bv);
    CHECK_OK(dcf_ser_read_u8(&t, &u8v));       CHECK_EQ(u8v, 1);
    CHECK_OK(dcf_ser_read_i16(&t, &i16v));     CHECK_EQ(i16v, -2);
    CHECK_OK(dcf_ser_read_u32(&t, &u32v));     CHECK_EQ(u32v, 3);
    CHECK_OK(dcf_ser_read_i64(&t, &i64v));     CHECK(i64v == -4);
    CHECK_OK(dcf_ser_read_f32(&t, &fv));       CHECK(fv == 1.5f);
    CHECK_OK(dcf_ser_read_f64(&t, &dv));       CHECK(dv == 2.5);
    CHECK_OK(dcf_ser_read_varint(&t, &uv));    CHECK(uv == 0);
    CHECK_OK(dcf_ser_read_varint(&t, &uv));    CHECK(uv == 127);
    CHECK_OK(dcf_ser_read_varint(&t, &uv));    CHECK(uv == 128);
    CHECK_OK(dcf_ser_read_varint(&t, &uv));    CHECK(uv == UINT64_MAX);
    CHECK_OK(dcf_ser_read_varsint(&t, &sv));
    if (sv != INT64_MIN) {
        fprintf(stderr, "FAIL: write_varsint(INT64_MIN) read back as %lld\n", (long long)sv);
        return 1;
    }
    dcf_ser_writer_destroy(&w);
    return 0;
}

static int t_s0_varint_extremes_roundtrip(void) {
    static const uint64_t vals[] = {0, 1, 127, 128, 16383, 16384, 0xFFFFFFFFULL,
                                    0x7FFFFFFFFFFFFFFFULL, 0x8000000000000000ULL, UINT64_MAX};
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    for (size_t i = 0; i < sizeof vals / sizeof vals[0]; i++) CHECK_OK(dcf_ser_write_varint(&w, vals[i]));
    const uint8_t* d; size_t n;
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    DCFSerReader r;
    CHECK_OK(dcf_ser_reader_init(&r, d, n));
    CHECK_OK(dcf_ser_reader_validate(&r));
    for (size_t i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        uint64_t v = 0;
        CHECK_OK(dcf_ser_read_varint(&r, &v));
        CHECK(v == vals[i]);
    }
    dcf_ser_writer_destroy(&w);
    return 0;
}

/* ============================================================================
 * S1 - reader_skip advances position without bounds checks
 * ============================================================================ */

static int t_s1_skip_fixed_short(void) {
    static const struct { uint8_t tag; unsigned size; } fx[] = {
        {0x01,1},{0x02,1},{0x03,1},{0x04,2},{0x05,2},{0x06,4},{0x07,4},{0x0A,4},
        {0x08,8},{0x09,8},{0x0B,8},{0x30,8},{0x31,8},{0x13,16},
    };
    for (size_t i = 0; i < sizeof fx / sizeof fx[0]; i++) {
        for (unsigned have = 0; have < fx[i].size; have++) {
            Buf b = {0};
            b8(&b, fx[i].tag);
            for (unsigned k = 0; k < have; k++) b8(&b, 0x55);
            char what[64];
            snprintf(what, sizeof what, "tag 0x%02x with %u of %u bytes", fx[i].tag, have, fx[i].size);
            if (skip_case(b.p, b.n, 0, what)) return 1;
            free(b.p);
        }
    }
    return 0;
}

static int t_s1_skip_string_bytes_len_beyond_payload(void) {
    static const uint32_t lens[] = {3, 5, 0x7FFFFFFFu, 0x80000000u, 0xFFFFFFF0u, 0xFFFFFFFFu};
    static const uint8_t tags[] = {0x11, 0x12};
    for (size_t t = 0; t < 2; t++) {
        for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
            Buf b = {0};
            b8(&b, tags[t]); b32(&b, lens[i]);
            b8(&b, 'a'); b8(&b, 'b');           /* only 2 bytes of body */
            char what[64];
            snprintf(what, sizeof what, "tag 0x%02x len 0x%x, 2 bytes present", tags[t], lens[i]);
            if (skip_case(b.p, b.n, 0, what)) return 1;
            free(b.p);
        }
    }
    return 0;
}

static int t_s1_skip_map_struct_header_short(void) {
    for (unsigned have = 0; have < 6; have++) {        /* a MAP header after the tag is key_type, val_type, u32 count = 6 bytes */
        Buf b = {0};
        b8(&b, 0x21);
        for (unsigned k = 0; k < have; k++) b8(&b, 0x00);
        char what[48];
        snprintf(what, sizeof what, "MAP tag with %u header bytes", have);
        if (skip_case(b.p, b.n, 0, what)) return 1;
        free(b.p);
    }
    for (unsigned have = 0; have < 2; have++) {        /* STRUCT header is a u16 type id */
        Buf b = {0};
        b8(&b, 0x22);
        for (unsigned k = 0; k < have; k++) b8(&b, 0x00);
        char what[48];
        snprintf(what, sizeof what, "STRUCT tag with %u id bytes", have);
        if (skip_case(b.p, b.n, 0, what)) return 1;
        free(b.p);
    }
    return 0;
}

static int t_s1_remaining_never_underflows(void) {
    Buf b = {0};
    b8(&b, 0x08); b8(&b, 1); b8(&b, 2); b8(&b, 3);      /* U64 tag, 3 of 8 bytes */
    size_t flen;
    uint8_t* f = okframe(b.p, b.n, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, POL_RAW));
    (void)dcf_ser_reader_skip(&r);
    size_t rem = dcf_ser_reader_remaining(&r);
    if (rem > b.n) {
        fprintf(stderr, "FAIL: remaining() = %zu after skip over a %zu byte payload "
                "(position=%zu payload_end=%zu)\n", rem, b.n, r.position, r.payload_end);
        return 1;
    }
    return 0;
}

static int t_s1_read_raw_ptr_len_wrap(void) {
    Buf b = {0};
    bzero(&b, 4);
    size_t flen;
    uint8_t* f = okframe(b.p, b.n, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, POL_RAW));
    const void* p = NULL;
    /* position(17) + len wraps to a small number: must still be refused */
    CHECK_ERR(dcf_ser_read_raw_ptr(&r, &p, SIZE_MAX - 5));
    CHECK_ERR(dcf_ser_read_raw_ptr(&r, &p, SIZE_MAX));
    CHECK_ERR(dcf_ser_read_raw_ptr(&r, &p, (size_t)1 << 63));
    CHECK(reader_sane(&r, b.n));
    return 0;
}

static int t_s1_read_raw_len_wrap_copies(void) {
    Buf b = {0};
    bzero(&b, 4);
    size_t flen;
    uint8_t* f = okframe(b.p, b.n, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, POL_RAW));
    uint8_t out[16];
    /* the vulnerable path memcpy()s len bytes; len is whatever the caller read off the wire */
    CHECK_ERR(dcf_ser_read_raw(&r, out, SIZE_MAX - 5));
    CHECK(reader_sane(&r, b.n));
    return 0;
}

/* ============================================================================
 * S2 - reader_skip recurses without a depth limit
 * ============================================================================ */

enum { K_ARRAY, K_MAP, K_STRUCT };

/* `depth` nested containers of `kind`; the innermost is empty. Returns payload. */
static void nest(Buf* b, int kind, size_t depth) {
    /* open */
    for (size_t i = 0; i < depth; i++) {
        int innermost = (i + 1 == depth);
        if (kind == K_ARRAY) { b8(b, 0x20); b8(b, 0x20); b32(b, innermost ? 0 : 1); }
        else if (kind == K_MAP) { b8(b, 0x21); b8(b, 0x21); b8(b, 0x00); b32(b, innermost ? 0 : 1); }
        else { b8(b, 0x22); b16(b, 1); if (!innermost) { b16(b, 1); b8(b, 0x22); } }
    }
    /* close: a map's second element, a struct's end marker */
    for (size_t i = 0; i + 1 < depth; i++) {
        if (kind == K_MAP) b8(b, 0x00);
    }
    if (kind == K_STRUCT) for (size_t i = 0; i < depth; i++) { b16(b, 0); b8(b, 0); }
}

static int deep_skip(int kind, size_t depth, int want, const char* what) {
    Buf b = {0};
    nest(&b, kind, depth);
    int rc = skip_case(b.p, b.n, want, what);
    free(b.p);
    return rc;
}

static int t_s2_skip_nested_array_1m(void)  { return deep_skip(K_ARRAY, 1000000, 0x104, "1M nested arrays"); }
static int t_s2_skip_nested_map_1m(void)    { return deep_skip(K_MAP, 1000000, 0x104, "1M nested maps"); }
static int t_s2_skip_nested_struct_1m(void) { return deep_skip(K_STRUCT, 1000000, 0x104, "1M nested structs"); }

static int t_s2_skip_depth_boundary(void) {
    for (int kind = K_ARRAY; kind <= K_STRUCT; kind++) {
        Buf ok = {0}, bad = {0};
        nest(&ok, kind, DCF_SER_MAX_DEPTH);
        nest(&bad, kind, DCF_SER_MAX_DEPTH + 1);
        size_t flen;
        uint8_t* f = okframe(ok.p, ok.n, &flen);
        DCFSerReader r;
        CHECK_OK(open_reader(&r, f, flen, POL_RAW));
        CHECK_OK(dcf_ser_reader_skip(&r));                 /* exactly MAX_DEPTH: accepted */
        CHECK(dcf_ser_reader_at_end(&r));
        free(f);
        if (skip_case(bad.p, bad.n, 0x104, "MAX_DEPTH+1 nesting")) return 1;
        free(ok.p); free(bad.p);
    }
    return 0;
}

static int t_s2_schema_unknown_field_deep(void) {
    /* the real consumer path: read_struct_schema skips unknown fields */
    static const DCFSerField fl[] = { {"a", 1, DCF_TYPE_U8, DCF_FIELD_OPTIONAL, 0, 1} };
    static const DCFSerSchema sc = { "S", 0x77, fl, 1, 1 };
    Buf b = {0};
    b8(&b, 0x22); b16(&b, 0x77);
    b16(&b, 9); b8(&b, 0x20);                           /* unknown field 9 ... */
    for (size_t i = 0; i < 1000000; i++) { b8(&b, 0x20); b8(&b, 0x20); b32(&b, 1); }
    size_t flen;
    uint8_t* f = okframe(b.p, b.n, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, POL_RAW));
    uint8_t out = 0;
    DCFSerError e = dcf_ser_read_struct_schema(&r, &out, &sc);
    CHECK(e != DCF_SER_OK);
    return 0;
}

/* ============================================================================
 * S3 - count arithmetic: u32 overflow, counts never checked against bytes
 * ============================================================================ */

static int t_s3_map_count_overflow(void) {
    static const uint32_t counts[] = {0x80000000u, 0x80000001u, 0xFFFFFFFFu, 0x40000000u};
    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        Buf b = {0};
        b8(&b, 0x21); b8(&b, 0x02); b8(&b, 0x02); b32(&b, counts[i]);
        b8(&b, 0x00); b8(&b, 0x00); b8(&b, 0x00); b8(&b, 0x00);
        char what[48];
        snprintf(what, sizeof what, "map count 0x%x with 4 bytes of entries", counts[i]);
        if (skip_case(b.p, b.n, 0, what)) return 1;
        free(b.p);
    }
    return 0;
}

static int t_s3_array_count_beyond_payload(void) {
    static const uint32_t counts[] = {5, 0x7FFFFFFFu, 0xFFFFFFFFu};
    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        Buf b = {0};
        b8(&b, 0x20); b8(&b, 0x00); b32(&b, counts[i]);
        b8(&b, 0x00); b8(&b, 0x00);                     /* two NULL elements, not `count` */
        char what[48];
        snprintf(what, sizeof what, "array count 0x%x with 2 elements", counts[i]);
        if (skip_case(b.p, b.n, 0, what)) return 1;
        free(b.p);
    }
    return 0;
}

static int t_s3_count_equal_to_payload_ok(void) {
    /* control: an array of exactly as many NULL elements as it declares is fine */
    Buf b = {0};
    b8(&b, 0x20); b8(&b, 0x00); b32(&b, 10);
    bzero(&b, 10);
    size_t flen;
    uint8_t* f = okframe(b.p, b.n, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, POL_RAW));
    CHECK_OK(dcf_ser_reader_skip(&r));
    CHECK(dcf_ser_reader_at_end(&r));
    return 0;
}

static int t_s3_typed_begin_counts_capped(void) {
    {
        Buf b = {0};
        b8(&b, 0x20); b8(&b, 0x06); b32(&b, 0xFFFFFFFFu);
        size_t flen;
        uint8_t* f = okframe(b.p, b.n, &flen);
        DCFSerReader r;
        CHECK_OK(open_reader(&r, f, flen, POL_RAW));
        DCFSerType t; size_t c = 0;
        CHECK_ERR(dcf_ser_read_array_begin(&r, &t, &c));
        free(f); free(b.p);
    }
    {
        Buf b = {0};
        b8(&b, 0x21); b8(&b, 0x06); b8(&b, 0x06); b32(&b, 0xFFFFFFFFu);
        size_t flen;
        uint8_t* f = okframe(b.p, b.n, &flen);
        DCFSerReader r;
        CHECK_OK(open_reader(&r, f, flen, POL_RAW));
        DCFSerType kt, vt; size_t c = 0;
        CHECK_ERR(dcf_ser_read_map_begin(&r, &kt, &vt, &c));
        free(f); free(b.p);
    }
    return 0;
}

/* ============================================================================
 * S4 - header flags, length caps, framing ambiguity
 * ============================================================================ */

static int t_s4_no_crc_refused_by_default(void) {
    Buf b = {0};
    b8(&b, 0x02); b8(&b, 0x09);                         /* u8 9 */
    size_t flen;
    uint8_t* f = mkframe(DCF_SER_FLAG_NO_CRC, 0x0520, b.p, b.n, (uint32_t)b.n, 0, 0, &flen);
    DCFSerReader r;
    CHECK_ERR(open_reader(&r, f, flen, 0));
    CHECK_ERR(dcf_ser_validate_message(f, flen));
    return 0;
}

static int t_s4_no_crc_garbage_payload_not_trusted(void) {
    /* an attacker simply sets NO_CRC and drops the checksum: nothing vouches for the bytes */
    Buf b = {0};
    for (int i = 0; i < 32; i++) b8(&b, 0xEE);
    size_t flen;
    uint8_t* f = mkframe(DCF_SER_FLAG_NO_CRC, 0x0520, b.p, b.n, (uint32_t)b.n, 0, 0, &flen);
    DCFSerReader r;
    CHECK_ERR(open_reader(&r, f, flen, 0));
    return 0;
}

static int t_s4_no_crc_allowed_by_policy(void) {
    API_ABSENT_PROLOGUE;
#ifdef DCF_SER_HARDENED_API
    Buf b = {0};
    b8(&b, 0x02); b8(&b, 0x09);
    size_t flen;
    uint8_t* f = mkframe(DCF_SER_FLAG_NO_CRC, 0x0520, b.p, b.n, (uint32_t)b.n, 0, 0, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, DCF_SER_POLICY_ALLOW_NO_CRC));
    CHECK(!r.crc_verified);
    uint8_t v = 0;
    CHECK_OK(dcf_ser_read_u8(&r, &v));
    CHECK_EQ(v, 9);
    /* the opt-in is per reader: a fresh reader is strict again */
    DCFSerReader r2;
    CHECK_ERR(open_reader(&r2, f, flen, 0));
#endif
    return 0;
}

static int t_s4_unsupported_flag_bits(void) {
    static const uint8_t bits[] = {0x01, 0x02, 0x40, 0x80};
    Buf b = {0};
    b8(&b, 0x02); b8(&b, 0x09);
    for (size_t i = 0; i < sizeof bits; i++) {
        size_t flen;
        uint8_t* f = mkframe(bits[i], 0x0520, b.p, b.n, (uint32_t)b.n, 1, 0, &flen);
        DCFSerReader r;
        DCFSerError e = open_reader(&r, f, flen, 0);
        if (e == DCF_SER_OK) {
            fprintf(stderr, "FAIL: flag bit 0x%02x accepted and ignored\n", bits[i]);
            return 1;
        }
        free(f);
    }
    return 0;
}

static int t_s4_extended_and_reserved_never_allowed(void) {
    API_ABSENT_PROLOGUE;
#ifdef DCF_SER_HARDENED_API
    Buf b = {0};
    b8(&b, 0x02); b8(&b, 0x09);
    const uint32_t every = DCF_SER_POLICY_ALL;                  /* every flag at once */
    static const uint8_t never[] = {0x80, 0x40};
    for (size_t i = 0; i < sizeof never; i++) {
        size_t flen;
        uint8_t* f = mkframe(never[i], 0x0520, b.p, b.n, (uint32_t)b.n, 1, 0, &flen);
        DCFSerReader r;
        CHECK_ERR(open_reader(&r, f, flen, every));
        free(f);
    }
    /* COMPRESSED / ENCRYPTED are application flags: only the explicit opt-in lets them through */
    static const uint8_t app[] = {0x01, 0x02};
    for (size_t i = 0; i < sizeof app; i++) {
        size_t flen;
        uint8_t* f = mkframe(app[i], 0x0520, b.p, b.n, (uint32_t)b.n, 1, 0, &flen);
        DCFSerReader r, r2;
        CHECK_ERR(open_reader(&r, f, flen, DCF_SER_POLICY_ALLOW_NO_CRC));
        CHECK_OK(open_reader(&r2, f, flen, DCF_SER_POLICY_ALLOW_APP_FLAGS));
        free(f);
    }
#endif
    return 0;
}

static int t_s4_payload_len_cap(void) {
    /* payload_len above DCF_SER_MAX_MESSAGE is refused even when the bytes are all there and CRC-valid */
    size_t plen = (size_t)DCF_SER_MAX_MESSAGE + 1;
    uint8_t* pl = (uint8_t*)calloc(plen, 1);
    CHECK(pl != NULL);
    size_t flen;
    uint8_t* f = mkframe(0, 0x0520, pl, plen, (uint32_t)plen, 1, 0, &flen);
    DCFSerReader r;
    DCFSerError e = open_reader(&r, f, flen, POL_RAW);
    if (e == DCF_SER_OK) {
        fprintf(stderr, "FAIL: payload_len %zu (> DCF_SER_MAX_MESSAGE) accepted\n", plen);
        return 1;
    }
    CHECK_EQ(e, DCF_SER_ERR_TOO_LARGE);
    free(f);
    /* control: exactly DCF_SER_MAX_MESSAGE is allowed */
    f = mkframe(0, 0x0520, pl, plen - 1, (uint32_t)(plen - 1), 1, 0, &flen);
    CHECK_OK(open_reader(&r, f, flen, POL_RAW));
    return 0;
}

static int t_s4_trailing_bytes_refused(void) {
    Buf b = {0};
    b8(&b, 0x02); b8(&b, 0x09);
    size_t flen;
    uint8_t* f = mkframe(0, 0x0520, b.p, b.n, (uint32_t)b.n, 1, 3, &flen);
    DCFSerReader r;
    DCFSerError e = open_reader(&r, f, flen, 0);
    if (e == DCF_SER_OK) {
        fprintf(stderr, "FAIL: 3 bytes after the CRC silently accepted\n");
        return 1;
    }
    CHECK_EQ(e, ERR_POLICY);
    return 0;
}

static int t_s4_trailing_bytes_allowed_by_policy(void) {
    API_ABSENT_PROLOGUE;
#ifdef DCF_SER_HARDENED_API
    Buf b = {0};
    b8(&b, 0x02); b8(&b, 0x09);
    size_t flen;
    uint8_t* f = mkframe(0, 0x0520, b.p, b.n, (uint32_t)b.n, 1, 3, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, DCF_SER_POLICY_ALLOW_TRAILING));
    CHECK_EQ(r.payload_end, 17 + b.n);
    uint8_t v = 0;
    CHECK_OK(dcf_ser_read_u8(&r, &v));
    CHECK_EQ(v, 9);
#endif
    return 0;
}

static int t_s4_policy_setter_rules(void) {
    API_ABSENT_PROLOGUE;
#ifdef DCF_SER_HARDENED_API
    Buf b = {0};
    b8(&b, 0x02); b8(&b, 0x09);
    size_t flen;
    uint8_t* f = okframe(b.p, b.n, &flen);
    DCFSerReader r;
    CHECK_OK(dcf_ser_reader_init(&r, f, flen));
    CHECK_EQ(r.policy, 0);                                    /* strict by default */
    CHECK_EQ(dcf_ser_reader_set_policy(&r, 0x80000000u), DCF_SER_ERR_INVALID_ARG);   /* unknown bit */
    CHECK_EQ(r.policy, 0);
    CHECK_EQ(dcf_ser_reader_set_policy(NULL, 0), DCF_SER_ERR_NULL_PTR);
    CHECK_OK(dcf_ser_reader_set_policy(&r, DCF_SER_POLICY_ALLOW_TRAILING));
    CHECK_OK(dcf_ser_reader_validate(&r));
    /* frozen once validated: a policy change cannot retroactively bless a validated frame */
    CHECK_EQ(dcf_ser_reader_set_policy(&r, DCF_SER_POLICY_ALLOW_NO_CRC), DCF_SER_ERR_INVALID_ARG);
#endif
    return 0;
}

static int t_s4_version_major_checked_minor_free(void) {
    Buf b = {0};
    b8(&b, 0x02); b8(&b, 0x09);
    size_t flen;
    DCFSerReader r;
    uint8_t* f = mkframe(0, 0x0599, b.p, b.n, (uint32_t)b.n, 1, 0, &flen);
    CHECK_OK(open_reader(&r, f, flen, 0));                    /* any minor */
    free(f);
    f = mkframe(0, 0x0620, b.p, b.n, (uint32_t)b.n, 1, 0, &flen);
    CHECK_EQ(open_reader(&r, f, flen, 0), DCF_SER_ERR_VERSION_MISMATCH);
    return 0;
}

static int t_s4_streaming_flags_still_fine(void) {
    Buf b = {0};
    b8(&b, 0x02); b8(&b, 0x09);
    size_t flen;
    DCFSerReader r;
    uint8_t* f = mkframe(0x04 | 0x08 | 0x10, 0x0520, b.p, b.n, (uint32_t)b.n, 1, 0, &flen);
    CHECK_OK(open_reader(&r, f, flen, 0));
    return 0;
}

/* ============================================================================
 * S5 - writer space arithmetic wraps
 * ============================================================================ */

static int t_s5_write_raw_wrap_external(void) {
    uint8_t buf[1024];
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init_buffer(&w, buf, sizeof buf, 1, 0));
    uint8_t src[8] = {0};
    /* position(17) + len wraps to 6: the unchecked path memcpy()s ~2^64 bytes */
    CHECK_ERR(dcf_ser_write_raw(&w, src, SIZE_MAX - 10));
    CHECK(w.position <= w.capacity);
    return 0;
}

static int t_s5_write_raw_wrap_owned(void) {
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    uint8_t src[8] = {0};
    CHECK_ERR(dcf_ser_write_raw(&w, src, SIZE_MAX - 10));
    CHECK(w.position <= w.capacity);
    dcf_ser_writer_destroy(&w);
    return 0;
}

static int t_s5_write_reserve_wrap(void) {
    uint8_t buf[1024];
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init_buffer(&w, buf, sizeof buf, 1, 0));
    uint8_t* p = NULL;
    DCFSerError e = dcf_ser_write_reserve(&w, SIZE_MAX - 10, &p);
    if (e == DCF_SER_OK) {
        fprintf(stderr, "FAIL: reserve(SIZE_MAX-10) returned OK; position is now %zu (capacity %zu)\n",
                w.position, w.capacity);
        return 1;
    }
    CHECK(w.position <= w.capacity);
    return 0;
}

static int t_s5_grow_does_not_hang(void) {
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    uint8_t src[8] = {0};
    /* position + len >= 2^63: writer_grow's doubling loop overflows to 0 and never ends */
    CHECK_ERR(dcf_ser_write_raw(&w, src, ((size_t)1 << 63) + 5));
    CHECK_ERR(dcf_ser_write_reserve(&w, ((size_t)1 << 63) + 5, &(uint8_t*){NULL}));
    dcf_ser_writer_destroy(&w);
    return 0;
}

static int t_s5_raw_and_reserve_capped(void) {
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    uint8_t* p = NULL;
    CHECK_EQ(dcf_ser_write_reserve(&w, (size_t)DCF_SER_MAX_MESSAGE + 1, &p), DCF_SER_ERR_TOO_LARGE);
    dcf_ser_writer_destroy(&w);
    /* external buffer large enough in principle: the cap is on the message, not the buffer */
    uint8_t* big = (uint8_t*)malloc((size_t)DCF_SER_MAX_MESSAGE + 64);
    CHECK(big != NULL);
    CHECK_OK(dcf_ser_writer_init_buffer(&w, big, (size_t)DCF_SER_MAX_MESSAGE + 64, 1, 0));
    CHECK_EQ(dcf_ser_write_reserve(&w, (size_t)DCF_SER_MAX_MESSAGE + 1, &p), DCF_SER_ERR_TOO_LARGE);
    free(big);
    return 0;
}

static int t_s5_finish_refuses_oversize_payload(void) {
    size_t cap = (size_t)DCF_SER_MAX_MESSAGE + 64;
    uint8_t* big = (uint8_t*)malloc(cap);
    CHECK(big != NULL);
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init_buffer(&w, big, cap, 1, 0));
    uint8_t* p = NULL;
    CHECK_OK(dcf_ser_write_reserve(&w, (size_t)DCF_SER_MAX_MESSAGE, &p));     /* exactly the cap */
    DCFSerError we = dcf_ser_write_u8(&w, 1);                                 /* one value too many ... */
#ifdef DCF_SER_HARDENED_API
    CHECK_EQ(we, DCF_SER_ERR_TOO_LARGE);                                      /* ... is refused when written ... */
#else
    (void)we;
#endif
    const uint8_t* d; size_t n;                                               /* ... and finish() must not bless it */
    DCFSerError e = dcf_ser_writer_finish(&w, &d, &n);
    if (e == DCF_SER_OK) {
        fprintf(stderr, "FAIL: finish() produced a frame with payload_len %zu > DCF_SER_MAX_MESSAGE\n", n - 21);
        return 1;
    }
    free(big);
    return 0;
}

/* ============================================================================
 * S6 - schema API
 * ============================================================================ */

typedef struct { uint32_t a; uint32_t b; } Pair;
static const DCFSerField pair_fields[] = {
    DCF_SER_FIELD_DEF(Pair, a, DCF_TYPE_U32, 1),
    DCF_SER_FIELD_DEF(Pair, b, DCF_TYPE_U32, 2),
};
static const DCFSerSchema pair_schema = { "Pair", 0x300, pair_fields, 2, sizeof(Pair) };

/* Write a struct by hand: ids[i] with u32 values[i]; ntype overrides a field header type. */
static uint8_t* pair_frame(const uint16_t* ids, const uint32_t* vals, size_t n, size_t* flen) {
    DCFSerWriter w;
    if (dcf_ser_writer_init(&w, 3, 0) != DCF_SER_OK) exit(2);
    dcf_ser_write_struct_begin(&w, 0x300);
    for (size_t i = 0; i < n; i++) {
        dcf_ser_write_field(&w, ids[i], DCF_TYPE_U32);
        dcf_ser_write_u32(&w, vals[i]);
    }
    dcf_ser_write_struct_end(&w);
    const uint8_t* d; size_t len;
    if (dcf_ser_writer_finish(&w, &d, &len) != DCF_SER_OK) exit(2);
    uint8_t* copy = (uint8_t*)malloc(len);
    memcpy(copy, d, len);
    *flen = len;
    dcf_ser_writer_destroy(&w);
    return copy;
}

static int t_s6_required_field_enforced(void) {
    uint16_t ids[] = {1}; uint32_t vals[] = {5};
    size_t flen;
    uint8_t* f = pair_frame(ids, vals, 1, &flen);          /* field 2 (REQUIRED) is absent */
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, 0));
    Pair p = {0xdead, 0xbeef};
    DCFSerError e = dcf_ser_read_struct_schema(&r, &p, &pair_schema);
    if (e == DCF_SER_OK) {
        fprintf(stderr, "FAIL: DCF_FIELD_REQUIRED field 2 absent, read returned OK (a=%u b=%u)\n", p.a, p.b);
        return 1;
    }
    return 0;
}

static int t_s6_duplicate_field_refused(void) {
    uint16_t ids[] = {1, 2, 1}; uint32_t vals[] = {5, 6, 7};
    size_t flen;
    uint8_t* f = pair_frame(ids, vals, 3, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, 0));
    Pair p = {0, 0};
    DCFSerError e = dcf_ser_read_struct_schema(&r, &p, &pair_schema);
    if (e == DCF_SER_OK) {
        fprintf(stderr, "FAIL: field 1 sent twice (5 then 7), last one silently won: a=%u\n", p.a);
        return 1;
    }
    return 0;
}

static int t_s6_lax_policy_restores_old_behaviour(void) {
    API_ABSENT_PROLOGUE;
#ifdef DCF_SER_HARDENED_API
    {   /* missing required: tolerated under LAX_SCHEMA, field stays zero */
        uint16_t ids[] = {1}; uint32_t vals[] = {5};
        size_t flen;
        uint8_t* f = pair_frame(ids, vals, 1, &flen);
        DCFSerReader r;
        CHECK_OK(open_reader(&r, f, flen, DCF_SER_POLICY_LAX_SCHEMA));
        Pair p = {0xdead, 0xbeef};
        CHECK_OK(dcf_ser_read_struct_schema(&r, &p, &pair_schema));
        CHECK_EQ(p.a, 5); CHECK_EQ(p.b, 0);
    }
    {   /* duplicates: last wins under LAX_SCHEMA */
        uint16_t ids[] = {1, 2, 1}; uint32_t vals[] = {5, 6, 7};
        size_t flen;
        uint8_t* f = pair_frame(ids, vals, 3, &flen);
        DCFSerReader r;
        CHECK_OK(open_reader(&r, f, flen, DCF_SER_POLICY_LAX_SCHEMA));
        Pair p = {0, 0};
        CHECK_OK(dcf_ser_read_struct_schema(&r, &p, &pair_schema));
        CHECK_EQ(p.a, 7); CHECK_EQ(p.b, 6);
    }
#endif
    return 0;
}

static int t_s6_schema_roundtrip_control(void) {
    uint16_t ids[] = {1, 2}; uint32_t vals[] = {5, 6};
    size_t flen;
    uint8_t* f = pair_frame(ids, vals, 2, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, 0));
    Pair p = {0, 0};
    CHECK_OK(dcf_ser_read_struct_schema(&r, &p, &pair_schema));
    CHECK_EQ(p.a, 5); CHECK_EQ(p.b, 6);
    /* unknown extra field (id 9) is skipped, not an error */
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 3, 0));
    CHECK_OK(dcf_ser_write_struct_begin(&w, 0x300));
    CHECK_OK(dcf_ser_write_field(&w, 9, DCF_TYPE_ARRAY));
    CHECK_OK(dcf_ser_write_array_begin(&w, DCF_TYPE_U8, 2));
    CHECK_OK(dcf_ser_write_u8(&w, 1)); CHECK_OK(dcf_ser_write_u8(&w, 2));
    CHECK_OK(dcf_ser_write_array_end(&w));
    CHECK_OK(dcf_ser_write_field(&w, 1, DCF_TYPE_U32)); CHECK_OK(dcf_ser_write_u32(&w, 11));
    CHECK_OK(dcf_ser_write_field(&w, 2, DCF_TYPE_U32)); CHECK_OK(dcf_ser_write_u32(&w, 12));
    CHECK_OK(dcf_ser_write_struct_end(&w));
    const uint8_t* d; size_t n;
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    DCFSerReader r2;
    CHECK_OK(open_reader(&r2, d, n, 0));
    CHECK_OK(dcf_ser_read_struct_schema(&r2, &p, &pair_schema));
    CHECK_EQ(p.a, 11); CHECK_EQ(p.b, 12);
    dcf_ser_writer_destroy(&w);
    return 0;
}

typedef struct { const char* name; uint32_t id; } Named;
static const DCFSerField named_fields[] = {
    DCF_SER_FIELD_OPT(Named, name, DCF_TYPE_STRING, 1),
    DCF_SER_FIELD_OPT(Named, id, DCF_TYPE_U32, 2),
};
static const DCFSerSchema named_schema = { "Named", 0x301, named_fields, 2, sizeof(Named) };

static int t_s6_string_field_not_silently_dropped(void) {
    Named in = { "alice", 7 };
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 3, 0));
    CHECK_OK(dcf_ser_write_struct_schema(&w, &in, &named_schema));        /* the writer can emit it */
    const uint8_t* d; size_t n;
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    DCFSerReader r;
    CHECK_OK(open_reader(&r, d, n, 0));
    Named out = { (const char*)0x1, 0 };
    DCFSerError e = dcf_ser_read_struct_schema(&r, &out, &named_schema);
    if (e == DCF_SER_OK) {
        fprintf(stderr, "FAIL: schema read returned OK but dropped the STRING field (name=%p id=%u)\n",
                (const void*)out.name, out.id);
        return 1;
    }
    dcf_ser_writer_destroy(&w);
    return 0;
}

static int t_s6_schema_size_mismatch_read_overflows(void) {
    /* a mis-declared field: U64 but 4 bytes wide, in a 4-byte struct */
    static const DCFSerField fl[] = { {"x", 1, DCF_TYPE_U64, DCF_FIELD_REQUIRED, 0, 4} };
    static const DCFSerSchema sc = { "Bad", 0x302, fl, 1, 4 };
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 3, 0));
    CHECK_OK(dcf_ser_write_struct_begin(&w, 0x302));
    CHECK_OK(dcf_ser_write_field(&w, 1, DCF_TYPE_U64));
    CHECK_OK(dcf_ser_write_u64(&w, 0x1122334455667788ULL));
    CHECK_OK(dcf_ser_write_struct_end(&w));
    const uint8_t* d; size_t n;
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    DCFSerReader r;
    CHECK_OK(open_reader(&r, d, n, 0));
    uint8_t* target = (uint8_t*)malloc(4);                   /* exactly struct_size */
    CHECK(target != NULL);
    CHECK_ERR(dcf_ser_read_struct_schema(&r, target, &sc));
    free(target);
    dcf_ser_writer_destroy(&w);
    return 0;
}

static int t_s6_schema_offset_oob(void) {
    static const DCFSerField fl[] = { {"x", 1, DCF_TYPE_U32, DCF_FIELD_REQUIRED, 8, 4} };
    static const DCFSerSchema sc = { "Oob", 0x303, fl, 1, 4 };
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 3, 0));
    CHECK_OK(dcf_ser_write_struct_begin(&w, 0x303));
    CHECK_OK(dcf_ser_write_field(&w, 1, DCF_TYPE_U32));
    CHECK_OK(dcf_ser_write_u32(&w, 5));
    CHECK_OK(dcf_ser_write_struct_end(&w));
    const uint8_t* d; size_t n;
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    DCFSerReader r;
    CHECK_OK(open_reader(&r, d, n, 0));
    uint8_t* target = (uint8_t*)malloc(4);
    CHECK(target != NULL);
    CHECK_ERR(dcf_ser_read_struct_schema(&r, target, &sc));
    /* and the write direction reads out of bounds the same way */
    DCFSerWriter w2;
    CHECK_OK(dcf_ser_writer_init(&w2, 3, 0));
    CHECK_ERR(dcf_ser_write_struct_schema(&w2, target, &sc));
    free(target);
    dcf_ser_writer_destroy(&w);
    dcf_ser_writer_destroy(&w2);
    return 0;
}

static int t_s6_schema_size_mismatch_write(void) {
    static const DCFSerField fl[] = { {"x", 1, DCF_TYPE_U64, DCF_FIELD_REQUIRED, 0, 4} };
    static const DCFSerSchema sc = { "Bad", 0x302, fl, 1, 4 };
    uint8_t* src = (uint8_t*)malloc(4);
    CHECK(src != NULL);
    memset(src, 0x11, 4);
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 3, 0));
    CHECK_ERR(dcf_ser_write_struct_schema(&w, src, &sc));   /* reads 8 bytes out of a 4-byte block */
    free(src);
    dcf_ser_writer_destroy(&w);
    return 0;
}

#pragma pack(push, 1)
typedef struct { uint8_t pad; uint32_t v; uint64_t w; double d; } Packed;
#pragma pack(pop)
static const DCFSerField packed_fields[] = {
    { "v", 1, DCF_TYPE_U32, DCF_FIELD_REQUIRED, offsetof(Packed, v), 4 },
    { "w", 2, DCF_TYPE_U64, DCF_FIELD_REQUIRED, offsetof(Packed, w), 8 },
    { "d", 3, DCF_TYPE_F64, DCF_FIELD_REQUIRED, offsetof(Packed, d), 8 },
};
static const DCFSerSchema packed_schema = { "Packed", 0x304, packed_fields, 3, sizeof(Packed) };

static int t_s6_unaligned_fields(void) {
    Packed in;
    memset(&in, 0, sizeof in);
    in.v = 0x01020304; in.w = 0x1122334455667788ULL; in.d = 2.5;
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 3, 0));
    CHECK_OK(dcf_ser_write_struct_schema(&w, &in, &packed_schema));
    const uint8_t* d; size_t n;
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    DCFSerReader r;
    CHECK_OK(open_reader(&r, d, n, 0));
    Packed out;
    CHECK_OK(dcf_ser_read_struct_schema(&r, &out, &packed_schema));
    CHECK(out.v == in.v);
    CHECK(out.w == in.w);
    CHECK(out.d == in.d);
    dcf_ser_writer_destroy(&w);
    return 0;
}

/* ============================================================================
 * S7 - writer errors are not sticky; finish() is not idempotent-safe
 * ============================================================================ */

static int t_s7_failed_write_poisons_finish(void) {
    uint8_t buf[64];
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init_buffer(&w, buf, sizeof buf, 1, 0));
    uint8_t blob[100];
    memset(blob, 0x5A, sizeof blob);
    CHECK_OK(dcf_ser_write_u8(&w, 1));
    CHECK_ERR(dcf_ser_write_bytes(&w, blob, sizeof blob));     /* does not fit: BUFFER_FULL */
    CHECK(w.last_error != DCF_SER_OK);
    (void)dcf_ser_write_u8(&w, 2);                              /* a later small write that does fit */
    const uint8_t* d; size_t n;
    DCFSerError e = dcf_ser_writer_finish(&w, &d, &n);
    if (e == DCF_SER_OK) {
        fprintf(stderr, "FAIL: finish() returned a CRC-valid frame (%zu bytes) after a failed write\n", n);
        return 1;
    }
    return 0;
}

static int t_s7_every_failure_sets_last_error(void) {
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    CHECK_EQ(dcf_ser_write_array_end(&w), DCF_SER_ERR_MALFORMED);       /* end with no begin */
    CHECK_EQ(w.last_error, DCF_SER_ERR_MALFORMED);
    dcf_ser_writer_reset(&w, 1, 0);
    CHECK_EQ(w.last_error, DCF_SER_OK);
    CHECK_EQ(dcf_ser_write_string_n(&w, "x", (size_t)DCF_SER_MAX_STRING + 1), DCF_SER_ERR_TOO_LARGE);
    CHECK_EQ(w.last_error, DCF_SER_ERR_TOO_LARGE);
    dcf_ser_writer_reset(&w, 1, 0);
    CHECK_EQ(dcf_ser_write_array_begin(&w, DCF_TYPE_U8, (size_t)DCF_SER_MAX_ARRAY + 1), DCF_SER_ERR_TOO_LARGE);
    CHECK_EQ(w.last_error, DCF_SER_ERR_TOO_LARGE);
    dcf_ser_writer_reset(&w, 1, 0);
    for (int i = 0; i < DCF_SER_MAX_DEPTH; i++) CHECK_OK(dcf_ser_write_array_begin(&w, DCF_TYPE_U8, 0));
    CHECK_EQ(dcf_ser_write_array_begin(&w, DCF_TYPE_U8, 0), DCF_SER_ERR_DEPTH_EXCEEDED);
    CHECK_EQ(w.last_error, DCF_SER_ERR_DEPTH_EXCEEDED);
    const uint8_t* d; size_t n;
    CHECK_ERR(dcf_ser_writer_finish(&w, &d, &n));
    /* reset clears it and the writer is usable again */
    dcf_ser_writer_reset(&w, 1, 0);
    CHECK_OK(dcf_ser_write_u8(&w, 1));
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    dcf_ser_writer_destroy(&w);
    return 0;
}

static int t_s7_finish_twice(void) {
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    CHECK_OK(dcf_ser_write_u8(&w, 1));
    const uint8_t* d; size_t n1, n2;
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n1));
    uint8_t snapshot[64];
    CHECK(n1 <= sizeof snapshot);
    memcpy(snapshot, d, n1);
    DCFSerError e = dcf_ser_writer_finish(&w, &d, &n2);
    if (e == DCF_SER_OK) {
        fprintf(stderr, "FAIL: second finish() returned OK: length %zu -> %zu (a second CRC was appended)\n", n1, n2);
        return 1;
    }
    CHECK_EQ(w.position, n1);
    CHECK(memcmp(w.buffer, snapshot, n1) == 0);
    CHECK_OK(dcf_ser_validate_message(snapshot, n1));
    dcf_ser_writer_destroy(&w);
    return 0;
}

static int t_s7_write_after_finish_refused(void) {
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    CHECK_OK(dcf_ser_write_u8(&w, 1));
    const uint8_t* d; size_t n;
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    CHECK_ERR(dcf_ser_write_u8(&w, 2));
    CHECK_EQ(w.position, n);
    dcf_ser_writer_destroy(&w);
    return 0;
}

static int t_s7_null_data_with_length(void) {
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    size_t before = w.position;
    DCFSerError e1 = dcf_ser_write_string_n(&w, NULL, 5);
    if (e1 == DCF_SER_OK) {
        fprintf(stderr, "FAIL: write_string_n(NULL, 5) returned OK and wrote a length prefix with no bytes (%zu bytes)\n",
                w.position - before);
        return 1;
    }
    dcf_ser_writer_reset(&w, 1, 0);
    DCFSerError e2 = dcf_ser_write_bytes(&w, NULL, 5);
    if (e2 == DCF_SER_OK) {
        fprintf(stderr, "FAIL: write_bytes(NULL, 5) returned OK and wrote a length prefix with no bytes\n");
        return 1;
    }
    /* NULL with length 0 stays legal: an empty string / empty bytes */
    dcf_ser_writer_reset(&w, 1, 0);
    CHECK_OK(dcf_ser_write_string_n(&w, NULL, 0));
    CHECK_OK(dcf_ser_write_bytes(&w, NULL, 0));
    CHECK_OK(dcf_ser_write_string(&w, NULL));
    dcf_ser_writer_destroy(&w);
    return 0;
}

static int t_s7_writer_rejects_invalid_utf8(void) {
    API_ABSENT_PROLOGUE;
#ifdef DCF_SER_HARDENED_API
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    CHECK_ERR(dcf_ser_write_string_n(&w, "\xC0\x80", 2));
    dcf_ser_writer_reset(&w, 1, 0);
    CHECK_OK(dcf_ser_write_bytes(&w, "\xC0\x80", 2));           /* bytes are not text */
    dcf_ser_writer_destroy(&w);
#endif
    return 0;
}

/* ============================================================================
 * S8 - framing helper, varint, strings
 * ============================================================================ */

static int t_s8_old_message_length_not_hostile(void) {
    uint8_t hdr[17] = {0x44,0x43,0x46,0x53, 0x05,0x20, 0,1, 0, 0xFF,0xFF,0xFF,0xFF, 0,0,0,0};
    size_t total = dcf_ser_message_length(hdr);
    if (total > (size_t)DCF_SER_MAX_MESSAGE + 21) {
        fprintf(stderr, "FAIL: dcf_ser_message_length() returned %zu for payload_len 0xFFFFFFFF\n", total);
        return 1;
    }
    return 0;
}

static int t_s8_message_length_checked(void) {
    API_ABSENT_PROLOGUE;
#ifdef DCF_SER_HARDENED_API
    uint8_t hdr[17] = {0x44,0x43,0x46,0x53, 0x05,0x20, 0,1, 0, 0,0,0,5, 0,0,0,0};
    size_t total = 99;
    CHECK_OK(dcf_ser_message_length_checked(hdr, 17, &total));
    CHECK_EQ(total, 17 + 5 + 4);
    total = 99;
    CHECK_EQ(dcf_ser_message_length_checked(hdr, 16, &total), DCF_SER_ERR_TRUNCATED);
    CHECK_EQ(total, 99);                                        /* untouched on failure */
    CHECK_EQ(dcf_ser_message_length_checked(hdr, 0, &total), DCF_SER_ERR_TRUNCATED);
    CHECK_EQ(dcf_ser_message_length_checked(NULL, 17, &total), DCF_SER_ERR_NULL_PTR);
    CHECK_EQ(dcf_ser_message_length_checked(hdr, 17, NULL), DCF_SER_ERR_NULL_PTR);
    uint8_t bad[17]; memcpy(bad, hdr, 17);
    bad[0] = 0x00;
    CHECK_EQ(dcf_ser_message_length_checked(bad, 17, &total), DCF_SER_ERR_INVALID_MAGIC);
    memcpy(bad, hdr, 17); bad[4] = 0x06;
    CHECK_EQ(dcf_ser_message_length_checked(bad, 17, &total), DCF_SER_ERR_VERSION_MISMATCH);
    memcpy(bad, hdr, 17); bad[9] = 0xFF; bad[10] = 0xFF; bad[11] = 0xFF; bad[12] = 0xFF;
    CHECK_EQ(dcf_ser_message_length_checked(bad, 17, &total), DCF_SER_ERR_TOO_LARGE);
    memcpy(bad, hdr, 17); bad[9] = 0x01; bad[10] = 0x00; bad[11] = 0x00; bad[12] = 0x01;   /* MAX + 1 */
    CHECK_EQ(dcf_ser_message_length_checked(bad, 17, &total), DCF_SER_ERR_TOO_LARGE);
    memcpy(bad, hdr, 17); bad[9] = 0x01; bad[10] = 0x00; bad[11] = 0x00; bad[12] = 0x00;   /* MAX exactly */
    CHECK_OK(dcf_ser_message_length_checked(bad, 17, &total));
    CHECK_EQ(total, (size_t)DCF_SER_MAX_MESSAGE + 21);
    /* NO_CRC shortens the frame by the CRC */
    memcpy(bad, hdr, 17); bad[8] = DCF_SER_FLAG_NO_CRC;
    CHECK_OK(dcf_ser_message_length_checked(bad, 17, &total));
    CHECK_EQ(total, 17 + 5);
#endif
    return 0;
}

static int varint_payload_read(const uint8_t* body, size_t blen, uint32_t pol, uint64_t* out, DCFSerError* err) {
    Buf b = {0};
    b8(&b, 0x10);
    bput(&b, body, blen);
    size_t flen;
    uint8_t* f = okframe(b.p, b.n, &flen);
    DCFSerReader r;
    DCFSerError e = open_reader(&r, f, flen, pol | POL_RAW);
    if (e != DCF_SER_OK) { *err = e; free(f); free(b.p); return 0; }
    *out = 0x1234;
    *err = dcf_ser_read_varint(&r, out);
    free(f); free(b.p);
    return 0;
}

static int t_s8_varint_overlong_refused(void) {
    uint64_t v; DCFSerError e;
    static const uint8_t zero2[] = {0x80, 0x00};                 /* 0, in two bytes */
    static const uint8_t one3[]  = {0x81, 0x80, 0x00};           /* 1, in three bytes */
    static const uint8_t pad10[] = {0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00}; /* 0 in ten */
    varint_payload_read(zero2, sizeof zero2, 0, &v, &e);
    if (e == DCF_SER_OK) { fprintf(stderr, "FAIL: overlong varint 80 00 accepted (=%llu)\n", (unsigned long long)v); return 1; }
    varint_payload_read(one3, sizeof one3, 0, &v, &e);
    if (e == DCF_SER_OK) { fprintf(stderr, "FAIL: overlong varint 81 80 00 accepted (=%llu)\n", (unsigned long long)v); return 1; }
    varint_payload_read(pad10, sizeof pad10, 0, &v, &e);
    if (e == DCF_SER_OK) { fprintf(stderr, "FAIL: ten-byte zero varint accepted\n"); return 1; }
    /* canonical forms still decode */
    static const uint8_t one[] = {0x01}, z[] = {0x00}, c300[] = {0xAC, 0x02};
    varint_payload_read(z, 1, 0, &v, &e);      CHECK_OK(e); CHECK(v == 0);
    varint_payload_read(one, 1, 0, &v, &e);    CHECK_OK(e); CHECK(v == 1);
    varint_payload_read(c300, 2, 0, &v, &e);   CHECK_OK(e); CHECK(v == 300);
    return 0;
}

static int t_s8_varint_tenth_byte_bits_not_dropped(void) {
    uint64_t v; DCFSerError e;
    static const uint8_t drop[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F};  /* 10th byte 0x7F */
    static const uint8_t max[]  = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x01};  /* UINT64_MAX */
    static const uint8_t cont[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x81,0x00};
    varint_payload_read(drop, sizeof drop, 0, &v, &e);
    if (e == DCF_SER_OK) {
        fprintf(stderr, "FAIL: 10-byte varint with 10th byte 0x7F accepted, silently truncated to 0x%llx\n",
                (unsigned long long)v);
        return 1;
    }
    varint_payload_read(max, sizeof max, 0, &v, &e);
    CHECK_OK(e);
    CHECK(v == UINT64_MAX);
    varint_payload_read(cont, sizeof cont, 0, &v, &e);
    CHECK_ERR(e);
    return 0;
}

static int t_s8_varint_lax_policy(void) {
    API_ABSENT_PROLOGUE;
#ifdef DCF_SER_HARDENED_API
    uint64_t v; DCFSerError e;
    static const uint8_t zero2[] = {0x80, 0x00};
    static const uint8_t drop[]  = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F};
    varint_payload_read(zero2, sizeof zero2, DCF_SER_POLICY_ALLOW_NONCANONICAL_VARINT, &v, &e);
    CHECK_OK(e); CHECK(v == 0);
    /* losing bits is never allowed, policy or not */
    varint_payload_read(drop, sizeof drop, DCF_SER_POLICY_ALLOW_NONCANONICAL_VARINT, &v, &e);
    CHECK_ERR(e);
#endif
    return 0;
}

static int string_payload_read(const uint8_t* body, size_t blen, uint32_t len_field, uint32_t pol,
                               DCFSerError* err, int copy_api) {
    Buf b = {0};
    b8(&b, 0x11); b32(&b, len_field);
    bput(&b, body, blen);
    size_t flen;
    uint8_t* f = okframe(b.p, b.n, &flen);
    DCFSerReader r;
    DCFSerError e = open_reader(&r, f, flen, pol | POL_RAW);
    if (e != DCF_SER_OK) { *err = e; free(f); free(b.p); return 0; }
    if (copy_api) {
        char out[128]; size_t ol = 0;
        *err = dcf_ser_read_string_copy(&r, out, sizeof out, &ol);
    } else {
        const char* s; size_t sl;
        *err = dcf_ser_read_string(&r, &s, &sl);
    }
    free(f); free(b.p);
    return 0;
}

static int t_s8_string_cap_on_read(void) {
    size_t n = (size_t)DCF_SER_MAX_STRING + 1;
    uint8_t* body = (uint8_t*)malloc(n);
    CHECK(body != NULL);
    memset(body, 'a', n);
    DCFSerError e;
    string_payload_read(body, n, (uint32_t)n, 0, &e, 0);
    if (e == DCF_SER_OK) { fprintf(stderr, "FAIL: %zu byte string (> DCF_SER_MAX_STRING) accepted on read\n", n); return 1; }
    string_payload_read(body, n - 1, (uint32_t)(n - 1), 0, &e, 0);  /* exactly the cap: fine */
    CHECK_OK(e);
    return 0;
}

static int t_s8_utf8_validated(void) {
    static const struct { const char* name; const uint8_t b[6]; unsigned n; } bad[] = {
        {"lone continuation 80",       {0x80},                      1},
        {"overlong C0 80",             {0xC0, 0x80},                2},
        {"overlong C1 BF",             {0xC1, 0xBF},                2},
        {"overlong E0 80 80",          {0xE0, 0x80, 0x80},          3},
        {"overlong F0 80 80 80",       {0xF0, 0x80, 0x80, 0x80},    4},
        {"surrogate ED A0 80",         {0xED, 0xA0, 0x80},          3},
        {"above U+10FFFF F4 90 80 80", {0xF4, 0x90, 0x80, 0x80},    4},
        {"F5 lead",                    {0xF5, 0x80, 0x80, 0x80},    4},
        {"FF",                         {0xFF},                      1},
        {"truncated 2-byte",           {0xC3},                      1},
        {"truncated 3-byte",           {0xE2, 0x82},                2},
        {"truncated 4-byte",           {0xF0, 0x9F, 0x98},          3},
        {"bad continuation",           {0xE2, 0x41, 0x80},          3},
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        DCFSerError e;
        string_payload_read(bad[i].b, bad[i].n, bad[i].n, 0, &e, 0);
        if (e == DCF_SER_OK) { fprintf(stderr, "FAIL: invalid UTF-8 accepted: %s\n", bad[i].name); return 1; }
    }
    static const struct { const char* name; const uint8_t b[6]; unsigned n; } good[] = {
        {"ascii",              {'o', 'k'},                  2},
        {"U+0080",             {0xC2, 0x80},                2},
        {"U+07FF",             {0xDF, 0xBF},                2},
        {"U+0800",             {0xE0, 0xA0, 0x80},          3},
        {"U+D7FF",             {0xED, 0x9F, 0xBF},          3},
        {"U+E000",             {0xEE, 0x80, 0x80},          3},
        {"U+FFFF",             {0xEF, 0xBF, 0xBF},          3},
        {"U+10000",            {0xF0, 0x90, 0x80, 0x80},    4},
        {"U+10FFFF",           {0xF4, 0x8F, 0xBF, 0xBF},    4},
        {"embedded NUL",       {'a', 0x00, 'b'},            3},
    };
    for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
        DCFSerError e;
        string_payload_read(good[i].b, good[i].n, good[i].n, 0, &e, 0);
        if (e != DCF_SER_OK) { fprintf(stderr, "FAIL: valid UTF-8 refused: %s (0x%x)\n", good[i].name, e); return 1; }
    }
    return 0;
}

static int t_s8_utf8_lax_policy(void) {
    API_ABSENT_PROLOGUE;
#ifdef DCF_SER_HARDENED_API
    DCFSerError e;
    static const uint8_t bad[] = {0xC0, 0x80, 0xFF};
    string_payload_read(bad, sizeof bad, sizeof bad, 0, &e, 0);
    CHECK_ERR(e);
    string_payload_read(bad, sizeof bad, sizeof bad, DCF_SER_POLICY_ALLOW_INVALID_UTF8, &e, 0);
    CHECK_OK(e);
#endif
    return 0;
}

static int t_s8_string_copy_rejects_nul(void) {
    DCFSerError e;
    static const uint8_t with_nul[] = {'a', 0x00, 'b'};
    string_payload_read(with_nul, sizeof with_nul, sizeof with_nul, 0, &e, 1);
    if (e == DCF_SER_OK) { fprintf(stderr, "FAIL: read_string_copy accepted an embedded NUL (C-string truncation)\n"); return 1; }
    /* the length-delimited zero-copy API keeps NUL legal */
    string_payload_read(with_nul, sizeof with_nul, sizeof with_nul, 0, &e, 0);
    CHECK_OK(e);
    static const uint8_t plain[] = {'a', 'b', 'c'};
    string_payload_read(plain, sizeof plain, sizeof plain, 0, &e, 1);
    CHECK_OK(e);
    return 0;
}

/* ============================================================================
 * Strict structural validation (dcf_ser_validate_payload / validate)
 * ============================================================================ */

static int t_s9_strict_validate_rejects_hostile_payloads(void) {
    API_ABSENT_PROLOGUE;
#ifdef DCF_SER_HARDENED_API
    struct { const char* name; Buf b; } cases[16];
    size_t nc = 0;
    memset(cases, 0, sizeof cases);
#define CASE(nm) cases[nc].name = nm; nc++
    b8(&cases[nc].b, 0x08); b8(&cases[nc].b, 1); CASE("u64 with one byte");
    b8(&cases[nc].b, 0x11); b32(&cases[nc].b, 0xFFFFFFFFu); CASE("string with len 4G");
    b8(&cases[nc].b, 0x21); b8(&cases[nc].b, 2); b8(&cases[nc].b, 2); b32(&cases[nc].b, 0x80000000u); CASE("map count 2^31");
    b8(&cases[nc].b, 0x20); b8(&cases[nc].b, 0); b32(&cases[nc].b, 0xFFFFFFFFu); CASE("array count 2^32-1");
    nest(&cases[nc].b, K_ARRAY, 100000); CASE("100k nested arrays");
    nest(&cases[nc].b, K_STRUCT, 100000); CASE("100k nested structs");
    b8(&cases[nc].b, 0x22); b16(&cases[nc].b, 1); CASE("struct without end marker");
    b8(&cases[nc].b, 0x23); CASE("TUPLE tag (unsupported)");
    b8(&cases[nc].b, 0xFE); CASE("EXTENSION tag");
    b8(&cases[nc].b, 0x00); b8(&cases[nc].b, 0x55); CASE("trailing junk after a value");
    b8(&cases[nc].b, 0x10); b8(&cases[nc].b, 0x80); CASE("varint with dangling continuation");
#undef CASE
    for (size_t i = 0; i < nc; i++) {
        DCFSerError e = dcf_ser_validate_payload(cases[i].b.p, cases[i].b.n, 0);
        if (e == DCF_SER_OK) { fprintf(stderr, "FAIL: dcf_ser_validate_payload accepted: %s\n", cases[i].name); return 1; }
        size_t flen;
        uint8_t* f = okframe(cases[i].b.p, cases[i].b.n, &flen);
        DCFSerReader r;
        e = open_reader(&r, f, flen, 0);
        if (e == DCF_SER_OK) { fprintf(stderr, "FAIL: strict validate() accepted: %s\n", cases[i].name); return 1; }
        free(f);
        f = okframe(cases[i].b.p, cases[i].b.n, &flen);
        e = open_reader(&r, f, flen, DCF_SER_POLICY_ALLOW_UNSTRUCTURED);
        CHECK_OK(e);                                              /* the opt-out restores header-only validation */
        free(f);
    }
    /* empty payload is a valid (empty) sequence */
    CHECK_OK(dcf_ser_validate_payload(NULL, 0, 0));
    CHECK_EQ(dcf_ser_validate_payload(NULL, 1, 0), DCF_SER_ERR_NULL_PTR);
#endif
    return 0;
}

static int t_s9_typed_array_cap_beyond_count_limit(void) {
    /* count above DCF_SER_MAX_ARRAY with enough bytes to "back" it: the cap, not the
     * remaining-bytes check, has to be what refuses it */
    size_t n = (size_t)DCF_SER_MAX_ARRAY + 1;
    Buf a = {0};
    b8(&a, 0x20); b8(&a, 0x00); b32(&a, (uint32_t)n);
    bzero(&a, n);
    size_t flen;
    uint8_t* f = okframe(a.p, a.n, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, POL_RAW));
    DCFSerType t; size_t c = 0;
    DCFSerError e = dcf_ser_read_array_begin(&r, &t, &c);
    if (e == DCF_SER_OK) { fprintf(stderr, "FAIL: array count %zu (> DCF_SER_MAX_ARRAY) accepted by read_array_begin\n", c); return 1; }
    CHECK_EQ(e, DCF_SER_ERR_TOO_LARGE);
    free(f);
    /* exactly the cap, fully backed, is fine */
    Buf ok = {0};
    b8(&ok, 0x20); b8(&ok, 0x00); b32(&ok, DCF_SER_MAX_ARRAY);
    bzero(&ok, DCF_SER_MAX_ARRAY);
    f = okframe(ok.p, ok.n, &flen);
    CHECK_OK(open_reader(&r, f, flen, POL_RAW));
    CHECK_OK(dcf_ser_read_array_begin(&r, &t, &c));
    CHECK_EQ(c, DCF_SER_MAX_ARRAY);
    /* and the map equivalent */
    Buf m = {0};
    b8(&m, 0x21); b8(&m, 0); b8(&m, 0); b32(&m, (uint32_t)n);
    bzero(&m, 2 * n);
    uint8_t* f2 = okframe(m.p, m.n, &flen);
    DCFSerType kt, vt;
    CHECK_OK(open_reader(&r, f2, flen, POL_RAW));
    CHECK_EQ(dcf_ser_read_map_begin(&r, &kt, &vt, &c), DCF_SER_ERR_TOO_LARGE);
    return 0;
}

/* The structural walker (dcf_ser_validate_payload / strict validate) and the
 * typed readers must give the same answer on varints and strings: a payload
 * the walker blesses must not be one a typed read of the same bytes refuses. */
static int t_s9_validate_payload_agrees_with_typed_reads(void) {
    API_ABSENT_PROLOGUE;
#ifdef DCF_SER_HARDENED_API
    struct VC { const char* name; uint8_t bytes[16]; unsigned n; int want_ok; };
    static const struct VC varints[] = {
        {"0",                      {0x00}, 1, 1},
        {"127",                    {0x7F}, 1, 1},
        {"128",                    {0x80, 0x01}, 2, 1},
        {"UINT64_MAX",             {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x01}, 10, 1},
        {"2^63",                   {0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x01}, 10, 1},
        {"overlong 0 (80 00)",     {0x80, 0x00}, 2, 0},
        {"overlong 1 (81 00)",     {0x81, 0x00}, 2, 0},
        {"overlong 0 x10",         {0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00}, 10, 0},
        {"10th byte 2",            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x02}, 10, 0},
        {"10th byte 0x7F",         {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F}, 10, 0},
        {"10th byte 0x80 (cont.)", {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x80,0x00}, 11, 0},
        {"11 bytes",               {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x01}, 11, 0},
        {"dangling continuation",  {0x80}, 1, 0},
        {"empty",                  {0}, 0, 0},
    };
    for (size_t i = 0; i < sizeof varints / sizeof varints[0]; i++) {
        Buf b = {0};
        b8(&b, 0x10); bput(&b, varints[i].bytes, varints[i].n);
        DCFSerError walker = dcf_ser_validate_payload(b.p, b.n, 0);
        uint64_t v; DCFSerError typed;
        varint_payload_read(varints[i].bytes, varints[i].n, 0, &v, &typed);
        if ((walker == DCF_SER_OK) != varints[i].want_ok || (typed == DCF_SER_OK) != varints[i].want_ok) {
            fprintf(stderr, "FAIL: varint '%s': walker=0x%x typed=0x%x, want %s\n", varints[i].name,
                    walker, typed, varints[i].want_ok ? "OK" : "refusal");
            return 1;
        }
        free(b.p);
    }
    {   /* strings: the 64 KiB cap and UTF-8, walker vs typed */
        size_t cap = (size_t)DCF_SER_MAX_STRING;
        uint8_t* body = (uint8_t*)malloc(cap + 1);
        CHECK(body != NULL);
        memset(body, 'a', cap + 1);
        for (int over = 0; over < 2; over++) {
            size_t len = cap + (size_t)over;
            Buf b = {0};
            b8(&b, 0x11); b32(&b, (uint32_t)len); bput(&b, body, len);
            DCFSerError walker = dcf_ser_validate_payload(b.p, b.n, 0);
            DCFSerError typed;
            string_payload_read(body, len, (uint32_t)len, 0, &typed, 0);
            CHECK_EQ(walker == DCF_SER_OK, over == 0);
            CHECK_EQ(typed == DCF_SER_OK, over == 0);
            free(b.p);
        }
        static const uint8_t bad[] = {0xE2, 0x82};
        static const uint8_t good[] = {0xE2, 0x82, 0xAC};
        Buf b = {0};
        b8(&b, 0x11); b32(&b, sizeof bad); bput(&b, bad, sizeof bad);
        CHECK_ERR(dcf_ser_validate_payload(b.p, b.n, 0));
        CHECK_OK(dcf_ser_validate_payload(b.p, b.n, DCF_SER_POLICY_ALLOW_INVALID_UTF8));
        b.n = 0;
        b8(&b, 0x11); b32(&b, sizeof good); bput(&b, good, sizeof good);
        CHECK_OK(dcf_ser_validate_payload(b.p, b.n, 0));
    }
#endif
    return 0;
}

/* ============================================================================
 * S10 - found by the C-vs-gate differential: crc32_table[245] was mistyped
 * ============================================================================ */

/* Bitwise CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320): independent of the
 * library's table. `legacy` reproduces the old table entry 245. */
static uint32_t ref_crc32(const uint8_t* p, size_t n, int legacy) {
    uint32_t tbl[256];
    for (uint32_t t = 0; t < 256; t++) {
        uint32_t c = t;
        for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
        tbl[t] = c;
    }
    if (legacy) tbl[245] = 0xCDD706B3u;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) crc = tbl[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

static int t_s10_crc32_is_standard(void) {
    /* external vectors (Python zlib.crc32). A first byte of 0x0A looks up table entry
     * 0xFF ^ 0x0A = 245, the entry that was mistyped. */
    const uint8_t nl = 0x0A;
    if (dcf_ser_crc32(&nl, 1) != 0x32d70693u) {
        fprintf(stderr, "FAIL: crc32 of the single byte 0A is 0x%08x, standard CRC-32 is 0x32d70693\n",
                dcf_ser_crc32(&nl, 1));
        return 1;
    }
    const uint8_t v3[3] = {0x00, 0xF5, 0x01};
    CHECK_EQ(dcf_ser_crc32(v3, 3), 0xe18dfc7cu);
    uint8_t all[256];
    for (unsigned i = 0; i < 256; i++) all[i] = (uint8_t)i;
    CHECK_EQ(dcf_ser_crc32(all, 256), 0x29058c73u);
    CHECK_EQ(dcf_ser_crc32("123456789", 9), 0xCBF43926u);
    CHECK_EQ(dcf_ser_crc32("", 0), 0u);
    /* and against the bitwise reference on varied input */
    uint64_t x = 88172645463325252ULL;
    for (int round = 0; round < 3000; round++) {
        uint8_t buf[300];
        size_t n = (size_t)(round % 300);
        for (size_t i = 0; i < n; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; buf[i] = (uint8_t)x; }
        if (dcf_ser_crc32(buf, n) != ref_crc32(buf, n, 0)) {
            fprintf(stderr, "FAIL: crc32 differs from the bitwise reference at round %d (n=%zu)\n", round, n);
            return 1;
        }
    }
    return 0;
}

/* The deployed fleet computed the mistyped CRC. The reader can still accept it
 * for a migration window, but only when told to. */
static int t_s10_legacy_crc_is_opt_in(void) {
#ifdef DCF_SER_POLICY_ALLOW_LEGACY_CRC
    /* a payload whose CRC differs under the legacy table: scan for one */
    Buf b = {0};
    size_t flen = 0;
    uint8_t* f = NULL;
    for (unsigned v = 0; v < 256 && !f; v++) {
        b.n = 0;
        b8(&b, 0x02); b8(&b, v);
        uint8_t* cand = okframe(b.p, b.n, &flen);
        if (ref_crc32(cand, flen - 4, 1) != ref_crc32(cand, flen - 4, 0)) f = cand; else free(cand);
    }
    CHECK(f != NULL);                                           /* some frame really exercises entry 245 */
    uint8_t* g = (uint8_t*)malloc(flen);
    CHECK(g != NULL);
    memcpy(g, f, flen);
    uint32_t legacy = ref_crc32(g, flen - 4, 1);
    g[flen - 4] = (uint8_t)(legacy >> 24); g[flen - 3] = (uint8_t)(legacy >> 16);
    g[flen - 2] = (uint8_t)(legacy >> 8);  g[flen - 1] = (uint8_t)legacy;
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, 0));                       /* standard: accepted by default */
    CHECK_EQ(open_reader(&r, g, flen, 0), DCF_SER_ERR_CRC_MISMATCH);   /* legacy: refused by default */
    CHECK_OK(open_reader(&r, g, flen, DCF_SER_POLICY_ALLOW_LEGACY_CRC));
    CHECK(r.crc_verified);
    /* the opt-in widens nothing else: a frame with neither CRC is still refused */
    g[flen - 1] ^= 0x01;
    CHECK_EQ(open_reader(&r, g, flen, DCF_SER_POLICY_ALLOW_LEGACY_CRC), DCF_SER_ERR_CRC_MISMATCH);
    return 0;
#else
    fprintf(stderr, "FAIL: API absent (no DCF_SER_POLICY_ALLOW_LEGACY_CRC)\n");
    return 1;
#endif
}

/* ============================================================================
 * Review round 2 (independent reviewer's findings N1..N9, I1)
 * ============================================================================ */

/* ---- N1: write_varsint lost the sign fill (pre-existing, wire-visible) ------------------ */

/* The standard ZigZag vectors (protobuf / the library's own header comment): hard-coded,
 * never derived from the library's formula. `bytes` are the LEB128 of the zigzag value. */
static const struct { int64_t v; uint64_t zz; uint8_t bytes[10]; unsigned n; } zz_vectors[] = {
    { 0,                       0,                      {0x00}, 1 },
    { -1,                      1,                      {0x01}, 1 },
    { 1,                       2,                      {0x02}, 1 },
    { -2,                      3,                      {0x03}, 1 },
    { 2,                       4,                      {0x04}, 1 },
    { 63,                      126,                    {0x7E}, 1 },
    { -64,                     127,                    {0x7F}, 1 },
    { 64,                      128,                    {0x80, 0x01}, 2 },
    { -65,                     129,                    {0x81, 0x01}, 2 },
    { 2147483647,              4294967294ULL,          {0xFE, 0xFF, 0xFF, 0xFF, 0x0F}, 5 },
    { -2147483647 - 1,         4294967295ULL,          {0xFF, 0xFF, 0xFF, 0xFF, 0x0F}, 5 },
    { INT64_MAX,               UINT64_MAX - 1,         {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}, 10 },
    { INT64_MIN,               UINT64_MAX,             {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}, 10 },
};

static int t_n1_varsint_wire_vectors(void) {
    for (size_t i = 0; i < sizeof zz_vectors / sizeof zz_vectors[0]; i++) {
        DCFSerWriter w;
        CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
        CHECK_OK(dcf_ser_write_varsint(&w, zz_vectors[i].v));
        const uint8_t* d; size_t n;
        CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
        size_t want = 17 + 1 + zz_vectors[i].n + 4;
        uint8_t expect[1 + 10];
        expect[0] = 0x10;                                   /* VARINT tag */
        memcpy(expect + 1, zz_vectors[i].bytes, zz_vectors[i].n);
        if (n != want || memcmp(d + 17, expect, 1 + zz_vectors[i].n) != 0) {
            fprintf(stderr, "FAIL: write_varsint(%lld) put %zu payload bytes on the wire (first: %02x %02x ...), "
                    "zigzag value %llu = LEB128 of %u bytes expected\n", (long long)zz_vectors[i].v, n - 21,
                    n > 17 ? d[17] : 0, n > 18 ? d[18] : 0, (unsigned long long)zz_vectors[i].zz, zz_vectors[i].n);
            return 1;
        }
        dcf_ser_writer_destroy(&w);
    }
    return 0;
}

static int t_n1_varsint_reader_vectors(void) {
    /* the READER decodes the standard vectors from hand-built frames (control: it was always right) */
    for (size_t i = 0; i < sizeof zz_vectors / sizeof zz_vectors[0]; i++) {
        uint8_t pl[1 + 10];
        pl[0] = 0x10;
        memcpy(pl + 1, zz_vectors[i].bytes, zz_vectors[i].n);
        size_t flen;
        uint8_t* f = okframe(pl, 1 + zz_vectors[i].n, &flen);
        DCFSerReader r;
        CHECK_OK(open_reader(&r, f, flen, 0));
        int64_t out = 0x5555;
        CHECK_OK(dcf_ser_read_varsint(&r, &out));
        if (out != zz_vectors[i].v) {
            fprintf(stderr, "FAIL: read_varsint of zigzag %llu gave %lld, want %lld\n",
                    (unsigned long long)zz_vectors[i].zz, (long long)out, (long long)zz_vectors[i].v);
            return 1;
        }
        free(f);
    }
    return 0;
}

static int t_n1_varsint_roundtrip_negative(void) {
    static const int64_t vals[] = {0, 1, -1, 2, -2, 63, -64, 64, -65, 1000000, -1000000, 2147483647LL,
                                   -2147483648LL, 4294967296LL, -4294967296LL, INT64_MAX, INT64_MIN,
                                   INT64_MIN + 1, INT64_MAX - 1};
    for (size_t i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        DCFSerWriter w;
        CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
        CHECK_OK(dcf_ser_write_varsint(&w, vals[i]));
        const uint8_t* d; size_t n;
        CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
        DCFSerReader r;
        CHECK_OK(dcf_ser_reader_init(&r, d, n));
        CHECK_OK(dcf_ser_reader_validate(&r));
        int64_t out = 0x7777;
        CHECK_OK(dcf_ser_read_varsint(&r, &out));
        if (out != vals[i]) {
            fprintf(stderr, "FAIL: write_varsint(%lld) reads back as %lld\n", (long long)vals[i], (long long)out);
            return 1;
        }
        dcf_ser_writer_destroy(&w);
    }
    return 0;
}

/* ---- N2: the schema reader scanned the whole schema for every wire field ----------------- */

static double cpu_seconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

/* A struct of `nf` unknown 4-byte fields (id 0xFFFF, type NULL, value NULL) against a schema of
 * `nsch` fields; returns the best of three CPU times of dcf_ser_read_struct_schema. */
static double schema_scan_cpu(const uint8_t* frame, size_t flen, const DCFSerSchema* sc, void* target, DCFSerError* e_out) {
    double best = 1e9;
    for (int rep = 0; rep < 3; rep++) {
        DCFSerReader r;
        if (open_reader(&r, frame, flen, 0) != DCF_SER_OK) { *e_out = DCF_SER_ERR_INTERNAL; return 0; }
        double t0 = cpu_seconds();
        *e_out = dcf_ser_read_struct_schema(&r, target, sc);
        double dt = cpu_seconds() - t0;
        if (dt < best) best = dt;
    }
    return best;
}

static int t_n2_schema_lookup_not_linear(void) {
    enum { NF = 1000000 };
    Buf pl = {0};
    b8(&pl, 0x22); b16(&pl, 0x42);
    for (unsigned i = 0; i < NF; i++) { b16(&pl, 0xFFFF); b8(&pl, 0x00); b8(&pl, 0x00); }
    b16(&pl, 0); b8(&pl, 0);
    size_t flen;
    uint8_t* f = okframe(pl.p, pl.n, &flen);
    static DCFSerField big[256], one[1];
    static uint8_t target[256];
    for (unsigned i = 0; i < 256; i++) {
        big[i].name = "f"; big[i].field_id = (uint16_t)(i + 1); big[i].type = DCF_TYPE_U8;
        big[i].flags = 0; big[i].offset = i; big[i].size = 1;
    }
    one[0] = big[0];
    DCFSerSchema s256 = { "B", 0x42, big, 256, sizeof target };
    DCFSerSchema s1 = { "B", 0x42, one, 1, sizeof target };
    DCFSerError e1, e256;
    double t1 = schema_scan_cpu(f, flen, &s1, target, &e1);
    double t256 = schema_scan_cpu(f, flen, &s256, target, &e256);
    CHECK_OK(e1);
    CHECK_OK(e256);
    fprintf(stderr, "info: %d unknown fields: 1-field schema %.1f ms, 256-field schema %.1f ms (ratio %.2f)\n",
            NF, t1 * 1e3, t256 * 1e3, t256 / t1);
    /* a linear scan of 256 ids per wire field costs several times the 1-field case; an indexed lookup
     * (8 probes) stays within a small factor of it */
    if (t256 > 2.5 * t1) {
        fprintf(stderr, "FAIL: a 256-field schema costs %.2fx a 1-field schema per unknown wire field "
                "(%.1f ms vs %.1f ms): the id lookup is not O(log n)\n", t256 / t1, t256 * 1e3, t1 * 1e3);
        return 1;
    }
    return 0;
}

/* schema semantics the lookup must keep: first duplicate id in the SCHEMA wins, ids anywhere in 0..65535 */
static int t_n2_schema_lookup_semantics(void) {
    static const DCFSerField fl[] = {
        { "z", 65535, DCF_TYPE_U8, DCF_FIELD_OPTIONAL, 0, 1 },
        { "a", 7,     DCF_TYPE_U8, DCF_FIELD_OPTIONAL, 1, 1 },
        { "b", 7,     DCF_TYPE_U8, DCF_FIELD_OPTIONAL, 2, 1 },      /* duplicate id in the schema: the first one wins */
        { "c", 300,   DCF_TYPE_U8, DCF_FIELD_OPTIONAL, 3, 1 },
        { "d", 0,     DCF_TYPE_U8, DCF_FIELD_OPTIONAL, 4, 1 },      /* id 0 with type U8 is an ordinary field */
        { "e", 256,   DCF_TYPE_U8, DCF_FIELD_OPTIONAL, 5, 1 },
    };
    static const DCFSerSchema sc = { "S", 0x55, fl, 6, 6 };
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 3, 0));
    CHECK_OK(dcf_ser_write_struct_begin(&w, 0x55));
    static const uint16_t ids[] = {300, 7, 65535, 0, 256, 9999};
    for (unsigned i = 0; i < 6; i++) {
        CHECK_OK(dcf_ser_write_field(&w, ids[i], DCF_TYPE_U8));
        CHECK_OK(dcf_ser_write_u8(&w, (uint8_t)(10 + i)));
    }
    CHECK_OK(dcf_ser_write_struct_end(&w));
    const uint8_t* d; size_t n;
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    DCFSerReader r;
    CHECK_OK(open_reader(&r, d, n, 0));
    uint8_t out[6] = {0};
    CHECK_OK(dcf_ser_read_struct_schema(&r, out, &sc));
    CHECK_EQ(out[3], 10);      /* id 300 */
    CHECK_EQ(out[1], 11);      /* id 7 -> the FIRST schema entry "a", not "b" */
    CHECK_EQ(out[2], 0);
    CHECK_EQ(out[0], 12);      /* id 65535 */
    CHECK_EQ(out[4], 13);      /* id 0 */
    CHECK_EQ(out[5], 14);      /* id 256 */
    dcf_ser_writer_destroy(&w);
    return 0;
}

/* ---- N6: reader->depth leaks ---------------------------------------------------------------- */

static int t_n6_validate_resets_depth(void) {
    /* open DCF_SER_MAX_DEPTH containers on a frame of nested arrays ... */
    Buf pl = {0};
    for (int i = 0; i < DCF_SER_MAX_DEPTH; i++) { b8(&pl, 0x20); b8(&pl, 0x20); b32(&pl, 1); }
    b8(&pl, 0x00);
    size_t flen;
    uint8_t* f = okframe(pl.p, pl.n, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, 0));
    DCFSerType t; size_t c;
    for (int i = 0; i < DCF_SER_MAX_DEPTH; i++) CHECK_OK(dcf_ser_read_array_begin(&r, &t, &c));
    CHECK_EQ(r.depth, DCF_SER_MAX_DEPTH);
    /* ... then point the same reader at a fresh, flat frame WITHOUT reader_init */
    Buf q = {0};
    b8(&q, 0x20); b8(&q, 0x06); b32(&q, 1); b8(&q, 0x06); b32(&q, 5);
    size_t glen;
    uint8_t* g = okframe(q.p, q.n, &glen);
    r.buffer = g; r.length = glen;
    CHECK_OK(dcf_ser_reader_validate(&r));
    if (r.depth != 0) {
        fprintf(stderr, "FAIL: validate() left reader->depth = %zu from the previous frame\n", r.depth);
        return 1;
    }
    CHECK_OK(dcf_ser_read_array_begin(&r, &t, &c));
    return 0;
}

static int t_n6_failed_schema_read_leaves_reader_unchanged(void) {
    /* 40 sibling structs whose type_id differs from the consumer's schema: "read schema, on error skip" */
    enum { SIBLINGS = 40 };
    Buf pl = {0};
    for (int i = 0; i < SIBLINGS; i++) { b8(&pl, 0x22); b16(&pl, 0x0999); b16(&pl, 1); b8(&pl, 0x02); b8(&pl, 0x02); b8(&pl, (unsigned)i); b16(&pl, 0); b8(&pl, 0); }
    size_t flen;
    uint8_t* f = okframe(pl.p, pl.n, &flen);
    static const DCFSerField fl[] = { { "a", 1, DCF_TYPE_U8, DCF_FIELD_OPTIONAL, 0, 1 } };
    static const DCFSerSchema sc = { "S", 0x0123, fl, 1, 1 };
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, 0));
    int skipped = 0;
    while (!dcf_ser_reader_at_end(&r)) {
        size_t pos0 = r.position, depth0 = r.depth;
        uint8_t out = 0xAA;
        DCFSerError e = dcf_ser_read_struct_schema(&r, &out, &sc);
        if (e != DCF_SER_ERR_TYPE_MISMATCH) { fprintf(stderr, "FAIL: schema read of a foreign struct gave 0x%x\n", e); return 1; }
        if (r.depth != depth0) { fprintf(stderr, "FAIL: failed schema read left depth %zu -> %zu (sibling %d)\n", depth0, r.depth, skipped); return 1; }
        if (r.position != pos0) { fprintf(stderr, "FAIL: failed schema read moved position %zu -> %zu (sibling %d)\n", pos0, r.position, skipped); return 1; }
        e = dcf_ser_reader_skip(&r);
        if (e != DCF_SER_OK) { fprintf(stderr, "FAIL: skip of sibling %d failed with 0x%x\n", skipped, e); return 1; }
        skipped++;
    }
    CHECK_EQ(skipped, SIBLINGS);
    return 0;
}

static int t_n6_failed_schema_read_other_errors(void) {
    /* required field missing, duplicate id, truncated field: depth and position restored every time */
    static const DCFSerField fl[] = { { "a", 1, DCF_TYPE_U8, DCF_FIELD_REQUIRED, 0, 1 } };
    static const DCFSerSchema sc = { "S", 0x0123, fl, 1, 1 };
    for (int variant = 0; variant < 3; variant++) {
        Buf pl = {0};
        b8(&pl, 0x22); b16(&pl, 0x0123);
        if (variant == 1) { b16(&pl, 1); b8(&pl, 2); b8(&pl, 2); b8(&pl, 5); b16(&pl, 1); b8(&pl, 2); b8(&pl, 2); b8(&pl, 6); }
        if (variant == 2) { b16(&pl, 1); b8(&pl, 2); b8(&pl, 4); b16(&pl, 9); }       /* U16 value where U8 was due */
        b16(&pl, 0); b8(&pl, 0);
        size_t flen;
        uint8_t* f = okframe(pl.p, pl.n, &flen);
        DCFSerReader r;
        CHECK_OK(open_reader(&r, f, flen, 0));
        uint8_t out = 0;
        CHECK_ERR(dcf_ser_read_struct_schema(&r, &out, &sc));
        CHECK_EQ(r.depth, 0);
        CHECK_EQ(r.position, 17);
        CHECK_OK(dcf_ser_reader_skip(&r));                    /* the whole struct is still there to skip */
        CHECK(dcf_ser_reader_at_end(&r));
        free(f);
    }
    return 0;
}

/* ---- N4: len-0 raw reads on a reader whose init failed -------------------------------------- */

static int t_n4_read_raw_zero_on_failed_init(void) {
    DCFSerReader r;
    uint8_t few[5] = {0};
    CHECK_ERR(dcf_ser_reader_init(&r, few, sizeof few));        /* too short: refused, reader left zeroed */
    uint8_t out[1];
    const void* p = (const void*)0x1;
    CHECK_ERR(dcf_ser_read_raw(&r, out, 0));                    /* memcpy(out, NULL, 0) is undefined behaviour */
    CHECK_ERR(dcf_ser_read_raw_ptr(&r, &p, 0));
    CHECK(p == (const void*)0x1);                               /* *out_ptr untouched on error */
    /* a validated reader still allows a zero-length raw read */
    Buf b = {0};
    b8(&b, 0x00);
    size_t flen;
    uint8_t* f = okframe(b.p, b.n, &flen);
    DCFSerReader ok;
    CHECK_OK(open_reader(&ok, f, flen, 0));
    CHECK_OK(dcf_ser_read_raw(&ok, out, 0));
    CHECK_OK(dcf_ser_read_raw_ptr(&ok, &p, 0));
    CHECK(p != NULL);
    return 0;
}

/* ---- N5: a failed typed read must not move the reader ---------------------------------------- */

static int t_n5_typed_reads_are_atomic(void) {
    /* U16(0x1234), then a string whose body is invalid UTF-8, then a U32 with a short body (UNSTRUCTURED) */
    Buf pl = {0};
    b8(&pl, 0x04); b16(&pl, 0x1234);
    b8(&pl, 0x11); b32(&pl, 2); b8(&pl, 0xC0); b8(&pl, 0x80);
    b8(&pl, 0x06); b8(&pl, 0x01); b8(&pl, 0x02);
    size_t flen;
    uint8_t* f = okframe(pl.p, pl.n, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, POL_RAW));
    size_t at = r.position;
    uint8_t u8; uint32_t u32; const char* s; size_t sl; char sbuf[8]; uint64_t u64;
    /* type mismatch: read_u8 on a U16 */
    CHECK_EQ(dcf_ser_read_u8(&r, &u8), DCF_SER_ERR_TYPE_MISMATCH);
    if (r.position != at) { fprintf(stderr, "FAIL: read_u8 on a U16 moved the reader %zu -> %zu\n", at, r.position); return 1; }
    CHECK_EQ(dcf_ser_reader_peek_type(&r), DCF_TYPE_U16);
    CHECK_EQ(dcf_ser_read_varint(&r, &u64), DCF_SER_ERR_TYPE_MISMATCH);
    CHECK_EQ(r.position, at);
    uint16_t u16;
    CHECK_OK(dcf_ser_read_u16(&r, &u16));
    CHECK_EQ(u16, 0x1234);
    /* invalid UTF-8 string: refused, not consumed; copy API too */
    at = r.position;
    CHECK_ERR(dcf_ser_read_string(&r, &s, &sl));
    CHECK_EQ(r.position, at);
    CHECK_ERR(dcf_ser_read_string_copy(&r, sbuf, sizeof sbuf, &sl));
    CHECK_EQ(r.position, at);
    CHECK_EQ(dcf_ser_reader_peek_type(&r), DCF_TYPE_STRING);
    /* ... the application decides to take it as BYTES-like: raw skip of the 7 bytes, to reach the U32 */
    const void* rp;
    CHECK_OK(dcf_ser_read_raw_ptr(&r, &rp, 1 + 4 + 2));
    /* U32 with only 2 body bytes: TRUNCATED, nothing consumed */
    at = r.position;
    CHECK_EQ(dcf_ser_read_u32(&r, &u32), DCF_SER_ERR_TRUNCATED);
    CHECK_EQ(r.position, at);
    CHECK_EQ(dcf_ser_reader_peek_type(&r), DCF_TYPE_U32);

    /* a too-small copy buffer reports OVERFLOW and consumes nothing, so the caller can retry */
    Buf q = {0};
    b8(&q, 0x11); b32(&q, 5); bput(&q, "hello", 5);
    b8(&q, 0x12); b32(&q, 3); bput(&q, "abc", 3);
    size_t glen;
    uint8_t* g = okframe(q.p, q.n, &glen);
    DCFSerReader r2;
    CHECK_OK(open_reader(&r2, g, glen, 0));
    size_t need = 0;
    CHECK_EQ(dcf_ser_read_string_copy(&r2, sbuf, 3, &need), DCF_SER_ERR_OVERFLOW);
    CHECK_EQ(need, 5);
    CHECK_EQ(r2.position, 17);
    CHECK_OK(dcf_ser_read_string_copy(&r2, sbuf, sizeof sbuf, &need));
    CHECK(need == 5 && memcmp(sbuf, "hello", 6) == 0);
    uint8_t bbuf[2];
    size_t bpos = r2.position;
    CHECK_EQ(dcf_ser_read_bytes_copy(&r2, bbuf, sizeof bbuf, &need), DCF_SER_ERR_OVERFLOW);
    CHECK_EQ(need, 3);
    CHECK_EQ(r2.position, bpos);

    /* container headers: a refused array_begin consumes nothing and leaves depth alone */
    Buf z = {0};
    b8(&z, 0x20); b8(&z, 0x00); b32(&z, 0xFFFFFFFFu);
    size_t zlen;
    uint8_t* zf = okframe(z.p, z.n, &zlen);
    DCFSerReader r3;
    CHECK_OK(open_reader(&r3, zf, zlen, POL_RAW));
    DCFSerType et; size_t cnt;
    CHECK_ERR(dcf_ser_read_array_begin(&r3, &et, &cnt));
    CHECK_EQ(r3.position, 17);
    CHECK_EQ(r3.depth, 0);
    return 0;
}

/* ---- N7: the writer must not accept flag bits the reader can never accept -------------------- */

static int t_n7_writer_rejects_never_allowed_flags(void) {
    static const uint8_t bad[] = {0x40, 0x80, 0xC0, 0x41, 0xA0, 0xFF};
    for (size_t i = 0; i < sizeof bad; i++) {
        DCFSerWriter w;
        DCFSerError e = dcf_ser_writer_init(&w, 1, bad[i]);
        if (e == DCF_SER_OK) { fprintf(stderr, "FAIL: writer_init accepted flags 0x%02x\n", bad[i]); return 1; }
        CHECK_EQ(e, DCF_SER_ERR_INVALID_ARG);
        uint8_t buf[64];
        DCFSerWriter w2;
        CHECK_EQ(dcf_ser_writer_init_buffer(&w2, buf, sizeof buf, 1, bad[i]), DCF_SER_ERR_INVALID_ARG);
    }
    /* every other flag combination is still accepted by the writer (policy is the reader's business) */
    for (unsigned fl = 0; fl < 0x40; fl++) {
        DCFSerWriter w;
        CHECK_OK(dcf_ser_writer_init(&w, 1, (uint8_t)fl));
        dcf_ser_writer_destroy(&w);
    }
    /* reset() has no return value: bad flags make the writer fail closed instead */
    DCFSerWriter w;
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    dcf_ser_writer_reset(&w, 1, 0x80);
    const uint8_t* d; size_t n;
    CHECK_ERR(dcf_ser_write_u8(&w, 1));
    CHECK_ERR(dcf_ser_writer_finish(&w, &d, &n));
    dcf_ser_writer_reset(&w, 1, 0x00);                          /* and a good reset recovers it */
    CHECK_OK(dcf_ser_write_u8(&w, 1));
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    dcf_ser_writer_destroy(&w);
    return 0;
}

/* The writer is not a grammar enforcer. Each row of the README's "writer/reader asymmetries"
 * table is checked here so the table cannot rot. */
static int t_n7_documented_asymmetries(void) {
    const uint8_t* d; size_t n;
    DCFSerWriter w;
    /* 1. array count larger than the elements written */
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    CHECK_OK(dcf_ser_write_array_begin(&w, DCF_TYPE_U8, 3));
    CHECK_OK(dcf_ser_write_u8(&w, 1)); CHECK_OK(dcf_ser_write_array_end(&w));
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    CHECK_ERR(dcf_ser_validate_message(d, n));
    dcf_ser_writer_destroy(&w);
    /* 2. map count larger than the entries written */
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    CHECK_OK(dcf_ser_write_map_begin(&w, DCF_TYPE_U8, DCF_TYPE_U8, 2));
    CHECK_OK(dcf_ser_write_u8(&w, 1)); CHECK_OK(dcf_ser_write_u8(&w, 2)); CHECK_OK(dcf_ser_write_map_end(&w));
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    CHECK_ERR(dcf_ser_validate_message(d, n));
    dcf_ser_writer_destroy(&w);
    /* 2b. ... and MORE elements than the count: structurally fine, the extra is a top-level value */
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    CHECK_OK(dcf_ser_write_array_begin(&w, DCF_TYPE_U8, 1));
    CHECK_OK(dcf_ser_write_u8(&w, 1)); CHECK_OK(dcf_ser_write_u8(&w, 2)); CHECK_OK(dcf_ser_write_array_end(&w));
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    CHECK_OK(dcf_ser_validate_message(d, n));
    dcf_ser_writer_destroy(&w);
    /* 3. struct_begin without struct_end */
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    CHECK_OK(dcf_ser_write_struct_begin(&w, 1));
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    CHECK_ERR(dcf_ser_validate_message(d, n));
    dcf_ser_writer_destroy(&w);
    /* 4. write_field with id 0 and type NULL is the end marker: the struct ends early and the
     *    value after it is a stray top-level value (here a truncated string header) */
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    CHECK_OK(dcf_ser_write_struct_begin(&w, 1));
    CHECK_OK(dcf_ser_write_field(&w, 0, DCF_TYPE_NULL));
    CHECK_OK(dcf_ser_write_field(&w, 0x1100, DCF_TYPE_U8));      /* bytes 11 00 02: a STRING tag, short */
    CHECK_OK(dcf_ser_write_struct_end(&w));
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    CHECK_ERR(dcf_ser_validate_message(d, n));
    dcf_ser_writer_destroy(&w);
    /* 5. raw bytes are not tagged values */
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    CHECK_OK(dcf_ser_write_raw(&w, "\xFF\xFF", 2));
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    CHECK_ERR(dcf_ser_validate_message(d, n));
    { DCFSerReader r; CHECK_OK(dcf_ser_reader_init(&r, d, n)); CHECK_OK(dcf_ser_reader_set_policy(&r, DCF_SER_POLICY_ALLOW_UNSTRUCTURED)); CHECK_OK(dcf_ser_reader_validate(&r)); }
    dcf_ser_writer_destroy(&w);
    /* 6. NO_CRC / COMPRESSED / ENCRYPTED are policy, not grammar: written fine, refused by default */
    static const uint8_t pol_flags[] = {DCF_SER_FLAG_NO_CRC, DCF_SER_FLAG_COMPRESSED, DCF_SER_FLAG_ENCRYPTED};
    for (size_t i = 0; i < sizeof pol_flags; i++) {
        CHECK_OK(dcf_ser_writer_init(&w, 1, pol_flags[i]));
        CHECK_OK(dcf_ser_write_u8(&w, 1));
        CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
        CHECK_EQ(dcf_ser_validate_message(d, n), ERR_POLICY);
        dcf_ser_writer_destroy(&w);
    }
    /* 7. a field header type that differs from the value's tag: the grammar does not relate them,
     *    schema reads do (TYPE_MISMATCH) */
    CHECK_OK(dcf_ser_writer_init(&w, 1, 0));
    CHECK_OK(dcf_ser_write_struct_begin(&w, 0x300));
    CHECK_OK(dcf_ser_write_field(&w, 1, DCF_TYPE_U8));
    CHECK_OK(dcf_ser_write_u32(&w, 5));
    CHECK_OK(dcf_ser_write_struct_end(&w));
    CHECK_OK(dcf_ser_writer_finish(&w, &d, &n));
    CHECK_OK(dcf_ser_validate_message(d, n));
    { DCFSerReader r; Pair p; CHECK_OK(open_reader(&r, d, n, 0)); CHECK_ERR(dcf_ser_read_struct_schema(&r, &p, &pair_schema)); }
    dcf_ser_writer_destroy(&w);
    return 0;
}

/* ---- N8: a schema refused up front leaves the caller's struct untouched ---------------------- */

static int t_n8_refused_schema_leaves_struct_untouched(void) {
    Named out;
    memset(&out, 0xAA, sizeof out);
    Buf pl = {0};
    b8(&pl, 0x22); b16(&pl, 0x301); b16(&pl, 0); b8(&pl, 0);
    size_t flen;
    uint8_t* f = okframe(pl.p, pl.n, &flen);
    DCFSerReader r;
    CHECK_OK(open_reader(&r, f, flen, 0));
    CHECK_EQ(dcf_ser_read_struct_schema(&r, &out, &named_schema), DCF_SER_ERR_INVALID_TYPE);   /* STRING field */
    uint8_t* bytes = (uint8_t*)&out;
    for (size_t i = 0; i < sizeof out; i++) CHECK_EQ(bytes[i], 0xAA);                          /* untouched, NOT zeroed */
    CHECK_EQ(r.position, 17);
    /* whereas a wire-driven error zeroes it */
    static const DCFSerField fl[] = { { "a", 1, DCF_TYPE_U8, DCF_FIELD_REQUIRED, 0, 1 } };
    static const DCFSerSchema sc = { "S", 0x301, fl, 1, 1 };
    uint8_t one = 0xAA;
    CHECK_ERR(dcf_ser_read_struct_schema(&r, &one, &sc));       /* REQUIRED a is absent */
    CHECK_EQ(one, 0);
    return 0;
}

/* ---- I1: ALLOW_LEGACY_CRC is not "either CRC, nothing else" ---------------------------------- */

static int t_i1_legacy_crc_one_bit_blind_spot(void) {
#ifdef DCF_SER_POLICY_ALLOW_LEGACY_CRC
    /* 0xCDD706B3 ^ 0xCDD70693 == 0x20 and CRC is linear, so for a frame with exactly ONE lookup of
     * table entry 245, at byte j, legacy_crc(F') == std_crc(F) where F' is F with bit 5 of byte j+1
     * flipped. A standard-CRC frame corrupted in exactly that bit is therefore accepted as "legacy"
     * under the flag. The README says so; this test pins it down so the sentence cannot rot. */
    uint32_t tbl[256];
    for (uint32_t t = 0; t < 256; t++) { uint32_t c = t; for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1; tbl[t] = c; }
    uint64_t x = 0x1234567ULL;
    for (int attempt = 0; attempt < 20000; attempt++) {
        uint8_t body[24];
        for (unsigned i = 0; i < sizeof body; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; body[i] = (uint8_t)x; }
        Buf pl = {0};
        b8(&pl, 0x12); b32(&pl, sizeof body); bput(&pl, body, sizeof body);       /* BYTES: the body is free */
        size_t flen;
        uint8_t* f = okframe(pl.p, pl.n, &flen);
        free(pl.p);
        uint32_t crc = 0xFFFFFFFFu;
        unsigned hits = 0;
        size_t hit = 0;
        for (size_t i = 0; i < flen - 4; i++) {
            uint32_t idx = (crc ^ f[i]) & 0xFF;
            if (idx == 245) { hits++; hit = i; }
            crc = tbl[idx] ^ (crc >> 8);
        }
        if (hits != 1 || hit < 22 || hit + 1 >= flen - 4 - 1) { free(f); continue; }   /* want the hit and the next byte inside the body */
        f[hit + 1] ^= 0x20;
        DCFSerReader r;
        CHECK_EQ(open_reader(&r, f, flen, 0), DCF_SER_ERR_CRC_MISMATCH);                         /* strict: caught */
        CHECK_OK(open_reader(&r, f, flen, DCF_SER_POLICY_ALLOW_LEGACY_CRC));                      /* legacy flag: accepted */
        free(f);
        return 0;
    }
    fprintf(stderr, "FAIL: no suitable frame found\n");
    return 1;
#else
    fprintf(stderr, "FAIL: API absent\n");
    return 1;
#endif
}

/* ============================================================================
 * Runner
 * ============================================================================ */

typedef struct { const char* name; const char* finding; int (*fn)(void); } TestCase;

#define T(f, finding) { #f, finding, f }
static const TestCase tests[] = {
    T(t_s0_roundtrip_all_types, "S0"),
    T(t_s0_varint_extremes_roundtrip, "S0"),
    T(t_s1_skip_fixed_short, "S1"),
    T(t_s1_skip_string_bytes_len_beyond_payload, "S1"),
    T(t_s1_skip_map_struct_header_short, "S1"),
    T(t_s1_remaining_never_underflows, "S1"),
    T(t_s1_read_raw_ptr_len_wrap, "S1"),
    T(t_s1_read_raw_len_wrap_copies, "S1"),
    T(t_s2_skip_nested_array_1m, "S2"),
    T(t_s2_skip_nested_map_1m, "S2"),
    T(t_s2_skip_nested_struct_1m, "S2"),
    T(t_s2_skip_depth_boundary, "S2"),
    T(t_s2_schema_unknown_field_deep, "S2"),
    T(t_s3_map_count_overflow, "S3"),
    T(t_s3_array_count_beyond_payload, "S3 control"),
    T(t_s3_count_equal_to_payload_ok, "S0"),
    T(t_s3_typed_begin_counts_capped, "S3"),
    T(t_s4_no_crc_refused_by_default, "S4"),
    T(t_s4_no_crc_garbage_payload_not_trusted, "S4"),
    T(t_s4_no_crc_allowed_by_policy, "S4"),
    T(t_s4_unsupported_flag_bits, "S4"),
    T(t_s4_extended_and_reserved_never_allowed, "S4"),
    T(t_s4_payload_len_cap, "S4"),
    T(t_s4_trailing_bytes_refused, "S4"),
    T(t_s4_trailing_bytes_allowed_by_policy, "S4"),
    T(t_s4_policy_setter_rules, "S4"),
    T(t_s4_version_major_checked_minor_free, "S0"),
    T(t_s4_streaming_flags_still_fine, "S0"),
    T(t_s5_write_raw_wrap_external, "S5"),
    T(t_s5_write_raw_wrap_owned, "S5"),
    T(t_s5_write_reserve_wrap, "S5"),
    T(t_s5_grow_does_not_hang, "S5"),
    T(t_s5_raw_and_reserve_capped, "S5"),
    T(t_s5_finish_refuses_oversize_payload, "S4/S5"),
    T(t_s6_required_field_enforced, "S6"),
    T(t_s6_duplicate_field_refused, "S6"),
    T(t_s6_lax_policy_restores_old_behaviour, "S6"),
    T(t_s6_schema_roundtrip_control, "S0"),
    T(t_s6_string_field_not_silently_dropped, "S6"),
    T(t_s6_schema_size_mismatch_read_overflows, "S6"),
    T(t_s6_schema_offset_oob, "S6"),
    T(t_s6_schema_size_mismatch_write, "S6"),
    T(t_s6_unaligned_fields, "S6"),
    T(t_s7_failed_write_poisons_finish, "S7"),
    T(t_s7_every_failure_sets_last_error, "S7"),
    T(t_s7_finish_twice, "S7"),
    T(t_s7_write_after_finish_refused, "S7"),
    T(t_s7_null_data_with_length, "S7"),
    T(t_s7_writer_rejects_invalid_utf8, "S8"),
    T(t_s8_old_message_length_not_hostile, "S8"),
    T(t_s8_message_length_checked, "S8"),
    T(t_s8_varint_overlong_refused, "S8"),
    T(t_s8_varint_tenth_byte_bits_not_dropped, "S8"),
    T(t_s8_varint_lax_policy, "S8"),
    T(t_s8_string_cap_on_read, "S8"),
    T(t_s8_utf8_validated, "S8"),
    T(t_s8_utf8_lax_policy, "S8"),
    T(t_s8_string_copy_rejects_nul, "S8"),
    T(t_s9_strict_validate_rejects_hostile_payloads, "S3/S4"),
    T(t_s9_typed_array_cap_beyond_count_limit, "S3"),
    T(t_s9_validate_payload_agrees_with_typed_reads, "S8"),
    T(t_s10_crc32_is_standard, "S10"),
    T(t_s10_legacy_crc_is_opt_in, "S10"),
    T(t_n1_varsint_wire_vectors, "N1"),
    T(t_n1_varsint_reader_vectors, "N1 control"),
    T(t_n1_varsint_roundtrip_negative, "N1"),
    T(t_n2_schema_lookup_not_linear, "N2"),
    T(t_n2_schema_lookup_semantics, "N2 control"),
    T(t_n6_validate_resets_depth, "N6"),
    T(t_n6_failed_schema_read_leaves_reader_unchanged, "N6"),
    T(t_n6_failed_schema_read_other_errors, "N6"),
    T(t_n4_read_raw_zero_on_failed_init, "N4"),
    T(t_n5_typed_reads_are_atomic, "N5"),
    T(t_n7_writer_rejects_never_allowed_flags, "N7"),
    T(t_n7_documented_asymmetries, "N7"),
    T(t_n8_refused_schema_leaves_struct_untouched, "N8"),
    T(t_i1_legacy_crc_one_bit_blind_spot, "I1"),
};

static const char* first_interesting(const char* log) {
    static const char* keys[] = {"FAIL:", "ERROR: AddressSanitizer", "runtime error:", "ERROR: LeakSanitizer", "SUMMARY:"};
    const char* best = NULL;
    for (size_t k = 0; k < sizeof keys / sizeof keys[0]; k++) {
        const char* p = strstr(log, keys[k]);
        if (p && (!best || p < best)) best = p;
    }
    return best;
}

static int run_one(const TestCase* t, int verbose) {
    int pfd[2];
    if (pipe(pfd) != 0) { perror("pipe"); return 1; }
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], 2);
        close(pfd[1]);
        struct rlimit rl = { 8u * 1024 * 1024, 8u * 1024 * 1024 };
        setrlimit(RLIMIT_STACK, &rl);
        alarm(30);
        int rc = t->fn();
        _exit(rc ? 1 : 0);          /* skip atexit: test frames are deliberately not freed */
    }
    close(pfd[1]);
    char log[65536];
    size_t got = 0;
    for (;;) {
        ssize_t n = read(pfd[0], log + got, sizeof log - 1 - got);
        if (n <= 0) { if (n < 0 && got < sizeof log - 1) continue; break; }
        got += (size_t)n;
        if (got >= sizeof log - 1) {            /* keep draining so the child never blocks */
            char sink[4096];
            while (read(pfd[0], sink, sizeof sink) > 0) {}
            break;
        }
    }
    log[got] = '\0';
    close(pfd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    int pass = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    if (pass) {
        printf("  PASS  %-48s [%s]\n", t->name, t->finding);
        if (verbose && log[0]) printf("%s", log);          /* -v: a passing test's "info:" lines too */
        return 0;
    }
    char how[48];
    if (WIFSIGNALED(st)) snprintf(how, sizeof how, "signal %d", WTERMSIG(st));
    else snprintf(how, sizeof how, "exit %d", WEXITSTATUS(st));
    const char* line = first_interesting(log);
    char first[200] = "";
    if (line) {
        size_t i = 0;
        while (line[i] && line[i] != '\n' && i < sizeof first - 1) { first[i] = line[i]; i++; }
        first[i] = '\0';
    }
    printf("  FAIL  %-48s [%s] (%s) %s\n", t->name, t->finding, how, first);
    if (verbose) printf("----- child stderr -----\n%s\n------------------------\n", log);
    return 1;
}

int main(int argc, char** argv) {
    int verbose = 0;
    const char* filter = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) verbose = 1;
        else filter = argv[i];
    }
    printf("=== DCF hostile-input suite ===\n");
    int ran = 0, failed = 0;
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        if (filter && !strstr(tests[i].name, filter)) continue;
        ran++;
        failed += run_one(&tests[i], verbose);
    }
    printf("=== %d run, %d passed, %d failed ===\n", ran, ran - failed, failed);
    return failed ? 1 : 0;
}
