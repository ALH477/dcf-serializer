/**
 * @file dcf_serialize_fuzz.c
 * @brief Fuzz target for the DCF reader, writer and the C-vs-gate agreement
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
 *
 * One entry point, fuzz_one(data, size), two drivers:
 *
 *  - libFuzzer, when built with -DDCF_FUZZ_LIBFUZZER (clang -fsanitize=fuzzer):
 *    LLVMFuzzerTestOneInput() calls fuzz_one().
 *  - a deterministic mutation driver (the default; needs only a C compiler and
 *    the sanitizers): main() seeds a corpus from the writer, mutates it with a
 *    fixed PRNG and calls fuzz_one() until the time budget is spent.
 *
 * fuzz_one() interprets its input in one of four ways (the first byte chooses):
 *   0  the bytes ARE a frame, validated under a strict or random policy;
 *   1  the bytes are a PAYLOAD: wrapped in a valid header and CRC so the
 *      grammar is reached without the fuzzer having to guess a CRC;
 *   2  the bytes are a program for the WRITER; whatever the writer finishes,
 *      the strict reader must accept (round-trip property);
 *   3  as 1, but also compared against dcf_ser_validate_payload() directly.
 * After any validated frame it drives the typed readers, skip, and a schema
 * read to the end of the payload, checking the reader invariant
 * position <= payload_end <= length after every call. Under the strict policy
 * and up to the gate's capacity the C validator and the Exsecutor gate must
 * agree; a disagreement abort()s. Sanitizer reports, crashes and property
 * violations are the findings.
 *
 * Usage (default driver): dcf_serialize_fuzz [seconds]
 */

#include "dcf_serialize.h"
#ifndef DCF_SER_NO_GATE
#include "gate/dcfs_gate_host.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_INPUT 70000u

static unsigned long long st_frames_ok, st_frames_refused, st_writer_ok, st_writer_failed;

static void fail(const char* what) {
    fprintf(stderr, "dcf_serialize_fuzz: PROPERTY VIOLATED: %s\n", what);
    abort();
}

#define REQUIRE(c, what) do { if (!(c)) fail(what); } while (0)

/* ------------------------------------------------------------ frame helpers */

static void put_be32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* header + payload + CRC into out (size 21 + n). */
static size_t wrap_payload(uint8_t* out, const uint8_t* pl, size_t n, uint8_t flags) {
    out[0] = 'D'; out[1] = 'C'; out[2] = 'F'; out[3] = 'S';
    out[4] = 0x05; out[5] = 0x20; out[6] = 0x00; out[7] = 0x01;
    out[8] = flags;
    put_be32(out + 9, (uint32_t)n);
    put_be32(out + 13, 1);
    if (n) memcpy(out + 17, pl, n);
    put_be32(out + 17 + n, dcf_ser_crc32(out, 17 + n));
    return 21 + n;
}

/* ------------------------------------------------------------ the consumer */

typedef struct { uint32_t a; uint8_t b; uint64_t c; double d; } FuzzRec;
static const DCFSerField fuzz_fields[] = {
    { "a", 1, DCF_TYPE_U32, DCF_FIELD_REQUIRED, offsetof(FuzzRec, a), 4 },
    { "b", 2, DCF_TYPE_U8, DCF_FIELD_OPTIONAL, offsetof(FuzzRec, b), 1 },
    { "c", 3, DCF_TYPE_TIMESTAMP, DCF_FIELD_OPTIONAL, offsetof(FuzzRec, c), 8 },
    { "d", 4, DCF_TYPE_F64, DCF_FIELD_OPTIONAL, offsetof(FuzzRec, d), 8 },
};
static const DCFSerSchema fuzz_schema = { "FuzzRec", 0x0102, fuzz_fields, 4, sizeof(FuzzRec) };

static void invariant(const DCFSerReader* r) {
    REQUIRE(r->position <= r->payload_end, "position <= payload_end");
    REQUIRE(r->payload_end <= r->length, "payload_end <= length");
    REQUIRE(dcf_ser_reader_remaining(r) <= r->length, "remaining() did not underflow");
}

/* Read the value at the cursor with the typed reader its tag names; on any
 * error fall back to skip so the walk always makes progress or stops. */
static void consume(DCFSerReader* r) {
    for (int guard = 0; guard < 200000 && !dcf_ser_reader_at_end(r); guard++) {
        DCFSerType t = dcf_ser_reader_peek_type(r);
        size_t before = r->position;
        DCFSerError e = DCF_SER_OK;
        union { bool b; uint8_t u8; int8_t i8; uint16_t u16; int16_t i16; uint32_t u32; int32_t i32;
                uint64_t u64; int64_t i64; float f; double d; uint8_t uuid[16]; } v;
        const char* s; const void* p; size_t n; DCFSerType et, kt, vt; uint16_t id;
        char sbuf[64]; uint8_t bbuf[64];
        switch (t) {
            case DCF_TYPE_NULL:      e = dcf_ser_read_null(r); break;
            case DCF_TYPE_BOOL:      e = dcf_ser_read_bool(r, &v.b); break;
            case DCF_TYPE_U8:        e = dcf_ser_read_u8(r, &v.u8); break;
            case DCF_TYPE_I8:        e = dcf_ser_read_i8(r, &v.i8); break;
            case DCF_TYPE_U16:       e = dcf_ser_read_u16(r, &v.u16); break;
            case DCF_TYPE_I16:       e = dcf_ser_read_i16(r, &v.i16); break;
            case DCF_TYPE_U32:       e = dcf_ser_read_u32(r, &v.u32); break;
            case DCF_TYPE_I32:       e = dcf_ser_read_i32(r, &v.i32); break;
            case DCF_TYPE_U64:       e = dcf_ser_read_u64(r, &v.u64); break;
            case DCF_TYPE_I64:       e = dcf_ser_read_i64(r, &v.i64); break;
            case DCF_TYPE_F32:       e = dcf_ser_read_f32(r, &v.f); break;
            case DCF_TYPE_F64:       e = dcf_ser_read_f64(r, &v.d); break;
            case DCF_TYPE_VARINT:    e = (before & 1) ? dcf_ser_read_varint(r, &v.u64) : dcf_ser_read_varsint(r, &v.i64); break;
            case DCF_TYPE_STRING:
                if (before & 1) { e = dcf_ser_read_string(r, &s, &n); if (!e && n) (void)(volatile char)s[n - 1]; }
                else e = dcf_ser_read_string_copy(r, sbuf, sizeof sbuf, &n);
                break;
            case DCF_TYPE_BYTES:
                if (before & 1) { e = dcf_ser_read_bytes(r, &p, &n); if (!e && n) (void)((const volatile uint8_t*)p)[n - 1]; }
                else e = dcf_ser_read_bytes_copy(r, bbuf, sizeof bbuf, &n);
                break;
            case DCF_TYPE_UUID:      e = dcf_ser_read_uuid(r, v.uuid); break;
            case DCF_TYPE_TIMESTAMP: e = dcf_ser_read_timestamp(r, &v.u64); break;
            case DCF_TYPE_ARRAY: {
                e = dcf_ser_read_array_begin(r, &et, &n);
                if (!e) { REQUIRE(n <= DCF_SER_MAX_ARRAY && n <= dcf_ser_reader_remaining(r), "array count is backed by bytes"); (void)dcf_ser_read_array_end(r); }
                break;
            }
            case DCF_TYPE_MAP: {
                e = dcf_ser_read_map_begin(r, &kt, &vt, &n);
                if (!e) { REQUIRE(n <= DCF_SER_MAX_ARRAY && 2 * n <= dcf_ser_reader_remaining(r), "map count is backed by bytes"); (void)dcf_ser_read_map_end(r); }
                break;
            }
            case DCF_TYPE_STRUCT:    e = dcf_ser_read_struct_begin(r, &id); if (!e) (void)dcf_ser_read_struct_end(r); break;
            default:                 e = DCF_SER_ERR_INVALID_TYPE; break;
        }
        invariant(r);
        if (e != DCF_SER_OK || r->position == before) {
            /* the typed read refused or did not move: skip must either move or fail without moving */
            size_t at = r->position;
            DCFSerError se = dcf_ser_reader_skip(r);
            invariant(r);
            if (se != DCF_SER_OK) { REQUIRE(r->position == at, "a failed skip does not move"); return; }
            REQUIRE(r->position > at, "a successful skip moves");
        }
    }
}

static void consume_all(const uint8_t* frame, size_t n, uint32_t policy) {
    DCFSerReader r;
    if (dcf_ser_reader_init(&r, frame, n) != DCF_SER_OK) return;
    if (dcf_ser_reader_set_policy(&r, policy) != DCF_SER_OK) return;
    if (dcf_ser_reader_validate(&r) != DCF_SER_OK) {
        REQUIRE(!r.header_valid, "a refused frame is not marked valid");
        st_frames_refused++;
        return;
    }
    st_frames_ok++;
    invariant(&r);
    consume(&r);

    /* once more from the start: skip every top-level value and land exactly at the end */
    if (dcf_ser_reader_init(&r, frame, n) == DCF_SER_OK && dcf_ser_reader_set_policy(&r, policy) == DCF_SER_OK &&
        dcf_ser_reader_validate(&r) == DCF_SER_OK) {
        int values = 0;
        while (!dcf_ser_reader_at_end(&r) && values < 300000) {
            if (dcf_ser_reader_skip(&r) != DCF_SER_OK) break;
            invariant(&r);
            values++;
        }
        if (!(policy & DCF_SER_POLICY_ALLOW_UNSTRUCTURED)) {
            /* a structured payload has no leftovers */
            REQUIRE(dcf_ser_reader_at_end(&r), "strict validate promised skip would reach the end");
        }
    }

    /* and as a schema struct */
    if (dcf_ser_reader_init(&r, frame, n) == DCF_SER_OK && dcf_ser_reader_set_policy(&r, policy) == DCF_SER_OK &&
        dcf_ser_reader_validate(&r) == DCF_SER_OK) {
        FuzzRec rec;
        (void)dcf_ser_read_struct_schema(&r, &rec, &fuzz_schema);
        invariant(&r);
    }
}

#ifndef DCF_SER_NO_GATE
static void agree_with_gate(const uint8_t* f, size_t n) {
    if (n > DCFS_GATE_CORPUS_CAP) return;
    DCFSerReader r;
    int c = 0;
    if (dcf_ser_reader_init(&r, f, n) == DCF_SER_OK &&
        dcf_ser_reader_set_policy(&r, DCF_SER_POLICY_NO_GATE) == DCF_SER_OK) {
        c = (dcf_ser_reader_validate(&r) == DCF_SER_OK);
    }
    DcfsGateResult g = dcfs_gate_judge(f, n, NULL);
    REQUIRE(g != DCFS_GATE_TRAP, "the gate trapped");
    REQUIRE((g == DCFS_GATE_ADMIT) == c, "C validator and Exsecutor gate disagree");
}
#else
static void agree_with_gate(const uint8_t* f, size_t n) { (void)f; (void)n; }
#endif

/* ------------------------------------------------------------ writer programs */

typedef struct { const uint8_t* p; size_t n, i; } Cursor;
static unsigned next8(Cursor* c) { return c->i < c->n ? c->p[c->i++] : 0; }
static uint16_t next16(Cursor* c) { unsigned hi = next8(c); unsigned lo = next8(c); return (uint16_t)(hi << 8 | lo); }
static uint32_t next32(Cursor* c) { uint32_t hi = next16(c); uint32_t lo = next16(c); return hi << 16 | lo; }
static uint64_t next64(Cursor* c) { uint64_t hi = next32(c); uint64_t lo = next32(c); return hi << 32 | lo; }

static int emit_value(DCFSerWriter* w, Cursor* c, unsigned depth) {
    unsigned op = next8(c) % 24;
    DCFSerError e = DCF_SER_OK;
    switch (op) {
        case 0: e = dcf_ser_write_null(w); break;
        case 1: e = dcf_ser_write_bool(w, next8(c) & 1); break;
        case 2: e = dcf_ser_write_u8(w, (uint8_t)next8(c)); break;
        case 3: e = dcf_ser_write_i16(w, (int16_t)next16(c)); break;
        case 4: e = dcf_ser_write_u32(w, next32(c)); break;
        case 5: e = dcf_ser_write_u64(w, next64(c)); break;
        case 6: e = dcf_ser_write_f32(w, (float)next8(c)); break;
        case 7: e = dcf_ser_write_f64(w, (double)next8(c) / 3.0); break;
        case 8: e = dcf_ser_write_timestamp(w, next64(c)); break;
        case 9: {
            unsigned shift = next8(c) % 64;
            uint64_t v = next64(c);
            e = dcf_ser_write_varint(w, v >> shift);
            break;
        }
        case 10: e = dcf_ser_write_varsint(w, (int64_t)next64(c)); break;
        case 11: {
            uint8_t u[16];
            for (int k = 0; k < 16; k++) u[k] = (uint8_t)next8(c);
            e = dcf_ser_write_uuid(w, u);
            break;
        }
        case 12: case 13: {                                   /* string from the stream: may be invalid UTF-8 */
            unsigned n = next8(c) % 12;
            char s[16];
            for (unsigned k = 0; k < n; k++) s[k] = (char)next8(c);
            e = dcf_ser_write_string_n(w, s, n);
            break;
        }
        case 14: {
            unsigned n = next8(c) % 12;
            uint8_t s[16];
            for (unsigned k = 0; k < n; k++) s[k] = (uint8_t)next8(c);
            e = dcf_ser_write_bytes(w, s, n);
            break;
        }
        case 15: case 16: case 17: {                          /* array */
            if (depth >= 6) { e = dcf_ser_write_null(w); break; }
            unsigned n = next8(c) % 5;
            e = dcf_ser_write_array_begin(w, (DCFSerType)next8(c), n);
            for (unsigned k = 0; !e && k < n; k++) if (emit_value(w, c, depth + 1)) e = DCF_SER_ERR_INTERNAL;
            if (!e) e = dcf_ser_write_array_end(w);
            break;
        }
        case 18: case 19: {                                   /* map */
            if (depth >= 6) { e = dcf_ser_write_null(w); break; }
            unsigned n = next8(c) % 4;
            DCFSerType kt = (DCFSerType)next8(c);
            DCFSerType vt = (DCFSerType)next8(c);
            e = dcf_ser_write_map_begin(w, kt, vt, n);
            for (unsigned k = 0; !e && k < 2 * n; k++) if (emit_value(w, c, depth + 1)) e = DCF_SER_ERR_INTERNAL;
            if (!e) e = dcf_ser_write_map_end(w);
            break;
        }
        default: {                                            /* struct */
            if (depth >= 6) { e = dcf_ser_write_null(w); break; }
            unsigned n = next8(c) % 4;
            e = dcf_ser_write_struct_begin(w, next16(c));
            for (unsigned k = 0; !e && k < n; k++) {
                uint16_t id = (uint16_t)(1 + next16(c) % 65535);   /* never the end marker */
                e = dcf_ser_write_field(w, id, (DCFSerType)next8(c));
                if (!e && emit_value(w, c, depth + 1)) e = DCF_SER_ERR_INTERNAL;
            }
            if (!e) e = dcf_ser_write_struct_end(w);
            break;
        }
    }
    return e != DCF_SER_OK;
}

static void writer_roundtrip(const uint8_t* prog, size_t n, uint8_t flags) {
    DCFSerWriter w;
    if (dcf_ser_writer_init(&w, 0x77, flags) != DCF_SER_OK) return;
    Cursor c = { prog, n, 0 };
    int failed = 0;
    unsigned values = 0;
    while (c.i < c.n && values < 40 && !failed) { failed = emit_value(&w, &c, 0); values++; }
    const uint8_t* d; size_t len;
    DCFSerError fe = dcf_ser_writer_finish(&w, &d, &len);
    if (failed) {
        st_writer_failed++;
        REQUIRE(fe != DCF_SER_OK, "a writer that failed must not finish");
    } else {
        st_writer_ok++;
        REQUIRE(fe == DCF_SER_OK, "a writer whose writes all succeeded finishes");
        /* the round-trip property: what the writer finishes, the strict reader takes */
        DCFSerError ve = dcf_ser_validate_message(d, len);
        if (flags & DCF_SER_FLAG_NO_CRC) REQUIRE(ve == DCF_SER_ERR_POLICY, "strict reader refuses NO_CRC");
        else REQUIRE(ve == DCF_SER_OK, "strict reader accepts what the writer finished");
        DCFSerError second = dcf_ser_writer_finish(&w, &d, &len);
        REQUIRE(second != DCF_SER_OK, "second finish is refused");
        consume_all(d, len, (flags & DCF_SER_FLAG_NO_CRC) ? DCF_SER_POLICY_ALLOW_NO_CRC : 0);
    }
    dcf_ser_writer_destroy(&w);
}

/* ------------------------------------------------------------ the entry point */

void fuzz_one(const uint8_t* data, size_t size);

/* data[0]: low 2 bits = mode, bits 4..6 = frame flags (modes 1, 3), bits 6, 7 = LAX_SCHEMA / APP_FLAGS policy
 * data[1]: one in four values selects a random policy from its high 6 bits
 * data[2..]: the frame, the payload, or the writer program */
void fuzz_one(const uint8_t* data, size_t size) {
    if (size < 3 || size > MAX_INPUT) return;
    unsigned mode = data[0] & 3;
    uint32_t policy = 0;
    if ((data[1] & 3) == 0) {
        policy = (uint32_t)(data[1] >> 2) & 0x3F;
        if (data[0] & 0x40) policy |= DCF_SER_POLICY_LAX_SCHEMA;
        if (data[0] & 0x80) policy |= DCF_SER_POLICY_ALLOW_APP_FLAGS;
    }
    const uint8_t* body = data + 2;
    size_t bn = size - 2;

    if (mode == 0) {
        consume_all(body, bn, policy);
        if (policy == 0) agree_with_gate(body, bn);
    } else if (mode == 1 || mode == 3) {
        uint8_t* f = (uint8_t*)malloc(bn + 21);
        if (!f) return;
        uint8_t flags = (uint8_t)((data[0] >> 2) & 0x1C);                           /* STREAMING|FINAL|PRIORITY */
        size_t n = wrap_payload(f, body, bn, flags);
        consume_all(f, n, policy);
        if (policy == 0) {
            agree_with_gate(f, n);
            if (mode == 3) {
                DCFSerError pe = dcf_ser_validate_payload(body, bn, 0);
                REQUIRE((pe == DCF_SER_OK) == (dcf_ser_validate_message(f, n) == DCF_SER_OK),
                        "validate_payload and strict validate agree about the payload");
            }
        }
        free(f);
    } else {
        writer_roundtrip(body, bn, (uint8_t)((data[0] >> 2) & 0x3C));              /* includes NO_CRC (0x20) sometimes */
    }
}

#ifdef DCF_FUZZ_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    fuzz_one(data, size);
    return 0;
}
#else

/* ------------------------------------------------------------ mutation driver */

static uint64_t rs = 0x853C49E6748FEA9BULL;
static uint64_t rnd(void) { rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27; return rs * 0x2545F4914F6CDD1DULL; }

typedef struct { uint8_t* p; size_t n; unsigned mode; } Input;

/* A seed is [mode byte][policy byte][frame | payload | writer program]. */
static Input seed_make(void) {
    uint8_t prog[160];
    size_t pn = 8 + rnd() % (sizeof prog - 8);
    for (size_t i = 0; i < pn; i++) prog[i] = (uint8_t)rnd();
    Input in = { NULL, 0, 0 };
    unsigned kind = (unsigned)(rnd() % 3);                           /* 0 frame, 1 payload, 2 writer program */
    if (kind == 2) {
        in.p = (uint8_t*)malloc(pn + 2);
        in.p[0] = 2; in.p[1] = 1;
        memcpy(in.p + 2, prog, pn);
        in.n = pn + 2; in.mode = 2;
        return in;
    }
    DCFSerWriter w;
    if (dcf_ser_writer_init(&w, 0x42, 0) != DCF_SER_OK) return in;
    Cursor c = { prog, pn, 0 };
    int failed = 0;
    for (unsigned v = 0; c.i < c.n && v < 20 && !failed; v++) failed = emit_value(&w, &c, 0);
    const uint8_t* d; size_t len;
    if (!failed && dcf_ser_writer_finish(&w, &d, &len) == DCF_SER_OK) {
        const uint8_t* src = kind == 0 ? d : d + 17;
        size_t sn = kind == 0 ? len : len - 21;
        in.p = (uint8_t*)malloc(sn + 2);
        in.p[0] = 0; in.p[1] = 1;
        memcpy(in.p + 2, src, sn);
        in.n = sn + 2; in.mode = kind == 0 ? 0 : 1;
    }
    dcf_ser_writer_destroy(&w);
    return in;
}

static void mutate(Input* in) {
    if (in->n == 0) return;
    unsigned rounds = 1 + (unsigned)(rnd() % 4);
    while (rounds--) {
        size_t pos = rnd() % in->n;
        switch (rnd() % 8) {
            case 0: in->p[pos] ^= (uint8_t)(1u << (rnd() % 8)); break;
            case 1: in->p[pos] = (uint8_t)rnd(); break;
            case 2: in->p[pos] = (uint8_t)(rnd() % 3 == 0 ? 0xFF : (rnd() % 2 ? 0x80 : 0x00)); break;
            case 3: if (in->n < MAX_INPUT) { in->p = (uint8_t*)realloc(in->p, in->n + 1); memmove(in->p + pos + 1, in->p + pos, in->n - pos); in->p[pos] = (uint8_t)rnd(); in->n++; } break;
            case 4: if (in->n > 2) { memmove(in->p + pos, in->p + pos + 1, in->n - pos - 1); in->n--; } break;
            case 5: if (in->n > 8) in->n = 2 + rnd() % (in->n - 2); break;
            case 6: if (in->n + 4 < MAX_INPUT) { in->p = (uint8_t*)realloc(in->p, in->n + 4); for (int k = 0; k < 4; k++) in->p[in->n + k] = (uint8_t)rnd(); in->n += 4; } break;
            default: if (in->n >= 6) { pos = rnd() % (in->n - 4); static const uint32_t v[] = {0, 1, 0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFFu, 0x100000u, 0x100001u, 65536, 65537};
                       uint32_t x = v[rnd() % (sizeof v / sizeof v[0])]; in->p[pos] = (uint8_t)(x >> 24); in->p[pos+1] = (uint8_t)(x >> 16); in->p[pos+2] = (uint8_t)(x >> 8); in->p[pos+3] = (uint8_t)x; } break;
        }
    }
}

int main(int argc, char** argv) {
    double budget = argc > 1 ? atof(argv[1]) : 10.0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    unsigned long long runs = 0, seeds = 0;
    for (;;) {
        Input base = seed_make();
        if (!base.p) continue;
        seeds++;
        for (int round = 0; round < 40; round++) {
            Input in = { (uint8_t*)malloc(base.n), base.n };
            memcpy(in.p, base.p, base.n);
            in.p[0] = (uint8_t)(base.mode == 1 ? (1 + (rnd() % 2) * 2) : base.mode);   /* payload seeds: mode 1 or 3 */
            in.p[0] |= (uint8_t)(rnd() & 0xFC);
            mutate(&in);
            if (in.n >= 2) fuzz_one(in.p, in.n);
            runs++;
            free(in.p);
        }
        free(base.p);
        if ((seeds & 15) == 0) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            if ((double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-9 >= budget) break;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("dcf_serialize_fuzz: %llu inputs from %llu seeds in %.1f s: %llu frames validated and consumed, %llu refused; "
           "%llu writer programs round-tripped, %llu failed cleanly\n"
           "dcf_serialize_fuzz: no crash, no sanitizer report, no property violation\n",
           runs, seeds, (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) * 1e-9,
           st_frames_ok, st_frames_refused, st_writer_ok, st_writer_failed);
    return 0;
}
#endif
