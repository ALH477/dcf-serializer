/**
 * @file dcfs_gate_diff_test.c
 * @brief Differential test: the C validator against the Exsecutor gate
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
 *
 * Two independent implementations of one frame policy (header, CRC-32, payload
 * grammar) exist in this repository: the C reference in dcf_serialize.c
 * (dcf_ser_reader_validate under the strict policy, gate consultation off) and
 * the Exsecutor unit gate/dcfs_gate.gen.c (reached through dcfs_gate_judge).
 * They are written from the same grammar text and must agree, on every frame up
 * to the gate's capacity of 65557 bytes, about ADMIT versus REFUSE.
 *
 * This test feeds both the same frames and counts disagreements. It exits 0 only
 * if there are none. Frame sources, all deterministic (fixed PRNG seed):
 *   1. random structured payloads (every value type, nesting, UTF-8, varints),
 *   2. byte-level mutations of them, with and without the length and CRC
 *      repaired afterwards (an unrepaired CRC would make every case die at the
 *      CRC check and never reach the grammar),
 *   3. structured families: nesting depth sweeps, count and length boundaries,
 *      every flag value, header field off-by-ones, every prefix of a frame,
 *      varint shapes, UTF-8 tables.
 * Frames above the capacity are checked one way only: whatever the C validator
 * accepts, the header-only gate must accept too.
 *
 * Usage: dcfs_gate_diff_test [cases]      (default 250000 random cases)
 */

#include "../dcf_serialize.h"
#include "dcfs_gate_host.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- utilities */

typedef struct { uint8_t* p; size_t n, cap; } Buf;

static void bput(Buf* b, const void* d, size_t n) {
    if (b->n + n > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < b->n + n) nc *= 2;
        b->p = (uint8_t*)realloc(b->p, nc);
        if (!b->p) { fprintf(stderr, "out of memory\n"); exit(2); }
        b->cap = nc;
    }
    if (n) memcpy(b->p + b->n, d, n);
    b->n += n;
}
static void b8(Buf* b, unsigned v)  { uint8_t x = (uint8_t)v; bput(b, &x, 1); }
static void b16(Buf* b, unsigned v) { b8(b, v >> 8); b8(b, v & 0xFF); }
static void b32(Buf* b, uint32_t v) { b16(b, v >> 16); b16(b, v & 0xFFFF); }
static void bclear(Buf* b) { b->n = 0; }

static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void) {
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}
static unsigned rn(unsigned n) { return n ? (unsigned)(rnd() % n) : 0; }

/* ---------------------------------------------------------------- the frame */

static void put_be32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* header + payload (+ CRC when crc != 0). plen_field is written as given. */
static void build_frame(Buf* out, uint8_t flags, uint16_t version, const uint8_t* pl, size_t plen,
                        uint32_t plen_field, int crc) {
    bclear(out);
    b32(out, 0x44434653u);
    b16(out, version);
    b16(out, (unsigned)rn(65536));
    b8(out, flags);
    b32(out, plen_field);
    b32(out, (uint32_t)rnd());
    bput(out, pl, plen);
    if (crc) b32(out, dcf_ser_crc32(out->p, out->n));
}

/* Recompute payload_len (frame_len - 21) and/or the CRC over everything but the last 4 bytes. */
static void repair(Buf* f, int fix_len, int fix_crc) {
    if (f->n >= 21) {
        if (fix_len) put_be32(f->p + 9, (uint32_t)(f->n - 21));
        if (fix_crc) put_be32(f->p + f->n - 4, dcf_ser_crc32(f->p, f->n - 4));
    }
}

/* ------------------------------------------------------------ the two verdicts */

static unsigned long long c_err_hist[0x400];
static unsigned long long g_verdict_hist[256];

static int c_accepts(const uint8_t* f, size_t n, DCFSerError* why) {
    DCFSerReader r;
    DCFSerError e = dcf_ser_reader_init(&r, f, n);
    if (e == DCF_SER_OK) {
        e = dcf_ser_reader_set_policy(&r, DCF_SER_POLICY_NO_GATE);
        if (e == DCF_SER_OK) e = dcf_ser_reader_validate(&r);
    }
    *why = e;
    return e == DCF_SER_OK;
}

static unsigned long long cases, both_admit, both_refuse, disagreements, big_cases, big_c_admit,
                          big_violations, traps;

static void hexdump(const uint8_t* f, size_t n) {
    for (size_t i = 0; i < n && i < 96; i++) fprintf(stderr, "%02x", f[i]);
    if (n > 96) fprintf(stderr, "...(%zu bytes)", n);
    fprintf(stderr, "\n");
}

/* Compare one frame. */
static void check(const uint8_t* f, size_t n, const char* family) {
    DCFSerError why;
    int c = c_accepts(f, n, &why);
    uint8_t verdict = 0;
    DcfsGateResult g = dcfs_gate_judge(f, n, &verdict);
    c_err_hist[(unsigned)why & 0x3FF]++;
    if (g == DCFS_GATE_TRAP) { traps++; fprintf(stderr, "TRAP [%s] n=%zu: ", family, n); hexdump(f, n); }
    if (n > DCFS_GATE_CORPUS_CAP) {
        /* header-only gate: it must not refuse what the full C validator accepts */
        big_cases++;
        if (c) {
            big_c_admit++;
            if (g != DCFS_GATE_ADMIT) {
                big_violations++;
                fprintf(stderr, "BIG VIOLATION [%s] n=%zu C accepted, gate verdict %u\n", family, n, verdict);
            }
        }
        return;
    }
    cases++;
    g_verdict_hist[verdict]++;
    int gate = (g == DCFS_GATE_ADMIT);
    if (c && gate) both_admit++;
    else if (!c && !gate) both_refuse++;
    else {
        disagreements++;
        if (disagreements <= 10) {
            fprintf(stderr, "DISAGREEMENT [%s] n=%zu: C %s (0x%x), gate %s (verdict %u)\n  ", family, n,
                    c ? "ADMITS" : "refuses", why, gate ? "ADMITS" : "refuses", verdict);
            hexdump(f, n);
        }
    }
}

/* ------------------------------------------------------------ payload generator */

static const uint32_t scalars[] = {0, 1, 0x7F, 0x80, 0x7FF, 0x800, 0xD7FF, 0xE000, 0xFFFF, 0x10000, 0x10FFFF};

static void put_utf8(Buf* b, uint32_t cp) {
    if (cp < 0x80) b8(b, cp);
    else if (cp < 0x800) { b8(b, 0xC0 | (cp >> 6)); b8(b, 0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) { b8(b, 0xE0 | (cp >> 12)); b8(b, 0x80 | ((cp >> 6) & 0x3F)); b8(b, 0x80 | (cp & 0x3F)); }
    else { b8(b, 0xF0 | (cp >> 18)); b8(b, 0x80 | ((cp >> 12) & 0x3F)); b8(b, 0x80 | ((cp >> 6) & 0x3F)); b8(b, 0x80 | (cp & 0x3F)); }
}

/* LEB128, canonical; `overlong` extra zero groups make it a non-canonical encoding of the same number. */
static void put_varint(Buf* b, uint64_t v, unsigned overlong) {
    uint8_t tmp[16];
    unsigned n = 0;
    do {
        uint8_t byte = (uint8_t)(v & 0x7F);
        v >>= 7;
        if (v) byte |= 0x80;
        tmp[n++] = byte;
    } while (v);
    while (overlong-- && n < 11) { tmp[n - 1] |= 0x80; tmp[n++] = 0x00; }
    bput(b, tmp, n);
}

static void gen_value(Buf* b, unsigned depth, unsigned budget);

static void gen_scalar(Buf* b) {
    static const struct { uint8_t tag; unsigned size; } fx[] = {
        {0x00,0},{0x01,1},{0x02,1},{0x03,1},{0x04,2},{0x05,2},{0x06,4},{0x07,4},{0x0A,4},
        {0x08,8},{0x09,8},{0x0B,8},{0x30,8},{0x31,8},{0x13,16},
    };
    unsigned i = rn(sizeof fx / sizeof fx[0]);
    b8(b, fx[i].tag);
    for (unsigned k = 0; k < fx[i].size; k++) b8(b, (unsigned)rnd());
}

static void gen_value(Buf* b, unsigned depth, unsigned budget) {
    unsigned k = rn(budget > 0 && depth < 36 ? 100 : 55);
    if (k < 35) { gen_scalar(b); return; }
    if (k < 45) {                                          /* varint */
        b8(b, 0x10);
        uint64_t v = rnd();
        v >>= rn(64);                                       /* two calls in one expression would be unspecified order */
        put_varint(b, v, rn(10) == 0 ? 1 + rn(2) : 0);     /* sometimes non-canonical */
        return;
    }
    if (k < 52) {                                          /* string */
        Buf s = {0};
        unsigned n = rn(8);
        for (unsigned i = 0; i < n; i++) {
            if (rn(6) == 0) put_utf8(&s, scalars[rn(sizeof scalars / sizeof scalars[0])]);
            else if (rn(4) == 0) b8(&s, 0x80 + rn(0x80));        /* usually invalid */
            else put_utf8(&s, 0x20 + rn(0x5F));
        }
        b8(b, 0x11); b32(b, (uint32_t)s.n); bput(b, s.p, s.n);
        free(s.p);
        return;
    }
    if (k < 55) {                                          /* bytes */
        unsigned n = rn(12);
        b8(b, 0x12); b32(b, n);
        for (unsigned i = 0; i < n; i++) b8(b, (unsigned)rnd());
        return;
    }
    if (k < 70) {                                          /* array */
        unsigned n = rn(5);
        b8(b, 0x20); b8(b, (unsigned)rnd()); b32(b, n);
        for (unsigned i = 0; i < n; i++) gen_value(b, depth + 1, budget - 1);
        return;
    }
    if (k < 80) {                                          /* map */
        unsigned n = rn(4);
        b8(b, 0x21); b8(b, (unsigned)rnd()); b8(b, (unsigned)rnd()); b32(b, n);
        for (unsigned i = 0; i < 2 * n; i++) gen_value(b, depth + 1, budget - 1);
        return;
    }
    if (k < 95) {                                          /* struct */
        unsigned n = rn(5);
        b8(b, 0x22); b16(b, (unsigned)rnd());
        for (unsigned i = 0; i < n; i++) {
            b16(b, 1 + rn(65535)); b8(b, (unsigned)rnd());
            gen_value(b, depth + 1, budget - 1);
        }
        b16(b, 0); b8(b, 0);
        return;
    }
    /* an unsupported or unassigned tag, occasionally */
    static const uint8_t odd[] = {0x23, 0x32, 0x33, 0xFE, 0xFF, 0x0C, 0x14, 0x24, 0x40, 0x7F};
    b8(b, odd[rn(sizeof odd)]);
}

static void gen_payload(Buf* b) {
    bclear(b);
    unsigned n = rn(9);
    for (unsigned i = 0; i < n; i++) gen_value(b, 0, 6);
}

/* ------------------------------------------------------------ mutation */

static const uint8_t interesting8[] = {0x00, 0x01, 0x02, 0x7F, 0x80, 0x81, 0xBF, 0xC0, 0xC2, 0xDF, 0xE0,
                                       0xED, 0xEF, 0xF0, 0xF4, 0xF5, 0xFE, 0xFF};
static const uint32_t interesting32[] = {0, 1, 2, 3, 4, 5, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0xFFFF0,
                                         0x100000, 0x100001, 0x7FFFFFFFu, 0x80000000u, 0x80000001u,
                                         0xFFFFFFFEu, 0xFFFFFFFFu, 0x1000000, 0x1000001, 65536, 65537};

static void mutate(Buf* f) {
    unsigned rounds = 1 + rn(3);
    while (rounds--) {
        if (f->n == 0) { b8(f, (unsigned)rnd()); continue; }
        size_t pos = rnd() % f->n;
        switch (rn(10)) {
            case 0: f->p[pos] ^= (uint8_t)(1u << rn(8)); break;
            case 1: f->p[pos] = (uint8_t)rnd(); break;
            case 2: f->p[pos] = interesting8[rn(sizeof interesting8)]; break;
            case 3: {                                                  /* insert a byte */
                uint8_t x = (rn(2) ? (uint8_t)rnd() : interesting8[rn(sizeof interesting8)]);
                Buf t = {0};
                bput(&t, f->p, pos); b8(&t, x); bput(&t, f->p + pos, f->n - pos);
                free(f->p); *f = t;
                break;
            }
            case 4: {                                                  /* delete a byte */
                memmove(f->p + pos, f->p + pos + 1, f->n - pos - 1);
                f->n--;
                break;
            }
            case 5: {                                                  /* overwrite 4 bytes with an interesting u32 */
                if (f->n >= 4) {
                    pos = rnd() % (f->n - 3);
                    put_be32(f->p + pos, interesting32[rn(sizeof interesting32 / sizeof interesting32[0])]);
                }
                break;
            }
            case 6: {                                                  /* duplicate a chunk */
                size_t len = 1 + rnd() % (f->n - pos > 16 ? 16 : f->n - pos);
                Buf t = {0};
                bput(&t, f->p, pos + len); bput(&t, f->p + pos, len); bput(&t, f->p + pos + len, f->n - pos - len);
                free(f->p); *f = t;
                break;
            }
            case 7: f->n = pos; break;                                 /* truncate */
            case 8: { unsigned k = 1 + rn(6); while (k--) b8(f, (unsigned)rnd()); break; }   /* extend */
            default: {                                                 /* swap two bytes */
                size_t other = rnd() % f->n;
                uint8_t t = f->p[pos]; f->p[pos] = f->p[other]; f->p[other] = t;
                break;
            }
        }
    }
}

static const uint8_t flag_choices[] = {0x00, 0x00, 0x00, 0x04, 0x08, 0x10, 0x1C, 0x0C, 0x14, 0x18};

/* ------------------------------------------------------------ families */

static void family_random(unsigned long long count) {
    Buf pl = {0}, f = {0};
    for (unsigned long long i = 0; i < count; i++) {
        gen_payload(&pl);
        uint8_t flags = flag_choices[rn(sizeof flag_choices)];
        uint16_t ver = (uint16_t)(0x0500 | rn(256));
        build_frame(&f, flags, ver, pl.p, pl.n, (uint32_t)pl.n, 1);
        if (rn(4) == 0) { check(f.p, f.n, "valid-ish"); }
        /* mutate, then repair to varying degrees */
        mutate(&f);
        switch (rn(10)) {
            case 0: break;                                   /* raw mutation */
            case 1: case 2: repair(&f, 0, 1); break;         /* CRC only: length may lie */
            default: repair(&f, 1, 1); break;                /* length and CRC: the grammar gets a turn */
        }
        check(f.p, f.n, "mutated");
    }
    free(pl.p); free(f.p);
}

typedef enum { N_ARRAY, N_MAP, N_STRUCT } NestKind;

static void nest(Buf* b, NestKind kind, unsigned depth) {
    for (unsigned i = 0; i < depth; i++) {
        int inner = (i + 1 == depth);
        if (kind == N_ARRAY) { b8(b, 0x20); b8(b, 0x20); b32(b, inner ? 0 : 1); }
        else if (kind == N_MAP) { b8(b, 0x21); b8(b, 0x21); b8(b, 0); b32(b, inner ? 0 : 1); }
        else { b8(b, 0x22); b16(b, 1); if (!inner) { b16(b, 1); b8(b, 0x22); } }
    }
    if (kind == N_MAP) for (unsigned i = 0; i + 1 < depth; i++) b8(b, 0);
    if (kind == N_STRUCT) for (unsigned i = 0; i < depth; i++) { b16(b, 0); b8(b, 0); }
}

static void emit_check(const uint8_t* pl, size_t plen, const char* family) {
    Buf f = {0};
    build_frame(&f, 0, 0x0520, pl, plen, (uint32_t)plen, 1);
    check(f.p, f.n, family);
    /* and the same payload under the other framing mistakes */
    build_frame(&f, 0, 0x0520, pl, plen, (uint32_t)plen + 1, 1);   check(f.p, f.n, family);
    if (plen) { build_frame(&f, 0, 0x0520, pl, plen, (uint32_t)plen - 1, 1); check(f.p, f.n, family); }
    free(f.p);
}

static void family_nesting(void) {
    for (int kind = N_ARRAY; kind <= N_STRUCT; kind++) {
        for (unsigned d = 0; d <= 40; d++) {
            Buf b = {0};
            nest(&b, (NestKind)kind, d);
            emit_check(b.p, b.n, "nesting");
            /* two siblings, to be sure depth is released on the way out */
            nest(&b, (NestKind)kind, d);
            emit_check(b.p, b.n, "nesting-x2");
            free(b.p);
        }
    }
    /* mixed nesting: a stack of alternating kinds */
    for (unsigned d = 28; d <= 36; d++) {
        Buf b = {0};
        for (unsigned i = 0; i < d; i++) {
            int inner = (i + 1 == d);
            switch (i % 3) {
                case 0: b8(&b, 0x20); b8(&b, 0); b32(&b, inner ? 0 : 1); break;
                case 1: b8(&b, 0x21); b8(&b, 0); b8(&b, 0); b32(&b, inner ? 0 : 1); break;
                default: b8(&b, 0x22); b16(&b, 7); if (!inner) { b16(&b, 2); b8(&b, 0x22); } break;
            }
        }
        /* close what needs closing, innermost first */
        for (unsigned i = d; i-- > 0;) {
            if (i + 1 == d) { if (i % 3 == 2) { b16(&b, 0); b8(&b, 0); } continue; }
            if (i % 3 == 1) b8(&b, 0);
            if (i % 3 == 2) { b16(&b, 0); b8(&b, 0); }
        }
        emit_check(b.p, b.n, "nesting-mixed");
        free(b.p);
    }
}

static void family_counts(void) {
    static const uint32_t counts[] = {0, 1, 2, 3, 9, 10, 11, 12, 100, 1048575, 1048576, 1048577,
                                      0x7FFFFFFFu, 0x80000000u, 0x80000001u, 0xFFFFFFFFu, 0x40000000u};
    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        for (unsigned fill = 0; fill <= 24; fill += 1) {
            Buf b = {0};
            b8(&b, 0x20); b8(&b, 0); b32(&b, counts[i]);
            for (unsigned k = 0; k < fill; k++) b8(&b, 0);
            emit_check(b.p, b.n, "array-count");
            b.n = 0;
            b8(&b, 0x21); b8(&b, 0); b8(&b, 0); b32(&b, counts[i]);
            for (unsigned k = 0; k < fill; k++) b8(&b, 0);
            emit_check(b.p, b.n, "map-count");
            free(b.p);
        }
    }
    /* counts that exactly fit and one more, with multi-byte elements */
    for (unsigned n = 0; n < 40; n++) {
        for (int extra = -1; extra <= 1; extra++) {
            Buf b = {0};
            b8(&b, 0x20); b8(&b, 6); b32(&b, (uint32_t)((int)n + extra));
            for (unsigned k = 0; k < n; k++) { b8(&b, 6); b32(&b, k); }
            emit_check(b.p, b.n, "array-exact");
            free(b.p);
        }
    }
}

static void family_strings(void) {
    static const uint8_t bad[][6] = {
        {0x80}, {0xBF}, {0xC0,0x80}, {0xC1,0xBF}, {0xC2}, {0xC2,0x7F}, {0xC2,0xC0}, {0xDF,0xBF}, {0xE0,0x9F,0xBF},
        {0xE0,0xA0,0x80}, {0xE0,0x80,0x80}, {0xED,0xA0,0x80}, {0xED,0x9F,0xBF}, {0xEE,0x80,0x80}, {0xE2,0x82},
        {0xE2,0x82,0x41}, {0xF0,0x8F,0xBF,0xBF}, {0xF0,0x90,0x80,0x80}, {0xF4,0x8F,0xBF,0xBF}, {0xF4,0x90,0x80,0x80},
        {0xF5,0x80,0x80,0x80}, {0xF8,0x88,0x80,0x80,0x80}, {0xFF}, {0xFE}, {0xF0,0x9F,0x98}, {0xF0,0x9F,0x98,0x80,0x80},
    };
    static const unsigned bad_n[] = {1,1,2,2,1,2,2,2,3,3,3,3,3,3,2,3,4,4,4,4,4,5,1,1,3,5};
    for (size_t i = 0; i < sizeof bad_n / sizeof bad_n[0]; i++) {
        for (unsigned pre = 0; pre < 3; pre++) {
            for (unsigned post = 0; post < 3; post++) {
                Buf b = {0};
                b8(&b, 0x11); b32(&b, pre + bad_n[i] + post);
                for (unsigned k = 0; k < pre; k++) b8(&b, 'a');
                bput(&b, bad[i], bad_n[i]);
                for (unsigned k = 0; k < post; k++) b8(&b, 0x80 + k);
                emit_check(b.p, b.n, "utf8");
                free(b.p);
            }
        }
    }
    /* every scalar value boundary, and every 2-byte sequence lead/continuation pair */
    for (unsigned lead = 0x80; lead <= 0xFF; lead++) {
        for (unsigned c1 = 0x00; c1 <= 0xFF; c1 += (c1 == 0x7F ? 1 : (c1 >= 0x78 && c1 <= 0xC8 ? 1 : 7))) {
            Buf b = {0};
            b8(&b, 0x11); b32(&b, 4); b8(&b, lead); b8(&b, c1); b8(&b, 0x80); b8(&b, 0x80);
            emit_check(b.p, b.n, "utf8-pairs");
            free(b.p);
        }
    }
    for (size_t i = 0; i < sizeof scalars / sizeof scalars[0]; i++) {
        Buf s = {0}, b = {0};
        put_utf8(&s, scalars[i]);
        b8(&b, 0x11); b32(&b, (uint32_t)s.n); bput(&b, s.p, s.n);
        emit_check(b.p, b.n, "utf8-scalar");
        free(s.p); free(b.p);
    }
    /* string lengths around what fits in a 65536-byte payload; and past the cap */
    static const uint32_t lens[] = {0, 1, 65530, 65531, 65532, 65533, 65535, 65536, 65537, 0xFFFF, 0x10000, 0xFFFFFFFFu};
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        for (unsigned tag = 0x11; tag <= 0x12; tag++) {
            Buf b = {0};
            b8(&b, tag); b32(&b, lens[i]);
            size_t fill = lens[i] > 65535 ? 65530 : lens[i];
            for (size_t k = 0; k < fill; k++) b8(&b, 'x');
            emit_check(b.p, b.n, "string-len");
            free(b.p);
        }
    }
}

static void family_varints(void) {
    for (unsigned len = 1; len <= 12; len++) {
        for (unsigned last = 0; last < 256; last += (last < 4 ? 1 : (last == 0x7E ? 1 : 0x21))) {
            for (unsigned fillbyte = 0x80; fillbyte <= 0xFF; fillbyte += 0x7F) {
                Buf b = {0};
                b8(&b, 0x10);
                for (unsigned k = 0; k + 1 < len; k++) b8(&b, fillbyte);
                b8(&b, last);
                emit_check(b.p, b.n, "varint");
                /* followed by another value, to see where the varint ended */
                b8(&b, 0x02); b8(&b, 0x55);
                emit_check(b.p, b.n, "varint+next");
                free(b.p);
            }
        }
    }
}

static void family_headers(void) {
    Buf pl = {0}, f = {0};
    b8(&pl, 0x02); b8(&pl, 0x09); b8(&pl, 0x11); b32(&pl, 2); b8(&pl, 'h'); b8(&pl, 'i');
    for (unsigned flags = 0; flags < 256; flags++) {
        build_frame(&f, (uint8_t)flags, 0x0520, pl.p, pl.n, (uint32_t)pl.n, 1);
        check(f.p, f.n, "flags");
        build_frame(&f, (uint8_t)flags, 0x0520, pl.p, pl.n, (uint32_t)pl.n, 0);      /* no CRC bytes at all */
        check(f.p, f.n, "flags-nocrc");
    }
    for (unsigned major = 0; major < 256; major += (major < 8 ? 1 : 50)) {
        build_frame(&f, 0, (uint16_t)((major << 8) | 0x20), pl.p, pl.n, (uint32_t)pl.n, 1);
        check(f.p, f.n, "version");
    }
    build_frame(&f, 0, 0x0520, pl.p, pl.n, (uint32_t)pl.n, 1);
    Buf good = {0};
    bput(&good, f.p, f.n);
    for (size_t i = 0; i < 17; i++) {                             /* every header byte: ±1, 0x00, 0xFF; CRC repaired and not */
        static const int deltas[] = {1, -1, 0x40, -0x40};
        for (size_t d = 0; d < 4; d++) {
            bclear(&f); bput(&f, good.p, good.n);
            f.p[i] = (uint8_t)(f.p[i] + deltas[d]);
            check(f.p, f.n, "header-byte");
            repair(&f, 0, 1);
            check(f.p, f.n, "header-byte+crc");
        }
    }
    static const uint32_t plens[] = {0, 1, (uint32_t)0 /* placeholder */, 0x00FFFFFFu, 0x01000000u, 0x01000001u, 0x7FFFFFFFu,
                                     0x80000000u, 0xFFFFFFFFu, 0xFFFFFFFCu, 0xFFFFFFEBu};
    for (size_t i = 0; i < sizeof plens / sizeof plens[0]; i++) {
        uint32_t p = i == 2 ? (uint32_t)pl.n : plens[i];
        build_frame(&f, 0, 0x0520, pl.p, pl.n, p, 1);
        check(f.p, f.n, "payload_len");
    }
    /* every prefix of a good frame, and the frame plus 1..8 junk bytes */
    for (size_t n = 0; n <= good.n; n++) check(good.p, n, "prefix");
    for (unsigned extra = 1; extra <= 8; extra++) {
        bclear(&f); bput(&f, good.p, good.n);
        for (unsigned k = 0; k < extra; k++) b8(&f, 0xAA);
        check(f.p, f.n, "suffix");
    }
    free(pl.p); free(f.p); free(good.p);
}

static void family_struct_shapes(void) {
#define SHAPE(...) do { const uint8_t s_[] = {__VA_ARGS__}; emit_check(s_, sizeof s_, "struct-shape"); } while (0)
    /* end marker lookalikes: id 0 with a non-NULL type, id != 0 with type NULL */
    SHAPE(0x22,0,1, 0,0,0);                         /* empty struct */
    SHAPE(0x22,0,1, 0,0,0x02, 0x02,5, 0,0,0);       /* id 0 type U8 is an ordinary field */
    SHAPE(0x22,0,1, 0,5,0x00, 0x00, 0,0,0);         /* id 5 type NULL, then a NULL value */
    SHAPE(0x22,0,1, 0,5,0x00);                      /* id 5 type NULL, no value, no end */
    SHAPE(0x22,0,1);                                /* no end marker */
    SHAPE(0x22,0,1, 0,0);                           /* end marker cut short */
    SHAPE(0x22,0);                                  /* header cut short */
    SHAPE(0x22,0,1, 0,1,0x02, 0x02,5);              /* a field but no end */
    SHAPE(0x20,0,0,0,0,2, 0x22,0,1, 0,0,0);         /* array of 2: a struct, then nothing */
    SHAPE(0x20,0,0,0,0,2, 0x22,0,1, 0,0,0, 0x00);   /* array of 2: a struct, then NULL */
    SHAPE(0x22,0,1, 0,1,0x20, 0x20,0,0,0,0,1, 0,0,0, 0,0,0);  /* struct{array[struct-end-marker]} */
    SHAPE(0x00, 0x00, 0x00);                        /* three NULLs */
    SHAPE(0x22,0,1, 0xFF,0xFF,0x00, 0x00, 0,0,0);   /* max field id */
#undef SHAPE
}

static void family_big(void) {
    /* frames at and past the gate's 65557-byte capacity */
    static const size_t sizes[] = {65536, 65540, 65552, 65553, 65554, 65556, 65557 - 21 + 0, 65557 - 21 + 1, 65557 - 21 + 2, 65600,
                                   1 << 20, 3 * (1 << 20), 16u * 1024 * 1024 - 2, 16u * 1024 * 1024 - 1, 16u * 1024 * 1024};
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        size_t plen = sizes[i];
        uint8_t* pl = (uint8_t*)calloc(plen ? plen : 1, 1);       /* NULL values: a valid payload of any size */
        Buf f = {0};
        build_frame(&f, 0, 0x0520, pl, plen, (uint32_t)plen, 1);
        check(f.p, f.n, "big-valid");
        if (plen > 8) { pl[plen / 2] = 0xFF; build_frame(&f, 0, 0x0520, pl, plen, (uint32_t)plen, 1); check(f.p, f.n, "big-badtag"); }
        build_frame(&f, 0, 0x0520, pl, plen, (uint32_t)plen, 1);
        f.p[f.n - 1] ^= 1;
        check(f.p, f.n, "big-badcrc");
        build_frame(&f, 0, 0x0520, pl, plen, (uint32_t)plen + 1, 1);
        check(f.p, f.n, "big-badlen");
        free(f.p); free(pl);
    }
}

/* ------------------------------------------------------------ main */

int main(int argc, char** argv) {
    unsigned long long random_cases = 250000;
    unsigned long long required = 200000;                 /* the default run must be a real one */
    if (argc > 1) { random_cases = strtoull(argv[1], NULL, 0); required = 0; }   /* a short run (valgrind) is the caller's choice */

    printf("=== DCFS differential: C validator vs Exsecutor gate ===\n");
    family_headers();
    family_nesting();
    family_counts();
    family_strings();
    family_varints();
    family_struct_shapes();
    family_big();
    unsigned long long structured = cases;
    family_random(random_cases);

    printf("frames <= %u bytes compared : %llu (%llu structured, %llu random/mutated)\n", DCFS_GATE_CORPUS_CAP,
           cases, structured, cases - structured);
    printf("  both admit                : %llu\n", both_admit);
    printf("  both refuse               : %llu\n", both_refuse);
    printf("  DISAGREEMENTS             : %llu\n", disagreements);
    printf("frames  > %u bytes (one-way): %llu, C admitted %llu, gate refused an admitted one %llu\n",
           DCFS_GATE_CORPUS_CAP, big_cases, big_c_admit, big_violations);
    printf("gate traps contained        : %llu\n", traps);
    printf("gate verdicts hit (verdict:count):");
    for (unsigned v = 0; v < 256; v++) if (g_verdict_hist[v]) printf(" %u:%llu", v, g_verdict_hist[v]);
    printf("\n");
    printf("C error codes hit (code:count):");
    for (unsigned e = 0; e < 0x400; e++) if (c_err_hist[e]) printf(" 0x%x:%llu", e, c_err_hist[e]);
    printf("\n");

    int ok = disagreements == 0 && big_violations == 0 && traps == 0 && cases >= required;
    printf(ok ? "=== PASS: 0 disagreements ===\n" : "=== FAIL ===\n");
    return ok ? 0 : 1;
}
