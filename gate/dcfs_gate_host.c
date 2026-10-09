/**
 * @file dcfs_gate_host.c
 * @brief Host glue for the Exsecutor-generated DCFS admission gate
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
 *
 * Two jobs:
 *
 *  1. Marshalling. The emitted C takes `unsigned char *` buffers whose FULL
 *     declared size must be readable and takes lengths as uint64_t. A frame up
 *     to 65557 bytes is copied into a zero-padded 65557-byte buffer; a larger
 *     frame is represented by its first 17 bytes plus its length.
 *
 *  2. Containment of a trap. A unit built by `exsc --emitte c` imports one
 *     symbol, `_Noreturn void exsrt_abortus(unsigned kind)`, called on any trap
 *     (bounds, overflow, `terminus`). The default host behaviour is abort(),
 *     which would let one hostile frame kill a network-facing process IF a trap
 *     were ever reachable. The gate is written not to trap (examples/dcfs_gate/
 *     proba_c.sh sweeps every length 0..cap+5 and 2^63, 2^64-1), but a guarantee
 *     of "cannot happen" is not a reason to leave abort() armed. So a trap inside
 *     a guarded call longjmps back here and dcfs_gate_judge() returns
 *     DCFS_GATE_TRAP (dcf_serialize.c turns that into DCF_SER_ERR_INTERNAL and
 *     refuses the frame). With no guard active, exsrt_abortus still abort()s.
 *
 *     This is the idea of Exsecutor's examples/abortus/tutela.c, re-implemented
 *     here (rather than linked) so the library has no dependency on the
 *     Exsecutor tree and so the guard is private to it. The guard is a
 *     `_Thread_local` pointer to the active jmp_buf: a trap on thread A can only
 *     ever jump to a setjmp made by thread A. (tutela.c's own chain is also
 *     _Thread_local by declaration; that is read from its source here, not
 *     exercised by this repository -- see gate/README.md.)
 *
 *     C11 7.13.2.1: after longjmp, objects of the setjmp-calling function that
 *     were changed since the setjmp and are not volatile are indeterminate. The
 *     function that calls setjmp (guarded_call) changes none: its parameters and
 *     `prior` are written once before setjmp, and the only datum read after a
 *     longjmp is the volatile thread-local `tl_trap_kind`.
 */

#include "dcfs_gate_host.h"

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define exsrt_abortus dcfs_gate_trap
#include "dcfs_gate.gen.h"
#undef exsrt_abortus

/* ---------------------------------------------------------------- the guard */

/* The active guard of THIS thread, or NULL. Static storage duration, so
 * 7.13.2.1p3 does not apply to it. */
static _Thread_local jmp_buf* tl_guard;
static _Thread_local volatile unsigned tl_trap_kind;

/* Hidden: the emitted unit (dcfs_gate_unit.c) calls it, nothing outside the
 * library should. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
_Noreturn void dcfs_gate_trap(unsigned kind);

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
_Noreturn void dcfs_gate_trap(unsigned kind) {
    jmp_buf* g = tl_guard;
    if (g != NULL) {
        tl_guard = NULL;                         /* the guard is spent */
        tl_trap_kind = kind != 0 ? kind : 0xffffffffu;
        longjmp(*g, 1);
    }
    fprintf(stderr, "dcfs_gate: trap %u outside a guard\n", kind);
    abort();
}

typedef void (*guarded_fn)(void* ctx);

/* Runs fn(ctx) under a guard. Returns 0 if it returned, else the trap kind. */
static unsigned guarded_call(guarded_fn fn, void* ctx) {
    jmp_buf jb;
    jmp_buf* const prior = tl_guard;             /* set before setjmp, never changed after */
    tl_guard = &jb;
    tl_trap_kind = 0;
    if (setjmp(jb) == 0) {
        fn(ctx);
        tl_guard = prior;
        return 0;
    }
    tl_guard = prior;
    return tl_trap_kind;
}

/* ------------------------------------------------------------ the gate calls */

typedef struct {
    unsigned char* buf;
    uint64_t       n;
    int            whole;        /* 1: admitte_corpus, 0: admitte_caput */
    uint64_t       verdict;
} JudgeCtx;

static void judge_thunk(void* p) {
    JudgeCtx* c = (JudgeCtx*)p;
    c->verdict = c->whole ? exs_admitte_corpus(c->buf, c->n) : exs_admitte_caput(c->buf, c->n);
}

/* The whole-frame gate reads its declared 65557 bytes; keep them in
 * thread-local storage (a 64 KiB frame on a small thread stack is not a risk
 * worth taking) and keep them zero between calls. */
static _Thread_local unsigned char tl_corpus[DCFS_GATE_CORPUS_CAP];

DcfsGateResult dcfs_gate_judge(const uint8_t* frame, size_t len, uint8_t* verdict) {
    JudgeCtx c;
    unsigned char head[17];
    unsigned k;

    if (verdict) *verdict = 255;
    if (len == 0 || frame == NULL) {
        /* nothing to copy; the gate answers 1 (fewer than 17 bytes) for n < 17 */
        memset(head, 0, sizeof head);
        c.buf = head; c.n = 0; c.whole = 0; c.verdict = 0;
        k = guarded_call(judge_thunk, &c);
    } else if (len <= DCFS_GATE_CORPUS_CAP) {
        memcpy(tl_corpus, frame, len);           /* the tail is already zero */
        c.buf = tl_corpus; c.n = len; c.whole = 1; c.verdict = 0;
        k = guarded_call(judge_thunk, &c);
        memset(tl_corpus, 0, len);               /* restore the zero padding, trapped or not */
    } else {
        memcpy(head, frame, sizeof head);        /* len > 65557 >= 17 */
        c.buf = head; c.n = (uint64_t)len; c.whole = 0; c.verdict = 0;
        k = guarded_call(judge_thunk, &c);
    }

    if (k != 0) return DCFS_GATE_TRAP;
    if (verdict) *verdict = (uint8_t)c.verdict;
    return c.verdict == 0 ? DCFS_GATE_ADMIT : DCFS_GATE_REJECT;
}

/* ------------------------------------------------------------------ selftest */

static void trap_thunk(void* p) {
    dcfs_gate_trap(*(unsigned*)p);
}

int dcfs_gate_guard_selftest(unsigned kind) {
    unsigned k = kind;
    unsigned got = guarded_call(trap_thunk, &k);
    unsigned expect = kind != 0 ? kind : 0xffffffffu;
    return got == expect && tl_guard == NULL;
}
