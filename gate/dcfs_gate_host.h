/**
 * @file dcfs_gate_host.h
 * @brief Host glue for the Exsecutor-generated DCFS admission gate
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
 *
 * The gate itself (dcfs_gate.gen.c) is C emitted by `exsc --emitte c` from
 * examples/dcfs_gate/dcfs_gate.exsc in the Exsecutor tree; see gate/PROVENANCE.md.
 * This header is the only thing dcf_serialize.c sees of it.
 */

#ifndef DCFS_GATE_HOST_H
#define DCFS_GATE_HOST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Capacity of the whole-frame gate (17 header + 65536 payload + 4 CRC). */
#define DCFS_GATE_CORPUS_CAP 65557u

typedef enum DcfsGateResult {
    DCFS_GATE_ADMIT  = 0,   /* the gate admitted the frame */
    DCFS_GATE_REJECT = 1,   /* the gate refused it; *verdict says which check */
    DCFS_GATE_TRAP   = 2    /* the gate trapped (a bug); the trap was contained */
} DcfsGateResult;

/**
 * Ask the gate about ONE frame of exactly `len` bytes (header, payload, CRC).
 *
 *  - len <= DCFS_GATE_CORPUS_CAP: the frame is copied into a zero-padded buffer
 *    of the gate's declared size and the whole-frame gate runs on it
 *    (header policy, CRC-32, payload grammar).
 *  - larger: only the header policy runs, on the first 17 bytes and the length
 *    (the payload is never copied).
 *
 * A trap inside the gate does not end the process: it returns DCFS_GATE_TRAP
 * (and abort()s only if no guard is active, which cannot happen on this path).
 * Thread-safe: the guard and the copy buffer are thread-local.
 * `verdict` (optional) receives the gate's verdict byte, 0 = admitted; for a
 * trap it receives 255. Verdicts are tabulated in gate/README.md.
 */
DcfsGateResult dcfs_gate_judge(const uint8_t* frame, size_t len, uint8_t* verdict);

/**
 * Test hook: run a function that traps, under the guard, and report whether
 * the guard returned (1) and left the thread's guard state clean.
 */
int dcfs_gate_guard_selftest(unsigned kind);

#ifdef __cplusplus
}
#endif

#endif /* DCFS_GATE_HOST_H */
