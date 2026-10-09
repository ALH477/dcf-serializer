/**
 * @file dcfs_gate_unit.c
 * @brief The emitted Exsecutor gate, compiled as one self-contained unit
 *
 * SPDX-License-Identifier: BSD-3-Clause (this wrapper; see gate/PROVENANCE.md
 * for the status of the emitted file it includes)
 *
 * dcfs_gate.gen.c is included unmodified (it is byte-identical to what
 * `exsc --emitte c` printed; scripts/check-gate-fresh.sh checks that). The two
 * things done around it:
 *
 *  - `exsrt_abortus`, the one symbol the emitted C imports and which must not
 *    return, is renamed to `dcfs_gate_trap` (defined in dcfs_gate_host.c) so it
 *    cannot collide with another Exsecutor unit linked into the same program.
 *  - the unit's functions get hidden visibility: nothing but dcfs_gate_host.c
 *    needs them, and a shared libdcf_serialize does not export them.
 *
 * Compile this file on its own as GNU C11 (the emitted C uses GNU extensions):
 *     cc -std=gnu11 -c dcfs_gate_unit.c
 */
#define exsrt_abortus dcfs_gate_trap
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC visibility push(hidden)
#endif
#include "dcfs_gate.gen.c"
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC visibility pop
#endif
