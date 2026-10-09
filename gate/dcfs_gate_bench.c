/**
 * @file dcfs_gate_bench.c
 * @brief What the Exsecutor gate costs next to the C validator (make bench)
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
 *
 * Builds one valid frame of roughly the stated size and times dcfs_gate_judge()
 * against dcf_ser_reader_validate() under DCF_SER_POLICY_NO_GATE (so the C
 * figure excludes the gate). Wall-clock, single thread, one run: the numbers
 * depend on the machine; they are here to be re-measured, not quoted.
 */
#define _POSIX_C_SOURCE 200809L
#include "../dcf_serialize.h"
#include "dcfs_gate_host.h"

#include <stdio.h>
#include <time.h>

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static int bench(const char* name, size_t payload_bytes, unsigned iters) {
    DCFSerWriter w;
    if (dcf_ser_writer_init(&w, 1, 0) != DCF_SER_OK) return 1;
    size_t left = payload_bytes;
    while (left > 40) {
        (void)dcf_ser_write_u32(&w, 7);
        left -= 5;
        if (left > 100) { (void)dcf_ser_write_string(&w, "hello world, this is text"); left -= 30; }
    }
    const uint8_t* d;
    size_t n;
    if (dcf_ser_writer_finish(&w, &d, &n) != DCF_SER_OK) return 1;

    double t0 = now();
    for (unsigned i = 0; i < iters; i++) {
        if (dcfs_gate_judge(d, n, NULL) != DCFS_GATE_ADMIT) { fprintf(stderr, "gate refused the frame\n"); return 1; }
    }
    double t1 = now();
    for (unsigned i = 0; i < iters; i++) {
        DCFSerReader r;
        if (dcf_ser_reader_init(&r, d, n) != DCF_SER_OK ||
            dcf_ser_reader_set_policy(&r, DCF_SER_POLICY_NO_GATE) != DCF_SER_OK ||
            dcf_ser_reader_validate(&r) != DCF_SER_OK) { fprintf(stderr, "C refused the frame\n"); return 1; }
    }
    double t2 = now();

    double bytes = (double)n * (double)iters;
    printf("%-6s frame=%6zu B   gate %8.2f us/frame (%6.1f MB/s)   C validate %7.2f us/frame (%6.1f MB/s)\n",
           name, n, (t1 - t0) / iters * 1e6, bytes / (t1 - t0) / 1e6, (t2 - t1) / iters * 1e6, bytes / (t2 - t1) / 1e6);
    dcf_ser_writer_destroy(&w);
    return 0;
}

int main(void) {
    int bad = 0;
    bad |= bench("small", 100, 200000);
    bad |= bench("1 KiB", 1000, 50000);
    bad |= bench("8 KiB", 8000, 10000);
    bad |= bench("64 KiB", 65000, 1000);
    return bad;
}
