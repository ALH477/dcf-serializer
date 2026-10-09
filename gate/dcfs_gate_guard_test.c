/**
 * @file dcfs_gate_guard_test.c
 * @brief The trap guard around the Exsecutor gate: contained, thread-local, restored
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
 *
 * The gate is written not to trap, so the guard cannot be exercised by feeding
 * it frames. These tests drive it with a deliberate trap (dcfs_gate_guard_selftest)
 * and check what a network-facing host needs:
 *   - a trap inside a guarded call RETURNS (it does not end the process);
 *   - the guard is spent and the thread's state is clean afterwards;
 *   - the gate still answers correctly after a trap;
 *   - eight threads trapping and judging concurrently never see each other's guard;
 *   - a trap with NO guard active still abort()s (fail-stop is the default).
 * Linked against the static library: dcfs_gate_trap has hidden visibility.
 */
#define _POSIX_C_SOURCE 200809L
#include "../dcf_serialize.h"
#include "dcfs_gate_host.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern void dcfs_gate_trap(unsigned kind);

static unsigned char good[64];
static size_t good_len;

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", #c, __FILE__, __LINE__); return 1; } } while (0)

static int one_round(unsigned kind) {
    CHECK(dcfs_gate_guard_selftest(kind) == 1);
    uint8_t v = 99;
    CHECK(dcfs_gate_judge(good, good_len, &v) == DCFS_GATE_ADMIT && v == 0);
    unsigned char bad[64];
    memcpy(bad, good, good_len);
    bad[good_len - 1] ^= 0x40;
    CHECK(dcfs_gate_judge(bad, good_len, &v) == DCFS_GATE_REJECT && v == 8);
    return 0;
}

typedef struct { int id; int failed; } Worker;

static void* worker(void* p) {
    Worker* w = (Worker*)p;
    for (int i = 0; i < 20000; i++) {
        if (one_round((unsigned)(1 + (i + w->id) % 5))) { w->failed = 1; break; }
    }
    return NULL;
}

int main(void) {
    printf("=== DCFS gate guard ===\n");
    DCFSerWriter w;
    if (dcf_ser_writer_init(&w, 1, 0) != DCF_SER_OK) return 2;
    dcf_ser_write_u8(&w, 9);
    dcf_ser_write_string(&w, "ok");
    const uint8_t* d; size_t n;
    if (dcf_ser_writer_finish(&w, &d, &n) != DCF_SER_OK || n > sizeof good) return 2;
    memcpy(good, d, n);
    good_len = n;
    dcf_ser_writer_destroy(&w);

    int failures = 0;

    /* 1. a trap returns, whatever its kind, including the kind-0 that must not read as success */
    for (unsigned kind = 0; kind <= 9; kind++) failures += one_round(kind);
    printf("  %s  trap kinds 0..9 each return to the caller; the gate answers before and after\n", failures ? "FAIL" : "PASS");

    /* 2. threads */
    enum { T = 8 };
    pthread_t th[T];
    Worker ws[T];
    int tf = 0;
    for (int i = 0; i < T; i++) { ws[i].id = i; ws[i].failed = 0; if (pthread_create(&th[i], NULL, worker, &ws[i])) tf++; }
    for (int i = 0; i < T; i++) { pthread_join(th[i], NULL); tf += ws[i].failed; }
    printf("  %s  8 threads x 20000 rounds of (trap, admit, refuse), each on its own guard\n", tf ? "FAIL" : "PASS");
    failures += tf;
    failures += one_round(3);

    /* 3. no guard: fail-stop */
    pid_t pid = fork();
    if (pid == 0) {
        if (!freopen("/dev/null", "w", stderr)) _exit(3);
        dcfs_gate_trap(3);
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    int aborted = WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT;
    printf("  %s  a trap with no guard active abort()s (as every Exsecutor host does by default)\n", aborted ? "PASS" : "FAIL");
    failures += !aborted;

    printf(failures ? "=== FAIL ===\n" : "=== PASS ===\n");
    return failures ? 1 : 0;
}
