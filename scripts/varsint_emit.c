/**
 * @file varsint_emit.c
 * @brief Print one frame per signed value, written with dcf_ser_write_varsint
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 DeMoD LLC. All rights reserved.
 *
 * Output, one line per value:  <decimal value> <hex of the whole frame>
 * scripts/varsint_interop.py decodes these with its own LEB128 / ZigZag / CRC-32
 * (zlib) and compares them with the standard ZigZag vectors, so the check does not
 * share a line of code, or an assumption, with the library.
 */
#include "../dcf_serialize.h"

#include <stdint.h>
#include <stdio.h>

int main(void) {
    static const int64_t vals[] = {
        0, -1, 1, -2, 2, 63, -64, 64, -65, 8191, -8192, 1000000, -1000000,
        2147483647LL, -2147483647LL - 1, 4294967296LL, -4294967296LL,
        INT64_MAX, INT64_MIN, INT64_MAX - 1, INT64_MIN + 1,
    };
    for (size_t i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        DCFSerWriter w;
        const uint8_t* d;
        size_t n;
        if (dcf_ser_writer_init(&w, 1, 0) != DCF_SER_OK) return 2;
        if (dcf_ser_write_varsint(&w, vals[i]) != DCF_SER_OK) return 2;
        if (dcf_ser_writer_finish(&w, &d, &n) != DCF_SER_OK) return 2;
        printf("%lld ", (long long)vals[i]);
        for (size_t k = 0; k < n; k++) printf("%02x", d[k]);
        printf("\n");
        dcf_ser_writer_destroy(&w);
    }
    return 0;
}
