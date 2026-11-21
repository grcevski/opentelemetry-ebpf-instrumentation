// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <bpfcore/bpf_helpers.h>

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}
static inline long
bpf_loop(unsigned int n, int (*f)(unsigned int, void *), void *ctx, unsigned long long flags) {
    (void)flags;
    for (unsigned int i = 0; i < n; i++) {
        if (f(i, ctx)) {
            break;
        }
    }
    return 0;
}
static unsigned int writes, fail_at;
static bool fail_reads;
static long read_user(void *dst, unsigned int n, const void *src) {
    if (fail_reads) {
        return -EFAULT;
    }
    memcpy(dst, src, n);
    return 0;
}
static long write_user(void *dst, const void *src, unsigned int n) {
    if (++writes == fail_at) {
        return -EFAULT;
    }
    memcpy(dst, src, n);
    return 0;
}
#define bpf_probe_read_user read_user
#define bpf_probe_write_user write_user
#include <common/rust_http_buffer.h>

static unsigned char header_chunk[k_http1_read_chunk_bytes];
static unsigned char legacy_header[TRACE_BUF_SIZE];
static http1_header_scan_t header_scan;
static void *lookup_scratch(void *map, const void *key) {
    (void)key;
    if (map == &rust_http1_scan_storage) {
        return &header_scan;
    }
    if (map == &tp_char_buf_storage) {
        return legacy_header;
    }
    return map == &http1_header_buf_storage ? header_chunk : NULL;
}

static void test_forwarded_http1(bool use_bpf_loop) {
    const char original[] =
        "X-Test: keep\r\nTraceparent: 00-00000000000000000000000000000001-1111111111111111-01\r\n";
    const char expected[] =
        "X-Test: keep\r\nTraceparent: 00-00000000000000000000000000000001-0200000000000000-00\r\n";
    const tp_info_t wire = {
        .trace_id = {[TRACE_ID_SIZE_BYTES - 1] = 1}, .span_id = {2}, .flags = 0};
    g_bpf_traceparent_enabled = true;
    g_bpf_loop_enabled = use_bpf_loop;
    for (unsigned int fail = 0; fail <= 1; fail++) {
        unsigned char data[sizeof(original)];
        memcpy(data, original, sizeof(data));
        writes = 0;
        fail_at = fail;
        assert(rust_http1_rewrite_traceparent(
                   (u64)data, sizeof(data) - 1, &wire, g_bpf_loop_enabled) == !fail);
        assert(writes == 1);
        assert(memcmp(data, fail ? original : expected, sizeof(data)) == 0);
    }
    unsigned char missing[] = "X-Test: keep\r\n";
    writes = 0;
    fail_at = 0;
    assert(!rust_http1_rewrite_traceparent(
        (u64)missing, sizeof(missing) - 1, &wire, g_bpf_loop_enabled));
    assert(writes == 0);
    unsigned char embedded[] =
        "X-Test: traceparent: 00-00000000000000000000000000000001-1111111111111111-01\r\n";
    assert(!rust_http1_rewrite_traceparent(
        (u64)embedded, sizeof(embedded) - 1, &wire, g_bpf_loop_enabled));
    assert(writes == 0);
    g_bpf_traceparent_enabled = false;
}

static void test_large_forwarded_http1(void) {
    const unsigned char header[] =
        "Traceparent: 00-00000000000000000000000000000001-1111111111111111-01\r\n\r\n";
    const u32 offsets[] = {349,
                           350,
                           1000,
                           1020,
                           4090,
                           8190,
                           k_http1_max_header_bytes - TRACE_PARENT_HEADER_LEN,
                           k_http1_max_header_bytes - TRACE_PARENT_HEADER_LEN + 1};
    const tp_info_t wire = {.trace_id = {1}, .span_id = {2}, .flags = 0};
    g_bpf_traceparent_enabled = true;
    g_bpf_loop_enabled = true;
    fail_at = 0;
    for (u32 i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        unsigned char data[k_http1_max_header_bytes + sizeof(header)];
        const u32 offset = offsets[i];
        memset(data, 'a', offset);
        memcpy(data, "X-Padding: ", sizeof("X-Padding: ") - 1);
        memcpy(data + offset - 2, "\r\n", 2);
        memcpy(data + offset, header, sizeof(header));
        const u32 len = offset + sizeof(header) - 1;
        unsigned char expected[sizeof(data)];
        memcpy(expected, data, len);
        const bool fits = offset + TRACE_PARENT_HEADER_LEN <= k_http1_max_header_bytes;
        if (fits) {
            make_tp_string(expected + offset + TP_LOWER_SIZE, &wire);
        }
        writes = 0;
        assert(rust_http1_rewrite_traceparent((u64)data, len, &wire, g_bpf_loop_enabled) == fits);
        assert(writes == fits);
        assert(memcmp(data, expected, len) == 0);
        fail_reads = true;
        writes = 0;
        assert(!rust_http1_rewrite_traceparent((u64)data, len, &wire, g_bpf_loop_enabled));
        assert(writes == 0);
        fail_reads = false;
        memcpy(data + offset, header, sizeof(header));
        memcpy(expected, data, len);
        const bool legacy_fits = offset < 350;
        if (legacy_fits) {
            make_tp_string(expected + offset + TP_LOWER_SIZE, &wire);
        }
        g_bpf_loop_enabled = false;
        assert(rust_http1_rewrite_traceparent((u64)data, len, &wire, g_bpf_loop_enabled) ==
               legacy_fits);
        assert(writes == legacy_fits);
        assert(memcmp(data, expected, len) == 0);
        g_bpf_loop_enabled = true;
    }
    g_bpf_traceparent_enabled = false;
}

int main(void) {
    bpf_map_lookup_elem_hook = lookup_scratch;
    test_forwarded_http1(false);
    test_forwarded_http1(true);
    test_large_forwarded_http1();
    return 0;
}
