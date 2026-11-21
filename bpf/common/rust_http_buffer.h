// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/http1_traceparent.h>
#include <common/tracing.h>
#include <logger/bpf_dbg.h>
#include <maps/rust_protocol.h>
#include <maps/tp_char_buf_mem.h>

enum { k_rust_max_buffer = 1 << 24 };

SCRATCH_MEM_TYPED(rust_http1_scan, http1_header_scan_t);

typedef struct rust_http_args {
    rust_http_request_t request;
    u64 buffer;
    u64 start_len;
} rust_http_args_t;

static __always_inline bool rust_read_u64(u64 object, u32 offset, u64 *value) {
    return object && bpf_probe_read_user(value, sizeof(*value), (void *)(object + offset)) == 0;
}

// Keep the bounded scan separate from task bookkeeping for the verifier.
static __noinline bool
rust_http1_rewrite_traceparent_loop(u64 address, u64 len, const tp_info_t *wire) {
    if (!g_bpf_traceparent_enabled || !g_bpf_loop_enabled) {
        return false;
    }

    // Callback byte accesses to a stack-resident header can conflict with register spills.
    http1_header_scan_t *scan = rust_http1_scan_mem();
    if (!scan) {
        return false;
    }

    __builtin_memset(scan, 0, sizeof(*scan));
    scan->phase = k_http1_header_name;
    const u32 scanned_len = min(len, (u64)k_http1_max_header_bytes);
    http1_read_headers(scan, (const unsigned char *)address, scanned_len, k_http1_memory_user);

    if (!scan->valid || scan->value_length != TP_MAX_VAL_LENGTH) {
        return false;
    }

    if (scan->bytes < TP_MAX_VAL_LENGTH || scan->bytes > scanned_len) {
        return false;
    }

    // The scanner stops after the last value byte, including when a value crosses chunks.
    const u32 offset = scan->bytes - TP_MAX_VAL_LENGTH;
    unsigned char *value = scan->header + TP_LOWER_SIZE;
    make_tp_string(value, wire);

    return bpf_probe_write_user((void *)(address + offset), value, TP_MAX_VAL_LENGTH) == 0;
}

static __noinline bool
rust_http1_rewrite_traceparent_legacy(u64 address, u64 len, const tp_info_t *wire) {
    if (!g_bpf_traceparent_enabled || len < TRACE_PARENT_HEADER_LEN) {
        return false;
    }

    unsigned char *buf = tp_char_buf_mem();
    if (!buf) {
        return false;
    }

    u32 captured = min(len, TRACE_BUF_SIZE - 1);
    bpf_clamp_umax(captured, TRACE_BUF_SIZE - 1);
    if (bpf_probe_read_user(buf, captured, (void *)address) != 0) {
        return false;
    }
    buf[captured] = '\0';

    unsigned char *header = bpf_strstr_tp_loop__legacy(buf, captured);
    if (!header) {
        return false;
    }

    u32 offset = header - buf;
    if (offset > captured - TRACE_PARENT_HEADER_LEN) {
        return false;
    }

    bpf_clamp_umax(offset, TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN);

    if (offset) {
        u32 previous = offset - 1;
        bpf_clamp_umax(previous, TRACE_BUF_SIZE - 1);
        if (buf[previous] != '\n') {
            return false;
        }
    }

    unsigned char *value = buf + offset + TP_LOWER_SIZE;
    make_tp_string(value, wire);
    return bpf_probe_write_user(
               (void *)(address + offset + TP_LOWER_SIZE), value, TP_MAX_VAL_LENGTH) == 0;
}

static __always_inline bool
rust_http1_rewrite_traceparent(u64 address, u64 len, const tp_info_t *wire, bool use_bpf_loop) {
    if (use_bpf_loop) {
        return rust_http1_rewrite_traceparent_loop(address, len, wire);
    }
    return rust_http1_rewrite_traceparent_legacy(address, len, wire);
}
