// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <logger/bpf_dbg.h>

#include <pid/pid.h>

SEC("uprobe/libpython3.so:context_run")
int BPF_UPROBE(obi_uprobe_context_run, void *context) {
    (void)ctx;

    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    // find the current trace key for this thread, this is the thread that runs a new python context
    // trace_key_t t_key = {0};
    // task_tid(&t_key.p_key);
    // t_key.extra_id = extra_runtime_id();

    // make a new map in a map file (maps directory), that contains key context, value the trace key.
    // (u64)context -> trace_key_t (client thread)
    // current_python_context_map

    bpf_dbg_printk("=== uprobe Python context_run id=%d =%llx ===", id, context);

    return 0;
}

SEC("uprobe/libpython3.so:copy_current_ret")
int BPF_UPROBE(obi_uprobe_copy_current_ret, void *context) {
    (void)ctx;

    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe Python PyContext_CopyCurrent id=%d =%llx ===", id, context);

    // find the current trace key for this thread, this is the thread that creates a new context, the parent thread
    // trace_key_t t_key = {0};
    // task_tid(&t_key.p_key);
    // t_key.extra_id = extra_runtime_id();

    // make a new map in a map file (maps directory), that contains key context, value the trace key.
    // (u64)context -> trace_key_t (parent thread)
    // parent_context_map

    return 0;
}