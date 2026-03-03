// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <pid/maps/map_sizing.h>
#include <pid/types/pid_metadata.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, k_max_concurrent_pids);
    __type(key, u32);
    __type(value, pid_metadata_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} pid_names SEC(".maps");
