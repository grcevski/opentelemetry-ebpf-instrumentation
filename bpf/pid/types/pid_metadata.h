// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum { k_pid_metadata_len = 64 };

typedef struct pid_metadata {
    unsigned char buf[k_pid_metadata_len];
    u32 len;
} pid_metadata_t;
