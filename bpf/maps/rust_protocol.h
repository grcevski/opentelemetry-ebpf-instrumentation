// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <maps/rust_tasks.h>
#include <common/connection_info.h>

enum rust_message_layout : u8 {
    k_rust_message_callback = 1,
    k_rust_message_list = 2,
    k_rust_message_request = 4,
};

typedef struct rust_protocol_config {
    u32 vec_ptr;
    u32 vec_len;
    u32 vec_cap;
    u32 request_headers;
    u32 header_entries;
    u32 header_count;
    u32 bucket_size;
    u32 name_ptr;
    u32 name_len;
    u32 value_ptr;
    u32 value_len;
    u32 list_head;
    u32 list_index;
    u32 slot_mask;
    u32 message_tx_tag;
    u32 message_tx_some;
    u32 message_tx_pointer;
    u32 message_rx_tag;
    u32 message_rx_some;
    u32 message_rx_pointer;
    u32 message_rx_headers;
    u8 http1;
    u8 inject;
    u8 message;
    u8 _pad;
} rust_protocol_config_t;

typedef struct rust_wire_key {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    u32 pid;
} rust_wire_key_t;

enum rust_injection_result : u8 {
    k_rust_injection_none = 0,
    k_rust_injection_succeeded = 1,
    k_rust_injection_skipped = 2,
    k_rust_injection_application_owned = 3,
};

typedef struct rust_http_request {
    tp_info_t wire;
    tp_info_pid_t parent;
    u8 inject;
    u8 injection_result;
    u8 observed;
    u8 forwarded;
    u8 _pad[4];
} rust_http_request_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_task_key_t);
    __type(value, rust_http_request_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_http1_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, rust_protocol_config_t);
    __uint(max_entries, k_max_rust_processes);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_protocol_configs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_wire_key_t);
    __type(value, tp_info_pid_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_wire_parents SEC(".maps");
