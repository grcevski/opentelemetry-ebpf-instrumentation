// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "bpfcore/utils.h"
#include "bpfcore/vmlinux_amd64.h"
#include "generictracer/protocol_common.h"
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/egress_key.h>
#include <common/http_buf_size.h>
#include <common/http_types.h>
#include <common/msg_buffer.h>
#include <common/scratch_mem.h>
#include <common/ssl_helpers.h>
#include <common/tc_common.h>
#include <common/tp_info.h>
#include <common/trace_common.h>
#include <common/trace_util.h>
#include <common/tracing.h>

#include <generictracer/protocol_http.h>
#include <generictracer/protocol_tcp.h>
#include <generictracer/protocol_http2.h>

#include <logger/bpf_dbg.h>

#include <maps/incoming_trace_map.h>
#include <maps/msg_buffers.h>
#include <maps/sock_dir.h>

#include <tpinjector/maps/sk_tp_info_pid_map.h>

#include <pid/types/pid_metadata.h>
#include <pid/maps/pid_metadata_storage.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Flags to control what tpinjector should inject
enum {
    k_inject_http_headers = 1 << 0, // Bit 0: inject HTTP headers
    k_inject_tcp_options = 1 << 1,  // Bit 1: inject TCP options
};

volatile const u32 inject_flags =
    k_inject_http_headers | k_inject_tcp_options; // default: both enabled

// TCP option kind for OpenTelemetry context propagation
// Kind 25 is unassigned per IANA TCP Parameters registry (released 2000-12-18)
// Better than experimental options (253-254) which must not be shipped as defaults
enum { k_tcp_option_kind_otel = 25 };

const char obi_ctx[] = "Obi-Context: \r\n";
const u32 k_inject_metadata_header_len = sizeof(obi_ctx) - 1;

enum { k_protocol_detect_request = 1, k_protocol_detect_response = 2 };

enum {
    k_tail_write_msg_traceparent,
    k_tail_find_existing_tp,
    k_tail_create_tp,
    k_tail_extend_and_write_tp,
    k_tail_extend_and_write_response,
    k_tail_write_response_metadata,
};

int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg);
int obi_packet_extender_find_existing_tp(struct sk_msg_md *msg);
int obi_packet_extender_create_tp(struct sk_msg_md *msg);
int obi_extend_and_write_tp(struct sk_msg_md *msg);
int obi_extend_and_write_response(struct sk_msg_md *msg);
int obi_write_response_metadata(struct sk_msg_md *msg);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 6);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} extender_jump_table SEC(".maps") = {
    .values =
        {
            [k_tail_extend_and_write_tp] = (void *)&obi_extend_and_write_tp,
            [k_tail_extend_and_write_response] = (void *)&obi_extend_and_write_response,
            [k_tail_write_response_metadata] = (void *)&obi_write_response_metadata,
            [k_tail_write_msg_traceparent] = (void *)&obi_packet_extender_write_msg_tp,
            [k_tail_find_existing_tp] = (void *)&obi_packet_extender_find_existing_tp,
            [k_tail_create_tp] = (void *)&obi_packet_extender_create_tp,
        },
};

typedef struct tailcall_ctx {
    pid_connection_info_t p_conn;
    tp_info_t parent_tp;
    egress_key_t e_key;
    u32 write_offset;
    u8 niter;
    bool has_parent_tp;
    u8 pad[6];
} tailcall_ctx;

SCRATCH_MEM(tailcall_ctx);
SCRATCH_MEM_SIZED(tp_str_buf, 64)

#ifndef ENOMSG
#define ENOMSG 42
#endif

struct tp_option {
    u8 kind;
    u8 len;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
};

static __always_inline const char *tp_string_from_opt(const struct tp_option *opt) {
    unsigned char *buf = tp_str_buf_mem();

    if (!buf) {
        return NULL;
    }

    unsigned char *ptr = buf;

    // Version
    *ptr++ = '0';
    *ptr++ = '0';
    *ptr++ = '-';

    // Trace ID
    encode_hex(ptr, opt->trace_id, TRACE_ID_SIZE_BYTES);
    ptr += TRACE_ID_CHAR_LEN;

    *ptr++ = '-';

    // SpanID
    encode_hex(ptr, opt->span_id, SPAN_ID_SIZE_BYTES);
    ptr += SPAN_ID_CHAR_LEN;

    *ptr++ = '-';

    *ptr++ = '0';
    *ptr++ = '\0';

    return (const char *)buf;
}

static __always_inline void print_tp(const char *msg, const tp_info_t *tp) {
    if (!g_bpf_debug) {
        return;
    }

    unsigned char tp_buf_str[TP_MAX_VAL_LENGTH];
    make_tp_string(tp_buf_str, tp);
    bpf_dbg_printk("%s: %s", msg, tp_buf_str);
}

static __always_inline egress_key_t make_key(const connection_info_t *conn) {
    egress_key_t e_key = {
        .d_port = conn->d_port,
        .s_port = conn->s_port,
    };

    sort_egress_key(&e_key);

    return e_key;
}

// This is setup here for Go and SSL tracking.
// Essentially, when the Go or the OpenSSL userspace
// probes activate for an outgoing HTTP request they setup this
// outgoing_trace_map for us. We then know this is a connection we should
// be injecting the Traceparent in. Another place which sets up this map is
// the kprobe on tcp_sendmsg, however that happens after the sock_msg runs,
// so we have a different detection for that - protocol_detector.
static __always_inline tp_info_pid_t *get_tp_info_pid(const egress_key_t *e_key) {
    return bpf_map_lookup_elem(&outgoing_trace_map, e_key);
}

static __always_inline void set_tp_info_pid(const egress_key_t *e_key, const tp_info_pid_t *tp_p) {
    bpf_map_update_elem(&outgoing_trace_map, e_key, tp_p, BPF_ANY);
}

static __always_inline void clear_tp_info_pid(const egress_key_t *e_key) {
    bpf_map_delete_elem(&outgoing_trace_map, e_key);
}

static __always_inline u8 already_tracked(const pid_connection_info_t *p_conn, const u8 type) {
    return already_tracked_http(p_conn, type) || already_tracked_tcp(p_conn) ||
           already_tracked_http2(p_conn);
}

// Extracts what we need for connection_info_t from bpf_sock_ops if the
// communication is IPv4
static __always_inline connection_info_t sk_ops_extract_key_ip4(struct bpf_sock_ops *ops) {
    connection_info_t conn = {};

    const u32 local_ip4 = ops->local_ip4;
    const u32 remote_ip4 = ops->remote_ip4;
    const u32 local_port = ops->local_port;
    const u32 remote_port = bpf_ntohl(ops->remote_port);

    __builtin_memcpy(conn.s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.s_ip[3] = local_ip4;
    __builtin_memcpy(conn.d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.d_ip[3] = remote_ip4;

    conn.s_port = local_port;
    conn.d_port = remote_port;

    return conn;
}

// Extracts what we need for connection_info_t from bpf_sock_ops if the
// communication is IPv6
// The order of copying the data from bpf_sock_ops matters and must match how
// the struct is laid in vmlinux.h, otherwise the verifier thinks we are modifying
// the context twice.
static __always_inline connection_info_t sk_ops_extract_key_ip6(struct bpf_sock_ops *ops) {
    connection_info_t conn = {};

    conn.d_ip[0] = ops->remote_ip6[0];
    conn.d_ip[1] = ops->remote_ip6[1];
    conn.d_ip[2] = ops->remote_ip6[2];
    conn.d_ip[3] = ops->remote_ip6[3];
    conn.s_ip[0] = ops->local_ip6[0];
    conn.s_ip[1] = ops->local_ip6[1];
    conn.s_ip[2] = ops->local_ip6[2];
    conn.s_ip[3] = ops->local_ip6[3];

    const u32 local_port = ops->local_port;
    const u32 remote_port = bpf_ntohl(ops->remote_port);

    conn.d_port = remote_port;
    conn.s_port = local_port;

    return conn;
}

static __always_inline connection_info_t get_connection_info_ops(struct bpf_sock_ops *ops) {
    return ops->family == AF_INET6 ? sk_ops_extract_key_ip6(ops) : sk_ops_extract_key_ip4(ops);
}

// Extracts what we need for connection_info_t from sk_msg_md if the
// communication is IPv4
static __always_inline connection_info_t sk_msg_extract_key_ip4(const struct sk_msg_md *msg) {
    connection_info_t conn = {};

    __builtin_memcpy(conn.s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.s_ip[3] = msg->local_ip4;
    __builtin_memcpy(conn.d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.d_ip[3] = msg->remote_ip4;

    conn.s_port = msg->local_port;
    conn.d_port = bpf_ntohl(msg->remote_port);

    return conn;
}

// Extracts what we need for connection_info_t from sk_msg_md if the
// communication is IPv6
// The order of copying the data from bpf_sock_ops matters and must match how
// the struct is laid in vmlinux.h, otherwise the verifier thinks we are modifying
// the context twice.
static __always_inline connection_info_t sk_msg_extract_key_ip6(struct sk_msg_md *msg) {
    connection_info_t conn = {};

    sk_msg_read_remote_ip6(msg, conn.d_ip);
    sk_msg_read_local_ip6(msg, conn.s_ip);

    conn.d_port = bpf_ntohl(sk_msg_remote_port(msg));
    conn.s_port = sk_msg_local_port(msg);

    return conn;
}

static __always_inline void init_tp_ctx_parent_tp(tailcall_ctx *t_ctx) {
    t_ctx->parent_tp.ts = bpf_ktime_get_ns();
    t_ctx->parent_tp.flags = 1;

    t_ctx->has_parent_tp = find_parent_trace_for_client_request(
        &t_ctx->p_conn, t_ctx->p_conn.conn.d_port, &t_ctx->parent_tp);
}

static __always_inline bool create_trace_info(const tailcall_ctx *t_ctx, tp_info_pid_t *tp_p) {
    // t_ctx->parent_tp was initialised earlier in init_tp_ctx_parent_tp - if
    // t_ctx->has_parent_tp is true, then it actually contains a valid tp_info
    // with the corrent trace_id and parent_id - all we need to do is generate
    // a new span_id
    // this logic is cumbersome, but it is done so to avoid calling
    // find_trace_for_client_request multiple times (i.e. once here, and once
    // earlier in  k_tail_find_existing_tp - sorry!
    urand_bytes(tp_p->tp.span_id, sizeof(tp_p->tp.span_id));
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->pid = t_ctx->p_conn.pid;
    tp_p->req_type = EVENT_HTTP_CLIENT;

    if (t_ctx->has_parent_tp) {
        bpf_dbg_printk("found existing tp info");

        __builtin_memcpy(tp_p->tp.trace_id, t_ctx->parent_tp.trace_id, sizeof(tp_p->tp.trace_id));
        __builtin_memcpy(tp_p->tp.parent_id, t_ctx->parent_tp.span_id, sizeof(tp_p->tp.parent_id));
    } else {
        bpf_dbg_printk("generating tp info");

        new_trace_id(&tp_p->tp);
        __builtin_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    }

    return true;
}

static __always_inline void bpf_sock_ops_set_flags(struct bpf_sock_ops *skops, u8 flags) {
    bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | flags);
}

// Helper that writes in the sock map for a sock_ops program
static __always_inline void bpf_sock_ops_active_est_cb(struct bpf_sock_ops *skops) {
    const u64 cookie = bpf_get_socket_cookie(skops);

    bpf_sock_hash_update(skops, &sock_dir, (void *)&cookie, BPF_ANY);
    bpf_sock_ops_set_flags(skops, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
}

static __always_inline void bpf_sock_ops_passive_est_cb(struct bpf_sock_ops *skops) {
    const u64 cookie = bpf_get_socket_cookie(skops);

    bpf_sock_hash_update(skops, &sock_dir, (void *)&cookie, BPF_ANY);
    bpf_sock_ops_set_flags(skops, BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG);
}

static __always_inline void bpf_sock_ops_opt_len_cb(struct bpf_sock_ops *skops) {
    struct bpf_sock *sk = skops->sk;

    if (!sk) {
        return;
    }

    tp_info_pid_t *tp_pid = bpf_sk_storage_get(&sk_tp_info_pid_map, sk, NULL, 0);

    if (!tp_pid) {
        return;
    }

    const long ret = bpf_reserve_hdr_opt(skops, sizeof(struct tp_option), 0);

    if (ret != 0) {
        bpf_dbg_printk("failed to reserve TCP option: %d", ret);
        return;
    }
}

static __always_inline void bpf_sock_ops_write_hdr_cb(struct bpf_sock_ops *skops) {
    struct bpf_sock *sk = skops->sk;

    if (!sk) {
        return;
    }

    const tp_info_pid_t *tp_pid = bpf_sk_storage_get(&sk_tp_info_pid_map, sk, NULL, 0);

    if (!tp_pid) {
        bpf_dbg_printk("tp info not found");
        return;
    }

    // cleanup the storage to prevent it from being written more than once
    // (including during responses);
    bpf_sk_storage_delete(&sk_tp_info_pid_map, sk);

    struct tp_option opt = {.kind = k_tcp_option_kind_otel, .len = sizeof(struct tp_option)};

    __builtin_memcpy(opt.trace_id, tp_pid->tp.trace_id, sizeof(opt.trace_id));
    __builtin_memcpy(opt.span_id, tp_pid->tp.span_id, sizeof(opt.span_id));

    const long ret = bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0);

    if (ret != 0) {
        bpf_dbg_printk("failed to store option: %d", ret);
    }

    if (g_bpf_debug) {
        const char *tp_str = tp_string_from_opt(&opt);

        if (tp_str) {
            bpf_dbg_printk("written TP to TCP options: %s", tp_str);
        }
    }
}

static __always_inline void bpf_sock_ops_parse_hdr_cb(struct bpf_sock_ops *skops) {
    struct tp_option opt = {};
    opt.kind = k_tcp_option_kind_otel;

    const long ret = bpf_load_hdr_opt(skops, &opt, sizeof(opt), 0);

    if (ret == -ENOMSG) {
        return;
    }

    if (ret < 0) {
        bpf_dbg_printk("error parsing TCP option: %d", ret);
        return;
    }

    if (g_bpf_debug) {
        const char *tp_str = tp_string_from_opt(&opt);

        if (tp_str) {
            bpf_dbg_printk("found TP in TCP options: %s", tp_str);
        }
    }

    tp_info_pid_t tp = {};
    tp.valid = 1;

    __builtin_memcpy(tp.tp.trace_id, opt.trace_id, sizeof(tp.tp.trace_id));
    __builtin_memcpy(tp.tp.span_id, opt.span_id, sizeof(tp.tp.span_id));

    connection_info_t conn = get_connection_info_ops(skops);
    sort_connection_info(&conn);

    dbg_print_http_connection_info(&conn);
    bpf_map_update_elem(&incoming_trace_map, &conn, &tp, BPF_ANY);
}

// Tracks all outgoing sockets (BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
// We don't track incoming, those would be BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
SEC("sockops")
int obi_sockmap_tracker(struct bpf_sock_ops *skops) {
    struct bpf_sock *sk = skops->sk;

    if (!sk) {
        return 1;
    }

    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        bpf_sock_ops_active_est_cb(skops);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        bpf_sock_ops_passive_est_cb(skops);
        break;
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
        bpf_sock_ops_opt_len_cb(skops);
        break;
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
        bpf_sock_ops_write_hdr_cb(skops);
        break;
    case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
        bpf_sock_ops_parse_hdr_cb(skops);
        break;
    default:
        break;
    }

    return 1;
}

// This code is copied from the kprobe on tcp_sendmsg and it's called from
// the sock_msg program, which does the packet extension for injecting the
// Traceparent. Since the sock_msg runs before the kprobe on tcp_sendmsg, we
// need to extend the packet before we'll have the opportunity to setup the
// outgoing_trace_map metadata. We can directly perhaps run the same code that
// the kprobe on tcp_sendmsg does, but it's complicated, no tail calls from
// sock_msg programs and inlining will eventually hit us with the instruction
// limit when we eventually add HTTP2/gRPC support.
static __always_inline u8 protocol_detector(struct sk_msg_md *msg,
                                            u64 id,
                                            const connection_info_t *conn,
                                            const egress_key_t *e_key) {
    bpf_dbg_printk("id=%d, size=%d", id, msg->size);

    pid_connection_info_t p_conn = {};
    __builtin_memcpy(&p_conn.conn, conn, sizeof(connection_info_t));

    dbg_print_http_connection_info(&p_conn.conn);
    sort_connection_info(&p_conn.conn);
    p_conn.pid = pid_from_pid_tgid(id);

    if (msg->size == 0 || is_ssl_connection(&p_conn)) {
        return 0;
    }

    msg_buffer_t msg_buf = {
        .pos = 0,
        .real_size = msg->size > k_msg_buffer_size_max ? k_msg_buffer_size_max : msg->size,
        .cpu_id = bpf_get_smp_processor_id(),
    };

    bpf_probe_read_kernel(msg_buf.fallback_buf, k_kprobes_http2_buf_size, msg->data);

    const u16 copy_bytes =
        msg_buf.real_size > k_kprobes_http2_buf_size ? msg_buf.real_size : k_kprobes_http2_buf_size;

    unsigned char **msg_ptr = bpf_map_lookup_elem(&msg_buffer_mem, &(u32){0});

    if (!msg_ptr) {
        bpf_d_printk("failed to reserve msg_buffer space [%s]", __FUNCTION__);
        return 0;
    }

    msg_ptr[0] = 0;
    bpf_probe_read_kernel(msg_ptr, copy_bytes & k_msg_buffer_size_max_mask, msg->data);
    bpf_map_update_elem(&msg_buffer_mem, &(u32){0}, msg_ptr, BPF_ANY);

    // We setup any call that looks like HTTP request to be extended.
    // This must match exactly to what the decision will be for
    // the kprobe program on tcp_sendmsg, which sets up the
    // outgoing_trace_map data used by Traffic Control to write the
    // actual 'Traceparent:...' string.

    if (bpf_map_update_elem(&msg_buffers, e_key, &msg_buf, BPF_ANY)) {
        // fail if we can't setup a msg buffer
        return 0;
    }

    u8 pkt_type = PACKET_TYPE_REQUEST;

    u8 is_response = is_http_response_buf((const unsigned char *)msg_ptr);
    if (is_response) {
        pkt_type = PACKET_TYPE_RESPONSE;
    }

    // We should check if we have already seen this request and we've
    // started tracking it. We only want to extend the first packet that
    // looks like HTTP, not something that's passing HTTP in the body.
    if (already_tracked(&p_conn, pkt_type)) {
        bpf_dbg_printk("already extended before, ignoring this packet...");
        return 0;
    }

    if (is_http_request_buf((const unsigned char *)msg_ptr)) {
        bpf_dbg_printk("setting up request to be extended");

        return k_protocol_detect_request;
    }

    if (is_response) {
        return k_protocol_detect_response;
    }

    return 0;
}

static __always_inline connection_info_t get_connection_info(struct sk_msg_md *msg) {
    return msg->family == AF_INET6 ? sk_msg_extract_key_ip6(msg) : sk_msg_extract_key_ip4(msg);
}

static __always_inline void
write_metadata_buffer(unsigned char *buf, pid_metadata_t *metadata, u32 metadata_len) {
    *buf++ = 'O';
    *buf++ = 'b';
    *buf++ = 'i';
    *buf++ = '-';
    *buf++ = 'C';
    *buf++ = 'o';
    *buf++ = 'n';
    *buf++ = 't';
    *buf++ = 'e';
    *buf++ = 'x';
    *buf++ = 't';
    *buf++ = ':';
    *buf++ = ' ';

    u32 len = metadata_len;
    bpf_clamp_umax(len, k_pid_metadata_len);

    for (u32 i = 0; i < len; i++) {
        unsigned char p = metadata->buf[i];
        *buf++ = p;
    }

    *buf++ = '\r';
    *buf++ = '\n';
}

static __always_inline void make_tp_string_skb(unsigned char *buf,
                                               const tp_info_t *tp,
                                               pid_metadata_t *metadata,
                                               u32 metadata_len,
                                               const unsigned char *end) {
    asm volatile("" : "=r"(buf) : "0"(buf));

    const __attribute__((unused)) unsigned char *tp_string = buf;

    *buf++ = 'T';
    *buf++ = 'r';
    *buf++ = 'a';
    *buf++ = 'c';
    *buf++ = 'e';
    *buf++ = 'p';
    *buf++ = 'a';
    *buf++ = 'r';
    *buf++ = 'e';
    *buf++ = 'n';
    *buf++ = 't';
    *buf++ = ':';
    *buf++ = ' ';

    // Version
    *buf++ = '0';
    *buf++ = '0';
    if ((void *)buf + TP_SIZE + 12 > (void *)end) {
        return;
    }
    *buf++ = '-';

    // Trace ID
    encode_hex(buf, tp->trace_id, TRACE_ID_SIZE_BYTES);
    buf += TRACE_ID_CHAR_LEN;

    if ((void *)buf + TP_SIZE + 12 > (void *)end) {
        return;
    }
    *buf++ = '-';

    // SpanID
    encode_hex(buf, tp->span_id, SPAN_ID_SIZE_BYTES);
    buf += SPAN_ID_CHAR_LEN;

    *buf++ = '-';

    *buf++ = '0';
    *buf++ = (tp->flags == 0) ? '0' : '1';
    *buf++ = '\r';
    *buf++ = '\n';

    if (metadata) {
        write_metadata_buffer(buf, metadata, metadata_len);
    }

    bpf_dbg_printk("tp_string=%s", tp_string);
}

static __always_inline void
make_metadata_string_skb(unsigned char *buf, pid_metadata_t *metadata, u32 metadata_len) {
    asm volatile("" : "=r"(buf) : "0"(buf));

    const __attribute__((unused)) unsigned char *tp_string = buf;

    write_metadata_buffer(buf, metadata, metadata_len);

    bpf_dbg_printk("metadata_string=%s", tp_string);
}

SEC("sk_msg")
int obi_extend_and_write_tp(struct sk_msg_md *msg) {
    unsigned char *data = ctx_msg_data(msg);

    if (!data) {
        return SK_PASS;
    }

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return SK_PASS;
    }

    const u64 id = bpf_get_current_pid_tgid();
    const u32 host_pid = pid_from_pid_tgid(id);

    u32 expand_size = TP_SIZE;
    pid_metadata_t *metadata = bpf_map_lookup_elem(&pid_names, &host_pid);
    u32 metadata_len = 0;
    if (metadata) {
        bpf_d_printk("found metadata, size=%d!", metadata->len);
        if (metadata->len < 16) {
            metadata_len = 16;
        } else if (metadata->len < 32) {
            metadata_len = 32;
        } else {
            metadata_len = k_pid_metadata_len;
        }
        expand_size += k_inject_metadata_header_len + metadata_len;
    }

    const long err = bpf_msg_push_data(msg, t_ctx->write_offset, expand_size, 0);

    bpf_clamp_umax(expand_size, 256);

    if (err != 0) {
        bpf_d_printk("failed to push data: %d [%s]", err, __FUNCTION__);
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);
    bpf_dbg_printk("offset to split=%d, available=%u, size=%u",
                   t_ctx->write_offset,
                   msg->data_end - msg->data,
                   msg->size);

    if (!msg->data) {
        bpf_d_printk("null data [%s]", __FUNCTION__);
        return SK_PASS;
    }

    u32 off = t_ctx->write_offset;
    bpf_clamp_umax(off, 4096);

    unsigned char *ptr = msg->data + off;

    if ((void *)ptr + TP_SIZE + metadata_len + k_inject_metadata_header_len >= msg->data_end) {
        bpf_d_printk("not enough space [%s]", __FUNCTION__);
        return SK_PASS;
    }

    make_tp_string_skb(ptr, &tp_p->tp, metadata, metadata_len, msg->data_end);

    return SK_PASS;
}

SEC("sk_msg")
int obi_extend_and_write_response(struct sk_msg_md *msg) {
    unsigned char *data = ctx_msg_data(msg);

    if (!data) {
        return SK_PASS;
    }

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    u32 write_offset = t_ctx->write_offset;

    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return SK_PASS;
    }

    const u64 id = bpf_get_current_pid_tgid();
    const u32 host_pid = pid_from_pid_tgid(id);

    pid_metadata_t *metadata = bpf_map_lookup_elem(&pid_names, &host_pid);
    if (!metadata) {
        return SK_PASS;
    }
    bpf_printk("found metadata, size=%d!", metadata->len);

    u32 extra_len = k_pid_metadata_len;
    if (metadata->len < 16) {
        extra_len = 16;
    } else if (metadata->len < 32) {
        extra_len = 32;
    }

    u32 expand_size = k_inject_metadata_header_len + extra_len;

    const long err = bpf_msg_push_data(msg, write_offset, expand_size, 0);

    bpf_clamp_umax(expand_size, 256);

    if (err != 0) {
        bpf_d_printk("failed to push data: %d [%s]", err, __FUNCTION__);
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);
    bpf_dbg_printk("offset to split=%d, available=%u, size=%u",
                   write_offset,
                   msg->data_end - msg->data,
                   msg->size);

    if (!msg->data) {
        bpf_d_printk("null data [%s]", __FUNCTION__);
        return SK_PASS;
    }

    bpf_clamp_umax(write_offset, 4096);

    unsigned char *ptr = msg->data + write_offset;

    if ((void *)ptr + expand_size + k_inject_metadata_header_len >= msg->data_end) {
        bpf_d_printk("not enough space [%s]", __FUNCTION__);
        return SK_PASS;
    }

    make_metadata_string_skb(ptr, metadata, extra_len);

    return SK_PASS;
}

SEC("sk_msg")
int obi_write_response_metadata(struct sk_msg_md *msg) {
    unsigned char *data = ctx_msg_data(msg);

    if (!data) {
        return SK_PASS;
    }

    const u32 newline_pos = find_first_pos_of(data, ctx_msg_data_end(msg), '\n');

    if (newline_pos == INVALID_POS) {
        return false;
    }

    u32 write_offset = newline_pos + 1;

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return false;
    }

    t_ctx->write_offset = write_offset;

    bpf_tail_call_static(msg, &extender_jump_table, k_tail_extend_and_write_response);

    return SK_PASS;
}

static __always_inline bool write_msg_traceparent(struct sk_msg_md *msg) {
    unsigned char *data = ctx_msg_data(msg);

    if (!data) {
        return false;
    }

    const u32 newline_pos = find_first_pos_of(data, ctx_msg_data_end(msg), '\n');

    if (newline_pos == INVALID_POS) {
        return false;
    }

    const u32 write_offset = newline_pos + 1;

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return false;
    }

    t_ctx->write_offset = write_offset;

    bpf_tail_call_static(msg, &extender_jump_table, k_tail_extend_and_write_tp);

    bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
    return true;
}

static __always_inline void schedule_write_tcp_option(struct sk_msg_md *msg, tp_info_pid_t *tp_p) {
    struct bpf_sock *sk = msg->sk;

    if (!sk) {
        return;
    }

    tp_info_pid_t *stp =
        bpf_sk_storage_get(&sk_tp_info_pid_map, sk, NULL, BPF_SK_STORAGE_GET_F_CREATE);

    if (!stp) {
        return;
    }

    // associate it also with this socket for the tcp options program
    *stp = *tp_p;

    tp_p->written = 1;
}

static __always_inline void write_http_traceparent(struct sk_msg_md *msg, tp_info_pid_t *tp_pid) {
    // used for the upcoming tailcall
    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return;
    }

    tp_pid->written = 1;
    *tp_p = *tp_pid;

    bpf_tail_call_static(msg, &extender_jump_table, k_tail_write_msg_traceparent);

    bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
}

static __always_inline void handle_existing_tp_pid(struct sk_msg_md *msg,
                                                   u64 id,
                                                   const connection_info_t *conn,
                                                   const egress_key_t *e_key,
                                                   tp_info_pid_t *tp_pid) {
    if (inject_flags & k_inject_tcp_options) {
        schedule_write_tcp_option(msg, tp_pid);
    }

    // shortcut: if valid == 0, this is not a HTTP request (likely SSL, but
    // could be anything really - don't bother with protocol_detector)
    if (tp_pid->valid == 0) {
        clear_tp_info_pid(e_key);
        return;
    }

    // check if this really is a HTTP request whose headers we can also extend
    // (it could be an SSL packet instead, or just rubbish, for instance)
    const bool is_http = protocol_detector(msg, id, conn, e_key);

    if (is_http == k_protocol_detect_request) {
        // here we'll leave it for protocol_http clean it up
        if (inject_flags & k_inject_http_headers) {
            write_http_traceparent(msg, tp_pid);
        }
    } else {
        clear_tp_info_pid(e_key);
    }
}

// Sock_msg program which detects packets where it should add space for
// the 'Traceparent' string. It extends the HTTP header and writes the
// Traceparent string.
SEC("sk_msg")
int obi_packet_extender(struct sk_msg_md *msg) {
    // If neither injection method is enabled, nothing to do
    if (!(inject_flags & (k_inject_http_headers | k_inject_tcp_options))) {
        return SK_PASS;
    }

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    const u64 id = bpf_get_current_pid_tgid();
    const connection_info_t conn = get_connection_info(msg);
    const egress_key_t e_key = make_key(&conn);

    t_ctx->p_conn.conn = conn;
    t_ctx->p_conn.pid = pid_from_pid_tgid(id);
    t_ctx->e_key = e_key;
    t_ctx->niter = 0;

    tp_info_pid_t *tp_pid = get_tp_info_pid(&e_key);

    // Higher-level uprobes have already set the tp_pid for us (either Go, or SSL)
    if (tp_pid) {
        handle_existing_tp_pid(msg, id, &conn, &e_key, tp_pid);
        return SK_PASS;
    }

    // At this stage, there were no previously TP information setup - it's the first
    // time we are seeing this packet - so we need to detect whether this is the start
    // of a new request and perform any injection if so.
    // Valid PID only works for kprobes since Go programs don't add their
    // PIDs to the PID map (we instrument the binaries), handled in the
    // previous check
    if (!valid_pid(id)) {
        return SK_PASS;
    }

    bpf_dbg_printk("MSG=%llx:%d ->", conn.s_ip[3], conn.s_port);
    bpf_dbg_printk("MSG TO=%llx:%d", conn.d_ip[3], conn.d_port);
    bpf_dbg_printk("MSG SIZE=%u", msg->size);

    if (msg->size <= MIN_HTTP_SIZE) {
        // not enough data to detect anything, bail
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    // TODO: execute the protocol handlers here with tail calls, don't
    // rely on tcp_sendmsg to do it and record these message buffers.

    const u8 is_http = protocol_detector(msg, id, &conn, &e_key);

    // at this point, we can't handle anything other than HTTP, as we need to be able
    // to tell whether this is the start of a new request
    if (!is_http) {
        return SK_PASS;
    }

    // at this point we've found the start of a new HTTP request

    bpf_dbg_printk("len=%d, s_port=%d", msg->size, msg->local_port);
    bpf_dbg_printk("buf=[%s]", msg->data);
    bpf_dbg_printk("ptr=%llx, end=%llx", ctx_msg_data(msg), ctx_msg_data_end(msg));
    bpf_dbg_printk("BUF=[%s]", ctx_msg_data(msg));

    init_tp_ctx_parent_tp(t_ctx);

    if (is_http == k_protocol_detect_response) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_write_response_metadata);
    } else {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_find_existing_tp);
    }

    return SK_PASS;
}

//k_tail_write_msg_traceparent
SEC("sk_msg")
int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("=== sk_msg ===");

    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        bpf_dbg_printk("empty tp_buf");
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    if (!write_msg_traceparent(msg)) {
        bpf_d_printk("failed to write traceparent [%s]", __FUNCTION__);
    }

    print_tp("written TP to headers", &tp_p->tp);
    bpf_dbg_printk("BUF=[%s]", msg->data);

    return SK_PASS;
}

static __always_inline void
assign_parent_tp(const tailcall_ctx *t_ctx, tp_info_t *tp, unsigned char *span_id) {
    if (!t_ctx->has_parent_tp) {
        return;
    }

    // test if the trace ids are equal - if they aren't, we don't
    // assign a parent
    if (__bpf_memcmp(tp->trace_id, t_ctx->parent_tp.trace_id, TRACE_ID_SIZE_BYTES) != 0) {
        return;
    }

    __builtin_memcpy(tp->parent_id, t_ctx->parent_tp.span_id, SPAN_ID_SIZE_BYTES);

    // check if the TP we parsed is a legimate one, or a
    // proxy-forwarded header - in which case we need to
    // override it
    if (__bpf_memcmp(tp->span_id, t_ctx->parent_tp.parent_id, SPAN_ID_SIZE_BYTES) != 0) {
        return;
    }

    // at this point, the span id of this outgoing call is equal to the span
    // id of the parent call (i.e. the Traceparent header is the same), which
    // hints it's being forwarded by some kind of proxy - in this case, we
    // generate a new span id and overwrite the header

    bpf_dbg_printk("detected forwarded TP header, overriding span id");

    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);

    encode_hex(span_id, tp->span_id, SPAN_ID_SIZE_BYTES);
}

//k_tail_find_existing_tp
SEC("sk_msg")
int obi_packet_extender_find_existing_tp(struct sk_msg_md *msg) {
    const u32 k_max_iter = 4; // iterate up to 4KB

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return SK_PASS;
    }

    const u32 niter = t_ctx->niter;

    if (niter >= k_max_iter) {
        return SK_PASS;
    }

    unsigned char *b = msg->data;
    const unsigned char *e = msg->data_end;
    unsigned char *ptr = b + (niter * 1024);

    if (ptr >= e) {
        return SK_PASS;
    }

    bpf_dbg_printk("looking for traceparent header (iter=%u)", niter);

    const u32 data_size = (e - ptr) & 0x3ff; // 1KB chunks per iteration

    for (u32 i = 0; i < data_size; ++i) {
        if ((ptr + TP_SIZE >= e) || is_eoh(ptr)) {
            bpf_tail_call_static(msg, &extender_jump_table, k_tail_create_tp);
            break;
        }

        if (is_traceparent(ptr)) {
            ptr += TP_TID_PREFIX_SIZE;

            decode_hex(tp_p->tp.trace_id, ptr, TRACE_ID_CHAR_LEN);

            ptr += TRACE_ID_CHAR_LEN;

            if (*ptr++ != '-') {
                return SK_PASS;
            }

            decode_hex(tp_p->tp.span_id, ptr, SPAN_ID_CHAR_LEN);

            unsigned char *span_id = ptr;

            ptr += SPAN_ID_CHAR_LEN;

            if (*ptr++ != '-') {
                return SK_PASS;
            }

            decode_hex((unsigned char *)&tp_p->tp.flags, ptr, FLAGS_CHAR_LEN);

            ptr += FLAGS_CHAR_LEN;

            if (*ptr++ != '\r' || *ptr != '\n') {
                return SK_PASS;
            }

            // if we got to this point, we managed to parse a valid
            // 'Traceparent: ...' header that we can utilise

            assign_parent_tp(t_ctx, &tp_p->tp, span_id);

            tp_p->tp.ts = bpf_ktime_get_ns();
            tp_p->tp.flags = 1;
            tp_p->valid = 1;
            tp_p->written = 1;
            tp_p->pid = t_ctx->p_conn.pid;
            tp_p->req_type = EVENT_HTTP_CLIENT;

            print_tp("found TP in headers", &tp_p->tp);

            set_tp_info_pid(&t_ctx->e_key, tp_p);

            if (inject_flags & k_inject_tcp_options) {
                schedule_write_tcp_option(msg, tp_p);
            }

            return SK_PASS;
        }

        ++ptr;
    }

    t_ctx->niter++;

    if (t_ctx->niter < k_max_iter) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_find_existing_tp);
    } else {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_create_tp);
    }

    return SK_PASS;
}

//k_tail_create_tp
SEC("sk_msg")
int obi_packet_extender_create_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return SK_PASS;
    }

    if (!create_trace_info(t_ctx, tp_p)) {
        return SK_PASS;
    }

    tp_p->written = 1;

    // associate this tp_info to this request
    set_tp_info_pid(&t_ctx->e_key, tp_p);

    if (inject_flags & k_inject_tcp_options) {
        schedule_write_tcp_option(msg, tp_p);
    }

    if (inject_flags & k_inject_http_headers) {
        // write the HTTP headers
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_write_msg_traceparent);
        bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
    }

    return SK_PASS;
}
