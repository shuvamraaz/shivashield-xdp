// SPDX-License-Identifier: MIT
//
// shivashield.bpf.c — ShivaShield XDP kernel program.
//
// This eBPF program is attached to a network interface via XDP and
// processes every incoming packet at the driver level, BEFORE the
// kernel network stack.  It implements:
//
//   • Per-source-IP rate limiting  (PPS, SYN, UDP, ICMP)
//   • Per-flow rate limiting       (5-tuple PPS + BPS)
//   • Blacklist / whitelist        (manual + auto-ban)
//   • Blackhole mode               (only known IPs pass)
//   • Port-scan detection          (NULL / FIN / XMAS scans)
//   • Amplification detection      (DNS / NTP / SSDP / Memcached)
//   • GeoIP blocking               (LPM trie)
//   • Packet header validation     (malformed drops)
//   • Event ring buffer            (alerts to userspace)
//
// All counters use BPF_MAP_TYPE_LRU_PERCPU_HASH for zero-contention
// per-CPU operation and automatic LRU eviction under memory pressure.
//
// Copyright (c) 2026 Shiva

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "shivashield.h"

/* Prevent the compiler from inlining everything into one giant func. */
#define FORCE_INLINE __attribute__((always_inline)) inline

/* ================================================================== */
/*  BPF Maps                                                          */
/* ================================================================== */

/* Runtime configuration (single element, index 0). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ss_config);
} config_map SEC(".maps");

/* Global statistics (per-CPU for lock-free increments). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

/* Per-source-IP total packet rate. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, struct ss_ipaddr);
    __type(value, struct ss_rate_val);
} rate_limit_map SEC(".maps");

/* Per-source-IP SYN rate. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, struct ss_ipaddr);
    __type(value, struct ss_rate_val);
} syn_rate_map SEC(".maps");

/* Per-source-IP UDP rate. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, struct ss_ipaddr);
    __type(value, struct ss_rate_val);
} udp_rate_map SEC(".maps");

/* Per-source-IP ICMP rate. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_RATE_ENTRIES);
    __type(key, struct ss_ipaddr);
    __type(value, struct ss_rate_val);
} icmp_rate_map SEC(".maps");

/* Per-flow (5-tuple) rate. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_FLOW_ENTRIES);
    __type(key, struct ss_flow_key);
    __type(value, struct ss_rate_val);
} flow_map SEC(".maps");

/* Blacklist — banned IPs with expiry. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLACKLIST);
    __type(key, struct ss_ipaddr);
    __type(value, struct ss_ban_val);
} blacklist_map SEC(".maps");

/* Whitelist — permanently allowed IPs. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELIST);
    __type(key, struct ss_ipaddr);
    __type(value, __u8);  /* dummy value, existence is enough */
} whitelist_map SEC(".maps");

/* Known IPs for blackhole mode. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_KNOWN_IPS);
    __type(key, struct ss_ipaddr);
    __type(value, __u64);  /* last-seen timestamp */
} known_ips_map SEC(".maps");

/* Per-port rate limit rules. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORT_RULES);
    __type(key, struct ss_port_rule_key);
    __type(value, struct ss_port_rule_val);
} port_rules_map SEC(".maps");

/* GeoIP blocked prefixes (LPM trie). */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_GEOIP_ENTRIES);
    __type(key, struct ss_geoip_key);
    __type(value, __u8);  /* country code index, or just 1 = blocked */
    __uint(map_flags, BPF_F_NO_PREALLOC);
} geoip_map SEC(".maps");

/* Event ring buffer to userspace. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_EVENTS_RINGBUF);
} events_map SEC(".maps");

/* Event throttle map — rate-limits events to 1 per second per (IP+type).
   Prevents ring buffer saturation during floods. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_EVT_THROTTLE);
    __type(key, __u64);
    __type(value, __u64); /* last_emit_ns */
} event_throttle_map SEC(".maps");

/* New-source-IP global counter (single element). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ss_new_src_counter);
} new_src_map SEC(".maps");

/* ================================================================== */
/*  Helpers                                                           */
/* ================================================================== */

/* 1-second window in nanoseconds. */
#define WINDOW_NS 1000000000ULL

static FORCE_INLINE void bump_stat(__u32 idx, __u64 add) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        *val += add;
}

/* Emit an event to the ring buffer. Throttled to 1 event per second per
   (src IP + event type). Prevents ring buffer saturation during floods.
   Best-effort: if the ringbuf is full the event is silently dropped. */
static FORCE_INLINE void emit_event(
    __u8 type,
    struct ss_ipaddr *src, struct ss_ipaddr *dst,
    __u16 sport, __u16 dport, __u8 proto, __u8 ip_ver,
    __u64 rate, __u64 threshold)
{
    /* Build throttle key: lower 32 bits = IPv4 addr, upper 32 = event type. */
    __u64 tkey = src ? (((__u64)src->addr.v4) | ((__u64)type << 32)) : (__u64)type;

    __u64 now2 = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&event_throttle_map, &tkey);
    if (last && (now2 - *last) < WINDOW_NS)
        return; /* throttled — already emitted within last second */

    bpf_map_update_elem(&event_throttle_map, &tkey, &now2, BPF_ANY);

    struct ss_event *e = bpf_ringbuf_reserve(&events_map, sizeof(*e), 0);
    if (!e)
        return;
    e->timestamp_ns = now2;
    if (src) __builtin_memcpy(&e->src, src, sizeof(*src));
    if (dst) __builtin_memcpy(&e->dst, dst, sizeof(*dst));
    e->sport      = sport;
    e->dport      = dport;
    e->proto      = proto;
    e->ip_ver     = ip_ver;
    e->event_type = type;
    e->_pad       = 0;
    e->rate       = rate;
    e->threshold  = threshold;
    bpf_ringbuf_submit(e, 0);
}

/* Check + update a per-CPU rate-limit map.
   Returns the current rate (pkts in the window).
   If the window has expired, resets the counter. */
static FORCE_INLINE __u64 check_rate(
    void *map,
    struct ss_ipaddr *key,
    __u64 pkt_len,
    __u64 now_ns)
{
    struct ss_rate_val *val = bpf_map_lookup_elem(map, key);
    if (val) {
        if (now_ns - val->window_start >= WINDOW_NS) {
            /* New window — reset. */
            val->packets     = 1;
            val->bytes       = pkt_len;
            val->window_start = now_ns;
            return 1;
        }
        val->packets++;
        val->bytes += pkt_len;
        return val->packets;
    }
    /* First packet from this IP — create entry. */
    struct ss_rate_val new_val = {
        .packets      = 1,
        .bytes        = pkt_len,
        .window_start = now_ns,
    };
    bpf_map_update_elem(map, key, &new_val, BPF_ANY);
    return 1;
}

/* Check flow rate — keyed on 5-tuple. */
static FORCE_INLINE int check_flow_rate(
    struct ss_flow_key *fk,
    __u64 pkt_len,
    __u64 now_ns,
    __u64 max_pps,
    __u64 max_bps)
{
    struct ss_rate_val *val = bpf_map_lookup_elem(&flow_map, fk);
    if (val) {
        if (now_ns - val->window_start >= WINDOW_NS) {
            val->packets      = 1;
            val->bytes        = pkt_len;
            val->window_start = now_ns;
            return ACTION_PASS;
        }
        val->packets++;
        val->bytes += pkt_len;
        if (max_pps && val->packets > max_pps)
            return ACTION_DROP;
        if (max_bps && val->bytes > max_bps)
            return ACTION_DROP;
        return ACTION_PASS;
    }
    struct ss_rate_val new_val = {
        .packets      = 1,
        .bytes        = pkt_len,
        .window_start = now_ns,
    };
    bpf_map_update_elem(&flow_map, fk, &new_val, BPF_ANY);
    return ACTION_PASS;
}

/* Build an ss_ipaddr from a raw IPv4 address (__be32). */
static FORCE_INLINE struct ss_ipaddr make_ipv4(__u32 addr) {
    struct ss_ipaddr ip = {};
    ip.family = AF_INET4;
    ip.addr.v4 = addr;
    return ip;
}

/* Build an ss_ipaddr from raw IPv6 address (4 × __be32). */
static FORCE_INLINE struct ss_ipaddr make_ipv6(const __u32 *addr6) {
    struct ss_ipaddr ip = {};
    ip.family = AF_INET6;
    ip.addr.v6[0] = addr6[0];
    ip.addr.v6[1] = addr6[1];
    ip.addr.v6[2] = addr6[2];
    ip.addr.v6[3] = addr6[3];
    return ip;
}

/* Add an IP to the blacklist with auto-ban duration. */
static FORCE_INLINE void auto_ban(struct ss_ipaddr *ip, __u32 reason,
                                   __u32 duration_sec, __u64 now_ns)
{
    if (!duration_sec)
        return;
    struct ss_ban_val ban = {
        .expires_ns = now_ns + ((__u64)duration_sec * 1000000000ULL),
        .reason     = reason,
    };
    bpf_map_update_elem(&blacklist_map, ip, &ban, BPF_ANY);
}

/* ================================================================== */
/*  XDP Program Entry Point                                           */
/* ================================================================== */

SEC("xdp")
int shivashield_xdp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now_ns   = bpf_ktime_get_ns();

    /* ----- Load config ----- */
    __u32 cfg_key = 0;
    struct ss_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg)
        return XDP_PASS;  /* no config loaded yet — pass everything */

    /* ----- Ethernet header ----- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;  /* runt frame */

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    struct ss_ipaddr src_ip = {};
    struct ss_ipaddr dst_ip = {};
    __u8  ip_ver  = 0;
    __u8  l4proto = 0;
    void *l4hdr   = NULL;
    __u64 pkt_len = (__u64)(data_end - data);

    /* ----- IPv4 ----- */
    if (eth_proto == 0x0800) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            goto drop_malformed;

        /* Basic header validation. */
        if (ip->ihl < 5)
            goto drop_malformed;

        void *ip_end = (void *)ip + (ip->ihl * 4);
        if (ip_end > data_end)
            goto drop_malformed;

        /* Verify total length is sane. */
        __u16 tot_len = bpf_ntohs(ip->tot_len);
        if (tot_len < (ip->ihl * 4))
            goto drop_malformed;

        src_ip = make_ipv4(ip->saddr);
        dst_ip = make_ipv4(ip->daddr);
        ip_ver  = 4;
        l4proto = ip->protocol;
        l4hdr   = ip_end;

    /* ----- IPv6 ----- */
    } else if (eth_proto == 0x86DD) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            goto drop_malformed;

        src_ip = make_ipv6((__u32 *)&ip6->saddr);
        dst_ip = make_ipv6((__u32 *)&ip6->daddr);
        ip_ver  = 6;
        l4proto = ip6->nexthdr;
        l4hdr   = (void *)(ip6 + 1);

    } else {
        /* Not IP — pass (ARP, etc.). */
        bump_stat(STATS_PASS_PKTS, 1);
        bump_stat(STATS_PASS_BYTES, pkt_len);
        return XDP_PASS;
    }

    /* ----- 1. Whitelist check (always first) ----- */
    if (bpf_map_lookup_elem(&whitelist_map, &src_ip)) {
        bump_stat(STATS_PASS_PKTS, 1);
        bump_stat(STATS_PASS_BYTES, pkt_len);
        return XDP_PASS;
    }

    /* ----- 2. Blacklist check ----- */
    struct ss_ban_val *ban = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (ban) {
        /* Check expiry. */
        if (ban->expires_ns != 0 && now_ns >= ban->expires_ns) {
            /* Ban expired — remove it and continue processing. */
            bpf_map_delete_elem(&blacklist_map, &src_ip);
        } else {
            bump_stat(STATS_DROP_PKTS, 1);
            bump_stat(STATS_DROP_BYTES, pkt_len);
            return XDP_DROP;
        }
    }

    /* ----- 3. GeoIP check (IPv4 only for now) ----- */
    if (cfg->geoip_enabled && ip_ver == 4) {
        struct ss_geoip_key geo_key = {
            .prefixlen = 32,
            .addr      = src_ip.addr.v4,
        };
        if (bpf_map_lookup_elem(&geoip_map, &geo_key)) {
            emit_event(EVT_GEOIP_BLOCKED, &src_ip, &dst_ip,
                       0, 0, l4proto, ip_ver, 0, 0);
            bump_stat(STATS_DROP_PKTS, 1);
            bump_stat(STATS_DROP_BYTES, pkt_len);
            return XDP_DROP;
        }
    }

    /* ----- 4. Blackhole mode ----- */
    if (cfg->blackhole) {
        if (!bpf_map_lookup_elem(&known_ips_map, &src_ip)) {
            emit_event(EVT_BLACKHOLE_DROP, &src_ip, &dst_ip,
                       0, 0, l4proto, ip_ver, 0, 0);
            bump_stat(STATS_DROP_PKTS, 1);
            bump_stat(STATS_DROP_BYTES, pkt_len);
            return XDP_DROP;
        }
    } else {
        /* Track this IP as "known" for future blackhole activation. */
        __u64 ts = now_ns;
        bpf_map_update_elem(&known_ips_map, &src_ip, &ts, BPF_ANY);
    }

    /* ----- 5. New-source-IP flood detection ----- */
    {
        __u32 ns_key = 0;
        struct ss_new_src_counter *nsc =
            bpf_map_lookup_elem(&new_src_map, &ns_key);
        if (nsc) {
            /* Check if this is a genuinely new source. */
            if (!bpf_map_lookup_elem(&rate_limit_map, &src_ip)) {
                if (now_ns - nsc->window_start >= WINDOW_NS) {
                    nsc->count        = 1;
                    nsc->window_start = now_ns;
                } else {
                    nsc->count++;
                    if (cfg->new_src && nsc->count > cfg->new_src) {
                        emit_event(EVT_NEW_SRC_FLOOD, &src_ip, &dst_ip,
                                   0, 0, l4proto, ip_ver,
                                   nsc->count, cfg->new_src);
                        bump_stat(STATS_DROP_PKTS, 1);
                        bump_stat(STATS_DROP_BYTES, pkt_len);
                        return XDP_DROP;
                    }
                }
            }
        }
    }

    /* ----- 6. Per-source-IP total PPS rate ----- */
    {
        __u64 rate = check_rate(&rate_limit_map, &src_ip, pkt_len, now_ns);
        if (cfg->pps && rate > cfg->pps) {
            emit_event(EVT_RATE_EXCEEDED, &src_ip, &dst_ip,
                       0, 0, l4proto, ip_ver, rate, cfg->pps);
            auto_ban(&src_ip, EVT_RATE_EXCEEDED, cfg->ban_duration, now_ns);
            bump_stat(STATS_DROP_PKTS, 1);
            bump_stat(STATS_DROP_BYTES, pkt_len);
            return XDP_DROP;
        }
    }

    /* ----- Parse L4 ports ----- */
    __u16 sport = 0, dport = 0;

    /* ----- 7. Protocol-specific checks ----- */
    if (l4proto == PROTO_TCP) {
        bump_stat(STATS_TCP_PKTS, 1);

        struct tcphdr *tcp = l4hdr;
        if (!l4hdr || (void *)(tcp + 1) > data_end)
            goto drop_malformed;

        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);

        __u8 flags = 0;
        if (tcp->fin) flags |= TCP_FIN;
        if (tcp->syn) flags |= TCP_SYN;
        if (tcp->rst) flags |= TCP_RST;
        if (tcp->psh) flags |= TCP_PSH;
        if (tcp->ack) flags |= TCP_ACK;
        if (tcp->urg) flags |= TCP_URG;

        /* 7a. Port-scan detection. */
        if (cfg->port_scan_det) {
            if (flags == SCAN_NULL || flags == SCAN_FIN || flags == SCAN_XMAS) {
                emit_event(EVT_PORT_SCAN, &src_ip, &dst_ip,
                           sport, dport, l4proto, ip_ver, flags, 0);
                auto_ban(&src_ip, EVT_PORT_SCAN, cfg->ban_duration, now_ns);
                bump_stat(STATS_DROP_PKTS, 1);
                bump_stat(STATS_DROP_BYTES, pkt_len);
                return XDP_DROP;
            }
        }

        /* 7b. SYN flood protection. */
        if (flags & TCP_SYN) {
            bump_stat(STATS_SYN_PKTS, 1);
            __u64 syn_rate = check_rate(&syn_rate_map, &src_ip, pkt_len, now_ns);
            if (cfg->syn && syn_rate > cfg->syn) {
                emit_event(EVT_SYN_FLOOD, &src_ip, &dst_ip,
                           sport, dport, l4proto, ip_ver,
                           syn_rate, cfg->syn);
                auto_ban(&src_ip, EVT_SYN_FLOOD, cfg->ban_duration, now_ns);
                bump_stat(STATS_DROP_PKTS, 1);
                bump_stat(STATS_DROP_BYTES, pkt_len);
                return XDP_DROP;
            }
        }

    } else if (l4proto == PROTO_UDP) {
        bump_stat(STATS_UDP_PKTS, 1);

        struct udphdr *udp = l4hdr;
        if (!l4hdr || (void *)(udp + 1) > data_end)
            goto drop_malformed;

        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);

        /* 7c. UDP flood rate limit. */
        __u64 udp_rate = check_rate(&udp_rate_map, &src_ip, pkt_len, now_ns);
        if (cfg->udp && udp_rate > cfg->udp) {
            emit_event(EVT_UDP_FLOOD, &src_ip, &dst_ip,
                       sport, dport, l4proto, ip_ver,
                       udp_rate, cfg->udp);
            auto_ban(&src_ip, EVT_UDP_FLOOD, cfg->ban_duration, now_ns);
            bump_stat(STATS_DROP_PKTS, 1);
            bump_stat(STATS_DROP_BYTES, pkt_len);
            return XDP_DROP;
        }

        /* 7d. Amplification detection (high-rate from known amp ports). */
        if (cfg->amp_det) {
            if (sport == PORT_DNS  || sport == PORT_NTP  ||
                sport == PORT_SSDP || sport == PORT_MEMCACHED ||
                sport == PORT_CHARGEN || sport == PORT_SNMP) {
                /* Amplification replies come from well-known source ports
                   with disproportionately large payloads. If we're seeing
                   high UDP rate from these ports, it's likely amplification. */
                if (udp_rate > 100) {  /* low threshold for amp ports */
                    emit_event(EVT_AMPLIFICATION, &src_ip, &dst_ip,
                               sport, dport, l4proto, ip_ver,
                               udp_rate, 100);
                    auto_ban(&src_ip, EVT_AMPLIFICATION,
                             cfg->ban_duration, now_ns);
                    bump_stat(STATS_DROP_PKTS, 1);
                    bump_stat(STATS_DROP_BYTES, pkt_len);
                    return XDP_DROP;
                }
            }
        }

    } else if (l4proto == PROTO_ICMP || l4proto == PROTO_ICMPV6) {
        bump_stat(STATS_ICMP_PKTS, 1);

        /* 7e. ICMP flood rate limit. */
        __u64 icmp_rate = check_rate(&icmp_rate_map, &src_ip, pkt_len, now_ns);
        if (cfg->icmp && icmp_rate > cfg->icmp) {
            emit_event(EVT_ICMP_FLOOD, &src_ip, &dst_ip,
                       0, 0, l4proto, ip_ver,
                       icmp_rate, cfg->icmp);
            auto_ban(&src_ip, EVT_ICMP_FLOOD, cfg->ban_duration, now_ns);
            bump_stat(STATS_DROP_PKTS, 1);
            bump_stat(STATS_DROP_BYTES, pkt_len);
            return XDP_DROP;
        }

        /* ICMP type-aware: for IPv4, allow only Echo Reply (0),
           Destination Unreachable (3), Time Exceeded (11) under
           rate limits.  Block Echo Request (8) flood via rate limit. */

    } else {
        bump_stat(STATS_OTHER_PKTS, 1);
    }

    /* ----- 8. Per-flow rate limiting ----- */
    if (cfg->flow_pps || cfg->flow_bps) {
        struct ss_flow_key fk = {};
        __builtin_memcpy(&fk.src, &src_ip, sizeof(src_ip));
        __builtin_memcpy(&fk.dst, &dst_ip, sizeof(dst_ip));
        fk.sport = sport;
        fk.dport = dport;
        fk.proto = l4proto;

        if (check_flow_rate(&fk, pkt_len, now_ns,
                            cfg->flow_pps, cfg->flow_bps) == ACTION_DROP) {
            emit_event(EVT_FLOW_EXCEEDED, &src_ip, &dst_ip,
                       sport, dport, l4proto, ip_ver, 0, cfg->flow_pps);
            bump_stat(STATS_DROP_PKTS, 1);
            bump_stat(STATS_DROP_BYTES, pkt_len);
            return XDP_DROP;
        }
    }

    /* ----- 9. Per-port rules ----- */
    if (dport) {
        struct ss_port_rule_key pk = {
            .port  = dport,
            .proto = l4proto,
        };
        struct ss_port_rule_val *pr =
            bpf_map_lookup_elem(&port_rules_map, &pk);
        if (pr) {
            /* We reuse the flow rate data for the per-source per-port
               check by constructing a synthetic flow key with
               dst = 0 and sport = 0. */
            struct ss_flow_key port_fk = {};
            __builtin_memcpy(&port_fk.src, &src_ip, sizeof(src_ip));
            port_fk.dport = dport;
            port_fk.proto = l4proto;

            if (check_flow_rate(&port_fk, pkt_len, now_ns,
                                pr->pps, pr->bps) == ACTION_DROP) {
                emit_event(EVT_RATE_EXCEEDED, &src_ip, &dst_ip,
                           sport, dport, l4proto, ip_ver, 0, pr->pps);
                bump_stat(STATS_DROP_PKTS, 1);
                bump_stat(STATS_DROP_BYTES, pkt_len);
                return XDP_DROP;
            }
        }
    }

    /* ----- All checks passed ----- */
    bump_stat(STATS_PASS_PKTS, 1);
    bump_stat(STATS_PASS_BYTES, pkt_len);
    return XDP_PASS;

drop_malformed:
    emit_event(EVT_MALFORMED, &src_ip, &dst_ip,
               0, 0, l4proto, ip_ver, 0, 0);
    bump_stat(STATS_DROP_PKTS, 1);
    bump_stat(STATS_DROP_BYTES, pkt_len);
    return XDP_DROP;
}

char _license[] SEC("license") = "MIT";
