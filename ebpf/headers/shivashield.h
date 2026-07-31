/* SPDX-License-Identifier: MIT
 *
 * shivashield.h — Shared type definitions for ShivaShield XDP.
 *
 * This header is included by both the eBPF C program and (via bpf2go)
 * the Go userspace daemon.  Every struct here must be plain-old-data
 * with fixed-width integer types so the kernel verifier and Go's
 * unsafe.Sizeof agree on layout.
 *
 * Copyright (c) 2026 Shiva
 */

#ifndef __SHIVASHIELD_H__
#define __SHIVASHIELD_H__

/* ------------------------------------------------------------------ */
/*  Fixed-width types when compiled outside the kernel tree            */
/* ------------------------------------------------------------------ */
#ifdef __BPF__
#include "vmlinux.h"
#else
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t  __s32;
typedef int64_t  __s64;
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

/* Maximum entries for each map — tune for your RAM budget. */
#define MAX_RATE_ENTRIES    1000000  /* per-IP rate counters          */
#define MAX_FLOW_ENTRIES     500000  /* per-flow counters             */
#define MAX_BLACKLIST        100000  /* banned IPs                    */
#define MAX_WHITELIST         10000  /* permanently allowed IPs       */
#define MAX_KNOWN_IPS         100000  /* blackhole known-IPs (reduced) */
#define MAX_PORT_RULES          256  /* per-port rate rules           */
#define MAX_GEOIP_ENTRIES    200000  /* GeoIP LPM trie entries        */
#define MAX_EVENTS_RINGBUF  (1<<22) /* 4 MB ring buffer (was 1MB)    */
#define MAX_EVT_THROTTLE     200000  /* event throttle entries        */

/* Action verdicts (mirrored in Go). */
#define ACTION_PASS  0
#define ACTION_DROP  1

/* Event types emitted to the ring buffer. */
#define EVT_RATE_EXCEEDED    1
#define EVT_SYN_FLOOD        2
#define EVT_UDP_FLOOD        3
#define EVT_ICMP_FLOOD       4
#define EVT_FLOW_EXCEEDED    5
#define EVT_PORT_SCAN        6
#define EVT_AMPLIFICATION    7
#define EVT_GEOIP_BLOCKED    8
#define EVT_BLACKLISTED      9
#define EVT_BLACKHOLE_DROP  10
#define EVT_MALFORMED       11
#define EVT_NEW_SRC_FLOOD   12
#define EVT_IP_BANNED       13

/* IP version flags. */
#define AF_INET4  4
#define AF_INET6  6

/* Protocol numbers. */
#define PROTO_TCP   6
#define PROTO_UDP  17
#define PROTO_ICMP  1
#define PROTO_ICMPV6 58

/* TCP flags. */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

/* Port-scan detection: suspicious flag combinations. */
#define SCAN_NULL  0x00                        /* no flags            */
#define SCAN_FIN   TCP_FIN                     /* FIN only            */
#define SCAN_XMAS  (TCP_FIN | TCP_PSH | TCP_URG) /* FIN+PSH+URG     */

/* Well-known amplification ports. */
#define PORT_DNS       53
#define PORT_NTP      123
#define PORT_SSDP    1900
#define PORT_MEMCACHED 11211
#define PORT_CHARGEN   19
#define PORT_SNMP     161

/* Stats array indices. */
#define STATS_PASS_PKTS      0
#define STATS_DROP_PKTS      1
#define STATS_PASS_BYTES     2
#define STATS_DROP_BYTES     3
#define STATS_TCP_PKTS       4
#define STATS_UDP_PKTS       5
#define STATS_ICMP_PKTS      6
#define STATS_OTHER_PKTS     7
#define STATS_SYN_PKTS       8
#define STATS_DROP_BANNED    9
#define STATS_DROP_RATE      10
#define STATS_DROP_BOGUS_TCP 11
#define STATS_DROP_GEOIP     12
#define STATS_DROP_BLACKHOLE 13
#define STATS_DROP_SCAN      14
#define STATS_DROP_AMP       15
#define STATS_DROP_NONIPV4   16
#define STATS_MAX            17

/* ------------------------------------------------------------------ */
/*  Config pushed from userspace → config_map[0]                      */
/* ------------------------------------------------------------------ */
struct ss_config {
    __u64 pps;           /* max total pkts/s per source IP             */
    __u64 syn;           /* max TCP SYN/s per source IP                */
    __u64 udp;           /* max UDP pkts/s per source IP               */
    __u64 icmp;          /* max ICMP pkts/s per source IP              */
    __u64 new_src;       /* max new source IPs/s (global)              */
    __u64 flow_pps;      /* max pkts/s per 5-tuple flow                */
    __u64 flow_bps;      /* max bytes/s per 5-tuple flow               */
    __u32 ban_duration;  /* seconds to auto-ban (0 = no ban)           */
    __u32 blackhole;     /* 1 = blackhole mode active                  */
    __u32 geoip_enabled; /* 1 = GeoIP blocking active                  */
    __u32 port_scan_det; /* 1 = port-scan detection enabled            */
    __u32 amp_det;       /* 1 = amplification detection enabled        */
    __u32 _pad;          /* alignment padding                          */
};

/* ------------------------------------------------------------------ */
/*  IP address — supports both v4 and v6                              */
/* ------------------------------------------------------------------ */
struct ss_ipaddr {
    __u8  family;        /* AF_INET4 or AF_INET6                       */
    __u8  _pad[3];
    union {
        __u32 v4;        /* network byte order                         */
        __u32 v6[4];     /* 128-bit IPv6 in network byte order         */
    } addr;
};

/* ------------------------------------------------------------------ */
/*  Rate-limit counter (value in per-CPU LRU maps)                    */
/* ------------------------------------------------------------------ */
struct ss_rate_val {
    __u64 packets;       /* packets in the current window              */
    __u64 bytes;         /* bytes in the current window                */
    __u64 window_start;  /* ktime_ns when this window began            */
};

/* ------------------------------------------------------------------ */
/*  Flow key (5-tuple)                                                */
/* ------------------------------------------------------------------ */
struct ss_flow_key {
    struct ss_ipaddr src;
    struct ss_ipaddr dst;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  _pad[3];
};

/* ------------------------------------------------------------------ */
/*  Blacklist entry (value in blacklist_map)                          */
/* ------------------------------------------------------------------ */
struct ss_ban_val {
    __u64 expires_ns;    /* ktime_ns when the ban expires; 0=permanent */
    __u32 reason;        /* EVT_* that caused the ban                  */
    __u32 _pad;
};

/* ------------------------------------------------------------------ */
/*  Port rule (value in port_rules_map)                               */
/* ------------------------------------------------------------------ */
struct ss_port_rule_key {
    __u16 port;
    __u8  proto;         /* PROTO_TCP or PROTO_UDP                     */
    __u8  _pad;
};

struct ss_port_rule_val {
    __u64 pps;           /* max pkts/s to this port from one src       */
    __u64 bps;           /* max bytes/s to this port from one src      */
};

/* ------------------------------------------------------------------ */
/*  GeoIP LPM trie key                                                */
/* ------------------------------------------------------------------ */
struct ss_geoip_key {
    __u32 prefixlen;     /* number of significant bits                 */
    __u32 addr;          /* IPv4 address in network byte order         */
};

/* ------------------------------------------------------------------ */
/*  Event emitted via ring buffer to userspace                        */
/* ------------------------------------------------------------------ */
struct ss_event {
    __u64 timestamp_ns;  /* ktime_ns                                   */
    struct ss_ipaddr src;
    struct ss_ipaddr dst;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  ip_ver;        /* 4 or 6                                     */
    __u8  event_type;    /* EVT_*                                      */
    __u8  _pad;
    __u64 rate;          /* current rate that triggered the event       */
    __u64 threshold;     /* configured threshold that was exceeded      */
};

/* ------------------------------------------------------------------ */
/*  New-source tracking (global counter in a single-element array)    */
/* ------------------------------------------------------------------ */
struct ss_new_src_counter {
    __u64 count;
    __u64 window_start;
};

#endif /* __SHIVASHIELD_H__ */
